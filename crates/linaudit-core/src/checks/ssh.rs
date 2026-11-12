//! category: ssh — port de checks.d/20-ssh.sh.
//! Configuración efectiva de OpenSSH (`sshd -T`). Si `sshd -T` no funciona (típicamente sin root),
//! cae a un parseo estático de los archivos, sin defaults y sin bloques Match.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use super::Context;
use super::util::{check_file_perm, command_output, file_mode, find_command, glob, mode_within};
use crate::model::{Emitter, ResultExt, Severity::{self, *}};
use crate::tr;

/// Tope de anidamiento de `Include` (como el límite de sshd): corta ciclos para no desbordar la pila.
const MAX_INCLUDE_DEPTH: u32 = 16;

/// Tope global de archivos de config procesados por una auditoría estática. El `Include` de sshd
/// admite globs y un árbol auditado hostil puede plantar muchísimos drop-ins (y hacerlos incluirse
/// unos a otros) para inflar el trabajo a lo ancho, no en profundidad: el tope de profundidad no lo
/// acota. Al superarse se deja de expandir (fail-safe: no se lee más, se conserva lo ya parseado).
/// 512 cubre de sobra cualquier `sshd_config.d/` legítimo (decenas de archivos como mucho).
const MAX_INCLUDE_FILES: usize = 512;

/// Tope de bytes que se leen de un archivo de config. Un árbol auditado hostil podría plantar un
/// archivo regular enorme que, slurpeado entero, agotaría la memoria del auditor. Los que superan
/// este tamaño se omiten; una config normal (unos pocos KB) se lee completa. 4 MiB es holgado.
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// Presupuesto ACUMULADO de bytes de contenido bufferizados a lo largo de TODA la expansión de
/// `Include`. El tope por archivo (`MAX_FILE_BYTES`) y el de número de archivos (`MAX_INCLUDE_FILES`)
/// no acotan el pico real de memoria: un `sshd_config.d/` hostil con miles de archivos de ~4 MiB
/// cada uno haría que la capa de colección (`resolve_include`) slurpeara (nº de entradas x 4 MiB)
/// a la vez, acotado sólo por el tamaño del directorio -> OOM. Este presupuesto se contabiliza EN
/// la capa de colección a medida que se lee cada archivo (uno a uno, de forma perezosa): al
/// rebasarlo se deja de leer y se marca `truncated`. Como nunca se decrementa, el total de bytes
/// jamás bufferizado en la expansión entera queda acotado (~`MAX_TOTAL_BYTES` + un archivo), de modo
/// que el pico de memoria está acotado con independencia del tamaño del directorio o del fan-out.
/// 64 MiB cubre de sobra cualquier `sshd_config.d/` legítimo (unos pocos KB en total).
const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;

/// Estado compartido a través de la recursión de `Include`: archivos ya procesados (dedup por ruta
/// canónica) y cuántos se han procesado en total. El dedup colapsa el fan-out de exponencial a
/// lineal (cada archivo distinto se procesa a lo sumo una vez) y además rompe ciclos de include.
#[derive(Default)]
struct IngestState {
    visited: HashSet<PathBuf>,
    files: usize,
    /// Bytes de contenido ya bufferizados por la capa de colección en toda la expansión. Se pasa a
    /// `resolve_include` como punto de partida de su presupuesto y se acumula con lo que cada
    /// resolución bufferiza (incluido lo que el dedup descarte luego), nunca se decrementa: así el
    /// total jamás leído queda acotado a `MAX_TOTAL_BYTES` y el pico de memoria no depende del
    /// tamaño del directorio.
    total_bytes: u64,
    /// true si la expansión se truncó: se omitió un archivo de config que SÍ estaba presente,
    /// sea por el tope global de archivos (`MAX_INCLUDE_FILES`) o por el tope de bytes de
    /// `read_bounded` (un regular que superó `MAX_FILE_BYTES`, o ilegible). Un archivo AUSENTE
    /// no cuenta: una config que no existe es normal, no un parseo incompleto. Cuando esto es
    /// true, las claves ausentes caerían a su default y NO deben reportarse como un PASS firme.
    truncated: bool,
    /// Claves (normalizadas a minúsculas) cuya PRIMERA aparición se fijó DESPUÉS de que ya se
    /// hubiera producido un skip (`truncated` ya true). En el layout habitual (Debian/Ubuntu) el
    /// `Include /etc/ssh/sshd_config.d/*.conf` va cerca del PRINCIPIO, antes del cuerpo: si un
    /// drop-in presente de ahí se omite por un tope, sshd igualmente lo leería PRIMERO y podría
    /// sobrescribir cualquier valor que el principal fije MÁS ABAJO con "gana la primera aparición".
    /// Por eso el valor parseado de esas claves no es de confianza (el drop-in omitido, de mayor
    /// precedencia, pudo haberlas pisado) y se marcan contaminadas. Una clave fijada ANTES de
    /// cualquier skip sí es autoritativa y NO se contamina.
    tainted: HashSet<String>,
}

/// Resultado de resolver un patrón `Include`: los archivos leídos como pares `(ruta, contenido)`
/// y si se omitió alguno que SÍ estaba presente (p. ej. un regular que superó `MAX_FILE_BYTES`).
/// Un objetivo ausente o fuera de `fs_root` no marca `truncated`: no es un parseo truncado.
#[derive(Default)]
pub struct Resolved {
    pub files: Vec<(PathBuf, String)>,
    pub truncated: bool,
}

/// Configuración de sshd: clave en minúsculas -> valor.
#[derive(Debug, Default, Clone)]
pub struct SshdConfig {
    values: HashMap<String, String>,
    /// true si salió del parseo estático (sin defaults de sshd ni Match).
    pub is_static: bool,
    /// true si el parseo estático quedó incompleto: se omitió un drop-in presente (tope de bytes o
    /// de archivos). Con esto puesto, una clave ausente caería a su default seguro y produciría un
    /// PASS falso; `evaluate_config` degrada esos veredictos a indeterminados en vez de a PASS.
    pub truncated: bool,
    /// Claves (en minúsculas) cuyo valor parseado NO es de confianza: su primera aparición se fijó
    /// después de un skip, de modo que un drop-in omitido de mayor precedencia pudo haberlas pisado.
    /// `evaluate_config` las trata como indeterminadas (WARN), igual que si estuvieran ausentes.
    tainted: HashSet<String>,
}

impl SshdConfig {
    /// Salida de `sshd -T`: una línea `clave valor` por opción, claves ya en minúsculas.
    pub fn from_sshd_t(out: &str) -> Self {
        let mut values = HashMap::new();
        for line in out.lines() {
            let mut it = line.splitn(2, ' ');
            if let (Some(k), Some(v)) = (it.next(), it.next()) {
                values.entry(k.to_ascii_lowercase()).or_insert_with(|| v.trim().to_string());
            }
        }
        SshdConfig { values, is_static: false, truncated: false, tainted: HashSet::new() }
    }

    /// Parseo estático partiendo de sshd_config, expandiendo cada `Include` en su posición
    /// (como sshd): gana la primera aparición de cada clave y se corta en el primer `Match`.
    /// `resolve` entrega, por cada patrón `Include`, los archivos que casan como pares
    /// `(ruta canónica, contenido)` en orden léxico. La ruta identifica el archivo para el dedup.
    ///
    /// Esto respeta la precedencia real de sshd: un valor fijado en el archivo principal ANTES del
    /// `Include` gana sobre el drop-in; los drop-in sólo ganan cuando el `Include` aparece antes del
    /// ajuste. No se asume que los drop-in siempre prevalecen.
    pub fn from_main<F: Fn(&str, usize, u64) -> Resolved>(main: &str, resolve: &F) -> Self {
        let mut values = HashMap::new();
        let mut state = IngestState::default();
        Self::ingest(main, resolve, &mut values, 0, &mut state);
        SshdConfig { values, is_static: true, truncated: state.truncated, tainted: state.tainted }
    }

    /// Procesa un texto de config línea a línea, expandiendo `Include` en su posición y aplicando
    /// "gana la primera aparición". Devuelve true si se encontró un `Match` (señal de corte global).
    /// `depth` acota el anidamiento de `Include`: una config que se auto-incluye (ciclo) desbordaría
    /// la pila, así que al pasar el tope se ignora el `Include` (igual que el límite de sshd).
    /// `state` dedup por ruta canónica (cada archivo se procesa como mucho una vez, lo que convierte
    /// el fan-out exponencial en lineal) y acota el total de archivos; juntos hacen que la expansión
    /// converja aunque el árbol auditado sea hostil.
    fn ingest<F: Fn(&str, usize, u64) -> Resolved>(
        text: &str,
        resolve: &F,
        values: &mut HashMap<String, String>,
        depth: u32,
        state: &mut IngestState,
    ) -> bool {
        for line in text.lines() {
            let mut words = line.split_whitespace();
            let Some(k) = words.next() else { continue };
            if k.starts_with('#') {
                continue;
            }
            let k = k.to_ascii_lowercase();
            if k == "match" {
                return true;
            }
            if k == "include" {
                if depth >= MAX_INCLUDE_DEPTH {
                    continue;
                }
                for pattern in words {
                    // Se pasan los contadores compartidos para que la capa de colección aplique el
                    // presupuesto (nº de archivos y bytes acumulados) MIENTRAS lee, uno a uno, y pare
                    // antes de slurpear un directorio entero. Así el pico de memoria no depende del
                    // tamaño del directorio.
                    let resolved = resolve(pattern, state.files, state.total_bytes);
                    // Un drop-in presente que se omitió al resolver (tope de bytes/archivos/ilegible,
                    // o un glob que no se supo expandir) trunca el parseo: lo que ese archivo fijaría
                    // queda sin leer y no debe darse por su default.
                    if resolved.truncated {
                        state.truncated = true;
                    }
                    // Contabilizar TODO lo que la resolución ya bufferizó (incluido lo que el dedup
                    // descarte a continuación), para que la siguiente resolución parta del total real
                    // y el presupuesto acumulado acote el pico de memoria de la expansión entera.
                    state.total_bytes = state
                        .total_bytes
                        .saturating_add(resolved.files.iter().map(|(_, c)| c.len() as u64).sum());
                    for (path, content) in resolved.files {
                        // Dedup: un archivo ya procesado (o un ciclo) se omite sin reprocesarse.
                        if !state.visited.insert(path) {
                            continue;
                        }
                        // Tope global: al superarse se deja de expandir, conservando lo ya parseado.
                        // El archivo presente queda sin procesar, así que el parseo es incompleto.
                        if state.files >= MAX_INCLUDE_FILES {
                            state.truncated = true;
                            continue;
                        }
                        state.files += 1;
                        if Self::ingest(&content, resolve, values, depth + 1, state) {
                            return true;
                        }
                    }
                }
                continue;
            }
            // "Gana la primera aparición": sólo la primera vez que se ve la clave fija su valor. Si esa
        // primera fijación ocurre cuando ya hubo un skip (`truncated`), un drop-in de mayor precedencia
        // omitido pudo haberla pisado: se marca contaminada para no darla por autoritativa.
        if let std::collections::hash_map::Entry::Vacant(e) = values.entry(k) {
            if state.truncated {
                state.tainted.insert(e.key().clone());
            }
            e.insert(words.collect::<Vec<_>>().join(" "));
        }
        }
        false
    }

    /// Valor parseado de `key` si aparece explícitamente (no vacío); `None` si está ausente.
    /// Distinguir "parseado" de "ausente" permite no dar por bueno un default cuando el parseo
    /// quedó incompleto.
    fn lookup(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(String::as_str).filter(|v| !v.is_empty())
    }

    pub fn get<'a>(&'a self, key: &str, default: &'a str) -> &'a str {
        self.lookup(key).unwrap_or(default)
    }

    /// true si `key` (misma normalización que `lookup`: palabra clave en minúsculas) tiene un valor
    /// parseado que NO es de confianza por haberse fijado tras un skip. El control debe tratarla como
    /// indeterminada en vez de dar por bueno su valor. La ruta de `sshd -T` nunca contamina (set vacío).
    fn is_tainted(&self, key: &str) -> bool {
        self.tainted.contains(key)
    }

    fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

/// Canonicaliza `candidate` y la devuelve sólo si queda dentro de `root` (ya canonicalizado).
/// Al canonicalizar se resuelven `..` y symlinks, de modo que un objetivo que escape del árbol
/// auditado queda descartado antes de leerlo. Devuelve `None` si no existe o escapa.
fn within_root(root: &Path, candidate: &Path) -> Option<PathBuf> {
    let canon = std::fs::canonicalize(candidate).ok()?;
    canon.starts_with(root).then_some(canon)
}

/// Lee un archivo de config acotando el tamaño: un archivo regular plantado por un atacante podría
/// ser enorme y agotar la memoria si se leyera entero con `read_to_string`. Se consulta primero el
/// tamaño en metadata y se omite (devuelve `None`) el que supere `MAX_FILE_BYTES`; el resto se lee
/// completo (una config normal son unos pocos KB, muy por debajo del tope).
fn read_bounded(path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    if meta.len() > MAX_FILE_BYTES {
        return None;
    }
    std::fs::read_to_string(path).ok()
}

/// Resuelve un patrón `Include` de sshd al contenido de los archivos que casan, en orden léxico.
/// Los patrones relativos se resuelven respecto a /etc/ssh, como hace sshd.
///
/// Endurecimiento: el contenido de la config auditada NO es de confianza y no debe poder dirigir
/// qué archivos se abren fuera del árbol auditado. Por eso todo objetivo se confina a `fs_root`:
/// se rechazan patrones con `..`, cada ruta (incluidos symlinks) se canonicaliza y se verifica que
/// siga dentro de `fs_root`, y sólo se leen archivos regulares (nunca fifos/dispositivos que
/// podrían colgar al auditor corriendo como root).
fn resolve_include(ctx: &Context, pattern: &str, files_so_far: usize, bytes_so_far: u64) -> Resolved {
    // Un patrón con un componente `..` podría escapar del árbol auditado: se descarta de entrada.
    if pattern.split('/').any(|seg| seg == "..") {
        return Resolved::default();
    }
    let Ok(root) = std::fs::canonicalize(&ctx.fs_root) else { return Resolved::default() };
    let abs = if pattern.starts_with('/') { pattern.to_string() } else { format!("/etc/ssh/{pattern}") };
    let p = ctx.path(&abs);
    let (Some(dir), Some(name)) = (p.parent(), p.file_name()) else { return Resolved::default() };
    let name = name.to_string_lossy();
    // Metacaracteres de glob de sshd. La ÚNICA forma que esta función sabe expandir es un único '*'
    // en el componente de nombre, sin glob en los componentes de directorio.
    let is_meta = |s: &str| s.contains(['*', '?', '[']);
    // Se mira el directorio del PATRÓN (no el ya prefijado con fs_root, que podría contener estos
    // caracteres de forma legítima) para detectar un glob en un componente de directorio.
    let pat_dir = Path::new(&abs).parent().map(|d| d.to_string_lossy().into_owned()).unwrap_or_default();
    let dir_has_glob = is_meta(&pat_dir);
    // Forma soportada: exactamente un '*' en el nombre, nada de '?'/'[' ni un segundo '*', y sin
    // glob en el directorio.
    let star = name.find('*');
    let name_single_star = matches!(star, Some(i)
        if !name[..i].contains(['*', '?', '[']) && !name[i + 1..].contains(['*', '?', '[']));

    let paths = if !dir_has_glob && name_single_star {
        let i = star.unwrap();
        // El directorio del glob debe existir y quedar dentro de fs_root antes de listarlo.
        match within_root(&root, dir) {
            Some(_) => glob(dir, &name[..i], &name[i + 1..]),
            None => return Resolved::default(),
        }
    } else if dir_has_glob || is_meta(&name) {
        // Patrón con glob que NO se sabe expandir (glob en un componente de directorio, o '?'/'['
        // o un segundo '*' en el nombre). Tratarlo como literal canonicalizaría a nada y el drop-in
        // se saltaría EN SILENCIO (falso negativo de evasión): un veredicto por default daría un PASS
        // falso. Se marca `truncated` para que el control degrade a WARN indeterminado en vez de PASS.
        return Resolved { files: Vec::new(), truncated: true };
    } else {
        vec![p.clone()]
    };

    // Presupuesto en la CAPA DE COLECCIÓN: se lee un archivo a la vez y se para en cuanto el tope de
    // número de archivos (`MAX_INCLUDE_FILES`) o el de bytes acumulados (`MAX_TOTAL_BYTES`) se
    // rebasaría, marcando `truncated`. Así, aunque el directorio tenga un millón de entradas de ~4
    // MiB, se leen a lo sumo ~`MAX_INCLUDE_FILES` archivos y ~`MAX_TOTAL_BYTES` en total: el pico de
    // memoria queda acotado con independencia del tamaño del directorio.
    let mut out = Resolved::default();
    let mut produced: usize = 0; // archivos bufferizados en ESTA resolución
    let mut buffered: u64 = 0; // bytes bufferizados en ESTA resolución
    for f in paths.iter().filter_map(|f| within_root(&root, f)).filter(|f| f.is_file()) {
        // Tope global de archivos: ya no caben más; se para y se marca truncado (sin leer más).
        if files_so_far.saturating_add(produced) >= MAX_INCLUDE_FILES {
            out.truncated = true;
            break;
        }
        // Se consulta el tamaño en metadata ANTES de leer, para no slurpear nunca un archivo que
        // rebasaría el tope por archivo o el presupuesto acumulado.
        let len = match std::fs::metadata(&f) {
            Ok(m) => m.len(),
            Err(_) => {
                out.truncated = true; // ilegible: se omite, parseo incompleto
                continue;
            }
        };
        // Regular enorme: se omite sin leerlo (como el tope por archivo) y marca truncado; se sigue
        // con el resto (los demás drop-ins presentes sí se leen).
        if len > MAX_FILE_BYTES {
            out.truncated = true;
            continue;
        }
        // Leer este archivo rebasaría el presupuesto acumulado total: se para aquí (fail-safe,
        // acotado), dejando el parseo incompleto.
        if bytes_so_far.saturating_add(buffered).saturating_add(len) > MAX_TOTAL_BYTES {
            out.truncated = true;
            break;
        }
        match std::fs::read_to_string(&f) {
            Ok(c) => {
                buffered = buffered.saturating_add(c.len() as u64);
                produced += 1;
                out.files.push((f, c));
            }
            Err(_) => out.truncated = true, // ilegible: se omite, parseo incompleto
        }
    }
    out
}

/// Carga la configuración estática arrancando desde sshd_config y expandiendo sus `Include`.
fn static_config(ctx: &Context) -> SshdConfig {
    let main = read_bounded(&ctx.path("/etc/ssh/sshd_config")).unwrap_or_default();
    SshdConfig::from_main(&main, &|pattern, files, bytes| resolve_include(ctx, pattern, files, bytes))
}

pub fn run(ctx: &Context, em: &mut Emitter) {
    let sshd = if ctx.is_live() {
        find_command("sshd")
    } else {
        Some(ctx.path("/usr/sbin/sshd")).filter(|p| p.exists())
    };
    let Some(sshd) = sshd else {
        em.na("SSH-000", Info, tr!("OpenSSH server")).with_detail(tr!("sshd is not installed"));
        return;
    };

    let from_t = if ctx.is_live() { command_output(&sshd, &["-T"]).map(|o| SshdConfig::from_sshd_t(&o)) } else { None };
    let cfg = match from_t {
        Some(c) if !c.is_empty() => c,
        _ => {
            let c = static_config(ctx);
            if c.is_empty() {
                em.error("SSH-000", High, tr!("sshd configuration"))
                    .with_detail(tr!("could not read or evaluate the configuration (not root?)"));
                return;
            }
            c
        }
    };

    evaluate_config(em, &cfg);
    check_match_blocks(ctx, em);
    check_files(ctx, em);
}

/// Resuelve el valor de `key` para un control, teniendo en cuenta un parseo estático incompleto.
///
/// Si el parseo estático quedó truncado (se omitió un drop-in presente) y la clave NO aparece en lo
/// parseado, su valor caería al default seguro y produciría un PASS que la config real no respalda:
/// eso es justo el falso PASS del hallazgo. En ese caso emite un WARN indeterminado (nunca un PASS)
/// y devuelve `None` para que el control no evalúe con el default. Si la clave se parseó de verdad
/// (valor autoritativo) o el parseo está completo, devuelve `Some(valor)` y el control sigue normal.
fn settled<'a>(
    em: &mut Emitter,
    cfg: &'a SshdConfig,
    incomplete: bool,
    id: &str,
    sev: Severity,
    key: &str,
    default: &'a str,
) -> Option<&'a str> {
    // Indeterminada si el parseo quedó incompleto y, o bien la clave está ausente (caería a su
    // default), o bien su valor parseado está contaminado (se fijó tras un skip y un drop-in omitido
    // de mayor precedencia pudo haberla pisado). En ambos casos el valor no respalda un PASS firme.
    if incomplete && (cfg.lookup(key).is_none() || cfg.is_tainted(key)) {
        em.warn(id, sev, tr!("configuration could not be fully evaluated"))
            .with_detail(tr!("a present drop-in was skipped (file/byte cap); this setting is indeterminate"));
        return None;
    }
    Some(cfg.get(key, default))
}

/// SSH-001..009, 011..013: opciones de la configuración efectiva.
pub fn evaluate_config(em: &mut Emitter, cfg: &SshdConfig) {
    let note = if cfg.is_static { tr!(" (static config, no defaults: sshd -T unavailable)") } else { "" };

    // Parseo estático truncado: se omitió un drop-in presente, así que las claves ausentes no se
    // pueden dar por sus defaults. Se avisa a nivel global (como el SSH-000 de config vacía) y cada
    // control cuyo veredicto dependa de un default se degrada a indeterminado vía `settled`.
    let incomplete = cfg.is_static && cfg.truncated;
    if incomplete {
        em.error("SSH-000", High, tr!("sshd configuration"))
            .with_detail(tr!("could not fully evaluate the configuration: a present drop-in was skipped (file/byte cap); settings that fall back to defaults are reported as indeterminate, not PASS"));
    }

    if let Some(v) = settled(em, cfg, incomplete, "SSH-001", High, "permitrootlogin", "prohibit-password") {
    match v {
        "no" => {
            em.pass("SSH-001", High, tr!("Direct root login disabled"));
        }
        "prohibit-password" | "without-password" | "forced-commands-only" => {
            em.warn("SSH-001", High, tr!("Root can log in over SSH with a key only"))
                .with_detail(format!("PermitRootLogin {v}{note}"))
                .with_fix(tr!("PermitRootLogin no and use sudo"));
        }
        _ => {
            em.fail("SSH-001", High, tr!("Root can log in over SSH with a password"))
                .with_detail(format!("PermitRootLogin {v}{note}"))
                .with_fix("PermitRootLogin no");
        }
    }
    }

    if let Some(v) = settled(em, cfg, incomplete, "SSH-002", Medium, "passwordauthentication", "yes") {
    if v == "no" {
        em.pass("SSH-002", Medium, tr!("Password authentication disabled"));
    } else {
        em.fail("SSH-002", Medium, tr!("SSH accepts password authentication"))
            .with_detail(format!("PasswordAuthentication {v}{note}"))
            .with_fix(tr!("Use keys (or a waiver if there is SSO/IPA)"));
    }
    }

    if let Some(v) = settled(em, cfg, incomplete, "SSH-003", Critical, "permitemptypasswords", "no") {
    if v == "no" {
        em.pass("SSH-003", Critical, tr!("PermitEmptyPasswords disabled"));
    } else {
        em.fail("SSH-003", Critical, tr!("SSH allows empty passwords"))
            .with_detail(format!("PermitEmptyPasswords {v}"))
            .with_fix("PermitEmptyPasswords no");
    }
    }

    if let Some(v) = settled(em, cfg, incomplete, "SSH-004", Low, "maxauthtries", "6") {
    if v.parse::<i64>().is_ok_and(|n| n <= 6) {
        em.pass("SSH-004", Low, tr!("MaxAuthTries is reasonable")).with_detail(format!("MaxAuthTries {v}"));
    } else {
        em.warn("SSH-004", Low, tr!("MaxAuthTries is high")).with_detail(format!("MaxAuthTries {v}")).with_fix("MaxAuthTries 4");
    }
    }

    if let Some(v) = settled(em, cfg, incomplete, "SSH-005", Low, "x11forwarding", "no") {
    if v == "no" {
        em.pass("SSH-005", Low, tr!("X11Forwarding disabled"));
    } else {
        em.warn("SSH-005", Low, tr!("X11Forwarding enabled"))
            .with_detail(format!("X11Forwarding {v}{note}"))
            .with_fix("X11Forwarding no");
    }
    }

    if cfg.is_static {
        em.na("SSH-006", Medium, tr!("Weak cryptographic algorithms")).with_detail(tr!("requires sshd -T"));
    } else {
        let weak = |key: &str, is_weak: fn(&str) -> bool| {
            cfg.get(key, "").split(',').filter(|a| is_weak(a)).collect::<Vec<_>>().join(",")
        };
        let c = weak("ciphers", |a| {
            ["3des", "arcfour", "blowfish", "cast128"].iter().any(|w| a.contains(w)) || a.ends_with("-cbc")
        });
        let m = weak("macs", |a| a.starts_with("hmac-md5") || a.starts_with("umac-64") || a.contains("hmac-sha1-96"));
        let k = weak("kexalgorithms", |a| {
            ["group1-sha1", "group14-sha1", "group-exchange-sha1"].iter().any(|w| a.contains(w))
        });
        if c.is_empty() && m.is_empty() && k.is_empty() {
            em.pass("SSH-006", Medium, tr!("No weak cryptographic algorithms"));
        } else {
            let mut d = Vec::new();
            if !c.is_empty() {
                d.push(format!("ciphers: {c}"));
            }
            if !m.is_empty() {
                d.push(format!("macs: {m}"));
            }
            if !k.is_empty() {
                d.push(format!("kex: {k}"));
            }
            em.fail("SSH-006", Medium, tr!("Weak SSH algorithms enabled"))
                .with_detail(d.join(" "))
                .with_fix(tr!("Set explicit Ciphers/MACs/KexAlgorithms (e.g. crypto-policies on RHEL)"));
        }
    }

    if let Some(v) = settled(em, cfg, incomplete, "SSH-007", Low, "logingracetime", "120") {
    let v = v.strip_suffix('s').unwrap_or(v);
    if v.parse::<i64>().is_ok_and(|n| n <= 60) {
        em.pass("SSH-007", Low, "LoginGraceTime <= 60s").with_detail(format!("{v} s"));
    } else {
        em.warn("SSH-007", Low, tr!("LoginGraceTime is high")).with_detail(format!("{v}s")).with_fix("LoginGraceTime 30");
    }
    }

    if let Some(v) = settled(em, cfg, incomplete, "SSH-008", Low, "clientaliveinterval", "0") {
    if v.parse::<i64>().is_ok_and(|n| n > 0) {
        em.pass("SSH-008", Low, tr!("Idle session timeout")).with_detail(format!("ClientAliveInterval {v}"));
    } else {
        em.warn("SSH-008", Low, tr!("No timeout for idle SSH sessions"))
            .with_detail(format!("ClientAliveInterval {v}"))
            .with_fix(tr!("ClientAliveInterval 300 / ClientAliveCountMax 0 (or TMOUT)"));
    }
    }

    if let Some(v) = settled(em, cfg, incomplete, "SSH-009", Medium, "gatewayports", "no") {
    if v == "no" {
        em.pass("SSH-009", Medium, tr!("GatewayPorts disabled"));
    } else {
        em.warn("SSH-009", Medium, tr!("GatewayPorts enabled")).with_detail(format!("GatewayPorts {v}")).with_fix("GatewayPorts no");
    }
    }

    if let Some(v) = settled(em, cfg, incomplete, "SSH-011", Low, "banner", "none") {
    if v != "none" {
        em.pass("SSH-011", Low, tr!("Legal banner configured")).with_detail(v);
    } else {
        em.warn("SSH-011", Low, tr!("No legal banner on SSH"))
            .with_detail("Banner none")
            .with_fix(tr!("Set Banner /etc/issue.net"));
    }
    }

    if let Some(v) = settled(em, cfg, incomplete, "SSH-012", High, "hostbasedauthentication", "no") {
    if v == "no" {
        em.pass("SSH-012", High, tr!("HostbasedAuthentication disabled"));
    } else {
        em.fail("SSH-012", High, tr!("HostbasedAuthentication enabled")).with_detail(v).with_fix("HostbasedAuthentication no");
    }
    }

    if let Some(v) = settled(em, cfg, incomplete, "SSH-013", Medium, "permituserenvironment", "no") {
    if v == "no" {
        em.pass("SSH-013", Medium, tr!("PermitUserEnvironment disabled"));
    } else {
        em.fail("SSH-013", Medium, tr!("PermitUserEnvironment enabled")).with_detail(v).with_fix("PermitUserEnvironment no");
    }
    }
}

/// Líneas dentro de bloques Match que reabren root o passwords vacíos.
pub fn weakening_match_lines(file: &str, text: &str) -> Vec<String> {
    let mut in_match = false;
    let mut out = Vec::new();
    for line in text.lines() {
        let mut w = line.split_whitespace();
        let Some(k) = w.next().map(str::to_ascii_lowercase) else { continue };
        if k == "match" {
            in_match = true;
            continue;
        }
        let v = w.next().unwrap_or("").to_ascii_lowercase();
        if in_match && (k == "permitrootlogin" || k == "permitemptypasswords") && v == "yes" {
            out.push(format!("{file}: {line}"));
        }
    }
    out
}

/// SSH-010
fn check_match_blocks(ctx: &Context, em: &mut Emitter) {
    let mut files = vec!["/etc/ssh/sshd_config".to_string()];
    files.extend(
        glob(&ctx.path("/etc/ssh/sshd_config.d"), "", ".conf")
            .iter()
            .filter_map(|p| p.file_name().map(|n| format!("/etc/ssh/sshd_config.d/{}", n.to_string_lossy()))),
    );
    let found: Vec<String> = files
        .iter()
        .filter_map(|f| std::fs::read_to_string(ctx.path(f)).ok().map(|t| weakening_match_lines(f, &t)))
        .flatten()
        .collect();
    if found.is_empty() {
        em.pass("SSH-010", Medium, tr!("No Match block re-enables root/empty passwords"));
    } else {
        em.fail("SSH-010", Medium, tr!("Match block weakens security"))
            .with_detail(found.join(" "))
            .with_fix(tr!("Review the Match blocks"));
    }
}

/// SSH-014..016: permisos y claves de host.
fn check_files(ctx: &Context, em: &mut Emitter) {
    check_file_perm(em, ctx, "SSH-014", Medium, tr!("sshd_config permissions"), "/etc/ssh/sshd_config", 0o644, Some(0));

    let bad: Vec<String> = glob(&ctx.path("/etc/ssh"), "ssh_host_", "_key")
        .iter()
        .filter_map(|p| {
            let m = file_mode(p)?;
            (!mode_within(m, 0o640)).then(|| {
                let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                format!("/etc/ssh/{name}({m:o})")
            })
        })
        .collect();
    if bad.is_empty() {
        em.pass("SSH-015", High, tr!("Host private keys have correct permissions"));
    } else {
        em.fail("SSH-015", High, tr!("Host private keys readable by others"))
            .with_detail(bad.join(" "))
            .with_fix("chmod 600 /etc/ssh/ssh_host_*_key");
    }

    if ctx.path("/etc/ssh/ssh_host_dsa_key").exists() {
        em.warn("SSH-016", Medium, tr!("DSA host key present (obsolete)"))
            .with_detail("/etc/ssh/ssh_host_dsa_key")
            .with_fix(tr!("Remove it and drop the DSA HostKey"));
    } else {
        em.pass("SSH-016", Medium, tr!("No DSA host key"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CheckResult, Status};

    fn eval(cfg: &SshdConfig) -> HashMap<String, CheckResult> {
        let mut em = Emitter::new("ssh");
        evaluate_config(&mut em, cfg);
        em.into_results().into_iter().map(|r| (r.id.clone(), r)).collect()
    }

    #[test]
    fn defaults_de_sshd_t_endurecido() {
        let out = "permitrootlogin no\npasswordauthentication no\npermitemptypasswords no\nmaxauthtries 3\n\
                   x11forwarding no\nciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com\n\
                   macs hmac-sha2-256-etm@openssh.com\nkexalgorithms curve25519-sha256\nlogingracetime 30\n\
                   clientaliveinterval 300\ngatewayports no\nbanner /etc/issue.net\nhostbasedauthentication no\n\
                   permituserenvironment no\n";
        let r = eval(&SshdConfig::from_sshd_t(out));
        for (id, res) in &r {
            assert_eq!(res.status, Status::Pass, "{id}: {res:?}");
        }
        assert_eq!(r.len(), 12); // 001..009 y 011..013 (010 y 014..016 leen archivos)
    }

    #[test]
    fn detecta_algoritmos_debiles_y_root_con_password() {
        let out = "permitrootlogin yes\nciphers aes128-ctr,aes256-cbc,3des-cbc\nmacs hmac-md5,hmac-sha2-256\n\
                   kexalgorithms diffie-hellman-group14-sha1\n";
        let r = eval(&SshdConfig::from_sshd_t(out));
        assert_eq!(r["SSH-001"].status, Status::Fail);
        assert_eq!(r["SSH-006"].status, Status::Fail);
        assert_eq!(r["SSH-006"].detail, "ciphers: aes256-cbc,3des-cbc macs: hmac-md5 kex: diffie-hellman-group14-sha1");
    }

    /// Resolver de prueba: entrega `dropin` (con una ruta sintética) para el patrón del directorio
    /// drop-in habitual. La ruta identifica el archivo para el dedup del visited-set.
    fn dropin_resolver(dropin: &str) -> impl Fn(&str, usize, u64) -> Resolved + '_ {
        move |pattern: &str, _files: usize, _bytes: u64| {
            if pattern == "/etc/ssh/sshd_config.d/*.conf" {
                Resolved {
                    files: vec![(PathBuf::from("/etc/ssh/sshd_config.d/10-x.conf"), dropin.to_string())],
                    truncated: false,
                }
            } else {
                Resolved::default()
            }
        }
    }

    #[test]
    fn parseo_estatico_respeta_primera_aparicion_y_corta_en_match() {
        let dropin = "PasswordAuthentication no\n";
        // Include al tope: el drop-in se expande antes que los ajustes del principal, así que gana.
        let main = "Include /etc/ssh/sshd_config.d/*.conf\n# comentario\nPasswordAuthentication yes\n\
                    PermitRootLogin no\nMatch User x\nPermitRootLogin yes\n";
        let cfg = SshdConfig::from_main(main, &dropin_resolver(dropin));
        assert!(cfg.is_static);
        assert_eq!(cfg.get("passwordauthentication", "?"), "no");
        assert_eq!(cfg.get("permitrootlogin", "?"), "no");
        let r = eval(&cfg);
        assert_eq!(r["SSH-006"].status, Status::Na);
        // sin defaults: X11Forwarding usa el default asumido y no lleva nota
        assert_eq!(r["SSH-005"].status, Status::Pass);
    }

    #[test]
    fn main_antes_del_include_gana_sobre_dropin() {
        // sshd usa el primer valor obtenido: si el principal fija el valor seguro ANTES del Include,
        // el drop-in inseguro NO lo revierte.
        let dropin = "PasswordAuthentication yes\nPermitRootLogin yes\n";
        let main = "PasswordAuthentication no\nPermitRootLogin no\nInclude /etc/ssh/sshd_config.d/*.conf\n";
        let cfg = SshdConfig::from_main(main, &dropin_resolver(dropin));
        assert_eq!(cfg.get("passwordauthentication", "?"), "no");
        assert_eq!(cfg.get("permitrootlogin", "?"), "no");
        let r = eval(&cfg);
        assert_eq!(r["SSH-001"].status, Status::Pass);
        assert_eq!(r["SSH-002"].status, Status::Pass);
    }

    #[test]
    fn include_antes_del_setting_deja_ganar_al_dropin() {
        // Con el Include antes del ajuste, el drop-in se obtiene primero y gana.
        let dropin = "PasswordAuthentication yes\nPermitRootLogin yes\n";
        let main = "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication no\nPermitRootLogin no\n";
        let cfg = SshdConfig::from_main(main, &dropin_resolver(dropin));
        assert_eq!(cfg.get("passwordauthentication", "?"), "yes");
        assert_eq!(cfg.get("permitrootlogin", "?"), "yes");
        let r = eval(&cfg);
        assert_eq!(r["SSH-001"].status, Status::Fail);
        assert_eq!(r["SSH-002"].status, Status::Fail);
    }

    #[test]
    fn include_que_escapa_de_fs_root_se_ignora() {
        use crate::checks::fixture::Fixture;
        use std::os::unix::fs::symlink;

        let fx = Fixture::new();
        // El valor sólo puede venir de un Include: así un escape exitoso cambiaría el veredicto.
        fx.file("/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\n");
        // Un drop-in legítimo dentro del árbol auditado: debe seguir leyéndose.
        fx.file("/etc/ssh/sshd_config.d/10-ok.conf", "X11Forwarding yes\n");
        let ctx = fx.ctx();

        // Un archivo FUERA de fs_root con un ajuste inseguro que no debe filtrarse al veredicto.
        let outside = ctx.fs_root.parent().unwrap().join(format!("linaudit-escape-{}.conf", std::process::id()));
        std::fs::write(&outside, "PermitRootLogin yes\n").unwrap();
        // Un drop-in que es un symlink absoluto apuntando fuera del árbol auditado.
        let link = ctx.fs_root.join("etc/ssh/sshd_config.d/99-evil.conf");
        let _ = std::fs::remove_file(&link);
        symlink(&outside, &link).unwrap();

        let cfg = static_config(&ctx);
        let _ = std::fs::remove_file(&outside);

        // El symlink de escape NO se siguió: el ajuste del archivo externo no aparece.
        assert_eq!(cfg.get("permitrootlogin", "ausente"), "ausente");
        // El drop-in legítimo dentro del árbol sí se leyó: el confinamiento no rompe includes normales.
        assert_eq!(cfg.get("x11forwarding", "?"), "yes");
        // Un patrón con `..` se rechaza de entrada.
        assert!(resolve_include(&ctx, "/../../etc/passwd", 0, 0).files.is_empty());
    }

    #[test]
    fn include_ciclico_no_desborda_la_pila() {
        // Un resolver que siempre devuelve una config que se vuelve a incluir: sin tope, la recursión
        // desbordaría la pila (SIGABRT). El tope de profundidad corta el ciclo y la auditoría termina.
        let resolver = |_pattern: &str, _files: usize, _bytes: u64| Resolved {
            files: vec![(
                PathBuf::from("/etc/ssh/loop.conf"),
                "Include /etc/ssh/loop.conf\nPasswordAuthentication no\n".to_string(),
            )],
            truncated: false,
        };
        let main = "Include /etc/ssh/loop.conf\n";
        let cfg = SshdConfig::from_main(main, &resolver);
        assert!(cfg.is_static);
        // Terminó sin pánico y procesó las líneas tras el Include cortado.
        assert_eq!(cfg.get("passwordauthentication", "?"), "no");
    }

    #[test]
    fn fan_out_de_includes_converge_y_no_se_cuelga() {
        use crate::checks::fixture::Fixture;

        let fx = Fixture::new();
        fx.file("/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication no\n");
        // Veinte drop-ins y cada uno vuelve a incluir el MISMO glob: sin dedup por ruta, cada
        // archivo re-expandiría a los veinte y la recursión explotaría (~N^profundidad ingests).
        // Con el visited-set cada archivo se procesa una vez y la auditoría termina al instante.
        for i in 0..20 {
            fx.file(&format!("/etc/ssh/sshd_config.d/{i:02}-loop.conf"), "Include /etc/ssh/sshd_config.d/*.conf\n");
        }
        // Un drop-in real con un ajuste: comprueba que el fan-out se procesa de verdad, no se aborta.
        fx.file("/etc/ssh/sshd_config.d/50-val.conf", "X11Forwarding yes\n");
        let ctx = fx.ctx();

        let cfg = static_config(&ctx);
        // Terminó (no colgó) y leyó el drop-in real.
        assert_eq!(cfg.get("x11forwarding", "?"), "yes");
        // El principal fija el valor DESPUÉS del Include y ningún drop-in lo toca: gana el principal.
        assert_eq!(cfg.get("passwordauthentication", "?"), "no");
    }

    #[test]
    fn tope_de_archivos_detiene_la_expansion_sin_error() {
        // Un único Include que resuelve a muchísimos archivos distintos (a lo ancho, dentro del tope
        // de profundidad): el tope global de archivos corta la expansión sin error y conserva lo ya
        // parseado. Sin ese tope se procesarían los 1000.
        let resolver = |_pattern: &str, _files: usize, _bytes: u64| Resolved {
            files: (0..1000)
                .map(|n| (PathBuf::from(format!("/etc/ssh/gen/{n:04}.conf")), format!("Setting{n} val{n}\n")))
                .collect::<Vec<_>>(),
            truncated: false,
        };
        let main = "Include /etc/ssh/gen/*\nPasswordAuthentication no\n";
        let cfg = SshdConfig::from_main(main, &resolver);
        assert!(cfg.is_static);
        // Se detuvo en MAX_INCLUDE_FILES: los primeros se parsearon, uno muy por encima del tope no.
        assert_eq!(cfg.get("setting0", "ausente"), "val0");
        assert_eq!(cfg.get("setting999", "ausente"), "ausente");
        // Cortar por el tope de archivos deja el parseo incompleto: se marca truncated.
        assert!(cfg.truncated);
        // La línea del principal tras el Include se sigue procesando (fail-safe, sin abortar).
        assert_eq!(cfg.get("passwordauthentication", "?"), "no");
    }

    #[test]
    fn archivo_gigante_se_omite_por_tope_de_bytes() {
        use crate::checks::fixture::Fixture;

        let fx = Fixture::new();
        fx.file("/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\n");
        // Un drop-in normal y otro enorme: el gigante se omite sin slurpearse (evita el OOM); el
        // normal se lee completo y su ajuste llega al veredicto.
        fx.file("/etc/ssh/sshd_config.d/10-ok.conf", "X11Forwarding yes\n");
        fx.file("/etc/ssh/sshd_config.d/20-big.conf", &"#\n".repeat((MAX_FILE_BYTES as usize / 2) + 1));
        let ctx = fx.ctx();

        let cfg = static_config(&ctx);
        assert_eq!(cfg.get("x11forwarding", "?"), "yes");
    }

    #[test]
    fn dropin_omitido_por_bytes_no_da_pass_falso_en_critico() {
        use crate::checks::fixture::Fixture;

        let fx = Fixture::new();
        // El principal es legible y no vacío (el guard is_empty pasa), pero el drop-in presente que
        // fijaría PermitEmptyPasswords se omite por superar el tope de bytes. Sin la señal de parseo
        // incompleto, SSH-003 (Critical) caería al default "no" y daría un PASS falso.
        fx.file("/etc/ssh/sshd_config", "PasswordAuthentication no\nInclude /etc/ssh/sshd_config.d/*.conf\n");
        fx.file(
            "/etc/ssh/sshd_config.d/10-empty.conf",
            &format!("PermitEmptyPasswords yes\n{}", "#\n".repeat((MAX_FILE_BYTES as usize / 2) + 1)),
        );
        let ctx = fx.ctx();

        let cfg = static_config(&ctx);
        // Un drop-in presente omitido por bytes marca el parseo como incompleto.
        assert!(cfg.truncated);
        // El ajuste del drop-in no llegó: quedaría en su default seguro de no mediar la señal.
        assert_eq!(cfg.get("permitemptypasswords", "ausente"), "ausente");

        let r = eval(&cfg);
        // SSH-003 (Critical) NO es un PASS: es un WARN indeterminado.
        assert_eq!(r["SSH-003"].status, Status::Warn);
        // Se emite el SSH-000 global de cobertura incompleta.
        assert_eq!(r["SSH-000"].status, Status::Error);
        // Una clave que SÍ se parseó del principal sigue siendo autoritativa (PASS firme).
        assert_eq!(r["SSH-002"].status, Status::Pass);
    }

    #[test]
    fn dropin_omitido_antes_del_setting_contamina_la_clave_posterior() {
        // Layout Debian/Ubuntu: el Include va cerca del PRINCIPIO, antes del cuerpo. Un drop-in
        // presente de sshd_config.d/ se omite por un tope (truncated). El principal fija MÁS ABAJO
        // PermitEmptyPasswords no; con "gana la primera aparición" ese valor quedaría como autoritativo
        // y SSH-003 daría PASS. Pero sshd leería el drop-in omitido PRIMERO y podría aplicar
        // PermitEmptyPasswords yes -> empty passwords. Esa clave, fijada DESPUÉS del skip, está
        // contaminada y SSH-003 (Critical) debe ser WARN indeterminado, nunca PASS falso.
        let resolver = |pattern: &str, _files: usize, _bytes: u64| {
            if pattern == "/etc/ssh/sshd_config.d/*.conf" {
                // Un drop-in presente que el resolver omitió (p.ej. superó el tope de bytes).
                Resolved { files: vec![], truncated: true }
            } else {
                Resolved::default()
            }
        };
        // PasswordAuthentication se fija ANTES del Include; PermitEmptyPasswords, DESPUÉS.
        let main = "PasswordAuthentication no\nInclude /etc/ssh/sshd_config.d/*.conf\nPermitEmptyPasswords no\n";
        let cfg = SshdConfig::from_main(main, &resolver);
        assert!(cfg.truncated);
        // La clave fijada DESPUÉS del skip está contaminada; la de ANTES sigue siendo autoritativa.
        assert!(cfg.is_tainted("permitemptypasswords"));
        assert!(!cfg.is_tainted("passwordauthentication"));
        // Ambas claves están presentes en lo parseado (el taint, no la ausencia, degrada SSH-003).
        assert_eq!(cfg.get("permitemptypasswords", "ausente"), "no");

        let r = eval(&cfg);
        // SSH-003 (Critical): clave presente pero contaminada -> WARN indeterminado, no PASS.
        assert_eq!(r["SSH-003"].status, Status::Warn);
        // SSH-002: clave fijada ANTES de cualquier skip -> sigue siendo PASS firme autoritativo.
        assert_eq!(r["SSH-002"].status, Status::Pass);
        // Cobertura incompleta global.
        assert_eq!(r["SSH-000"].status, Status::Error);
    }

    #[test]
    fn tope_de_archivos_marca_incompleto_y_suprime_pass_por_default() {
        // Un Include que resuelve a muchísimos archivos: se corta en MAX_INCLUDE_FILES y el parseo
        // queda incompleto. Ninguno fija PermitEmptyPasswords, así que SSH-003 dependería del default.
        let resolver = |_pattern: &str, _files: usize, _bytes: u64| Resolved {
            files: (0..1000)
                .map(|n| (PathBuf::from(format!("/etc/ssh/gen/{n:04}.conf")), format!("Setting{n} val{n}\n")))
                .collect::<Vec<_>>(),
            truncated: false,
        };
        let main = "PasswordAuthentication no\nInclude /etc/ssh/gen/*\n";
        let cfg = SshdConfig::from_main(main, &resolver);
        assert!(cfg.truncated);

        let r = eval(&cfg);
        // SSH-003 depende del default "no": bajo parseo incompleto es WARN, no PASS.
        assert_eq!(r["SSH-003"].status, Status::Warn);
        assert_eq!(r["SSH-000"].status, Status::Error);
        // La clave presente en el principal sigue siendo autoritativa.
        assert_eq!(r["SSH-002"].status, Status::Pass);
    }

    #[test]
    fn config_estatica_completa_no_se_degrada() {
        // Un parseo estático COMPLETO (nada omitido) no marca truncated, no emite SSH-000 y produce
        // los mismos veredictos de siempre: los defaults siguen valiendo para claves ausentes.
        let dropin = "PermitEmptyPasswords no\n";
        let main = "Include /etc/ssh/sshd_config.d/*.conf\n";
        let cfg = SshdConfig::from_main(main, &dropin_resolver(dropin));
        assert!(!cfg.truncated);

        let r = eval(&cfg);
        assert!(!r.contains_key("SSH-000"));
        // Clave presente -> PASS firme.
        assert_eq!(r["SSH-003"].status, Status::Pass);
        // Claves ausentes caen a su default seguro y siguen dando PASS (sin regresión).
        assert_eq!(r["SSH-012"].status, Status::Pass);
        assert_eq!(r["SSH-013"].status, Status::Pass);
    }

    #[test]
    fn resolve_acota_la_coleccion_por_tope_de_archivos() {
        use crate::checks::fixture::Fixture;

        // Un único glob que casa MUCHOS más archivos que el tope: la capa de colección debe parar al
        // llegar a MAX_INCLUDE_FILES sin bufferizar el directorio entero. Prueba que el presupuesto
        // se aplica AL COLECTAR (en resolve_include), no después en ingest.
        let fx = Fixture::new();
        let total = MAX_INCLUDE_FILES + 100;
        for i in 0..total {
            fx.file(&format!("/etc/ssh/sshd_config.d/{i:04}-x.conf"), "# x\n");
        }
        let ctx = fx.ctx();

        let r = resolve_include(&ctx, "/etc/ssh/sshd_config.d/*.conf", 0, 0);
        // Sólo se leyeron hasta el tope: el resto del directorio NO se bufferizó.
        assert_eq!(r.files.len(), MAX_INCLUDE_FILES);
        assert!(r.truncated);
    }

    #[test]
    fn resolve_acota_la_coleccion_por_presupuesto_de_bytes() {
        use crate::checks::fixture::Fixture;

        // Con el presupuesto acumulado ya agotado al entrar, leer el primer archivo lo rebasaría: la
        // colección para de inmediato sin bufferizar nada y marca truncado. Prueba el presupuesto de
        // bytes sin tener que escribir 64 MiB en disco.
        let fx = Fixture::new();
        fx.file("/etc/ssh/sshd_config.d/10-a.conf", "X11Forwarding yes\n");
        fx.file("/etc/ssh/sshd_config.d/20-b.conf", "PermitRootLogin yes\n");
        let ctx = fx.ctx();

        let r = resolve_include(&ctx, "/etc/ssh/sshd_config.d/*.conf", 0, MAX_TOTAL_BYTES);
        assert!(r.files.is_empty());
        assert!(r.truncated);
    }

    #[test]
    fn glob_en_componente_de_directorio_marca_truncado_no_se_salta() {
        use crate::checks::fixture::Fixture;

        // Un Include con un glob en un COMPONENTE DE DIRECTORIO (forma que el resolver no sabe
        // expandir): no debe tratarse como literal y saltarse en silencio (falso negativo de
        // evasión). Se marca truncado para que el veredicto degrade a WARN en vez de un PASS falso.
        let fx = Fixture::new();
        fx.file("/etc/ssh/conf.d/sub/sshd.conf", "PermitRootLogin yes\n");
        let ctx = fx.ctx();

        let r = resolve_include(&ctx, "/etc/ssh/conf.d/*/sshd.conf", 0, 0);
        assert!(r.files.is_empty());
        assert!(r.truncated);

        // Otros metacaracteres no soportados en el nombre ('?', '[') también se marcan truncados.
        let r = resolve_include(&ctx, "/etc/ssh/conf.d/*/*.conf", 0, 0);
        assert!(r.truncated);
        let r = resolve_include(&ctx, "/etc/ssh/sshd_config.d/1?-x.conf", 0, 0);
        assert!(r.truncated);

        // Un parseo con un Include así queda marcado incompleto y SSH-003 degrada a WARN, no PASS.
        let main = "PasswordAuthentication no\nInclude /etc/ssh/conf.d/*/sshd.conf\n";
        let cfg = SshdConfig::from_main(main, &|pattern, files, bytes| resolve_include(&ctx, pattern, files, bytes));
        assert!(cfg.truncated);
        let res = eval(&cfg);
        assert_eq!(res["SSH-003"].status, Status::Warn);
        assert_eq!(res["SSH-000"].status, Status::Error);
    }

    #[test]
    fn match_que_reabre_root() {
        let t = "PermitRootLogin no\nMatch Address 10.0.0.0/8\n  PermitRootLogin yes\n";
        assert_eq!(weakening_match_lines("/etc/ssh/sshd_config", t), vec![
            "/etc/ssh/sshd_config:   PermitRootLogin yes".to_string()
        ]);
        assert!(weakening_match_lines("f", "PermitRootLogin yes\n").is_empty());
    }

    #[test]
    fn logingracetime_con_sufijo() {
        let r = eval(&SshdConfig::from_sshd_t("logingracetime 30s\n"));
        assert_eq!(r["SSH-007"].status, Status::Pass);
        let r = eval(&SshdConfig::from_sshd_t("logingracetime 2m\n"));
        assert_eq!(r["SSH-007"].status, Status::Warn);
    }
}
