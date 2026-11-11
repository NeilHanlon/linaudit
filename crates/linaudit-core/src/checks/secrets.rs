//! category: secrets — port de checks.d/40-secrets.sh y lib/secret_filter.awk.
//! Credenciales en texto plano, claves privadas, archivos de credenciales, historiales.
//!
//! REGLA: este módulo NUNCA pone el valor de un secreto en un resultado. Solo archivo y línea
//! (o archivo y permisos). Los tests de abajo lo verifican serializando los resultados.
//!
//! Divergencias con bash: sin root, cada control queda como ERROR con su severidad real (bash los
//! ponía todos como HIGH), y los nombres de archivo con espacios no se parten en pedazos.

use std::os::unix::fs::MetadataExt;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use regex::{Regex, RegexBuilder};

use super::Context;
use super::util::{Timed, expand_all, find_command, live_command_timeout, mode_within};
use super::walk::{WalkOpts, any_glob, glob_match, read_text, scan_timeout, size_below_k, walk};
use crate::model::{Emitter, ResultExt, Severity, Severity::*};
use crate::tr;

fn ci(p: &str) -> Regex {
    RegexBuilder::new(p).case_insensitive(true).build().expect("regex válida")
}

/// Clave sensible, comilla opcional (JSON), separador = o :, y algo de valor.
static KEYPAT: LazyLock<Regex> = LazyLock::new(|| {
    ci(r#"(passw(or)?d|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|auth[_-]?key|private[_-]?key|credential|bindpw)[a-zA-Z_.-]*["']?[[:space:]]*[=:][[:space:]]*[^[:space:]]"#)
});
/// usuario:password@ dentro de una URL.
static URLPAT: LazyLock<Regex> = LazyLock::new(|| ci(r"://[^/[:space:]:@$%{<]+:[^/[:space:]@$%{<]+@"));
static URLPAT_CS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"://[^/[:space:]:@$%{<]+:[^/[:space:]@$%{<]+@").expect("regex válida"));
static KEY_BEGIN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^-----BEGIN ([A-Z0-9]+ )?PRIVATE KEY-----").expect("regex válida"));
static KEY_END: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^-----END ([A-Z0-9]+ )?PRIVATE KEY-----").expect("regex válida"));
/// Secretos pasados por línea de comandos en historiales de shell.
static HISTORY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"((mysql|mysqldump|psql|mongo|mongosh|redis-cli)[^|;]*[[:space:]](-p[^[:space:]]+|--password[= ][^[:space:]]+))",
        r"|sshpass[[:space:]]+-p",
        r"|(curl|wget)[^|;]*[[:space:]](-u|--user|--password)[ =][^[:space:]]+:[^[:space:]]+",
        r"|(PASSWORD|PASSWD|SECRET|TOKEN|API_KEY)=[^[:space:]]+",
        r"|htpasswd[[:space:]]+-[a-z]*b",
    ))
    .expect("regex válida")
});

// ───────────────────────────────────────── filtro de falsos positivos (lib/secret_filter.awk)

static FILTER_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(passw(or)?d|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|auth[_-]?key|private[_-]?key|credential|bindpw)[a-z_.-]*['"]?[ \t]*[=:][ \t]*"#)
        .expect("regex válida")
});
static COMMENT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[ \t]*(#|;|//|--)").expect("regex válida"));
static SEP_TAIL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[ \t]*[=:][ \t]*$").expect("regex válida"));
static IGNORE_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(file|path|length|len|min|max|age|prompt|policy|regex|algorithm|hash|type|field|param|url|uri|dir|name|expire|expiry|attempts?|retry|retries|timeout|enabled?|required|ttl|interval|mode|class|prefix|suffix|sizes?|format|header|script|command|cmd)$")
        .expect("regex válida")
});
static IGNORE_VAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(none|null|nil|false|true|yes|no|on|off|x|required|requisite|sufficient|optional|prompt|env|file|sha256|sha512|md5|yescrypt|bcrypt|blowfish|unix|pam|ldap|secret|password|passwd|token|string|value|files|compat|systemd|sss|ldap|winbind|db|nis|nisplus|dns|resolve|myhostname|mymachines)$")
        .expect("regex válida")
});
static VERSION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[\^~><=]*[0-9]+(\.[0-9a-z*-]+)+$").expect("regex válida"));
/// Especificación de permisos tipo `rw-r--r--` (p.ej. reglas permfile de lynis), no una credencial.
static PERMS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[rwxsStT-]{9}([:/]|$)").expect("regex válida"));

/// true si la línea parece contener una credencial real (y no una referencia, ruta, opción, etc.).
/// Port directo de lib/secret_filter.awk. No devuelve el valor: solo sí/no.
pub fn looks_like_credential(content: &str) -> bool {
    let c = content.to_lowercase();
    if COMMENT.is_match(&c) {
        return false;
    }
    let Some(m) = FILTER_KEY.find(&c) else { return false };
    let key = SEP_TAIL.replace(m.as_str(), "").replace(['\'', '"'], "");
    if IGNORE_KEY.is_match(&key) {
        return false;
    }
    let val = &c[m.end()..];
    let val = val.strip_prefix(['\'', '"']).unwrap_or(val);
    let val = &val[..val.find([' ', '\t', '\'', '"', ';', ',']).unwrap_or(val.len())];
    if val.chars().count() < 4
        || val.starts_with(['$', '%', '{', '<', '(', '@', '/', '#', '*', '!', '['])
        || IGNORE_VAL.is_match(val)
        || VERSION.is_match(val)
        || PERMS.is_match(val)
    {
        return false;
    }
    true
}

// ───────────────────────────────────────── candidatos

/// Directorios que nunca son configuración de la instalación (código de terceros, docs, tests, runtimes).
const PRUNE: &[&str] = &[
    "/etc/ssl", "/etc/ca-certificates", "/etc/pam.d", "/etc/security", "/etc/ssh", "/etc/apt", "/etc/dpkg",
    "/etc/alternatives", "/etc/selinux", "/etc/X11", "/etc/fonts", "*/.git/objects", "*/node_modules", "*/.cache",
    "*/site-packages", "*/dist-packages", "*/.npm", "*/.m2", "*/.mozilla", "*/.local/share", "*/venv", "*/.venv",
    "*/gems", "*/rbenv", "*/.rbenv", "*/.pyenv", "*/.nvm", "*/.cargo", "*/.rustup", "*/google-cloud-sdk",
    "*/lib/python*", "*/lib/ruby", "*/share/doc", "*/share/man", "*/man", "*/docs", "*/doc", "*/test", "*/tests",
    "*/testdata", "*/spec", "*/examples", "*/example", "*/vendor", "*/third_party", "*/.gradle", "*/.sdkman",
];
const NOISE: &[&str] = &[
    "*.example", "*.sample", "*.dist", "*.md", "*.ronn", "*.rst", "*.html", "*.js", "*.map", "*.pyc", "*.py", "*.rb",
    "*.c", "*.h", "*.log", "*.dpkg-*", "*.min.*", "*.svg", "*.lock", "package*.json", "npm-shrinkwrap.json",
    "shadow*", "gshadow*", "passwd*", "*_history", "*.so*", "*.pem", "*.crt",
    // perfiles de auditoría (p.ej. lynis /etc/lynis/*.prf): reglas que NOMBRAN rutas y permisos, no credenciales
    "*.prf",
];
/// Fuera de /etc solo se miran archivos con nombre de configuración (evita escanear código fuente).
const CFGNAMES: &[&str] = &[
    "*.conf", "*.cfg", "*.cnf", "*.ini", "*.properties", "*.env", ".env", ".env.*", "*.yml", "*.yaml", "*.xml",
    "*.json", "*.toml", "*.sh", "*.bash", "*.config", "config*.php", "wp-config*.php", "settings*.php", "*.inc",
    "*.plist", "config.*", "settings.*", ".netrc", ".pgpass", ".my.cnf", ".git-credentials", "credentials", "*.rc",
    "*.service",
];
const APPDIRS: &[&str] =
    &["/opt", "/srv", "/var/www", "/root", "/home", "/usr/local/etc", "/usr/local/bin", "/usr/local/sbin"];

fn max_depth(ctx: &Context) -> Option<usize> {
    ctx.fast.then_some(3)
}

/// Archivos a revisar en busca de credenciales: todo /etc (menos ruido) y las configuraciones de las
/// carpetas de aplicaciones y homes.
fn candidates(ctx: &Context) -> Vec<String> {
    let prune = |p: &str| any_glob(PRUNE, p);
    let mut out = Vec::new();
    let mut visit = |e: &super::walk::Entry, cfg_only: bool| {
        if e.is_file()
            && size_below_k(e.meta, 1024)
            && !any_glob(NOISE, e.name())
            && (!cfg_only || any_glob(CFGNAMES, e.name()))
        {
            out.push(e.path.to_string());
        }
    };
    let opts = |deadline| WalkOpts { max_depth: max_depth(ctx), xdev: true, prune: Some(&prune), deadline: Some(deadline) };
    walk(ctx, "/etc", &opts(Instant::now() + scan_timeout()), &mut |e| visit(e, false));
    let deadline = Instant::now() + scan_timeout();
    for d in APPDIRS {
        walk(ctx, d, &opts(deadline), &mut |e| visit(e, true));
    }
    out
}

/// Archivo y línea de cada coincidencia, como `grep -HIn -m N`.
fn matches(ctx: &Context, files: &[String], re: &Regex, max: usize) -> Vec<(String, usize, String)> {
    super::util::grep_files(ctx, files, re, Some(max))
}

/// La primera línea de cada archivo que pasa el filtro: (archivo, línea). Nunca el contenido.
fn credential_hits(ctx: &Context, files: &[String]) -> Vec<(String, usize)> {
    let mut out: Vec<(String, usize)> = Vec::new();
    for (f, n, line) in matches(ctx, files, &KEYPAT, 3) {
        if out.iter().any(|(lf, _)| *lf == f) {
            continue;
        }
        if looks_like_credential(&line) {
            out.push((f, n));
        }
    }
    out
}

fn mode_of(ctx: &Context, f: &str) -> Option<u32> {
    std::fs::metadata(ctx.path(f)).ok().map(|m| m.mode() & 0o7777)
}

fn list_short(hits: &[(String, usize)]) -> String {
    hits.iter().take(8).map(|(f, n)| format!("{f}:{n}")).collect::<Vec<_>>().join(" ")
}

pub fn run(ctx: &Context, em: &mut Emitter) {
    if !ctx.root {
        let reason = tr!("root is required to read /root, /home and /etc");
        let all: [(&str, Severity); 8] = [
            ("SEC-001", Medium),
            ("SEC-002", High),
            ("SEC-003", Critical),
            ("SEC-004", Medium),
            ("SEC-005", High),
            ("SEC-006", Medium),
            ("SEC-007", High),
            ("SEC-008", High),
        ];
        for (id, sev) in all {
            em.error(id, sev, tr!("Credential search")).with_detail(reason);
        }
        return;
    }

    let cand = candidates(ctx);

    // SEC-001 / SEC-008: credenciales en texto plano en configuraciones
    let hits = credential_hits(ctx, &cand);
    if hits.is_empty() {
        em.pass("SEC-001", Medium, tr!("No obvious plaintext credentials"));
        em.pass("SEC-008", High, tr!("No credentials in world-readable files"));
    } else {
        em.warn("SEC-001", Medium, &tr!("Possible plaintext credentials ({n} files)", n = hits.len()))
            .with_detail(list_short(&hits))
            .with_fix(tr!("Move them to a secrets manager / EnvironmentFile with mode 600 (check for false positives)"));
        let wr: Vec<String> = hits
            .iter()
            .filter_map(|(f, n)| mode_of(ctx, f).filter(|m| m & 0o004 != 0).map(|m| format!("{f}:{n}({m:o})")))
            .collect();
        if wr.is_empty() {
            em.pass("SEC-008", High, tr!("Files with possible credentials are not world-readable"));
        } else {
            em.warn("SEC-008", High, tr!("Possible credentials in files readable by ALL users"))
                .with_detail(wr.iter().take(8).cloned().collect::<Vec<_>>().join(" "))
                .with_fix(tr!("chmod o-rwx <file> and rotate the credential if it is real"));
        }
    }

    // SEC-002: credenciales embebidas en URLs (git remotes, configs)
    let mut urls: Vec<(String, usize)> = Vec::new();
    for (f, n, line) in matches(ctx, &cand, &URLPAT, 2) {
        if !COMMENT_URL.is_match(&line) && !urls.iter().any(|(uf, _)| *uf == f) {
            urls.push((f, n));
        }
    }
    // los remotos de git viven en .git/config, que no entra en los candidatos
    let mut git = Vec::new();
    for root in ["/root", "/home", "/opt", "/srv", "/var/www"] {
        walk(ctx, root, &WalkOpts { max_depth: Some(6), xdev: true, ..Default::default() }, &mut |e| {
            if e.is_file() && glob_match("*/.git/config", e.path) {
                git.push(e.path.to_string());
            }
        });
    }
    for (f, n, _) in super::util::grep_files_raw(ctx, &git, &URLPAT_CS) {
        if !urls.iter().any(|(uf, _)| *uf == f) {
            urls.push((f, n));
        }
    }
    if urls.is_empty() {
        em.pass("SEC-002", High, tr!("No credentials embedded in URLs"));
    } else {
        em.warn("SEC-002", High, &tr!("Credentials embedded in URLs ({n} files)", n = urls.len()))
            .with_detail(list_short(&urls))
            .with_fix(tr!("Use a credential helper / deploy keys / environment variables"));
    }

    private_keys(ctx, em);
    ssh_keys_without_passphrase(ctx, em);
    credential_files(ctx, em);

    // SEC-006: secretos en historiales de shell
    let histories = expand_all(
        ctx,
        &[
            "/root/.bash_history", "/root/.zsh_history", "/home/*/.bash_history", "/home/*/.zsh_history",
            "/root/.mysql_history", "/home/*/.mysql_history",
        ],
    );
    let x: Vec<String> = histories
        .iter()
        .filter(|h| ctx.path(h).is_file())
        .filter_map(|h| {
            // como grep -c: también en historiales con bytes no válidos (zsh "metafica" caracteres)
            let bytes = std::fs::read(ctx.path(h)).ok()?;
            let n = String::from_utf8_lossy(&bytes).lines().filter(|l| HISTORY.is_match(l)).count();
            (n > 0).then(|| format!("{h}({n})"))
        })
        .collect();
    if x.is_empty() {
        em.pass("SEC-006", Medium, tr!("Shell histories without obvious credentials"));
    } else {
        em.warn("SEC-006", Medium, tr!("Credentials in shell histories"))
            .with_detail(x.join(" "))
            .with_fix(tr!("Rotate those credentials; HISTCONTROL=ignorespace and do not pass passwords on the command line"));
    }

    // SEC-007: credenciales en units de systemd y cron
    let mut files = Vec::new();
    for d in [
        "/etc/systemd/system", "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly",
        "/etc/cron.monthly", "/var/spool/cron",
    ] {
        walk(ctx, d, &WalkOpts::default(), &mut |e| {
            if e.is_file() {
                files.push(e.path.to_string());
            }
        });
    }
    if ctx.path("/etc/crontab").is_file() {
        files.push("/etc/crontab".into());
    }
    let sh = credential_hits(ctx, &files);
    if sh.is_empty() {
        em.pass("SEC-007", High, tr!("No obvious credentials in systemd units or cron"));
    } else {
        em.warn("SEC-007", High, tr!("Possible credentials in systemd units or cron"))
            .with_detail(list_short(&sh))
            .with_fix(tr!("Use EnvironmentFile= (mode 600) or LoadCredential="));
    }
}

static COMMENT_URL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[ \t]*(#|;|//)").expect("regex válida"));

/// SEC-003: claves privadas (el archivo EMPIEZA con la cabecera PEM y tiene su cierre) legibles por todos.
fn private_keys(ctx: &Context, em: &mut Emitter) {
    const ROOTS: &[&str] = &[
        "/etc", "/opt", "/srv", "/var/www", "/root", "/home", "/usr/local/etc", "/usr/local/bin", "/usr/local/sbin",
        "/tmp", "/var/tmp",
    ];
    const SKIP: &[&str] = &["*.md", "*.rst", "*.html", "*.py", "*.rb", "*.js", "*.c", "*.h", "*.pyc", "*.[1-9]", "*.ronn"];
    let prune = |p: &str| any_glob(PRUNE, p);
    let deadline = Instant::now() + scan_timeout();
    let mut files = Vec::new();
    for r in ROOTS {
        let opts = WalkOpts { max_depth: max_depth(ctx), xdev: true, prune: Some(&prune), deadline: Some(deadline) };
        walk(ctx, r, &opts, &mut |e| {
            if e.is_file() && size_below_k(e.meta, 16) && !any_glob(SKIP, e.name()) {
                files.push(e.path.to_string());
            }
        });
    }
    let (mut real, mut bad) = (0, Vec::new());
    for f in files {
        let Some(text) = read_text(&ctx.path(&f)) else { continue };
        if !text.lines().any(|l| KEY_BEGIN.is_match(l)) {
            continue;
        }
        let first = text.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
        if !KEY_BEGIN.is_match(first) || !text.lines().any(|l| KEY_END.is_match(l)) {
            continue;
        }
        real += 1;
        if let Some(m) = mode_of(ctx, &f).filter(|m| m & 0o004 != 0) {
            bad.push(format!("{f}({m:o})"));
        }
    }
    if bad.is_empty() {
        em.pass("SEC-003", Critical, &tr!("Private keys not world-readable ({real} found)", real = real));
    } else {
        em.fail("SEC-003", Critical, tr!("Private keys readable by ALL users"))
            .with_detail(bad.join(" "))
            .with_fix(tr!("chmod 600 <key> and treat the key as compromised (rotate it)"));
    }
}

/// SEC-004: claves SSH de usuario sin passphrase.
fn ssh_keys_without_passphrase(ctx: &Context, em: &mut Emitter) {
    if !(ctx.is_live() && find_command("ssh-keygen").is_some()) {
        em.na("SEC-004", Medium, tr!("SSH keys without a passphrase")).with_detail(tr!("ssh-keygen not installed"));
        return;
    }
    let mut x = Vec::new();
    for k in expand_all(ctx, &["/root/.ssh/id_*", "/home/*/.ssh/id_*"]) {
        if !ctx.path(&k).is_file() || k.ends_with(".pub") || !mode_of(ctx, &k).is_some_and(|m| mode_within(m, 0o600)) {
            continue;
        }
        // -y con passphrase vacía: si funciona, la clave no tiene passphrase. La salida (la clave
        // pública) se descarta.
        let out = live_command_timeout(ctx, "ssh-keygen", &["-y", "-P", "", "-f", &k], Duration::from_secs(30));
        if matches!(out, Some(Timed::Done(o)) if o.ok) {
            x.push(k);
        }
    }
    if x.is_empty() {
        em.pass("SEC-004", Medium, tr!("Users' SSH keys have a passphrase"));
    } else {
        em.warn("SEC-004", Medium, tr!("Private SSH keys without a passphrase"))
            .with_detail(x.join(" "))
            .with_fix(tr!("ssh-keygen -p -f <key> (or use ssh-agent/certificates; restrict service accounts with from=/command=)"));
    }
}

/// SEC-005: archivos de credenciales con permisos amplios.
fn credential_files(ctx: &Context, em: &mut Emitter) {
    const PRUNE5: &[&str] = &["*/node_modules", "*/.cache", "*/gems", "*/rbenv", "*/google-cloud-sdk"];
    const NAMES: &[&str] = &[".netrc", ".pgpass", ".git-credentials", ".my.cnf", ".env", "*.pfx", "*.p12", "*.jks", "*.kdbx"];
    let prune = |p: &str| any_glob(PRUNE5, p);
    let deadline = Instant::now() + scan_timeout();
    let mut bad = Vec::new();
    for r in ["/root", "/home", "/var/www", "/opt", "/srv"] {
        let opts = WalkOpts { max_depth: Some(6), xdev: true, prune: Some(&prune), deadline: Some(deadline) };
        walk(ctx, r, &opts, &mut |e| {
            let n = e.name();
            let is_cred = any_glob(NAMES, n)
                || (glob_match(".env.*", n) && !glob_match("*.example", n) && !glob_match("*.sample", n))
                || (n == "credentials" && glob_match("*/.aws/*", e.path));
            if e.is_file() && is_cred && !mode_within(e.mode(), 0o600) {
                bad.push(format!("{}({:o})", e.path, e.mode()));
            }
        });
    }
    if bad.is_empty() {
        em.pass("SEC-005", High, tr!("Credential files with mode 600"));
    } else {
        em.fail("SEC-005", High, tr!("Credential files with broad permissions"))
            .with_detail(bad.iter().take(8).cloned().collect::<Vec<_>>().join(" "))
            .with_fix(tr!("chmod 600 <file>"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::fixture::Fixture;
    use crate::model::Status;

    #[test]
    fn filtro_de_falsos_positivos() {
        for yes in [
            "password=Sup3rS3cret!",
            "DB_PASSWORD: \"hunter2-largo\"",
            "\"api_key\": \"abcd1234efgh\",",
            "bindpw: s3cr3t-ldap",
            "  token = ghp_abcdefghijklmnop",
        ] {
            assert!(looks_like_credential(yes), "debería detectar: {yes}");
        }
        for no in [
            "# password=Sup3rS3cret!",
            "; password=Sup3rS3cret!",
            "password_file=/etc/app/pass",
            "PasswordAuthentication no",
            "passwd:         files systemd",
            "token: ${GITHUB_TOKEN}",
            "secret=<cambiar>",
            "password=abc",
            "api_key_version=1.2.3",
            "password_min_length=12",
            "credential=none",
            "password = /run/secrets/db",
            // regla de perfil de lynis: nombra /etc/passwd y sus permisos, no es una credencial
            "permfile=/etc/passwd:rw-r--r--:root:-:WARN:",
        ] {
            assert!(!looks_like_credential(no), "no debería detectar: {no}");
        }
    }

    #[test]
    fn perfil_lynis_no_se_marca_como_credencial() {
        let f = Fixture::new();
        // la línea exacta del bug (issue #6): /etc/lynis/default.prf:312
        f.file("/etc/lynis/default.prf", "# perfil de lynis\npermfile=/etc/passwd:rw-r--r--:root:-:WARN:\n")
            .mode("/etc/lynis/default.prf", 0o644)
            // una credencial real debe seguir detectándose
            .file("/etc/app/real.conf", "db_password=Sup3rS3cretValue\n")
            .mode("/etc/app/real.conf", 0o644);
        let r = f.run(run);
        assert_eq!(r["SEC-001"].status, Status::Warn);
        assert!(!r["SEC-001"].detail.contains("default.prf"), "{}", r["SEC-001"].detail);
        assert!(!r["SEC-001"].detail.contains("lynis"), "{}", r["SEC-001"].detail);
        assert!(r["SEC-001"].detail.contains("/etc/app/real.conf"), "{}", r["SEC-001"].detail);
        assert_eq!(r["SEC-008"].status, Status::Warn, "real.conf es 644");
        assert!(!r["SEC-008"].detail.contains("default.prf"), "{}", r["SEC-008"].detail);
        assert!(r["SEC-008"].detail.contains("/etc/app/real.conf"), "{}", r["SEC-008"].detail);
    }

    /// Valores de secretos falsos que NUNCA pueden aparecer en un resultado.
    const SECRETS: &[&str] =
        &["Sup3rS3cretValue", "hunter2-db-pass", "ghp_TokenDePrueba123", "s3cr3tUrlPass", "HistoriaPass99"];

    fn fixture_con_secretos() -> Fixture {
        let f = Fixture::new();
        f.file("/etc/app/app.conf", "# configuración\nport=8080\ndb_password=Sup3rS3cretValue\n")
            .mode("/etc/app/app.conf", 0o644)
            .file("/etc/app/otra.conf", "password_file=/etc/app/pass\n")
            .file("/opt/svc/.env", "API_TOKEN=ghp_TokenDePrueba123\n")
            .mode("/opt/svc/.env", 0o640)
            .file("/opt/svc/README.md", "password=hunter2-db-pass\n")
            .file("/home/ana/proj/.git/config", "[remote \"origin\"]\n\turl = https://ana:s3cr3tUrlPass@git.example.com/x.git\n")
            .file("/home/ana/.bash_history", "ls\nmysql -u root -pHistoriaPass99 prod\ncd /\n")
            .file("/home/ana/.ssh/id_backup", "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n")
            .mode("/home/ana/.ssh/id_backup", 0o644)
            .file("/home/ana/notas.txt", "texto\n-----BEGIN RSA PRIVATE KEY-----\n(ejemplo en medio de un texto)\n")
            .mode("/home/ana/notas.txt", 0o644)
            .file("/etc/systemd/system/app.service", "[Service]\nEnvironment=SECRET_KEY=Sup3rS3cretValue\n");
        f
    }

    #[test]
    fn detecta_sin_mostrar_valores() {
        let f = fixture_con_secretos();
        let r = f.run(run);
        assert_eq!(r["SEC-001"].status, Status::Warn);
        assert!(r["SEC-001"].detail.contains("/etc/app/app.conf:3"), "{}", r["SEC-001"].detail);
        assert!(r["SEC-001"].detail.contains("/opt/svc/.env:1"));
        assert!(!r["SEC-001"].detail.contains("otra.conf"), "password_file no es una credencial");
        assert!(!r["SEC-001"].detail.contains("README"), "los .md no se revisan");
        assert_eq!(r["SEC-008"].status, Status::Warn, "app.conf es 644");
        assert!(r["SEC-008"].detail.contains("/etc/app/app.conf:3(644)"));
        assert_eq!(r["SEC-002"].detail, "/home/ana/proj/.git/config:2");
        assert_eq!(r["SEC-003"].detail, "/home/ana/.ssh/id_backup(644)", "notas.txt no empieza con la cabecera");
        assert_eq!(r["SEC-006"].detail, "/home/ana/.bash_history(1)");
        assert_eq!(r["SEC-007"].detail, "/etc/systemd/system/app.service:2");
        assert_eq!(r["SEC-004"].status, Status::Na, "en fixtures no se ejecuta ssh-keygen");

        // ningún valor de secreto puede aparecer en ningún campo, ni serializado a JSON
        let json = serde_json::to_string(&r.values().collect::<Vec<_>>()).unwrap();
        for s in SECRETS {
            assert!(!json.contains(s), "¡se filtró un secreto en el reporte!: {s}");
        }
    }

    #[test]
    fn archivos_de_credenciales() {
        let f = Fixture::new();
        f.file("/home/ana/.pgpass", "x").mode("/home/ana/.pgpass", 0o644);
        f.file("/home/ana/.netrc", "x").mode("/home/ana/.netrc", 0o600);
        f.file("/home/ana/.aws/credentials", "x").mode("/home/ana/.aws/credentials", 0o640);
        f.file("/home/ana/app/.env.example", "x").mode("/home/ana/app/.env.example", 0o644);
        let r = f.run(run);
        let d = &r["SEC-005"].detail;
        assert!(d.contains("/home/ana/.pgpass(644)") && d.contains("/home/ana/.aws/credentials(640)"), "{d}");
        assert!(!d.contains(".netrc") && !d.contains(".env.example"), "{d}");
    }

    #[test]
    fn sin_root_todo_queda_sin_evaluar() {
        let mut f = Fixture::new();
        f.is_root = false;
        let r = f.run(run);
        assert_eq!(r.len(), 8);
        assert!(r.values().all(|x| x.status == Status::Error));
        assert_eq!(r["SEC-003"].severity, Severity::Critical);
    }

    #[test]
    fn sistema_sin_secretos() {
        let f = Fixture::new();
        f.file("/etc/app.conf", "port=80\n");
        let r = f.run(run);
        for id in ["SEC-001", "SEC-002", "SEC-003", "SEC-005", "SEC-006", "SEC-007", "SEC-008"] {
            assert_eq!(r[id].status, Status::Pass, "{id}");
        }
        assert_eq!(r["SEC-003"].title, "Claves privadas no legibles por todos (0 halladas)");
    }
}
