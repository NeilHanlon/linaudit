//! Traducciones al estilo gettext.
//!
//! Los textos del código están en inglés y son la clave (msgid) de los catálogos `po/*.po`,
//! que van embebidos en el binario: funciona igual instalado desde el .deb que suelto.
//! Si falta una traducción se muestra el inglés.
//!
//! - `tr!("Text")` devuelve `&'static str` traducido.
//! - `tr!("Found {n} files in {dir}", n = count, dir = path.display())` traduce y después
//!   reemplaza los `{nombre}` (solo nombres, sin especificadores de formato; `{{` y `}}` son llaves).
//! - `trn!("{n} file", "{n} files", count, n = count)` elige singular/plural según el idioma.
//! - `N_!("Text")` marca un texto para extraer sin traducirlo todavía (tablas `const`);
//!   se traduce después con [`tr`].
//!
//! Los IDs de los controles, las claves del JSON y los valores de la CLI no se traducen.
//! Para actualizar los catálogos: `contrib/i18n-update.sh`.

use std::cell::Cell;
use std::collections::HashMap;
use std::fmt::Display;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Lang {
    En,
    Es,
}

impl Lang {
    pub const ALL: [Lang; 2] = [Lang::Es, Lang::En];

    /// Código estable (config, --lang, LINAUDIT_LANG).
    pub fn code(self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::Es => "es",
        }
    }

    /// Nombre del idioma en ese mismo idioma (para el selector: no se traduce).
    pub fn native_name(self) -> &'static str {
        match self {
            Lang::En => "English",
            Lang::Es => "Español",
        }
    }

    /// Acepta un código ("es", "en") o un locale POSIX ("es_AR.UTF-8", "en_US", "C").
    pub fn from_code(s: &str) -> Option<Lang> {
        let s = s.trim();
        let base = s.split(['_', '.', '@', '-']).next().unwrap_or("").to_ascii_lowercase();
        match base.as_str() {
            "es" => Some(Lang::Es),
            "en" | "c" | "posix" => Some(Lang::En),
            _ => None,
        }
    }

    /// Idioma según el entorno, con el orden de prioridad de gettext:
    /// LANGUAGE (lista separada por ':'), LC_ALL, LC_MESSAGES, LANG. `None` si no hay un idioma soportado.
    pub fn from_env() -> Option<Lang> {
        Self::from_env_with(|k| std::env::var(k).ok())
    }

    pub fn from_env_with(get: impl Fn(&str) -> Option<String>) -> Option<Lang> {
        let nonempty = |k: &str| get(k).filter(|v| !v.trim().is_empty());
        // gettext ignora LANGUAGE si el locale es C/POSIX
        let locale = ["LC_ALL", "LC_MESSAGES", "LANG"].into_iter().find_map(nonempty);
        let is_c = locale.as_deref().is_some_and(|l| matches!(l, "C" | "POSIX") || l.starts_with("C."));
        if !is_c {
            if let Some(list) = nonempty("LANGUAGE") {
                if let Some(l) = list.split(':').find_map(Lang::from_code) {
                    return Some(l);
                }
            }
        }
        locale.as_deref().and_then(Lang::from_code)
    }

    fn catalog(self) -> Option<&'static Catalog> {
        match self {
            Lang::En => None,
            Lang::Es => Some(&ES),
        }
    }
}

const LANG_EN: u8 = 0;
const LANG_ES: u8 = 1;

/// Idioma global. En los tests de este crate es castellano: los tests verifican los textos
/// históricos (los mismos que la versión bash).
static GLOBAL: AtomicU8 = AtomicU8::new(if cfg!(test) { LANG_ES } else { LANG_EN });

thread_local! {
    static OVERRIDE: Cell<Option<Lang>> = const { Cell::new(None) };
}

pub fn set_lang(l: Lang) {
    GLOBAL.store(if l == Lang::Es { LANG_ES } else { LANG_EN }, Ordering::Relaxed);
}

pub fn lang() -> Lang {
    OVERRIDE.with(|o| o.get()).unwrap_or(if GLOBAL.load(Ordering::Relaxed) == LANG_ES { Lang::Es } else { Lang::En })
}

/// Corre `f` con otro idioma solo en este hilo (para tests).
pub fn with_lang<R>(l: Lang, f: impl FnOnce() -> R) -> R {
    let prev = OVERRIDE.with(|o| o.replace(Some(l)));
    let out = f();
    OVERRIDE.with(|o| o.set(prev));
    out
}

/// Traduce un msgid al idioma actual.
pub fn tr(msgid: &'static str) -> &'static str {
    lang().catalog().and_then(|c| c.get(msgid)).unwrap_or(msgid)
}

/// Traduce un texto que no es un literal (por ejemplo, de una tabla marcada con `N_!`).
pub fn tr_dyn(msgid: &str) -> &str {
    match lang().catalog().and_then(|c| c.get(msgid)) {
        Some(s) => s,
        None => msgid,
    }
}

/// Traduce con contexto (para msgids iguales que necesitan traducciones distintas).
pub fn trc(ctx: &'static str, msgid: &'static str) -> &'static str {
    lang().catalog().and_then(|c| c.get(&format!("{ctx}\u{4}{msgid}"))).unwrap_or(msgid)
}

/// Singular o plural según `n`.
pub fn trn(singular: &'static str, plural: &'static str, n: u64) -> &'static str {
    let l = lang();
    if let Some(forms) = l.catalog().and_then(|c| c.plurals.get(singular)) {
        if let Some(s) = forms.get(plural_index(l, n)).filter(|s| !s.is_empty()) {
            return s;
        }
    }
    if n == 1 { singular } else { plural }
}

fn plural_index(l: Lang, n: u64) -> usize {
    match l {
        // Plural-Forms: nplurals=2; plural=(n != 1);
        Lang::En | Lang::Es => usize::from(n != 1),
    }
}

/// Reemplaza `{nombre}` por su valor. `{{`/`}}` son llaves literales; un nombre desconocido queda tal cual.
pub fn format(template: &str, args: &[(&str, &dyn Display)]) -> String {
    let mut out = String::with_capacity(template.len() + 16);
    let mut rest = template;
    while let Some(i) = rest.find(['{', '}']) {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        if tail.starts_with("{{") || tail.starts_with("}}") {
            out.push_str(&tail[..1]);
            rest = &tail[2..];
            continue;
        }
        if tail.starts_with('{') {
            if let Some(end) = tail.find('}') {
                let name = &tail[1..end];
                if let Some((_, v)) = args.iter().find(|(k, _)| *k == name) {
                    use std::fmt::Write;
                    let _ = write!(out, "{v}");
                    rest = &tail[end + 1..];
                    continue;
                }
            }
        }
        out.push_str(&tail[..1]);
        rest = &tail[1..];
    }
    out.push_str(rest);
    out
}

#[macro_export]
macro_rules! tr {
    ($msg:literal) => {
        $crate::i18n::tr($msg)
    };
    ($msg:literal, $($k:ident = $v:expr),+ $(,)?) => {
        $crate::i18n::format($crate::i18n::tr($msg), &[$((stringify!($k), &$v as &dyn ::std::fmt::Display)),+])
    };
}

#[macro_export]
macro_rules! trc {
    ($ctx:literal, $msg:literal) => {
        $crate::i18n::trc($ctx, $msg)
    };
    ($ctx:literal, $msg:literal, $($k:ident = $v:expr),+ $(,)?) => {
        $crate::i18n::format($crate::i18n::trc($ctx, $msg), &[$((stringify!($k), &$v as &dyn ::std::fmt::Display)),+])
    };
}

#[macro_export]
macro_rules! trn {
    ($s:literal, $p:literal, $n:expr) => {
        $crate::i18n::trn($s, $p, ($n) as u64)
    };
    ($s:literal, $p:literal, $n:expr, $($k:ident = $v:expr),+ $(,)?) => {
        $crate::i18n::format($crate::i18n::trn($s, $p, ($n) as u64), &[$((stringify!($k), &$v as &dyn ::std::fmt::Display)),+])
    };
}

/// Marca un texto para extraer sin traducirlo (gettext_noop). Se traduce después con [`tr`].
#[macro_export]
macro_rules! N_ {
    ($msg:literal) => {
        $msg
    };
}

// ---------------------------------------------------------------------------------------------
// Catálogos

#[derive(Debug, Default)]
pub struct Catalog {
    singular: HashMap<String, String>,
    plurals: HashMap<String, Vec<String>>,
}

impl Catalog {
    fn get(&self, key: &str) -> Option<&str> {
        self.singular.get(key).map(String::as_str).filter(|s| !s.is_empty())
    }

    /// Entradas (msgid con contexto si lo tiene -> msgstr), para tests.
    pub fn entries(&self) -> impl Iterator<Item = (&str, &str)> {
        self.singular.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    pub fn plural_entries(&self) -> impl Iterator<Item = (&str, &[String])> {
        self.plurals.iter().map(|(k, v)| (k.as_str(), v.as_slice()))
    }

    /// Parser de .po: msgctxt, msgid, msgid_plural, msgstr, msgstr[n], continuaciones y escapes.
    /// Se ignoran las entradas "fuzzy" (como gettext) y la cabecera.
    pub fn parse(po: &str) -> Catalog {
        #[derive(Default)]
        struct Entry {
            ctx: Option<String>,
            id: Option<String>,
            plural: Option<String>,
            strs: Vec<String>,
            fuzzy: bool,
        }
        let mut cat = Catalog::default();
        let mut cur = Entry::default();
        // a qué campo se pegan las líneas de continuación
        enum Field {
            None,
            Ctx,
            Id,
            Plural,
            Str(usize),
        }
        let mut field = Field::None;
        let mut flush = |e: &mut Entry| {
            let e = std::mem::take(e);
            let Some(id) = e.id else { return };
            if id.is_empty() || e.fuzzy {
                return;
            }
            let key = match e.ctx {
                Some(c) => format!("{c}\u{4}{id}"),
                None => id,
            };
            if e.plural.is_some() {
                cat.plurals.insert(key, e.strs);
            } else if let Some(s) = e.strs.into_iter().next() {
                cat.singular.insert(key, s);
            }
        };
        for line in po.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            // una entrada termina en su msgstr: lo que venga después (comentario, msgctxt, msgid) abre otra
            let starts_entry = line.starts_with('#') || line.starts_with("msgctxt") || line.starts_with("msgid ");
            if starts_entry && !cur.strs.is_empty() {
                flush(&mut cur);
                field = Field::None;
            }
            if let Some(flags) = line.strip_prefix("#,") {
                cur.fuzzy |= flags.split(',').any(|f| f.trim() == "fuzzy");
                continue;
            }
            if line.starts_with('#') {
                continue;
            }
            if line.starts_with('"') {
                let s = unquote(line);
                match field {
                    Field::Ctx => cur.ctx.get_or_insert_default().push_str(&s),
                    Field::Id => cur.id.get_or_insert_default().push_str(&s),
                    Field::Plural => cur.plural.get_or_insert_default().push_str(&s),
                    Field::Str(i) => {
                        if let Some(x) = cur.strs.get_mut(i) {
                            x.push_str(&s);
                        }
                    }
                    Field::None => {}
                }
                continue;
            }
            let (kw, rest) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
            let val = unquote(rest.trim());
            match kw {
                "msgctxt" => {
                    cur.ctx = Some(val);
                    field = Field::Ctx;
                }
                "msgid" => {
                    cur.id = Some(val);
                    field = Field::Id;
                }
                "msgid_plural" => {
                    cur.plural = Some(val);
                    field = Field::Plural;
                }
                "msgstr" => {
                    cur.strs = vec![val];
                    field = Field::Str(0);
                }
                _ if kw.starts_with("msgstr[") => {
                    let i: usize = kw[7..kw.len() - 1].parse().unwrap_or(0);
                    if cur.strs.len() <= i {
                        cur.strs.resize(i + 1, String::new());
                    }
                    cur.strs[i] = val;
                    field = Field::Str(i);
                }
                _ => {}
            }
        }
        flush(&mut cur);
        cat
    }
}

fn unquote(s: &str) -> String {
    let s = s.strip_prefix('"').and_then(|s| s.strip_suffix('"')).unwrap_or(s);
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some(o) => out.push(o),
            None => {}
        }
    }
    out
}

/// Escapa un texto para un .po.
pub fn po_quote(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

static ES: LazyLock<Catalog> = LazyLock::new(|| Catalog::parse(include_str!("../../../po/es.po")));

/// Catálogo de un idioma (None para inglés, que no tiene catálogo).
pub fn catalog(l: Lang) -> Option<&'static Catalog> {
    l.catalog()
}

pub mod extract;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formatea_nombres_y_llaves() {
        let n = 3;
        assert_eq!(format("{n} files in {dir}", &[("n", &n), ("dir", &"/tmp")]), "3 files in /tmp");
        assert_eq!(format("{{literal}} {x}", &[]), "{literal} {x}");
        assert_eq!(format("a } b {", &[]), "a } b {");
    }

    #[test]
    fn parsea_po() {
        let po = r#"
msgid ""
msgstr ""
"Content-Type: text/plain; charset=UTF-8\n"

#: a.rs
msgid "Hello"
msgstr "Hola"

msgid "multi"
"line"
msgstr "multi"
"línea \"con\" comillas\n"

#, fuzzy
msgid "Fuzzy"
msgstr "Difuso"

msgctxt "menu"
msgid "Open"
msgstr "Abrir"

msgid "{n} file"
msgid_plural "{n} files"
msgstr[0] "{n} archivo"
msgstr[1] "{n} archivos"

msgid "Untranslated"
msgstr ""
"#;
        let c = Catalog::parse(po);
        assert_eq!(c.get("Hello"), Some("Hola"));
        assert_eq!(c.get("multiline"), Some("multilínea \"con\" comillas\n"));
        assert_eq!(c.get("Fuzzy"), None);
        assert_eq!(c.get("menu\u{4}Open"), Some("Abrir"));
        assert_eq!(c.get("Open"), None);
        assert_eq!(c.plurals["{n} file"], vec!["{n} archivo", "{n} archivos"]);
        assert_eq!(c.get("Untranslated"), None);
        assert_eq!(c.get(""), None);
    }

    #[test]
    fn idioma_desde_el_entorno() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |k: &str| pairs.iter().find(|(kk, _)| *kk == k).map(|(_, v)| v.to_string())
        };
        assert_eq!(Lang::from_env_with(env(&[("LANG", "es_AR.UTF-8")])), Some(Lang::Es));
        assert_eq!(Lang::from_env_with(env(&[("LANG", "es_AR.UTF-8"), ("LC_ALL", "en_US.UTF-8")])), Some(Lang::En));
        assert_eq!(Lang::from_env_with(env(&[("LANG", "en_US.UTF-8"), ("LANGUAGE", "es:en")])), Some(Lang::Es));
        assert_eq!(Lang::from_env_with(env(&[("LANG", "C"), ("LANGUAGE", "es")])), Some(Lang::En));
        assert_eq!(Lang::from_env_with(env(&[("LANG", "fr_FR.UTF-8")])), None);
        assert_eq!(Lang::from_env_with(env(&[("LANG", "fr_FR.UTF-8"), ("LANGUAGE", "fr:es")])), Some(Lang::Es));
        assert_eq!(Lang::from_env_with(env(&[])), None);
    }

    #[test]
    fn ingles_es_el_msgid() {
        with_lang(Lang::En, || {
            assert_eq!(tr!("Some text that is not in any catalog"), "Some text that is not in any catalog");
            assert_eq!(trn!("{n} file", "{n} files", 1, n = 1), "1 file");
            assert_eq!(trn!("{n} file", "{n} files", 2, n = 2), "2 files");
        });
    }

    /// Cada texto marcado en el código tiene traducción al castellano, con los mismos `{nombres}`.
    #[test]
    fn catalogo_es_completo() {
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
        let msgs = extract::scan_workspace(std::path::Path::new(root)).expect("leer fuentes");
        assert!(!msgs.is_empty());
        let mut missing = Vec::new();
        let mut bad = Vec::new();
        for m in &msgs {
            let key = m.key();
            let found: Vec<&str> = match &m.plural {
                None => ES.get(&key).into_iter().collect(),
                Some(_) => ES.plurals.get(&key).map(|v| v.iter().map(String::as_str).collect()).unwrap_or_default(),
            };
            if found.iter().all(|s| s.is_empty()) {
                missing.push(format!("{} ({})", m.id, m.files.join(", ")));
                continue;
            }
            let want = placeholders(&m.id);
            for s in found {
                if placeholders(s) != want {
                    bad.push(format!("{:?} -> {:?}", m.id, s));
                }
            }
        }
        assert!(missing.is_empty(), "sin traducir en po/es.po (correr contrib/i18n-update.sh):\n{}", missing.join("\n"));
        assert!(bad.is_empty(), "traducciones con otros {{nombres}}:\n{}", bad.join("\n"));
    }

    fn placeholders(s: &str) -> std::collections::BTreeSet<String> {
        let s = s.replace("{{", "").replace("}}", "");
        let mut out = std::collections::BTreeSet::new();
        let mut rest = s.as_str();
        while let Some(i) = rest.find('{') {
            match rest[i..].find('}') {
                Some(j) => {
                    out.insert(rest[i + 1..i + j].to_string());
                    rest = &rest[i + j + 1..];
                }
                None => break,
            }
        }
        out
    }
}
