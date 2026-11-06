//! Extractor de textos traducibles (el xgettext de Debian 13 todavía no entiende Rust).
//!
//! Busca `tr!`, `trc!`, `trn!` y `N_!` seguidos de literales de texto en `crates/*/src/**/*.rs`,
//! salteando comentarios y los módulos de test (`#[cfg(test)]` al final de cada archivo).
//! Lo usan el test de cobertura del catálogo y `contrib/i18n-update.sh` (que genera el .pot).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::po_quote;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Msg {
    pub ctx: Option<String>,
    pub id: String,
    pub plural: Option<String>,
    /// Archivos donde aparece (relativos a la raíz del workspace).
    pub files: Vec<String>,
}

impl Msg {
    /// Clave en el catálogo (gettext separa contexto e id con \x04).
    pub fn key(&self) -> String {
        match &self.ctx {
            Some(c) => format!("{c}\u{4}{}", self.id),
            None => self.id.clone(),
        }
    }
}

/// Todos los textos del workspace, en orden de aparición y sin duplicados.
pub fn scan_workspace(root: &Path) -> std::io::Result<Vec<Msg>> {
    let mut files = Vec::new();
    for krate in std::fs::read_dir(root.join("crates"))? {
        collect_rs(&krate?.path().join("src"), &mut files);
    }
    files.sort();
    let mut order: Vec<String> = Vec::new();
    let mut by_key: BTreeMap<String, Msg> = BTreeMap::new();
    for f in files {
        let text = std::fs::read_to_string(&f)?;
        let rel = f.strip_prefix(root).unwrap_or(&f).to_string_lossy().into_owned();
        for m in scan_source(&text) {
            let key = m.key();
            match by_key.get_mut(&key) {
                Some(prev) => {
                    if !prev.files.contains(&rel) {
                        prev.files.push(rel.clone());
                    }
                }
                None => {
                    order.push(key.clone());
                    by_key.insert(key, Msg { files: vec![rel.clone()], ..m });
                }
            }
        }
    }
    Ok(order.into_iter().filter_map(|k| by_key.remove(&k)).collect())
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect_rs(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// Textos de un archivo fuente.
pub fn scan_source(src: &str) -> Vec<Msg> {
    let src = strip_test_module(src);
    let toks = tokenize(src);
    let mut out = Vec::new();
    let mut i = 0;
    while i < toks.len() {
        if let Tok::Macro(name) = &toks[i] {
            let lits: Vec<&String> = toks[i + 1..]
                .iter()
                .skip_while(|t| matches!(t, Tok::Open))
                .take_while(|t| matches!(t, Tok::Str(_) | Tok::Comma))
                .filter_map(|t| if let Tok::Str(s) = t { Some(s) } else { None })
                .collect();
            let m = match (name.as_str(), lits.as_slice()) {
                ("tr" | "N_", [id, ..]) => Some(Msg { ctx: None, id: (*id).clone(), plural: None, files: vec![] }),
                ("trc", [c, id, ..]) => Some(Msg { ctx: Some((*c).clone()), id: (*id).clone(), plural: None, files: vec![] }),
                ("trn", [s, p, ..]) => Some(Msg { ctx: None, id: (*s).clone(), plural: Some((*p).clone()), files: vec![] }),
                _ => None,
            };
            out.extend(m);
        }
        i += 1;
    }
    out
}

/// Corta en el `#[cfg(test)]` que abre el módulo de tests.
fn strip_test_module(src: &str) -> &str {
    let mut pos = 0;
    for line in src.split_inclusive('\n') {
        if line.trim() == "#[cfg(test)]" {
            // solo un módulo con cuerpo (`mod tests {`), no una declaración (`mod fixture;`)
            let rest = src[pos + line.len()..].trim_start();
            let rest = rest.strip_prefix("pub(crate) ").or_else(|| rest.strip_prefix("pub ")).unwrap_or(rest);
            if let Some(decl) = rest.strip_prefix("mod ") {
                let head = decl.split(['{', ';']).next().unwrap_or("");
                if decl[head.len()..].starts_with('{') {
                    return &src[..pos];
                }
            }
        }
        pos += line.len();
    }
    src
}

#[derive(Debug)]
enum Tok {
    Macro(String),
    Open,
    Comma,
    Str(String),
    Other,
}

/// Tokenizador mínimo: lo justo para encontrar `macro!(` y los literales que le siguen.
fn tokenize(src: &str) -> Vec<Tok> {
    let b: Vec<char> = src.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == '/' && b.get(i + 1) == Some(&'/') {
            while i < b.len() && b[i] != '\n' {
                i += 1;
            }
        } else if c == '/' && b.get(i + 1) == Some(&'*') {
            let mut depth = 0;
            while i < b.len() {
                if b[i] == '/' && b.get(i + 1) == Some(&'*') {
                    depth += 1;
                    i += 2;
                } else if b[i] == '*' && b.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
        } else if c == '"' {
            let (s, next) = string_lit(&b, i + 1);
            out.push(Tok::Str(s));
            i = next;
        } else if c == 'r' && matches!(b.get(i + 1), Some('"' | '#')) && !prev_is_ident(&b, i) {
            // r"..." o r#"..."#
            let mut j = i + 1;
            let mut hashes = 0;
            while b.get(j) == Some(&'#') {
                hashes += 1;
                j += 1;
            }
            if b.get(j) != Some(&'"') {
                out.push(Tok::Other);
                i += 1;
                continue;
            }
            j += 1;
            let start = j;
            loop {
                if j >= b.len() {
                    break;
                }
                if b[j] == '"' && (0..hashes).all(|k| b.get(j + 1 + k) == Some(&'#')) {
                    break;
                }
                j += 1;
            }
            out.push(Tok::Str(b[start..j.min(b.len())].iter().collect()));
            i = j + 1 + hashes;
        } else if c == '\'' {
            // carácter ('x', '\n', '\u{..}') o lifetime ('a)
            if b.get(i + 1) == Some(&'\\') {
                let mut j = i + 2;
                while j < b.len() && b[j] != '\'' {
                    j += 1;
                }
                i = j + 1;
            } else if b.get(i + 2) == Some(&'\'') {
                i += 3;
            } else {
                i += 1;
            }
            out.push(Tok::Other);
        } else if c.is_alphabetic() || c == '_' {
            let start = i;
            while i < b.len() && (b[i].is_alphanumeric() || b[i] == '_') {
                i += 1;
            }
            let word: String = b[start..i].iter().collect();
            if b.get(i) == Some(&'!') && matches!(word.as_str(), "tr" | "trc" | "trn" | "N_") {
                out.push(Tok::Macro(word));
                i += 1;
            } else {
                out.push(Tok::Other);
            }
        } else if c == '(' {
            out.push(Tok::Open);
            i += 1;
        } else if c == ',' {
            out.push(Tok::Comma);
            i += 1;
        } else if c.is_whitespace() {
            i += 1;
        } else {
            out.push(Tok::Other);
            i += 1;
        }
    }
    out
}

fn prev_is_ident(b: &[char], i: usize) -> bool {
    i > 0 && (b[i - 1].is_alphanumeric() || b[i - 1] == '_')
}

/// Literal normal desde `i` (después de la comilla). Aplica los escapes de Rust,
/// incluida la continuación `\` + salto de línea (que se come la indentación siguiente).
fn string_lit(b: &[char], mut i: usize) -> (String, usize) {
    let mut s = String::new();
    while i < b.len() {
        match b[i] {
            '"' => return (s, i + 1),
            '\\' => {
                i += 1;
                match b.get(i) {
                    Some('n') => s.push('\n'),
                    Some('t') => s.push('\t'),
                    Some('r') => s.push('\r'),
                    Some('0') => s.push('\0'),
                    Some('\n') => {
                        while i + 1 < b.len() && b[i + 1].is_whitespace() {
                            i += 1;
                        }
                    }
                    Some('u') => {
                        let end = (i..b.len()).find(|&k| b[k] == '}').unwrap_or(i);
                        let hex: String = b[i + 2..end].iter().collect();
                        if let Some(ch) = u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                            s.push(ch);
                        }
                        i = end;
                    }
                    Some('x') => {
                        let hex: String = b[i + 1..(i + 3).min(b.len())].iter().collect();
                        if let Some(ch) = u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                            s.push(ch);
                        }
                        i += 2;
                    }
                    Some(&o) => s.push(o),
                    None => {}
                }
                i += 1;
            }
            c => {
                s.push(c);
                i += 1;
            }
        }
    }
    (s, i)
}

/// Plantilla .pot con todos los textos.
pub fn render_pot(msgs: &[Msg], version: &str) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "# linaudit translation template.\n\
         # Generated by contrib/i18n-update.sh: do not edit by hand.\n\
         # This file is distributed under the same license as the linaudit package (AGPL-3.0-or-later).\n\
         #\n\
         #, fuzzy\n\
         msgid \"\"\n\
         msgstr \"\"\n\
         \"Project-Id-Version: linaudit {version}\\n\"\n\
         \"Report-Msgid-Bugs-To: https://github.com/alexiarstein/linaudit/issues\\n\"\n\
         \"Language: \\n\"\n\
         \"MIME-Version: 1.0\\n\"\n\
         \"Content-Type: text/plain; charset=UTF-8\\n\"\n\
         \"Content-Transfer-Encoding: 8bit\\n\"\n\
         \"Plural-Forms: nplurals=INTEGER; plural=EXPRESSION;\\n\"\n"
    ));
    for m in msgs {
        out.push('\n');
        out.push_str(&format!("#: {}\n", m.files.join(" ")));
        if m.id.contains('{') {
            out.push_str("#. {name} is replaced by a value: keep it exactly as is\n");
        }
        if let Some(c) = &m.ctx {
            out.push_str(&format!("msgctxt {}\n", po_quote(c)));
        }
        out.push_str(&format!("msgid {}\n", po_quote(&m.id)));
        match &m.plural {
            Some(p) => {
                out.push_str(&format!("msgid_plural {}\nmsgstr[0] \"\"\nmsgstr[1] \"\"\n", po_quote(p)));
            }
            None => out.push_str("msgstr \"\"\n"),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encuentra_macros_y_ignora_comentarios_y_tests() {
        let src = r##"
// tr!("en comentario")
/* tr!("en bloque") */
fn f() {
    let a = tr!("Hello");
    let b = tr!("Found {n}", n = 3);
    let c = trn!("{n} file", "{n} files", k, n = k);
    let d = trc!("menu", "Open");
    const X: &str = N_!("Table text");
    let e = tr!("long \
                 text with \"quotes\"");
    let f = tr!(r#"raw "x""#);
    let g = 'a'; let h = '"'; let i = format!("not tr!(\"x\")");
}
#[cfg(test)]
mod tests { fn t() { tr!("only in tests"); } }
"##;
        let decl = "#[cfg(test)]\nmod fixture;\nfn g() { tr!(\"after decl\"); }\n";
        assert_eq!(scan_source(decl).len(), 1);
        let got: Vec<(Option<String>, String, Option<String>)> =
            scan_source(src).into_iter().map(|m| (m.ctx, m.id, m.plural)).collect();
        let s = |x: &str| x.to_string();
        assert_eq!(
            got,
            vec![
                (None, s("Hello"), None),
                (None, s("Found {n}"), None),
                (None, s("{n} file"), Some(s("{n} files"))),
                (Some(s("menu")), s("Open"), None),
                (None, s("Table text"), None),
                (None, s("long text with \"quotes\""), None),
                (None, s("raw \"x\""), None),
            ]
        );
    }
}
