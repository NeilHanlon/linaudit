//! Recorrido de directorios equivalente a `find` (sin seguir symlinks), con -prune, -xdev,
//! -maxdepth y un límite de tiempo. Y comodines al estilo de `find -name` / `-path`.

use std::fs::Metadata;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use super::Context;

/// Tiempo máximo de cada barrido: LINAUDIT_SCAN_TIMEOUT segundos (120 por defecto).
/// LA_SCAN_TIMEOUT es el nombre de la versión bash y se sigue aceptando.
pub fn scan_timeout() -> Duration {
    let secs = ["LINAUDIT_SCAN_TIMEOUT", "LA_SCAN_TIMEOUT"]
        .iter()
        .find_map(|k| std::env::var(k).ok().and_then(|v| v.parse().ok()))
        .unwrap_or(120);
    Duration::from_secs(secs)
}

pub struct Entry<'a> {
    /// Ruta en el sistema auditado (ej. "/etc/passwd").
    pub path: &'a str,
    /// Ruta real a leer (difiere de `path` en tests con fixtures).
    pub real: &'a std::path::Path,
    pub meta: &'a Metadata,
    pub depth: usize,
}

impl Entry<'_> {
    pub fn name(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or(self.path)
    }
    pub fn is_file(&self) -> bool {
        self.meta.file_type().is_file()
    }
    pub fn is_dir(&self) -> bool {
        self.meta.file_type().is_dir()
    }
    pub fn mode(&self) -> u32 {
        self.meta.mode() & 0o7777
    }
}

#[derive(Default)]
pub struct WalkOpts<'a> {
    /// Como `-maxdepth`: la raíz es profundidad 0.
    pub max_depth: Option<usize>,
    /// Como `-xdev`: no entrar en otros filesystems.
    pub xdev: bool,
    /// Como `\( ... \) -prune`: la entrada (y lo que tenga adentro) se descarta.
    pub prune: Option<&'a dyn Fn(&str) -> bool>,
    pub deadline: Option<Instant>,
}

/// Recorre `root` en el mismo orden que `find` (preorden, en el orden de readdir).
/// Devuelve false si se cortó por tiempo.
pub fn walk(ctx: &Context, root: &str, opts: &WalkOpts, visit: &mut dyn FnMut(&Entry)) -> bool {
    let real = ctx.path(root);
    let Ok(meta) = std::fs::symlink_metadata(&real) else { return true };
    let dev = meta.dev();
    rec(root.to_string(), real, meta, 0, dev, opts, visit)
}

fn rec(
    path: String,
    real: PathBuf,
    meta: Metadata,
    depth: usize,
    dev: u64,
    opts: &WalkOpts,
    visit: &mut dyn FnMut(&Entry),
) -> bool {
    if opts.deadline.is_some_and(|d| Instant::now() > d) {
        return false;
    }
    if opts.prune.is_some_and(|p| p(&path)) {
        return true;
    }
    visit(&Entry { path: &path, real: &real, meta: &meta, depth });
    if !meta.file_type().is_dir() || opts.max_depth.is_some_and(|m| depth >= m) || (opts.xdev && meta.dev() != dev) {
        return true;
    }
    let Ok(dir) = std::fs::read_dir(&real) else { return true };
    for e in dir.flatten() {
        let Ok(m) = std::fs::symlink_metadata(e.path()) else { continue };
        let name = e.file_name();
        let name = name.to_string_lossy();
        let child = if path == "/" { format!("/{name}") } else { format!("{path}/{name}") };
        if !rec(child, e.path(), m, depth + 1, dev, opts, visit) {
            return false;
        }
    }
    true
}

/// Comodín estilo fnmatch sin FNM_PATHNAME (como `find -name` y `-path`): `*` y `?` cruzan `/`,
/// `[a-z]` y `[!x]` son clases.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0, 0);
    let (mut star, mut mark) = (None, 0);
    while ti < t.len() {
        if pi < p.len() {
            match p[pi] {
                '*' => {
                    star = Some(pi);
                    mark = ti;
                    pi += 1;
                    continue;
                }
                '?' => {
                    pi += 1;
                    ti += 1;
                    continue;
                }
                '[' => {
                    if let Some((matched, next)) = class(&p, pi, t[ti]) {
                        if matched {
                            pi = next;
                            ti += 1;
                            continue;
                        }
                    } else if t[ti] == '[' {
                        pi += 1;
                        ti += 1;
                        continue;
                    }
                }
                c if c == t[ti] => {
                    pi += 1;
                    ti += 1;
                    continue;
                }
                _ => {}
            }
        }
        match star {
            Some(s) => {
                pi = s + 1;
                mark += 1;
                ti = mark;
            }
            None => return false,
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

/// Evalúa una clase `[...]` que empieza en `p[i]`. Devuelve (coincide, índice siguiente).
fn class(p: &[char], i: usize, c: char) -> Option<(bool, usize)> {
    let mut j = i + 1;
    let negate = matches!(p.get(j), Some('!' | '^'));
    if negate {
        j += 1;
    }
    let mut matched = false;
    let mut first = true;
    while j < p.len() && (first || p[j] != ']') {
        first = false;
        if j + 2 < p.len() && p[j + 1] == '-' && p[j + 2] != ']' {
            if p[j] <= c && c <= p[j + 2] {
                matched = true;
            }
            j += 3;
        } else {
            if p[j] == c {
                matched = true;
            }
            j += 1;
        }
    }
    (j < p.len()).then_some((matched != negate, j + 1))
}

pub fn any_glob(patterns: &[&str], text: &str) -> bool {
    patterns.iter().any(|p| glob_match(p, text))
}

/// Contenido de un archivo de texto, o `None` si no se puede leer o es binario
/// (contiene NUL, como detecta `grep -I`).
pub fn read_text(real: &std::path::Path) -> Option<String> {
    let bytes = std::fs::read(real).ok()?;
    if bytes.contains(&0) {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// `-size -Nk` de find: el tamaño redondeado hacia arriba a KiB es menor que N.
pub fn size_below_k(meta: &Metadata, k: u64) -> bool {
    meta.len().div_ceil(1024) < k
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comodines_como_find() {
        assert!(glob_match("*/node_modules", "/home/a/proj/node_modules"));
        assert!(!glob_match("*/node_modules", "/home/a/node_modules_x"));
        assert!(glob_match("*/lib/python*", "/opt/x/lib/python3.12"));
        assert!(glob_match("*.[1-9]", "ls.1"));
        assert!(!glob_match("*.[1-9]", "ls.x"));
        assert!(glob_match(".env.*", ".env.local"));
        assert!(glob_match("*.dpkg-*", "sshd_config.dpkg-old"));
        assert!(glob_match("shadow*", "shadow-"));
        assert!(glob_match("/etc/ssl", "/etc/ssl"));
        assert!(!glob_match("/etc/ssl", "/etc/ssl/certs"));
        assert!(glob_match("*conf*", "/opt/tomcat/conf/server.xml"));
        assert!(glob_match("[!a]bc", "xbc"));
    }

    #[test]
    fn recorre_con_prune_y_profundidad() {
        let f = crate::checks::fixture::Fixture::new();
        f.file("/r/a/b/c.txt", "x").file("/r/skip/z", "x").file("/r/top", "x");
        let ctx = f.ctx();
        let prune = |p: &str| p.ends_with("/skip");
        let mut seen = Vec::new();
        walk(&ctx, "/r", &WalkOpts { max_depth: Some(2), prune: Some(&prune), ..Default::default() }, &mut |e| {
            seen.push(e.path.to_string())
        });
        seen.sort();
        assert_eq!(seen, ["/r", "/r/a", "/r/a/b", "/r/top"]);
    }
}
