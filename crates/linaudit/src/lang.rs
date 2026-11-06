//! Idioma de la interfaz y preferencia guardada por usuario.
//!
//! Prioridad: `--lang` / `LINAUDIT_LANG` > preferencia del usuario (`~/.config/linaudit/config.toml`)
//! > `language` en /etc/linaudit/config.toml > locale (LANGUAGE, LC_ALL, LC_MESSAGES, LANG) > inglés.
//!
//! La preferencia del usuario la escribe la pantalla de bienvenida la primera vez; para volver a
//! elegir, alcanza con borrar ese archivo. Con sudo se usa el home de quien lo llamó (SUDO_USER),
//! no el de root, y el archivo queda a nombre de esa persona.

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use linaudit_core::i18n::Lang;
use linaudit_core::tr;

/// De dónde salió el idioma.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// --lang o LINAUDIT_LANG
    Argument,
    /// Preferencia guardada por el usuario.
    Saved,
    /// /etc/linaudit/config.toml
    System,
    /// Locale del entorno.
    Locale,
    /// Ninguno de los anteriores: inglés.
    Default,
}

impl Source {
    /// Elegido a propósito (no hace falta preguntar).
    pub fn is_explicit(self) -> bool {
        matches!(self, Source::Argument | Source::Saved | Source::System)
    }
}

pub fn parse(s: &str) -> Result<Lang, String> {
    let list: Vec<&str> = Lang::ALL.iter().map(|l| l.code()).collect();
    Lang::from_code(s).ok_or_else(|| tr!("supported languages: {list}", list = list.join(", ")))
}

/// `--lang X` o `--lang=X` en la línea de comandos, antes de que clap la procese
/// (la ayuda de clap tiene que salir ya traducida).
pub fn from_argv(args: &[String]) -> Option<Lang> {
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        if a == "--" {
            break;
        }
        if a == "--lang" {
            return it.next().and_then(|v| Lang::from_code(v));
        }
        if let Some(v) = a.strip_prefix("--lang=") {
            return Lang::from_code(v);
        }
    }
    None
}

pub fn resolve(args: &[String], system_config: &Path) -> (Lang, Source) {
    if let Some(l) = from_argv(args) {
        return (l, Source::Argument);
    }
    if let Some(l) = std::env::var("LINAUDIT_LANG").ok().and_then(|v| Lang::from_code(&v)) {
        return (l, Source::Argument);
    }
    if let Some(l) = prefs_path().and_then(|p| read_language(&p)) {
        return (l, Source::Saved);
    }
    if let Some(l) = read_language(system_config) {
        return (l, Source::System);
    }
    match Lang::from_env() {
        Some(l) => (l, Source::Locale),
        None => (Lang::En, Source::Default),
    }
}

#[derive(serde::Deserialize)]
struct Prefs {
    language: Option<String>,
}

/// `language = "..."` de un archivo TOML. Si no existe o no se entiende, `None` (no es un error:
/// en el peor caso se vuelve a preguntar).
fn read_language(path: &Path) -> Option<Lang> {
    let text = std::fs::read_to_string(path).ok()?;
    let p: Prefs = toml::from_str(&text).ok()?;
    p.language.as_deref().and_then(Lang::from_code)
}

/// Usuario real detrás de sudo: (home, uid, gid).
fn sudo_user() -> Option<(PathBuf, u32, u32)> {
    if !linaudit_core::system::is_root() {
        return None;
    }
    let name = std::env::var("SUDO_USER").ok().filter(|u| !u.is_empty() && u != "root")?;
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        if f.len() < 6 || f[0] != name {
            return None;
        }
        Some((PathBuf::from(f[5]), f[2].parse().ok()?, f[3].parse().ok()?))
    })
}

/// Archivo de preferencias del usuario.
pub fn prefs_path() -> Option<PathBuf> {
    if let Some((home, _, _)) = sudo_user() {
        return Some(home.join(".config/linaudit/config.toml"));
    }
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(base.join("linaudit/config.toml"))
}

/// Ruta para mostrar, con `~` en vez del home.
pub fn display_path(p: &Path) -> String {
    let home = sudo_user().map(|(h, _, _)| h).or_else(|| std::env::var_os("HOME").map(PathBuf::from));
    match home.and_then(|h| p.strip_prefix(h).ok().map(Path::to_path_buf)) {
        Some(rel) => format!("~/{}", rel.display()),
        None => p.display().to_string(),
    }
}

/// Guarda el idioma elegido. Es lo único que linaudit escribe fuera de --output, y es
/// configuración propia en el home del usuario (nunca toca el sistema auditado).
pub fn save(lang: Lang) -> io::Result<PathBuf> {
    let path = prefs_path().ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME"))?;
    let owner = sudo_user().map(|(_, uid, gid)| (uid, gid));
    let dir = path.parent().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path"))?;
    // directorios que faltan, de afuera hacia adentro (para dárselos al usuario si se corre con sudo)
    let missing: Vec<&Path> = dir.ancestors().take_while(|d| !d.exists()).collect();
    for d in missing.iter().rev() {
        std::fs::create_dir(d)?;
        if let Some((uid, gid)) = owner {
            std::os::unix::fs::chown(d, Some(uid), Some(gid))?;
        }
    }
    let text = format!(
        "# linaudit: {}\n# {}\nlanguage = \"{}\"\n",
        tr!("user preferences"),
        tr!("Delete this file to choose the language again."),
        lang.code()
    );
    std::fs::write(&path, text)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
    if let Some((uid, gid)) = owner {
        std::os::unix::fs::chown(&path, Some(uid), Some(gid))?;
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(a: &[&str]) -> Vec<String> {
        std::iter::once("linaudit").chain(a.iter().copied()).map(String::from).collect()
    }

    #[test]
    fn lang_en_la_linea_de_comandos() {
        assert_eq!(from_argv(&argv(&["--lang", "es"])), Some(Lang::Es));
        assert_eq!(from_argv(&argv(&["--plain", "--lang=en"])), Some(Lang::En));
        assert_eq!(from_argv(&argv(&["--lang", "fr"])), None);
        assert_eq!(from_argv(&argv(&["--", "--lang", "es"])), None);
        assert_eq!(from_argv(&argv(&["--plain"])), None);
    }

    #[test]
    fn lee_la_preferencia() {
        let dir = std::env::temp_dir().join(format!("linaudit-lang-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("config.toml");
        std::fs::write(&f, "# x\nlanguage = \"es\"\n").unwrap();
        assert_eq!(read_language(&f), Some(Lang::Es));
        std::fs::write(&f, "language = \"klingon\"\n").unwrap();
        assert_eq!(read_language(&f), None);
        std::fs::write(&f, "no es toml [").unwrap();
        assert_eq!(read_language(&f), None);
        assert_eq!(read_language(&dir.join("no-existe")), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
