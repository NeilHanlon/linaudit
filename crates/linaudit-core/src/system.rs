//! Información básica del sistema auditado: distribución, usuario efectivo, hostname.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OsFamily {
    Debian,
    Rhel,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OsInfo {
    pub id: String,
    pub id_like: String,
    pub version: String,
    pub pretty: String,
    pub family: OsFamily,
    /// SUPPORT_END de os-release (fin de soporte), si la distro lo declara.
    pub support_end: String,
    /// true si la familia no salió de os-release sino del gestor de paquetes instalado
    /// (derivadas que no declaran ID_LIKE, como GoldenDog Linux).
    pub family_inferred: bool,
}

impl OsInfo {
    pub fn detect() -> Self {
        let mut os = Self::parse(&std::fs::read_to_string("/etc/os-release").unwrap_or_default());
        os.infer_family(std::path::Path::new("/"));
        os
    }

    /// Si os-release no alcanza para reconocer la familia, la deduce del gestor de paquetes.
    pub fn infer_family(&mut self, root: &std::path::Path) {
        if self.family != OsFamily::Unknown {
            return;
        }
        if root.join("var/lib/dpkg/status").is_file() {
            self.family = OsFamily::Debian;
        } else if root.join("var/lib/rpm").is_dir() || root.join("usr/lib/sysimage/rpm").is_dir() {
            self.family = OsFamily::Rhel;
        } else {
            return;
        }
        self.family_inferred = true;
    }

    /// Versión mayor (VERSION_ID hasta el primer punto).
    pub fn major(&self) -> &str {
        self.version.split('.').next().unwrap_or("")
    }

    pub fn parse(os_release: &str) -> Self {
        let get = |key: &str| {
            os_release
                .lines()
                .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
                .map(|v| v.trim().trim_matches(|c| c == '"' || c == '\'').to_string())
                .unwrap_or_default()
        };
        let id = get("ID");
        let id_like = get("ID_LIKE");
        let words = format!(" {id} {id_like} ");
        let family = if [" debian ", " ubuntu "].iter().any(|w| words.contains(w)) {
            OsFamily::Debian
        } else if [" rhel ", " fedora ", " centos ", " rocky ", " almalinux ", " ol "]
            .iter()
            .any(|w| words.contains(w))
        {
            OsFamily::Rhel
        } else {
            OsFamily::Unknown
        };
        let pretty = get("PRETTY_NAME");
        OsInfo {
            id: if id.is_empty() { "unknown".into() } else { id },
            id_like,
            version: get("VERSION_ID"),
            pretty: if pretty.is_empty() { "Linux".into() } else { pretty },
            family,
            support_end: get("SUPPORT_END"),
            family_inferred: false,
        }
    }
}

/// UID efectivo, leído de /proc/self/status (evita depender de libc).
pub fn effective_uid() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with("Uid:"))?;
    line.split_whitespace().nth(2)?.parse().ok()
}

pub fn is_root() -> bool {
    effective_uid() == Some(0)
}

/// Nombre de usuario para un UID según /etc/passwd.
pub fn user_name(uid: u32) -> Option<String> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|l| {
        let mut f = l.split(':');
        let name = f.next()?;
        f.next()?;
        (f.next()?.parse::<u32>().ok()? == uid).then(|| name.to_string())
    })
}

pub fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|h| h.trim().to_string())
        .unwrap_or_else(|_| crate::tr!("unknown").into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsea_os_release() {
        let o = OsInfo::parse(
            "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"13\"\nID=debian\n",
        );
        assert_eq!(o.id, "debian");
        assert_eq!(o.version, "13");
        assert_eq!(o.family, OsFamily::Debian);
        assert_eq!(o.pretty, "Debian GNU/Linux 13 (trixie)");

        let r = OsInfo::parse("ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"9.4\"\n");
        assert_eq!(r.family, OsFamily::Rhel);
        assert_eq!(r.pretty, "Linux");
        assert_eq!(r.major(), "9");
    }

    #[test]
    fn deduce_familia_de_derivadas_sin_id_like() {
        let dir = std::env::temp_dir().join(format!("linaudit-os-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("var/lib/dpkg")).unwrap();
        std::fs::write(dir.join("var/lib/dpkg/status"), "").unwrap();
        let mut o = OsInfo::parse("ID=goldendoglinux\nVERSION_ID=2\n");
        assert_eq!(o.family, OsFamily::Unknown);
        o.infer_family(&dir);
        assert_eq!(o.family, OsFamily::Debian);
        assert!(o.family_inferred);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
