//! category: accounts — port de checks.d/10-accounts.sh. Cuentas, passwords y sudo.

use std::collections::BTreeMap;

use super::Context;
use super::util::{PasswdEntry, login_defs_get, parse_passwd, parse_shadow, read};
use crate::model::{Emitter, ResultExt, Severity::*};
use crate::tr;

const SUDO_ERR: &str = crate::N_!("root is required to read /etc/sudoers");

pub fn run(ctx: &Context, em: &mut Emitter) {
    let uid_min: u32 = login_defs_get(ctx, "UID_MIN").and_then(|v| v.parse().ok()).unwrap_or(1000);
    let passwd = parse_passwd(&read(ctx, "/etc/passwd").unwrap_or_default());
    let shadow = read(ctx, "/etc/shadow").map(|t| parse_shadow(&t));
    // cuentas de servicio: UID por debajo de UID_MIN, sin contar root
    let is_service = |p: &PasswdEntry| p.uid.is_some_and(|u| u < uid_min && u != 0);

    // ACC-001: UID 0 duplicado
    let x = names(passwd.iter().filter(|p| p.uid == Some(0) && p.name != "root").map(|p| p.name.as_str()));
    if x.is_empty() {
        em.pass("ACC-001", Critical, tr!("Only root has UID 0"));
    } else {
        em.fail("ACC-001", Critical, tr!("Other accounts have UID 0"))
            .with_detail(x)
            .with_fix(tr!("Remove the account or give it another UID"));
    }

    // ACC-002: cuentas sin password
    match &shadow {
        Some(sh) => {
            let empty = sh
                .iter()
                .filter(|(_, h)| h.is_empty())
                .map(|(n, _)| n.as_str())
                .chain(passwd.iter().filter(|p| p.password.is_empty()).map(|p| p.name.as_str()));
            let x = names(empty);
            if x.is_empty() {
                em.pass("ACC-002", Critical, tr!("No account with an empty password"));
            } else {
                em.fail("ACC-002", Critical, tr!("Accounts with an empty password"))
                    .with_detail(x)
                    .with_fix(tr!("passwd -l <account>  (or set a password)"));
            }
        }
        None => {
            em.error("ACC-002", Critical, tr!("Accounts with an empty password"))
                .with_detail(tr!("cannot read /etc/shadow (not root?)"));
        }
    }

    // ACC-003: hashes en /etc/passwd en vez de shadow
    let x = names(passwd.iter().filter(|p| p.password != "x" && !p.password.is_empty()).map(|p| p.name.as_str()));
    if x.is_empty() {
        em.pass("ACC-003", High, tr!("Passwords in /etc/shadow (not in passwd)"));
    } else {
        em.fail("ACC-003", High, tr!("Hashes inside /etc/passwd")).with_detail(x).with_fix("pwconv");
    }

    // ACC-004 / ACC-005: sudo NOPASSWD
    if ctx.root {
        let (all, part) = sudo_nopasswd(&sudoers_text(ctx));
        if all.is_empty() {
            em.pass("ACC-004", High, tr!("sudo without NOPASSWD:ALL"));
        } else {
            em.fail("ACC-004", High, tr!("sudo NOPASSWD:ALL (root without a password)"))
                .with_detail(all.join(" "))
                .with_fix(tr!("Require a password or limit it to specific commands"));
        }
        if part.is_empty() {
            em.pass("ACC-005", Medium, tr!("sudo without scoped NOPASSWD"));
        } else {
            em.warn("ACC-005", Medium, tr!("sudo NOPASSWD on specific commands (review)"))
                .with_detail(part.join(" "))
                .with_fix(tr!("Check that no command allows escaping to a shell"));
        }
    } else {
        em.error("ACC-004", High, "sudo NOPASSWD:ALL").with_detail(crate::i18n::tr(SUDO_ERR));
        em.error("ACC-005", Medium, tr!("sudo scoped NOPASSWD")).with_detail(crate::i18n::tr(SUDO_ERR));
    }

    // ACC-006: cuentas de sistema con shell interactiva
    const NOLOGIN_SUFFIXES: [&str; 5] = ["nologin", "false", "sync", "shutdown", "halt"];
    let x: Vec<String> = passwd
        .iter()
        .filter(|p| is_service(p))
        .filter(|p| !matches!(p.name.as_str(), "sync" | "shutdown" | "halt"))
        .filter(|p| !NOLOGIN_SUFFIXES.iter().any(|s| p.shell.ends_with(s)))
        .map(|p| format!("{}({})", p.name, if p.shell.is_empty() { "/bin/sh" } else { &p.shell }))
        .collect();
    if x.is_empty() {
        em.pass("ACC-006", Medium, tr!("Service accounts without an interactive shell"));
    } else {
        em.warn("ACC-006", Medium, tr!("Service accounts with an interactive shell"))
            .with_detail(x.join(" "))
            .with_fix(tr!("usermod -s /usr/sbin/nologin <account> (unless needed)"));
    }

    // ACC-007: authorized_keys en cuentas de servicio
    let x: Vec<&str> = passwd
        .iter()
        .filter(|p| is_service(p))
        .flat_map(|p| {
            ["authorized_keys", "authorized_keys2"].into_iter().filter_map(move |k| {
                let f = ctx.path(&format!("{}/.ssh/{k}", p.home.trim_end_matches('/')));
                std::fs::metadata(f).is_ok_and(|m| m.len() > 0).then_some(p.name.as_str())
            })
        })
        .collect();
    if x.is_empty() {
        em.pass("ACC-007", Medium, tr!("Service accounts without authorized_keys"));
    } else {
        em.warn("ACC-007", Medium, tr!("Service accounts with authorized_keys"))
            .with_detail(x.join(" "))
            .with_fix(tr!("Confirm it is intentional (backups, rsync, etc.) and restrict it with from=/command="));
    }

    // ACC-008: UID duplicados (distintos de 0)
    let mut by_uid: BTreeMap<u32, Vec<&str>> = BTreeMap::new();
    for p in &passwd {
        if let Some(u) = p.uid.filter(|&u| u != 0) {
            by_uid.entry(u).or_default().push(&p.name);
        }
    }
    let dups: Vec<String> =
        by_uid.iter().filter(|(_, n)| n.len() > 1).map(|(u, n)| format!("uid {u}: {}", n.join(" "))).collect();
    if dups.is_empty() {
        em.pass("ACC-008", Medium, tr!("No duplicate UIDs"));
    } else {
        em.fail("ACC-008", Medium, tr!("Duplicate UIDs")).with_detail(dups.join("; ")).with_fix(tr!("Assign unique UIDs"));
    }

    // ACC-009: vencimiento de passwords. Divergencia con bash: un valor negativo (-1 = nunca vence)
    // en bash pasaba porque es "<= 365"; acá cuenta como sin vencimiento.
    let v = login_defs_get(ctx, "PASS_MAX_DAYS");
    if v.as_deref().and_then(|v| v.parse::<i64>().ok()).is_some_and(|n| (0..=365).contains(&n)) {
        em.pass("ACC-009", Medium, "PASS_MAX_DAYS <= 365").with_detail(format!("PASS_MAX_DAYS={}", v.unwrap_or_default()));
    } else {
        em.warn("ACC-009", Medium, tr!("Passwords without a reasonable expiry"))
            .with_detail(format!("PASS_MAX_DAYS={}", v.as_deref().unwrap_or(tr!("not set"))))
            .with_fix(tr!("Set PASS_MAX_DAYS <= 365 in /etc/login.defs (may not apply with SSO/IPA: use a waiver)"));
    }

    // ACC-010: longitud mínima de password
    match password_minlen(ctx) {
        None => {
            em.warn("ACC-010", Medium, tr!("No minimum password length policy"))
                .with_detail(tr!("pwquality/minlen not configured"))
                .with_fix(tr!("Install libpam-pwquality (or use authselect) and set minlen >= 12"));
        }
        Some(n) if n >= 12 => {
            em.pass("ACC-010", Medium, tr!("Minimum password length >= 12")).with_detail(format!("minlen={n}"));
        }
        Some(n) => {
            em.warn("ACC-010", Medium, tr!("Minimum password length is low"))
                .with_detail(format!("minlen={n}"))
                .with_fix(tr!("Raise minlen to 12 or more"));
        }
    }

    // ACC-011: hashes débiles (MD5 = $1$, DES = sin prefijo $)
    match &shadow {
        Some(sh) => {
            let weak = sh.iter().filter(|(_, h)| {
                h.starts_with("$1$") || (!h.is_empty() && !h.starts_with(['$', '!', '*']))
            });
            let x = names(weak.map(|(n, _)| n.as_str()));
            if x.is_empty() {
                em.pass("ACC-011", High, tr!("No MD5/DES hashes in /etc/shadow"));
            } else {
                em.fail("ACC-011", High, tr!("Accounts with a weak hash (MD5/DES)"))
                    .with_detail(x)
                    .with_fix(tr!("Force a password change with SHA-512/yescrypt"));
            }
        }
        None => {
            em.error("ACC-011", High, tr!("Weak hashes in /etc/shadow")).with_detail(tr!("cannot read /etc/shadow"));
        }
    }

    // ACC-012: algoritmo de hash por defecto
    match login_defs_get(ctx, "ENCRYPT_METHOD") {
        None => {
            em.na("ACC-012", Medium, tr!("Strong ENCRYPT_METHOD")).with_detail(tr!("not set in login.defs (PAM/authselect?)"));
        }
        Some(m) if matches!(m.as_str(), "SHA512" | "YESCRYPT" | "SHA256") => {
            em.pass("ACC-012", Medium, tr!("Strong ENCRYPT_METHOD")).with_detail(m);
        }
        Some(m) => {
            em.fail("ACC-012", Medium, tr!("Weak ENCRYPT_METHOD"))
                .with_detail(m)
                .with_fix(tr!("Use SHA512 or YESCRYPT in /etc/login.defs"));
        }
    }
}

fn names<'a>(it: impl Iterator<Item = &'a str>) -> String {
    it.collect::<Vec<_>>().join(" ")
}

/// /etc/sudoers.d (archivos sin punto ni ~, que es lo que sudo incluye) y /etc/sudoers.
fn sudoers_text(ctx: &Context) -> String {
    let mut files: Vec<_> = std::fs::read_dir(ctx.path("/etc/sudoers.d"))
        .map(|d| {
            d.flatten()
                .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
                .filter(|e| {
                    let n = e.file_name();
                    let n = n.to_string_lossy();
                    !n.contains('.') && !n.ends_with('~')
                })
                .map(|e| e.path())
                .collect()
        })
        .unwrap_or_default();
    files.sort();
    let main = ctx.path("/etc/sudoers");
    if main.is_file() {
        files.push(main);
    }
    files.iter().filter_map(|f| std::fs::read_to_string(f).ok()).collect::<Vec<_>>().join("\n")
}

/// Separa las reglas NOPASSWD en (NOPASSWD:ALL, NOPASSWD sobre comandos puntuales),
/// devolviendo el primer campo de cada línea (el usuario o %grupo).
pub fn sudo_nopasswd(text: &str) -> (Vec<String>, Vec<String>) {
    let (mut all, mut part) = (Vec::new(), Vec::new());
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("");
        if !line.contains("NOPASSWD") {
            continue;
        }
        let who = line.split_whitespace().next().unwrap_or("").to_string();
        if has_nopasswd_all(line) { all.push(who) } else { part.push(who) }
    }
    (all, part)
}

/// `NOPASSWD:` seguido (con espacios opcionales) de `ALL` como palabra completa.
fn has_nopasswd_all(line: &str) -> bool {
    line.match_indices("NOPASSWD:").any(|(i, m)| {
        let rest = line[i + m.len()..].trim_start();
        rest.strip_prefix("ALL").is_some_and(|after| after.is_empty() || after.starts_with([' ', '\t', ',']))
    })
}

/// minlen de pwquality (el último archivo que lo define gana) o, si no hay, de la línea de PAM.
fn password_minlen(ctx: &Context) -> Option<u32> {
    let mut files = vec![ctx.path("/etc/security/pwquality.conf")];
    files.extend(super::util::glob(&ctx.path("/etc/security/pwquality.conf.d"), "", ".conf"));
    let mut minlen = None;
    for f in files {
        let Ok(text) = std::fs::read_to_string(f) else { continue };
        let last = text.lines().filter_map(|l| {
            let (k, v) = l.trim_start().split_once('=')?;
            if k.trim_end() != "minlen" {
                return None;
            }
            let digits: String = v.trim_start().chars().take_while(char::is_ascii_digit).collect();
            digits.parse().ok()
        });
        if let Some(v) = last.last() {
            minlen = Some(v);
        }
    }
    if minlen.is_some() {
        return minlen;
    }
    ["/etc/pam.d/common-password", "/etc/pam.d/system-auth", "/etc/pam.d/password-auth"]
        .iter()
        .filter_map(|f| read(ctx, f))
        .flat_map(|t| {
            t.match_indices("minlen=")
                .map(|(i, m)| t[i + m.len()..].chars().take_while(char::is_ascii_digit).collect::<String>())
                .collect::<Vec<_>>()
        })
        .last()
        .and_then(|d| d.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::fixture::Fixture;
    use crate::model::Status;

    const PASSWD_OK: &str = "root:x:0:0:root:/root:/bin/bash\n\
        daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
        sync:x:4:65534:sync:/bin:/bin/sync\n\
        alexia:x:1000:1000::/home/alexia:/bin/bash\n";

    fn base() -> Fixture {
        let f = Fixture::new();
        f.file("/etc/passwd", PASSWD_OK)
            .file("/etc/shadow", "root:$y$j9T$abc:1::::::\ndaemon:*:1::::::\nalexia:$6$salt$hash:1::::::\n")
            .file("/etc/login.defs", "UID_MIN 1000\nPASS_MAX_DAYS 90\nENCRYPT_METHOD YESCRYPT\n")
            .file("/etc/security/pwquality.conf", "# minlen = 8\nminlen = 14\n")
            .file("/etc/sudoers", "root ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) ALL\n");
        f
    }

    #[test]
    fn sistema_sano_pasa_todo() {
        let r = base().run(run);
        for (id, x) in &r {
            assert_eq!(x.status, Status::Pass, "{id}: {x:?}");
        }
        assert_eq!(r.len(), 12);
    }

    #[test]
    fn detecta_cuentas_peligrosas() {
        let f = base();
        f.file(
            "/etc/passwd",
            &format!(
                "{PASSWD_OK}toor:x:0:0::/root:/bin/sh\nbackup:x:34:34::/var/backups:/bin/bash\n\
                 vieja:$1$abc$def:1001:1001::/home/vieja:/bin/bash\nclon:x:1000:1000::/home/clon:/bin/bash\n"
            ),
        )
        .file("/etc/shadow", "root::1::::::\nlegacy:abcDEF123:1::::::\nmd5:$1$x$y:1::::::\n")
        .file("/var/backups/.ssh/authorized_keys", "ssh-ed25519 AAAA backup@nas\n");
        let r = f.run(run);
        assert_eq!(r["ACC-001"].detail, "toor");
        assert_eq!(r["ACC-002"].detail, "root");
        assert_eq!(r["ACC-003"].detail, "vieja");
        assert_eq!(r["ACC-006"].detail, "backup(/bin/bash)");
        assert_eq!(r["ACC-007"].detail, "backup");
        assert_eq!(r["ACC-008"].detail, "uid 1000: alexia clon");
        assert_eq!(r["ACC-011"].detail, "legacy md5");
        assert_eq!(r["ACC-011"].status, Status::Fail);
    }

    #[test]
    fn sudoers_nopasswd() {
        let (all, part) = sudo_nopasswd(
            "admin ALL=(ALL) NOPASSWD: ALL\n\
             %ops ALL=(ALL) NOPASSWD:ALL, !/bin/su\n\
             backup ALL=(root) NOPASSWD: /usr/bin/rsync\n\
             # viejo ALL=(ALL) NOPASSWD: ALL\n\
             deploy ALL=(ALL) NOPASSWD: ALLOWED_CMDS\n",
        );
        assert_eq!(all, ["admin", "%ops"]);
        assert_eq!(part, ["backup", "deploy"]);
    }

    #[test]
    fn sudoers_d_ignora_archivos_con_punto() {
        let f = base();
        f.file("/etc/sudoers.d/90-admin", "admin ALL=(ALL) NOPASSWD: ALL\n")
            .file("/etc/sudoers.d/README.txt", "nadie ALL=(ALL) NOPASSWD: ALL\n")
            .file("/etc/sudoers.d/viejo~", "nadie ALL=(ALL) NOPASSWD: ALL\n");
        assert_eq!(f.run(run)["ACC-004"].detail, "admin");
    }

    #[test]
    fn sin_root_sudo_y_shadow_no_se_evaluan() {
        let mut f = base();
        f.is_root = false;
        f.mode("/etc/shadow", 0o000);
        let r = f.run(run);
        assert_eq!(r["ACC-004"].status, Status::Error);
        assert_eq!(r["ACC-005"].status, Status::Error);
        // si el test corre como root, chmod 000 no impide leer
        if !crate::system::is_root() {
            assert_eq!(r["ACC-002"].status, Status::Error);
            assert_eq!(r["ACC-011"].status, Status::Error);
        }
    }

    #[test]
    fn politicas_de_login_defs_y_pwquality() {
        let f = base();
        f.file("/etc/login.defs", "PASS_MAX_DAYS 99999\nPASS_MAX_DAYS 400\nENCRYPT_METHOD MD5\n")
            .file("/etc/security/pwquality.conf.d/50-local.conf", "minlen=8\n");
        let r = f.run(run);
        assert_eq!(r["ACC-009"].detail, "PASS_MAX_DAYS=400");
        assert_eq!(r["ACC-009"].status, Status::Warn);
        assert_eq!(r["ACC-010"].detail, "minlen=8");
        assert_eq!(r["ACC-012"].status, Status::Fail);

        f.file("/etc/login.defs", "PASS_MAX_DAYS -1\n");
        std::fs::remove_file(f.ctx().path("/etc/security/pwquality.conf")).unwrap();
        std::fs::remove_dir_all(f.ctx().path("/etc/security/pwquality.conf.d")).unwrap();
        f.file("/etc/pam.d/common-password", "password requisite pam_pwquality.so retry=3 minlen=12\n");
        let r = f.run(run);
        assert_eq!(r["ACC-009"].status, Status::Warn, "-1 = nunca vence");
        assert_eq!(r["ACC-010"].detail, "minlen=12");
        assert_eq!(r["ACC-012"].status, Status::Na);
    }
}
