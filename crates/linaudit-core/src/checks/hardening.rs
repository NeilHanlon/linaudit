//! category: hardening — port de checks.d/70-hardening.sh.
//! MAC (SELinux/AppArmor), auditoría, hora, logging, parámetros de kernel, servicios innecesarios.

use super::Context;
use super::util::{active_services, check_sysctl, command_output, find_command, glob, live_command, login_defs_get, read};
use crate::model::{Emitter, ResultExt, Severity::*};
use crate::tr;

const TIME_SERVICES: &[&str] = &["chronyd", "chrony", "ntpd", "ntp", "systemd-timesyncd"];
const SYSLOG_SERVICES: &[&str] = &["rsyslog", "syslog-ng", "syslog"];
const LOG_AGENTS: &[&str] = &[
    "filebeat", "elastic-agent", "fluent-bit", "td-agent", "fluentd", "promtail", "vector", "splunk",
    "SplunkForwarder", "nxlog", "wazuh-agent", "ossec", "datadog-agent", "auditbeat",
];
const UNNEEDED: &[&str] = &[
    "avahi-daemon", "cups", "cups-browsed", "bluetooth", "xinetd", "inetd", "telnet.socket", "telnetd", "rsh.socket",
    "rlogin.socket", "rexec.socket", "tftp.socket", "tftpd-hpa", "ypbind", "ypserv", "talk", "ntalk", "ModemManager",
    "rpcbind",
];
const BRUTEFORCE: &[&str] = &["fail2ban", "sshguard", "crowdsec", "crowdsec-firewall-bouncer"];

pub fn run(ctx: &Context, em: &mut Emitter) {
    // una sola consulta a systemd para todos los servicios del módulo
    let all: Vec<&str> = ["auditd", "systemd-journald"]
        .iter()
        .chain(TIME_SERVICES)
        .chain(SYSLOG_SERVICES)
        .chain(LOG_AGENTS)
        .chain(UNNEEDED)
        .chain(BRUTEFORCE)
        .copied()
        .collect();
    let active = active_services(ctx, &all);
    let is_active = |s: &str| active.contains(s);
    let any_active = |list: &[&str]| list.iter().any(|s| active.contains(*s));

    mac(ctx, em);

    // HRD-002 / HRD-003: auditd
    if is_active("auditd") {
        em.pass("HRD-002", Medium, tr!("auditd running"));
        let auditctl = if ctx.root && ctx.is_live() { find_command("auditctl") } else { None };
        match auditctl.map(|c| command_output(&c, &["-l"]).unwrap_or_default()) {
            Some(out) => {
                let n = out.lines().filter(|l| !l.starts_with("No rules")).count();
                if n > 0 {
                    em.pass("HRD-003", Low, tr!("auditd has rules loaded")).with_detail(tr!("{n} rules", n = n));
                } else {
                    em.warn("HRD-003", Low, tr!("auditd has no rules loaded")).with_fix(
                        tr!("Add rules (e.g. /usr/share/doc/auditd/examples or CIS/STIG) in /etc/audit/rules.d/"),
                    );
                }
            }
            None => {
                em.na("HRD-003", Low, tr!("auditd rules")).with_detail(tr!("root is required"));
            }
        }
    } else {
        em.warn("HRD-002", Medium, tr!("auditd is not running"))
            .with_fix(tr!("Install and enable auditd (or add a waiver if another audit/EDR agent is in place)"));
        em.na("HRD-003", Low, tr!("auditd rules")).with_detail(tr!("auditd inactive"));
    }

    // HRD-004: sincronización horaria
    if any_active(TIME_SERVICES) {
        let synced = live_command(ctx, "timedatectl", &["show", "-p", "NTPSynchronized", "--value"]);
        if synced.as_deref().map(str::trim) == Some("no") {
            em.warn("HRD-004", Medium, tr!("Time service active but not synchronized"))
                .with_detail("NTPSynchronized=no")
                .with_fix(tr!("Check the configured NTP servers"));
        } else {
            em.pass("HRD-004", Medium, tr!("Time synchronization active"));
        }
    } else {
        em.fail("HRD-004", Medium, tr!("No time synchronization service"))
            .with_fix(tr!("Install/enable chrony (accurate time is key for logs and Kerberos)"));
    }

    // HRD-005: logs persistentes
    if any_active(SYSLOG_SERVICES) {
        em.pass("HRD-005", Medium, tr!("syslog service active"));
    } else if is_active("systemd-journald") && journal_persistent(ctx) {
        em.pass("HRD-005", Medium, tr!("Persistent journald active"));
    } else {
        em.warn("HRD-005", Medium, tr!("No syslog or persistent journal"))
            .with_detail(tr!("logs are lost on reboot"))
            .with_fix(tr!("Install rsyslog or create /var/log/journal"));
    }

    // HRD-006: envío a un colector remoto
    let mut remote: Vec<&str> = Vec::new();
    if syslog_forwards(ctx) {
        remote.push(tr!("remote syslog"));
    }
    remote.extend(LOG_AGENTS.iter().filter(|a| is_active(a)));
    if remote.is_empty() {
        em.warn("HRD-006", Medium, tr!("Logs are not sent to a remote collector"))
            .with_detail(tr!("an attacker with root can wipe the local logs"))
            .with_fix(tr!("Forward to a SIEM/central syslog (rsyslog omfwd, filebeat, etc.)"));
    } else {
        em.pass("HRD-006", Medium, tr!("Logs sent to a remote collector")).with_detail(remote.join(" "));
    }

    // HRD-007..013: parámetros de kernel
    check_sysctl(em, ctx, "HRD-007", Medium, tr!("Full ASLR"), "kernel.randomize_va_space", &["2"]);
    check_sysctl(em, ctx, "HRD-008", Low, tr!("kptr_restrict enabled"), "kernel.kptr_restrict", &["1", "2"]);
    check_sysctl(em, ctx, "HRD-009", Low, tr!("dmesg restricted"), "kernel.dmesg_restrict", &["1"]);
    check_sysctl(em, ctx, "HRD-010", Medium, tr!("No core dumps from setuid processes"), "fs.suid_dumpable", &["0"]);
    check_sysctl(em, ctx, "HRD-011", Low, tr!("Hardlink protection"), "fs.protected_hardlinks", &["1"]);
    check_sysctl(em, ctx, "HRD-012", Low, tr!("Symlink protection"), "fs.protected_symlinks", &["1"]);
    check_sysctl(em, ctx, "HRD-013", Low, tr!("ptrace restricted (Yama)"), "kernel.yama.ptrace_scope", &["1", "2", "3"]);

    // HRD-014: servicios que rara vez se necesitan en un servidor
    let x: Vec<&str> = UNNEEDED.iter().copied().filter(|s| is_active(s)).collect();
    if x.is_empty() {
        em.pass("HRD-014", Medium, tr!("No typically unneeded services active"));
    } else {
        em.warn("HRD-014", Medium, tr!("Services rarely needed on a server"))
            .with_detail(x.join(" "))
            .with_fix(tr!("systemctl disable --now <service> (rpcbind is only needed for NFS/NIS)"));
    }

    // HRD-015: protección contra fuerza bruta
    if any_active(BRUTEFORCE) {
        em.pass("HRD-015", Low, tr!("Brute-force protection active"));
    } else {
        em.warn("HRD-015", Low, tr!("No fail2ban/sshguard/crowdsec"))
            .with_fix(tr!("Install fail2ban (or add a waiver if SSH is behind a bastion/VPN)"));
    }

    // HRD-016: umask por defecto
    let u = login_defs_get(ctx, "UMASK");
    let ok = u.as_deref().is_some_and(|u| matches!(u.strip_prefix('0').unwrap_or(u), "27" | "77" | "37"));
    let shown = u.as_deref().unwrap_or(tr!("not set"));
    if ok {
        em.pass("HRD-016", Low, tr!("Restrictive default umask")).with_detail(format!("UMASK {shown}"));
    } else {
        em.warn("HRD-016", Low, tr!("Permissive default umask"))
            .with_detail(format!("UMASK {shown}"))
            .with_fix(tr!("UMASK 027 in /etc/login.defs"));
    }

    // HRD-017: /etc/issue no debe filtrar versión del sistema (\r \m \s \v)
    let leaky: Vec<&str> = ["/etc/issue", "/etc/issue.net"]
        .into_iter()
        .filter(|f| {
            read(ctx, f).is_some_and(|t| t.as_bytes().windows(2).any(|w| w[0] == b'\\' && b"mrsv".contains(&w[1])))
        })
        .collect();
    if leaky.is_empty() {
        em.pass("HRD-017", Low, tr!("Local banners without system details"));
    } else {
        em.warn("HRD-017", Low, tr!("Local banners expose version/kernel"))
            .with_detail(leaky.join(" "))
            .with_fix(tr!("Replace with a legal banner without the \\r \\m \\s \\v escapes"));
    }
}

/// HRD-001: control de acceso obligatorio.
fn mac(ctx: &Context, em: &mut Emitter) {
    if let Some(mode) = live_command(ctx, "getenforce", &[]) {
        let mode = mode.trim();
        match mode {
            "Enforcing" => {
                em.pass("HRD-001", High, tr!("SELinux in Enforcing mode"));
            }
            "Permissive" => {
                em.warn("HRD-001", High, tr!("SELinux in Permissive mode (log only)"))
                    .with_detail(format!("getenforce = {mode}"))
                    .with_fix(tr!("setenforce 1 and set SELINUX=enforcing in /etc/selinux/config"));
            }
            _ => {
                em.fail("HRD-001", High, tr!("SELinux disabled"))
                    .with_detail(format!("getenforce = {}", if mode.is_empty() { "?" } else { mode }))
                    .with_fix(tr!("Enable SELinux (requires a relabel and reboot)"));
            }
        }
        return;
    }
    if read(ctx, "/sys/module/apparmor/parameters/enabled").as_deref().map(str::trim) == Some("Y") {
        // Divergencia con bash: sin root el kernel no deja leer la lista de perfiles; bash lo
        // tomaba como "0 perfiles" y daba una advertencia ALTA falsa. Acá queda como no evaluado.
        match read(ctx, "/sys/kernel/security/apparmor/profiles") {
            None => {
                em.error("HRD-001", High, tr!("AppArmor enabled"))
                    .with_detail(tr!("cannot read the profile list (root is required)"));
            }
            Some(p) if p.lines().count() > 0 => {
                em.pass("HRD-001", High, tr!("AppArmor active")).with_detail(tr!("{n} profiles loaded", n = p.lines().count()));
            }
            Some(_) => {
                em.warn("HRD-001", High, tr!("AppArmor enabled but no profiles loaded"))
                    .with_fix(tr!("Install/enable apparmor-profiles and apparmor.service"));
            }
        }
        return;
    }
    em.warn("HRD-001", High, tr!("No MAC active (neither SELinux nor AppArmor)"))
        .with_fix(tr!("Enable AppArmor (Debian/Ubuntu) or SELinux (RHEL)"));
}

fn journal_persistent(ctx: &Context) -> bool {
    if ctx.path("/var/log/journal").is_dir() {
        return true;
    }
    let mut files = vec![ctx.path("/etc/systemd/journald.conf")];
    files.extend(glob(&ctx.path("/etc/systemd/journald.conf.d"), "", ".conf"));
    files
        .iter()
        .filter_map(|f| std::fs::read_to_string(f).ok())
        .any(|t| t.lines().any(|l| l.starts_with("Storage=persistent")))
}

/// Configuración de rsyslog/syslog-ng que reenvía a otro host.
fn syslog_forwards(ctx: &Context) -> bool {
    let mut files = vec![ctx.path("/etc/rsyslog.conf"), ctx.path("/etc/syslog-ng/syslog-ng.conf")];
    files.extend(glob(&ctx.path("/etc/rsyslog.d"), "", ".conf"));
    files.iter().filter_map(|f| std::fs::read_to_string(f).ok()).any(|t| t.lines().any(forwards_line))
}

/// Equivalente a la regex de bash:
/// `^[^#]*[[:space:]]@@?[A-Za-z0-9\[]` | `omfwd` | `^[[:space:]]*destination.*(tcp|udp)`
pub fn forwards_line(line: &str) -> bool {
    if line.contains("omfwd") {
        return true;
    }
    if let Some(rest) = line.trim_start().strip_prefix("destination") {
        if rest.contains("tcp") || rest.contains("udp") {
            return true;
        }
    }
    let code = line.split('#').next().unwrap_or("").as_bytes();
    code.windows(2).enumerate().any(|(i, w)| {
        if !w[0].is_ascii_whitespace() || w[1] != b'@' {
            return false;
        }
        let mut j = i + 2;
        if code.get(j) == Some(&b'@') {
            j += 1;
        }
        code.get(j).is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'[')
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::fixture::Fixture;
    use crate::model::Status;

    fn hardened() -> Fixture {
        let mut f = Fixture::new();
        for s in ["auditd", "chrony", "rsyslog", "filebeat", "fail2ban", "systemd-journald"] {
            f.service(s);
        }
        f.file("/sys/module/apparmor/parameters/enabled", "Y\n")
            .file("/sys/kernel/security/apparmor/profiles", "/usr/bin/man (enforce)\nnvidia_modprobe (enforce)\n")
            .file("/proc/sys/kernel/randomize_va_space", "2\n")
            .file("/proc/sys/kernel/kptr_restrict", "1\n")
            .file("/proc/sys/kernel/dmesg_restrict", "1\n")
            .file("/proc/sys/fs/suid_dumpable", "0\n")
            .file("/proc/sys/fs/protected_hardlinks", "1\n")
            .file("/proc/sys/fs/protected_symlinks", "1\n")
            .file("/proc/sys/kernel/yama/ptrace_scope", "1\n")
            .file("/etc/login.defs", "UMASK 027\n")
            .file("/etc/issue", "Acceso solo autorizado\n");
        f
    }

    #[test]
    fn sistema_endurecido() {
        let r = hardened().run(run);
        // HRD-003 necesita auditctl, que en fixtures no se ejecuta
        assert_eq!(r["HRD-003"].status, Status::Na);
        for (id, x) in r.iter().filter(|(id, _)| *id != "HRD-003") {
            assert_eq!(x.status, Status::Pass, "{id}: {x:?}");
        }
        assert_eq!(r.len(), 17);
        assert_eq!(r["HRD-001"].detail, "2 perfiles cargados");
        assert_eq!(r["HRD-006"].detail, "filebeat");
    }

    #[test]
    fn sistema_por_defecto() {
        let mut f = Fixture::new();
        f.service("avahi-daemon").service("cups").service("systemd-journald");
        f.file("/proc/sys/kernel/kptr_restrict", "0\n")
            .file("/proc/sys/kernel/yama/ptrace_scope", "0\n")
            .file("/etc/issue", "Debian GNU/Linux 13 \\n \\l\n")
            .file("/etc/issue.net", "Ubuntu \\r\n")
            .dir("/var/log/journal");
        let r = f.run(run);
        assert_eq!(r["HRD-001"].status, Status::Warn);
        assert_eq!(r["HRD-002"].status, Status::Warn);
        assert_eq!(r["HRD-004"].status, Status::Fail);
        assert_eq!(r["HRD-005"].title, "journald persistente activo");
        assert_eq!(r["HRD-007"].status, Status::Na);
        assert_eq!(r["HRD-008"].detail, "kernel.kptr_restrict = 0 (esperado: 1 o 2)");
        assert_eq!(r["HRD-014"].detail, "avahi-daemon cups");
        assert_eq!(r["HRD-016"].detail, "UMASK sin definir");
        // \n y \l no exponen datos; \r (kernel) sí
        assert_eq!(r["HRD-017"].detail, "/etc/issue.net");
    }

    #[test]
    fn apparmor_sin_root_no_es_advertencia() {
        let f = Fixture::new();
        f.file("/sys/module/apparmor/parameters/enabled", "Y\n");
        let r = f.run(run);
        assert_eq!(r["HRD-001"].status, Status::Error);
    }

    #[test]
    fn reenvio_de_syslog() {
        for yes in [
            "*.* @@logs.example.com:514",
            "*.*  @10.0.0.5",
            "*.* @[2001:db8::1]:514",
            "action(type=\"omfwd\" target=\"siem\")",
            "  destination d_remote { tcp(\"siem\" port(514)); };",
        ] {
            assert!(forwards_line(yes), "{yes}");
        }
        for no in ["# *.* @@logs.example.com", "*.* /var/log/syslog", "user@host", "destination d_local { file(\"/x\"); };"]
        {
            assert!(!forwards_line(no), "{no}");
        }
    }
}
