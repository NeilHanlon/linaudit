//! category: patching — port de checks.d/60-patching.sh.
//! Actualizaciones de seguridad, reinicio pendiente, fin de soporte, repos sin firma.
//! PAT-008 (sin equivalente en bash): CVEs sin corrección en servicios de red, vía debsecan.
//!
//! Divergencia con bash: en derivadas que no declaran ID_LIKE (ej. GoldenDog Linux) bash no reconocía
//! la familia y todo quedaba N/A; acá la familia se deduce del gestor de paquetes (ver system.rs).

use std::os::unix::fs::MetadataExt;

use super::Context;
use super::util::{Timed, civil_date, dir_files, glob, live_command_full, live_command_timeout, pkg_installed, read, unit_enabled};
use crate::model::{Emitter, ResultExt, Severity::*};
use crate::system::OsFamily;
use crate::tr;
use crate::trc;

pub fn run(ctx: &Context, em: &mut Emitter) {
    match ctx.os.family {
        OsFamily::Debian => apt_updates(ctx, em),
        OsFamily::Rhel => {
            dnf_updates(ctx, em);
            em.na("PAT-002", Medium, tr!("Package index is recent")).with_detail(tr!("does not apply to dnf/yum (per-repo cache)"));
        }
        OsFamily::Unknown => {
            em.na("PAT-001", High, tr!("Pending security updates")).with_detail(tr!("unrecognized distro"));
        }
    }
    auto_updates(ctx, em);
    reboot_pending(ctx, em);
    end_of_life(ctx, em);
    unsigned_repos(ctx, em);
    third_party_origins(ctx, em);
    unfixed_cves(ctx, em);
}

/// Paquetes binarios de servicios de red (PAT-008) y las unidades de systemd que los ponen a correr:
/// un CVE sin corrección solo se reporta si alguna está habilitada (apache2-bin instalado como
/// dependencia, o cups/ssh en un desktop, no son un servicio expuesto).
/// Un paquete terminado en `*` es un prefijo (postgresql-17, exim4-daemon-heavy); `%p` es el paquete.
const NETWORK_SERVICES: &[(&str, &[&str])] = &[
    ("apache2-bin", &["apache2.service"]),
    ("nginx", &["nginx.service"]),
    ("nginx-*", &["nginx.service"]),
    ("lighttpd", &["lighttpd.service"]),
    ("haproxy", &["haproxy.service"]),
    ("squid", &["squid.service"]),
    ("varnish", &["varnish.service"]),
    ("openssh-server", &["ssh.service", "ssh.socket"]),
    ("postfix", &["postfix.service"]),
    ("exim4-daemon-*", &["exim4.service"]),
    ("dovecot-core", &["dovecot.service", "dovecot.socket"]),
    ("bind9", &["named.service", "bind9.service"]),
    ("unbound", &["unbound.service"]),
    ("dnsmasq-base", &["dnsmasq.service"]),
    ("samba", &["smbd.service"]),
    ("vsftpd", &["vsftpd.service"]),
    ("proftpd-core", &["proftpd.service"]),
    ("pure-ftpd", &["pure-ftpd.service"]),
    ("postgresql-1*", &["postgresql.service"]),
    ("mariadb-server", &["mariadb.service"]),
    ("mariadb-server-core", &["mariadb.service"]),
    ("redis-server", &["redis-server.service"]),
    ("memcached", &["memcached.service"]),
    ("cups-daemon", &["cups.service", "cups.socket"]),
    ("isc-dhcp-server", &["isc-dhcp-server.service"]),
    ("kea-dhcp4-server", &["kea-dhcp4-server.service"]),
    ("openvpn", &["openvpn.service"]),
    ("strongswan-charon", &["strongswan.service", "strongswan-starter.service"]),
    ("tomcat1*", &["%p.service"]),
];

/// Unidades de systemd del servicio de red que provee `pkg`, o `None` si no es uno.
fn service_units(pkg: &str) -> Option<Vec<String>> {
    let (_, units) = NETWORK_SERVICES.iter().find(|(w, _)| match w.strip_suffix('*') {
        Some(prefix) => pkg.starts_with(prefix),
        None => pkg == *w,
    })?;
    Some(units.iter().map(|u| u.replace("%p", pkg)).collect())
}

/// Suite de Debian para debsecan a partir de /etc/debian_version ("13.6" → trixie, "forky/sid" → sid).
/// Se usa en vez de VERSION_CODENAME porque las derivadas declaran su propio codename.
pub fn debian_suite(debian_version: &str) -> Option<&'static str> {
    let v = debian_version.trim();
    if v.ends_with("/sid") {
        return Some("sid");
    }
    match v.split('.').next()? {
        "11" => Some("bullseye"),
        "12" => Some("bookworm"),
        "13" => Some("trixie"),
        "14" => Some("forky"),
        _ => None,
    }
}

/// CVEs sin corrección por paquete en la salida `--format summary` de debsecan
/// (`CVE-AAAA-N paquete (fixed, remotely exploitable, high urgency)`), solo de servicios de red
/// con alguna unidad habilitada según `enabled`.
pub fn debsecan_unfixed(out: &str, enabled: &dyn Fn(&str) -> bool) -> std::collections::BTreeMap<String, Vec<String>> {
    let mut m: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    let mut active: std::collections::HashMap<String, bool> = Default::default();
    for l in out.lines() {
        let mut it = l.split_whitespace();
        let (Some(cve), Some(pkg)) = (it.next(), it.next()) else { continue };
        let notes = l.split_once('(').map(|(_, n)| n).unwrap_or("");
        if !cve.starts_with("CVE-") || notes.split(',').any(|n| n.trim().trim_end_matches(')') == "fixed") {
            continue;
        }
        // una consulta a systemd por paquete, no por CVE
        let on = *active
            .entry(pkg.to_string())
            .or_insert_with(|| service_units(pkg).is_some_and(|u| u.iter().any(|u| enabled(u))));
        if on {
            m.entry(pkg.to_string()).or_default().push(cve.to_string());
        }
    }
    m
}

/// PAT-008: CVEs publicados que todavía no tienen corrección en la distro (PAT-001 cubre los que sí).
/// Es el hueco entre el anuncio del upstream y el DSA: el security tracker ya los lista ese mismo día.
fn unfixed_cves(ctx: &Context, em: &mut Emitter) {
    let title = tr!("No unfixed CVEs in network services");
    let na = |em: &mut Emitter, why: &str| {
        em.na("PAT-008", Medium, title).with_detail(why.to_string());
    };
    if ctx.os.family != OsFamily::Debian {
        return na(em, &tr!("only Debian and derivatives (debsecan)"));
    }
    if ctx.os.id == "ubuntu" || ctx.os.id_like.split_whitespace().any(|x| x == "ubuntu") {
        return na(em, &tr!("debsecan does not support Ubuntu"));
    }
    if ctx.fast {
        return na(em, &tr!("skipped by --fast"));
    }
    let Some(suite) = read(ctx, "/etc/debian_version").as_deref().and_then(debian_suite) else {
        return na(em, &tr!("could not determine the Debian release"));
    };
    let args = ["--suite", suite, "--format", "summary", "--no-obsolete"];
    let out = match live_command_timeout(ctx, "debsecan", &args, std::time::Duration::from_secs(60)) {
        None => return na(em, &tr!("debsecan not installed (apt install debsecan)")),
        Some(Timed::TimedOut) => return na(em, &tr!("debsecan did not answer in 60 s")),
        Some(Timed::Done(o)) if !o.ok => {
            let e = o.stderr.lines().find(|l| !l.trim().is_empty()).unwrap_or("").to_string();
            return na(em, &tr!("debsecan failed (no network?): {e}", e = e));
        }
        Some(Timed::Done(o)) => o.stdout,
    };
    let unfixed = debsecan_unfixed(&out, &|u| unit_enabled(ctx, u));
    if unfixed.is_empty() {
        em.pass("PAT-008", Medium, title)
            .with_detail(tr!("enabled services, per the Debian security tracker ({suite})", suite = suite));
        return;
    }
    let n: usize = unfixed.values().map(Vec::len).sum();
    let detail: Vec<String> = unfixed
        .iter()
        .map(|(p, c)| if c.len() <= 4 { format!("{p}: {}", c.join(" ")) } else { format!("{p}: {} (+{})", c[..4].join(" "), c.len() - 4) })
        .collect();
    em.warn("PAT-008", Medium, &tr!("Network services with unfixed CVEs ({n})", n = n))
        .with_detail(detail.join("; "))
        .with_fix(tr!("No update yet: check security-tracker.debian.org for mitigations (PAT-001 will flag the update)"));
}

/// Paquetes con actualización de seguridad en la salida de `apt-get -s upgrade`,
/// o la primera línea de error (`E: ...`).
pub fn apt_security(out: &str) -> Result<Vec<String>, String> {
    if let Some(e) = out.lines().find(|l| l.starts_with("E:")) {
        return Err(e.to_string());
    }
    Ok(out
        .lines()
        .filter(|l| l.starts_with("Inst") && l.to_lowercase().contains("security"))
        .map(|l| l.split_whitespace().nth(1).unwrap_or("").to_string())
        .collect())
}

/// PAT-001 / PAT-002 en Debian/Ubuntu.
fn apt_updates(ctx: &Context, em: &mut Emitter) {
    let Some(out) = live_command_full(ctx, "apt-get", &["-s", "upgrade"], &[("LC_ALL", "C")]) else {
        em.na("PAT-001", High, tr!("Pending security updates")).with_detail(tr!("apt-get unavailable"));
        return;
    };
    match apt_security(&format!("{}\n{}", out.stdout, out.stderr)) {
        Err(e) => {
            em.error("PAT-001", High, tr!("Pending security updates"))
                .with_detail(tr!("apt-get -s failed: {e}", e = e));
        }
        Ok(pkgs) if pkgs.is_empty() => {
            em.pass("PAT-001", High, tr!("No pending security updates (per the local index)"));
        }
        Ok(pkgs) => {
            let n = pkgs.len();
            let title = tr!("{n} pending security updates", n = n);
            let r = if n < 10 { em.warn("PAT-001", High, &title) } else { em.fail("PAT-001", High, &title) };
            r.with_detail(pkgs.iter().take(8).cloned().collect::<Vec<_>>().join(" ")).with_fix("apt update && apt upgrade");
        }
    }

    // antigüedad del índice: si es viejo, PAT-001 puede subestimar los pendientes
    let newest = ["/var/lib/apt/periodic/update-success-stamp", "/var/lib/apt/lists"]
        .iter()
        .filter_map(|p| std::fs::metadata(ctx.path(p)).ok().map(|m| m.mtime()))
        .max();
    match newest {
        None => {
            em.na("PAT-002", Medium, tr!("Package index is recent")).with_detail(tr!("could not be determined"));
        }
        Some(t) => {
            let d = (ctx.now_unix - t) / 86_400;
            if d <= 7 {
                em.pass("PAT-002", Medium, &tr!("Package index updated {d} days ago", d = d));
            } else {
                em.warn("PAT-002", Medium, &tr!("Package index is old ({d} days): PAT-001 may underestimate pending updates", d = d))
                    .with_fix(tr!("apt update (or check the internal repo / apt-daily.timer)"));
            }
        }
    }
}

/// PAT-001 en RHEL y derivadas.
fn dnf_updates(ctx: &Context, em: &mut Emitter) {
    let title = tr!("Pending security updates");
    let args = ["-C", "-q", "updateinfo", "list", "security"];
    let Some((pm, out)) = ["dnf", "yum"].iter().find_map(|pm| live_command_full(ctx, pm, &args, &[]).map(|o| (*pm, o)))
    else {
        em.na("PAT-001", High, title).with_detail(tr!("dnf/yum unavailable"));
        return;
    };
    if !out.ok && out.stdout.trim().is_empty() {
        em.error("PAT-001", High, title).with_detail(tr!("no metadata cache for {pm} (run: {pm} makecache)", pm = pm));
        return;
    }
    let sec: Vec<&str> = out.stdout.lines().filter(|l| l.contains("/Sec.")).collect();
    let hi: Vec<&str> = sec.iter().copied().filter(|l| l.contains("Critical/Sec.") || l.contains("Important/Sec.")).collect();
    if !hi.is_empty() {
        em.fail("PAT-001", High, &tr!("{n} critical/important errata pending ({total} security in total)", n = hi.len(), total = sec.len()))
            .with_detail(hi.iter().take(6).filter_map(|l| l.split_whitespace().next()).collect::<Vec<_>>().join(" "))
            .with_fix(format!("{pm} update --security"));
    } else if !sec.is_empty() {
        em.warn("PAT-001", High, &tr!("{n} security errata pending", n = sec.len()))
            .with_fix(format!("{pm} update --security"));
    } else {
        em.pass("PAT-001", High, tr!("No security errata pending (per the local cache)"));
    }
}

/// `Unattended-Upgrade "1"` (con al menos un espacio en medio).
fn enables_unattended(text: &str) -> bool {
    text.match_indices("Unattended-Upgrade").any(|(i, m)| {
        let rest = &text[i + m.len()..];
        let trimmed = rest.trim_start();
        trimmed.len() < rest.len() && trimmed.starts_with("\"1\"")
    })
}

/// PAT-003
fn auto_updates(ctx: &Context, em: &mut Emitter) {
    match ctx.os.family {
        OsFamily::Debian => {
            let configured = || {
                dir_files(ctx, "/etc/apt/apt.conf.d")
                    .iter()
                    .any(|(_, p)| std::fs::read_to_string(p).is_ok_and(|t| enables_unattended(&t)))
            };
            if pkg_installed(ctx, "unattended-upgrades") && configured() {
                em.pass("PAT-003", Medium, tr!("Automatic security updates enabled"));
            } else {
                em.warn("PAT-003", Medium, tr!("No automatic security updates"))
                    .with_detail(tr!("unattended-upgrades not active"))
                    .with_fix(tr!("Enable it, or add a waiver if patching is managed centrally (Satellite/Ansible/etc.)"));
            }
        }
        OsFamily::Rhel => {
            let units =
                ["dnf-automatic-install.timer", "dnf-automatic.timer", "yum-cron.service", "dnf-automatic-notifyonly.timer"];
            if units.iter().any(|u| unit_enabled(ctx, u)) {
                em.pass("PAT-003", Medium, tr!("Automatic update mechanism enabled"));
            } else {
                em.warn("PAT-003", Medium, tr!("No automatic updates"))
                    .with_detail(tr!("dnf-automatic/yum-cron not enabled"))
                    .with_fix(tr!("Enable it or add a waiver if patching is centralized"));
            }
        }
        OsFamily::Unknown => {
            em.na("PAT-003", Medium, tr!("Automatic updates")).with_detail(tr!("unrecognized distro"));
        }
    }
}

/// PAT-004
fn reboot_pending(ctx: &Context, em: &mut Emitter) {
    match ctx.os.family {
        OsFamily::Debian => {
            if ctx.path("/var/run/reboot-required").exists() {
                let pkgs = read(ctx, "/var/run/reboot-required.pkgs").unwrap_or_default().replace('\n', " ");
                em.warn("PAT-004", Medium, tr!("Reboot pending after updates"))
                    .with_detail(pkgs.chars().take(200).collect::<String>())
                    .with_fix(tr!("Schedule a reboot"));
            } else {
                em.pass("PAT-004", Medium, tr!("No reboot pending"));
            }
        }
        OsFamily::Rhel => {
            let latest = live_command_full(ctx, "rpm", &["-q", "--last", "kernel"], &[])
                .and_then(|o| o.stdout.lines().next().and_then(|l| l.split_whitespace().next()).map(str::to_string))
                .map(|k| k.strip_prefix("kernel-").unwrap_or(&k).to_string());
            let running = read(ctx, "/proc/sys/kernel/osrelease").unwrap_or_default().trim().to_string();
            match latest {
                None => {
                    em.na("PAT-004", Medium, tr!("Running vs installed kernel")).with_detail(tr!("could not be determined"));
                }
                Some(l) if l == running => {
                    em.pass("PAT-004", Medium, tr!("Running the newest installed kernel"));
                }
                Some(l) => {
                    em.warn("PAT-004", Medium, tr!("Running a kernel other than the newest installed"))
                        .with_detail(tr!("running {running}, installed {l}", running = running, l = l))
                        .with_fix(tr!("Schedule a reboot"));
                }
            }
        }
        OsFamily::Unknown => {
            em.na("PAT-004", Medium, tr!("Reboot pending")).with_detail(tr!("unrecognized distro"));
        }
    }
}

/// Fecha de fin de soporte y de dónde salió.
pub fn eol_date(ctx: &Context) -> Option<(String, &'static str)> {
    let os = &ctx.os;
    if !os.support_end.is_empty() {
        return Some((os.support_end.clone(), "os-release"));
    }
    let from_csv = match os.id.as_str() {
        "debian" => read(ctx, "/usr/share/distro-info/debian.csv").and_then(|t| {
            t.lines().find_map(|l| {
                let f: Vec<&str> = l.split(',').collect();
                (f.first() == Some(&os.major())).then(|| {
                    let lts = f.get(6).copied().unwrap_or("");
                    if lts.is_empty() { f.get(5).copied().unwrap_or("") } else { lts }.to_string()
                })
            })
        }),
        "ubuntu" => read(ctx, "/usr/share/distro-info/ubuntu.csv").and_then(|t| {
            t.lines().find_map(|l| {
                let f: Vec<&str> = l.split(',').collect();
                f.first().is_some_and(|v| v.starts_with(&os.version)).then(|| f.get(5).copied().unwrap_or("").to_string())
            })
        }),
        _ => None,
    };
    if let Some(d) = from_csv.filter(|d| !d.is_empty()) {
        return Some((d, "distro-info-data"));
    }
    eol_table(&os.id, &os.version).map(|d| (d.to_string(), tr!("internal table (verify)")))
}

/// Tabla de último recurso (verificar contra el fabricante).
fn eol_table(id: &str, ver: &str) -> Option<&'static str> {
    let major = ver.split('.').next().unwrap_or("");
    Some(match (id, ver) {
        ("debian", "9") => "2022-06-30",
        ("debian", "10") => "2024-06-30",
        ("debian", "11") => "2026-08-31",
        ("debian", "12") => "2028-06-30",
        ("debian", "13") => "2030-06-30",
        ("ubuntu", "18.04") => "2023-05-31",
        ("ubuntu", "20.04") => "2025-05-31",
        ("ubuntu", "22.04") => "2027-04-30",
        ("ubuntu", "24.04") => "2029-04-30",
        ("centos", "7") => "2024-06-30",
        ("rhel" | "ol", _) if major == "7" => "2024-06-30",
        ("centos", _) if major == "8" => "2021-12-31",
        ("rhel" | "rocky" | "almalinux", _) if major == "8" => "2029-05-31",
        ("rhel" | "rocky" | "almalinux", _) if major == "9" => "2032-05-31",
        _ => return None,
    })
}

/// PAT-005
fn end_of_life(ctx: &Context, em: &mut Emitter) {
    let pretty = &ctx.os.pretty;
    let Some((eol, src)) = eol_date(ctx) else {
        em.na("PAT-005", High, tr!("Operating system within support"))
            .with_detail(tr!("no end-of-support date for {pretty}", pretty = pretty));
        return;
    };
    let today = civil_date(ctx.now_unix);
    let soon = civil_date(ctx.now_unix + 180 * 86_400);
    let detail = tr!("source: {src}", src = src);
    if eol <= today {
        em.fail("PAT-005", High, &tr!("{pretty} has been out of support since {eol}", pretty = pretty, eol = eol))
            .with_detail(detail)
            .with_fix(tr!("Migrate to a supported release (or buy extended support and add a waiver)"));
    } else if eol < soon {
        em.warn("PAT-005", High, &tr!("{pretty} support ends on {eol} (less than 180 days)", pretty = pretty, eol = eol))
            .with_detail(detail)
            .with_fix(tr!("Plan the migration"));
    } else {
        em.pass("PAT-005", High, &tr!("{pretty} supported until {eol}", pretty = pretty, eol = eol)).with_detail(detail);
    }
}

/// `[... trusted=yes ...]` en una línea de sources.list.
fn trusted_yes_option(line: &str) -> bool {
    line.match_indices('[').any(|(i, _)| {
        let rest = &line[i + 1..];
        rest[..rest.find(']').unwrap_or(rest.len())].contains("trusted=yes")
    })
}

/// Configuración de apt que desactiva la verificación. Divergencia con bash: una línea que lo
/// pone explícitamente en "false" (`Acquire::AllowInsecureRepositories "false";`) no cuenta.
fn apt_allows_unsigned(line: &str) -> bool {
    if line.trim_start().strip_prefix("Trusted:").is_some_and(|v| v.trim_start().starts_with("yes")) {
        return true;
    }
    ["AllowUnauthenticated", "allow-unauthenticated", "AllowInsecureRepositories"].iter().any(|k| line.contains(k))
        && !line.to_lowercase().contains("false")
}

fn yum_gpgcheck_off(line: &str) -> bool {
    ["gpgcheck", "repo_gpgcheck", "localpkg_gpgcheck"].iter().any(|k| {
        line.strip_prefix(k).and_then(|r| r.trim_start().strip_prefix('=')).is_some_and(|v| {
            let v = v.trim_start();
            v.starts_with('0') || v.starts_with("False") || v.starts_with("no")
        })
    })
}

/// PAT-006
fn unsigned_repos(ctx: &Context, em: &mut Emitter) {
    let title = tr!("Repositories with signature verification");
    let matching = |files: Vec<(String, std::path::PathBuf)>, pred: &dyn Fn(&str) -> bool| -> Vec<String> {
        files
            .into_iter()
            .filter(|(_, p)| std::fs::read_to_string(p).is_ok_and(|t| t.lines().any(pred)))
            .map(|(name, _)| name)
            .collect()
    };
    let mut x = match ctx.os.family {
        OsFamily::Debian => {
            let mut sources = file_if_exists(ctx, "/etc/apt/sources.list");
            sources.extend(dir_files(ctx, "/etc/apt/sources.list.d"));
            let mut conf = dir_files(ctx, "/etc/apt/sources.list.d");
            conf.extend(dir_files(ctx, "/etc/apt/apt.conf.d"));
            let mut v = matching(sources, &trusted_yes_option);
            v.extend(matching(conf, &apt_allows_unsigned));
            v
        }
        OsFamily::Rhel => {
            let mut files: Vec<_> = glob(&ctx.path("/etc/yum.repos.d"), "", ".repo")
                .into_iter()
                .map(|p| (format!("/etc/yum.repos.d/{}", p.file_name().unwrap_or_default().to_string_lossy()), p))
                .collect();
            files.extend(file_if_exists(ctx, "/etc/dnf/dnf.conf"));
            files.extend(file_if_exists(ctx, "/etc/yum.conf"));
            matching(files, &yum_gpgcheck_off)
        }
        OsFamily::Unknown => {
            em.na("PAT-006", High, title).with_detail(tr!("unrecognized distro"));
            return;
        }
    };
    x.sort();
    x.dedup();
    if x.is_empty() {
        em.pass("PAT-006", High, title);
    } else {
        em.fail("PAT-006", High, tr!("Repositories without signature verification (trusted=yes / gpgcheck=0)"))
            .with_detail(x.join(" "))
            .with_fix(tr!("Enable verification and import the repo key"));
    }
}

fn file_if_exists(ctx: &Context, abs: &str) -> Vec<(String, std::path::PathBuf)> {
    let p = ctx.path(abs);
    if p.is_file() { vec![(abs.to_string(), p)] } else { vec![] }
}

/// `https?://host` de cada línea.
fn url_hosts(line: &str) -> Vec<String> {
    let mut v = Vec::new();
    for scheme in ["http://", "https://"] {
        for (i, _) in line.match_indices(scheme) {
            let rest = &line[i + scheme.len()..];
            let host: String = rest.chars().take_while(|c| *c != '/' && !c.is_whitespace()).collect();
            if !host.is_empty() {
                v.push(format!("{scheme}{host}"));
            }
        }
    }
    v
}

/// PAT-007 (informativo)
fn third_party_origins(ctx: &Context, em: &mut Emitter) {
    let (files, prefixes, official): (Vec<_>, &[&str], &[&str]) = match ctx.os.family {
        OsFamily::Debian => {
            let mut f = file_if_exists(ctx, "/etc/apt/sources.list");
            f.extend(dir_files(ctx, "/etc/apt/sources.list.d"));
            (f, &["deb", "URIs:"], &["debian.org", "ubuntu.com", ".archive.ubuntu"])
        }
        OsFamily::Rhel => (
            glob(&ctx.path("/etc/yum.repos.d"), "", ".repo").into_iter().map(|p| (String::new(), p)).collect(),
            &["baseurl", "mirrorlist", "metalink"],
            &["redhat.com", "rockylinux.org", "almalinux.org", "centos.org", "fedoraproject.org"],
        ),
        OsFamily::Unknown => (vec![], &[], &[]),
    };
    let mut hosts: Vec<String> = files
        .iter()
        .filter_map(|(_, p)| std::fs::read_to_string(p).ok())
        .flat_map(|t| {
            t.lines()
                .filter(|l| prefixes.iter().any(|p| l.starts_with(p)))
                .flat_map(url_hosts)
                .collect::<Vec<_>>()
        })
        .filter(|h| !official.iter().any(|o| h.contains(o)))
        .collect();
    hosts.sort();
    hosts.dedup();
    let r = if hosts.is_empty() { trc!("package sources", "none").to_string() } else { hosts.join(" ") };
    em.pass("PAT-007", Info, &tr!("Non-standard package sources: {r}", r = r));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::fixture::Fixture;
    use crate::model::Status;
    use crate::system::OsInfo;

    #[test]
    fn unidades_de_servicio() {
        assert_eq!(service_units("openssh-server").unwrap(), ["ssh.service", "ssh.socket"]);
        assert_eq!(service_units("tomcat10").unwrap(), ["tomcat10.service"]);
        assert_eq!(service_units("exim4-daemon-heavy").unwrap(), ["exim4.service"]);
        assert!(service_units("linux-libc-dev").is_none());
        assert!(service_units("postgresql-client-17").is_none());
    }

    #[test]
    fn suite_de_debian() {
        assert_eq!(debian_suite("13.6\n"), Some("trixie"));
        assert_eq!(debian_suite("12.11"), Some("bookworm"));
        assert_eq!(debian_suite("forky/sid"), Some("sid"));
        assert_eq!(debian_suite("10.13"), None);
    }

    #[test]
    fn debsecan_solo_sin_corregir_y_de_servicios() {
        let out = "\
CVE-2026-119618 apache2-bin
CVE-2026-42356 apache2-bin (fixed)
CVE-2026-106023 apache2-bin (remotely exploitable, high urgency)
CVE-2026-1 linux-libc-dev
CVE-2026-2 postgresql-17 (low urgency)
CVE-2026-3 openssh-server (fixed, remotely exploitable)
CVE-2026-4 apache2-utils
CVE-2026-5 postgresql-client-17
TEMP-0000000-ABCDEF bind9
";
        let all = |_: &str| true;
        let m = debsecan_unfixed(out, &all);
        assert_eq!(m.len(), 2, "{m:?}");
        assert_eq!(m["apache2-bin"], ["CVE-2026-119618", "CVE-2026-106023"]);
        assert_eq!(m["postgresql-17"], ["CVE-2026-2"]);

        // apache2-bin instalado pero apache2.service deshabilitado: no cuenta
        let pg = |u: &str| u == "postgresql.service";
        let m = debsecan_unfixed(out, &pg);
        assert_eq!(m.keys().collect::<Vec<_>>(), ["postgresql-17"]);
    }

    #[test]
    fn parsea_apt_get_simulado() {
        let out = "Reading package lists...\n\
            Inst openssl [3.0.11-1] (3.0.15-1 Debian-Security:12/stable-security [amd64])\n\
            Inst vim [2:9.0-1] (2:9.0-2 Debian:12.8/stable [amd64])\n\
            Inst libssl3 [3.0.11-1] (3.0.15-1 Debian-Security:12/stable-security [amd64])\n\
            Conf openssl (3.0.15-1 Debian-Security:12/stable-security [amd64])\n";
        assert_eq!(apt_security(out).unwrap(), ["openssl", "libssl3"]);
        assert_eq!(apt_security("W: algo\nE: Could not get lock\n").unwrap_err(), "E: Could not get lock");
    }

    fn debian() -> Fixture {
        let f = Fixture::new();
        f.file("/etc/apt/sources.list", "deb http://deb.debian.org/debian trixie main\n")
            .file(
                "/var/lib/dpkg/status",
                "Package: unattended-upgrades\nStatus: install ok installed\nVersion: 2.12\n",
            )
            .file("/etc/apt/apt.conf.d/20auto-upgrades", "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n");
        f
    }

    #[test]
    fn debian_al_dia() {
        let r = debian().run(run);
        assert_eq!(r["PAT-001"].status, Status::Na, "en fixtures no se ejecuta apt-get");
        assert!(!r.contains_key("PAT-002"), "como en bash, sin apt-get no hay PAT-002");
        assert_eq!(r["PAT-003"].status, Status::Pass);
        assert_eq!(r["PAT-004"].status, Status::Pass);
        assert_eq!(r["PAT-005"].title, "Linux dentro de soporte hasta 2030-06-30");
        assert_eq!(r["PAT-005"].detail, "fuente: tabla interna (verificar)");
        assert_eq!(r["PAT-006"].status, Status::Pass);
        assert_eq!(r["PAT-007"].title, "Orígenes de paquetes no estándar: ninguno");
    }

    #[test]
    fn debian_con_problemas() {
        let f = debian();
        f.file("/var/run/reboot-required", "*** System restart required ***\n")
            .file("/var/run/reboot-required.pkgs", "linux-image-amd64\nlibc6\n")
            .file("/etc/apt/sources.list.d/docker.list", "deb [arch=amd64 trusted=yes] https://download.docker.com/linux/debian trixie stable\n")
            .file("/etc/apt/sources.list.d/vendor.sources", "Types: deb\nURIs: https://repo.vendor.example/apt\nTrusted: yes\n")
            .file("/etc/apt/apt.conf.d/99seguro", "Acquire::AllowInsecureRepositories \"false\";\n")
            .file("/etc/apt/apt.conf.d/20auto-upgrades", "APT::Periodic::Unattended-Upgrade \"0\";\n");
        let r = f.run(run);
        assert_eq!(r["PAT-003"].status, Status::Warn);
        assert_eq!(r["PAT-004"].detail, "linux-image-amd64 libc6 ");
        assert_eq!(r["PAT-006"].detail, "/etc/apt/sources.list.d/docker.list /etc/apt/sources.list.d/vendor.sources");
        assert_eq!(
            r["PAT-007"].title,
            "Orígenes de paquetes no estándar: https://download.docker.com https://repo.vendor.example"
        );
    }

    #[test]
    fn fin_de_soporte() {
        let mut f = Fixture::new();
        f.os = OsInfo::parse("ID=debian\nVERSION_ID=11\nPRETTY_NAME=\"Debian 11\"\n");
        f.file("/usr/share/distro-info/debian.csv", "version,codename,series,created,release,eol,eol-lts,eol-elts\n11,Bullseye,bullseye,2019-07-06,2021-08-14,2024-08-14,2026-08-31,2031-06-30\n");
        let r = f.run(run);
        assert_eq!(r["PAT-005"].status, Status::Fail);
        assert_eq!(r["PAT-005"].title, "Debian 11 está fuera de soporte desde 2026-08-31");

        f.os = OsInfo::parse("ID=fedora\nPRETTY_NAME=\"Fedora 41\"\nSUPPORT_END=2027-02-01\n");
        let r = f.run(run);
        assert_eq!(r["PAT-005"].status, Status::Warn);
        assert_eq!(r["PAT-005"].detail, "fuente: os-release");

        f.os = OsInfo::parse("ID=goldendoglinux\nPRETTY_NAME=\"GoldenDog Linux 2\"\n");
        assert_eq!(f.run(run)["PAT-005"].status, Status::Na);
        assert_eq!(eol_table("rocky", "9.4"), Some("2032-05-31"));
        assert_eq!(eol_table("ol", "7.9"), Some("2024-06-30"));
    }

    #[test]
    fn rhel_gpgcheck() {
        assert!(yum_gpgcheck_off("gpgcheck=0"));
        assert!(yum_gpgcheck_off("repo_gpgcheck = False"));
        assert!(!yum_gpgcheck_off("gpgcheck=1"));
        assert!(!yum_gpgcheck_off("#gpgcheck=0"));
        let mut f = Fixture::new();
        f.os = OsInfo::parse("ID=rocky\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=9.4\n");
        f.file("/etc/yum.repos.d/epel.repo", "[epel]\nbaseurl=https://dl.fedoraproject.org/pub/epel/9\ngpgcheck=1\n")
            .file("/etc/yum.repos.d/raro.repo", "[raro]\nbaseurl=http://mirror.raro.example/el9\ngpgcheck=0\n");
        let r = f.run(run);
        assert_eq!(r["PAT-002"].status, Status::Na);
        assert_eq!(r["PAT-003"].status, Status::Warn);
        assert_eq!(r["PAT-006"].detail, "/etc/yum.repos.d/raro.repo");
        assert_eq!(r["PAT-007"].title, "Orígenes de paquetes no estándar: http://mirror.raro.example");
    }

    #[test]
    fn unattended_requiere_espacio() {
        assert!(enables_unattended("APT::Periodic::Unattended-Upgrade \"1\";"));
        assert!(!enables_unattended("APT::Periodic::Unattended-Upgrade\"1\";"));
        assert!(!enables_unattended("APT::Periodic::Unattended-Upgrade \"0\";"));
    }
}
