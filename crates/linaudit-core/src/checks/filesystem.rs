//! category: filesystem — port de checks.d/30-filesystem.sh.
//! Permisos de archivos críticos, SUID/SGID, world-writable, opciones de montaje, capabilities.
//!
//! Divergencias con bash:
//! - FS-014 usa un índice de los archivos de dpkg en vez de `dpkg -S` por archivo: es mucho más rápido
//!   y además reconoce los alias de /usr unificado (/bin → /usr/bin), que `dpkg -S` reportaba como
//!   "no pertenece a ningún paquete" (falso positivo típico: /usr/bin/fusermount3).
//! - Las listas de FS-014..018 se ordenan por ruta (bash las ordenaba según la configuración regional).

use std::collections::HashSet;
use std::os::unix::fs::MetadataExt;
use std::time::Instant;

use super::Context;
use super::util::{
    Timed, check_file_perm, dir_files, live_command_full, live_command_timeout, login_defs_get, mode_within, parse_passwd,
    read,
};
use super::walk::{WalkOpts, scan_timeout, walk};
use crate::model::{Emitter, ResultExt, Severity, Severity::*};
use crate::system::OsFamily;
use crate::tr;

/// Un punto de montaje de /proc/self/mountinfo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    pub target: String,
    pub fstype: String,
    /// Opciones como las muestra `findmnt -o OPTIONS` (VFS + filesystem).
    pub options: String,
}

/// `\040` y compañía (escapes octales de mountinfo).
fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let octal = |j: usize| b.get(j).is_some_and(|c| (b'0'..=b'7').contains(c));
        if b[i] == b'\\' && octal(i + 1) && octal(i + 2) && octal(i + 3) {
            if let Ok(n) = u8::from_str_radix(&s[i + 1..i + 4], 8) {
                out.push(n);
                i += 4;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn parse_mountinfo(text: &str) -> Vec<Mount> {
    text.lines()
        .filter_map(|l| {
            let (pre, post) = l.split_once(" - ")?;
            let f: Vec<&str> = pre.split(' ').collect();
            let g: Vec<&str> = post.split(' ').collect();
            let vfs = *f.get(5)?;
            let sup: Vec<&str> = g.get(2).unwrap_or(&"").split(',').filter(|o| *o != "rw" && *o != "ro" && !o.is_empty()).collect();
            let mut options = vfs.to_string();
            if !sup.is_empty() {
                options.push(',');
                options.push_str(&sup.join(","));
            }
            Some(Mount { target: unescape(f.get(4)?), fstype: g.first()?.to_string(), options })
        })
        .collect()
}

/// El montaje que contiene `path` (el de punto de montaje más largo; si hay apilados, el último).
pub fn mount_of<'a>(mounts: &'a [Mount], path: &str) -> Option<&'a Mount> {
    mounts
        .iter()
        .filter(|m| m.target == "/" || path == m.target || path.starts_with(&format!("{}/", m.target)))
        .max_by_key(|m| m.target.len())
}

fn mounts(ctx: &Context) -> Vec<Mount> {
    parse_mountinfo(&read(ctx, "/proc/self/mountinfo").unwrap_or_default())
}

/// FS-006..008
fn check_mount(em: &mut Emitter, all: &[Mount], id: &str, sev: Severity, path: &str, want: &[&str]) {
    let Some(m) = mount_of(all, path) else {
        em.na(id, sev, &tr!("{path} mount", path = path)).with_detail(tr!("not a mount point"));
        return;
    };
    if m.target == "/" && path != "/" {
        em.warn(id, sev, &tr!("{path} with secure options", path = path))
            .with_detail(tr!("{path} is not a separate filesystem", path = path))
            .with_fix(tr!("Mount {path} separately with: {opts}", opts = want.join(" "), path = path));
        return;
    }
    let have = format!(",{},", m.options);
    let miss: Vec<&str> = want.iter().copied().filter(|o| !have.contains(&format!(",{o},"))).collect();
    if miss.is_empty() {
        em.pass(id, sev, &tr!("{path} with secure options", path = path)).with_detail(&m.options);
    } else {
        em.warn(id, sev, &tr!("{path} without secure options", path = path))
            .with_detail(tr!("missing: {missing} (current options: {current})", missing = miss.join(" "), current = m.options))
            .with_fix(tr!("Add {opts} in /etc/fstab (or a systemd mount unit)", opts = miss.join(",")));
    }
}

/// Binarios que nunca deberían ser SUID (GTFOBins).
fn gtfo(name: &str) -> bool {
    const NAMES: &[&str] = &[
        "bash", "sh", "dash", "zsh", "csh", "ksh", "find", "vim", "vi", "nano", "less", "more", "awk", "gawk", "mawk", "nmap",
        "perl", "ruby", "node", "lua", "env", "cp", "mv", "tar", "zip", "unzip", "rsync", "tee", "dd", "nice", "time",
        "timeout", "strace", "gdb", "docker", "systemctl", "journalctl", "xargs", "tclsh", "wish", "socat", "nc", "ncat",
        "netcat", "curl", "wget", "base64", "xxd", "taskset", "ionice", "flock", "busybox", "openssl", "git", "ssh", "scp",
        "screen", "tmux", "man", "chmod", "chown", "sed", "ed", "expect", "php", "vimdiff", "emacs",
    ];
    if NAMES.contains(&name) {
        return true;
    }
    // python3, python3.12, php8.2...
    ["python", "php"].iter().any(|p| name.strip_prefix(p).is_some_and(|v| v.chars().all(|c| c.is_ascii_digit() || c == '.')))
}

/// Índice de los archivos instalados por dpkg (todos los /var/lib/dpkg/info/*.list).
fn dpkg_files(ctx: &Context) -> HashSet<String> {
    dir_files(ctx, "/var/lib/dpkg/info")
        .into_iter()
        .filter(|(n, _)| n.ends_with(".list"))
        .filter_map(|(_, p)| std::fs::read_to_string(p).ok())
        .flat_map(|t| t.lines().map(str::to_string).collect::<Vec<_>>())
        .collect()
}

/// true si `p` (o su alias por /usr unificado) está en el índice de dpkg.
fn owned_by_dpkg(index: &HashSet<String>, p: &str) -> bool {
    if index.contains(p) {
        return true;
    }
    if let Some(rest) = p.strip_prefix("/usr") {
        if ["/bin/", "/sbin/", "/lib"].iter().any(|d| rest.starts_with(d)) && index.contains(rest) {
            return true;
        }
    }
    ["/bin/", "/sbin/", "/lib"].iter().any(|d| p.starts_with(d)) && index.contains(&format!("/usr{p}"))
}

/// Raíces de snapshots de backup (Timeshift rsync/btrfs, snapper): copias del sistema que el barrido
/// completo no recorre (FS-014..018 darían un hallazgo por cada copia) y que FS-019 controla aparte.
const SNAPSHOT_ROOTS: &[&str] = &["/timeshift", "/timeshift-btrfs", "/.snapshots"];

fn short(v: &[String]) -> String {
    v.iter().take(8).cloned().collect::<Vec<_>>().join(" ")
}

/// FS-018: agrupa cada archivo huérfano bajo el directorio huérfano más alto que lo contiene, para que
/// un volumen de contenedor (miles de archivos con el uid de la imagen) se lea como una sola línea.
fn group_orphans(orphan: &[(String, u32, u32)]) -> Vec<String> {
    use std::collections::BTreeMap;
    let set: HashSet<&str> = orphan.iter().map(|(p, ..)| p.as_str()).collect();
    let owner: std::collections::HashMap<&str, (u32, u32)> = orphan.iter().map(|(p, u, g)| (p.as_str(), (*u, *g))).collect();
    let mut groups: BTreeMap<&str, usize> = BTreeMap::new();
    for (p, ..) in orphan {
        let mut top = p.as_str();
        while let Some((parent, _)) = top.rsplit_once('/') {
            if parent.is_empty() || !set.contains(parent) {
                break;
            }
            top = parent;
        }
        *groups.entry(top).or_default() += 1;
    }
    let mut v: Vec<(&str, usize)> = groups.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    v.into_iter()
        .map(|(p, n)| {
            let (uid, gid) = owner[p];
            if n == 1 { format!("{p}({uid}:{gid})") } else { tr!("{path}({uid}:{gid}, {n} entries)", path = p, uid = uid, gid = gid, n = n) }
        })
        .collect()
}

pub fn run(ctx: &Context, em: &mut Emitter) {
    let uid_min: u32 = login_defs_get(ctx, "UID_MIN").and_then(|v| v.parse().ok()).unwrap_or(1000);

    // FS-001..005: archivos críticos
    check_file_perm(em, ctx, "FS-001", Critical, tr!("/etc/shadow permissions"), "/etc/shadow", 0o640, Some(0));
    check_file_perm(em, ctx, "FS-002", High, tr!("/etc/gshadow permissions"), "/etc/gshadow", 0o640, Some(0));
    check_file_perm(em, ctx, "FS-003", Medium, tr!("/etc/passwd permissions"), "/etc/passwd", 0o644, Some(0));
    check_file_perm(em, ctx, "FS-004", Medium, tr!("/etc/group permissions"), "/etc/group", 0o644, Some(0));
    check_file_perm(em, ctx, "FS-005", High, tr!("/etc/sudoers permissions"), "/etc/sudoers", 0o440, Some(0));

    // FS-006..008: opciones de montaje
    let all = mounts(ctx);
    check_mount(em, &all, "FS-006", Medium, "/tmp", &["nodev", "nosuid", "noexec"]);
    check_mount(em, &all, "FS-007", Medium, "/var/tmp", &["nodev", "nosuid", "noexec"]);
    check_mount(em, &all, "FS-008", Medium, "/dev/shm", &["nodev", "nosuid", "noexec"]);

    // FS-009 / FS-010: homes
    let passwd = parse_passwd(&read(ctx, "/etc/passwd").unwrap_or_default());
    let (mut ww, mut wr) = (Vec::new(), Vec::new());
    for p in passwd.iter().filter(|p| p.uid.is_some_and(|u| u >= uid_min && u < 65534)) {
        let Ok(m) = std::fs::metadata(ctx.path(&p.home)) else { continue };
        if !m.is_dir() {
            continue;
        }
        let mode = m.mode() & 0o7777;
        if mode & 0o002 != 0 {
            ww.push(format!("{}({mode:o})", p.name));
        }
        if !mode_within(mode, 0o750) {
            wr.push(format!("{}({mode:o})", p.name));
        }
    }
    if ww.is_empty() {
        em.pass("FS-009", High, tr!("No home directory is world-writable"));
    } else {
        em.fail("FS-009", High, tr!("Home directories writable by everyone"))
            .with_detail(ww.join(" "))
            .with_fix(tr!("chmod o-w <home> (ideally 750 or 700)"));
    }
    if wr.is_empty() {
        em.pass("FS-010", Low, tr!("Home directories with restrictive permissions (<=750)"));
    } else {
        em.warn("FS-010", Low, tr!("Home directories readable by other users")).with_detail(wr.join(" ")).with_fix(tr!("chmod 750 (or 700) on the home directories"));
    }

    // FS-011: capabilities peligrosas
    let args = ["-r", "/usr", "/bin", "/sbin", "/opt", "/home"];
    match live_command_timeout(ctx, "getcap", &args, scan_timeout()) {
        None => {
            em.na("FS-011", High, tr!("Dangerous capabilities on binaries")).with_detail(tr!("getcap not installed (libcap2-bin / libcap)"));
        }
        Some(t) => {
            let out = match t {
                Timed::Done(o) => o.stdout,
                Timed::TimedOut => String::new(),
            };
            const CAPS: &[&str] =
                &["cap_setuid", "cap_setgid", "cap_sys_admin", "cap_dac_override", "cap_dac_read_search", "cap_sys_ptrace", "cap_sys_module"];
            let x: Vec<&str> = out
                .lines()
                .filter(|l| CAPS.iter().any(|c| l.contains(c)))
                .filter_map(|l| l.split_whitespace().next())
                .filter(|f| !f.ends_with("/newuidmap") && !f.ends_with("/newgidmap"))
                .collect();
            if x.is_empty() {
                em.pass("FS-011", High, tr!("No dangerous capabilities on binaries"));
            } else {
                em.warn("FS-011", High, tr!("Binaries with dangerous capabilities"))
                    .with_detail(x.join(" "))
                    .with_fix(tr!("setcap -r <binary> unless essential"));
            }
        }
    }

    // FS-012: SUID/SGID donde nunca deberían estar (barrido rápido)
    let mut x = Vec::new();
    for root in ["/tmp", "/var/tmp", "/dev/shm", "/home", "/var/www", "/srv"] {
        walk(ctx, root, &WalkOpts { xdev: true, deadline: Some(Instant::now() + scan_timeout()), ..Default::default() }, &mut |e| {
            if x.len() < 20 && e.is_file() && e.mode() & 0o6000 != 0 {
                x.push(e.path.to_string());
            }
        });
    }
    if x.is_empty() {
        em.pass("FS-012", High, tr!("No SUID/SGID in tmp, home, www"));
    } else {
        em.fail("FS-012", High, tr!("SUID/SGID in an unusual location"))
            .with_detail(x.join(" "))
            .with_fix(tr!("Investigate: a typical persistence/escalation technique"));
    }

    // FS-019: snapshots de backup accesibles por otros usuarios (copias viejas de SUID, /etc/shadow, ...)
    let snaps: Vec<(&str, u32)> = SNAPSHOT_ROOTS
        .iter()
        .filter_map(|r| {
            let m = std::fs::symlink_metadata(ctx.path(r)).ok()?;
            m.is_dir().then_some((*r, m.mode() & 0o7777))
        })
        .collect();
    let open: Vec<String> = snaps.iter().filter(|(_, m)| m & 0o001 != 0).map(|(r, m)| format!("{r}({m:o})")).collect();
    if snaps.is_empty() {
        em.na("FS-019", Medium, tr!("Backup snapshots not accessible to other users")).with_detail(tr!("no snapshot directories"));
    } else if open.is_empty() {
        em.pass("FS-019", Medium, tr!("Backup snapshots not accessible to other users"));
    } else {
        em.fail("FS-019", Medium, tr!("Backup snapshots accessible to other users"))
            .with_detail(open.join(" "))
            .with_fix(tr!("chmod 700 <dir>: old SUID binaries and copies of /etc stay usable inside the snapshot"));
    }

    if ctx.fast {
        for (id, sev, title) in [
            ("FS-013", Critical, tr!("Dangerous SUID (GTFOBins)")),
            ("FS-014", High, tr!("SUID/SGID not provided by packages")),
            ("FS-015", High, tr!("World-writable files in system paths")),
            ("FS-016", Medium, tr!("World-writable files outside system paths")),
            ("FS-017", Medium, tr!("World-writable directories without the sticky bit")),
            ("FS-018", Medium, tr!("Files without an owner or group")),
        ] {
            em.na(id, sev, title).with_detail(tr!("skipped by --fast"));
        }
        return;
    }
    full_scan(ctx, em, &all, &passwd);
}

/// FS-013..018: un solo recorrido de los filesystems locales.
fn full_scan(ctx: &Context, em: &mut Emitter, all: &[Mount], passwd: &[super::util::PasswdEntry]) {
    const LOCAL: &[&str] = &["ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs"];
    const PRUNE: &[&str] = &[
        "/var/lib/docker", "/var/lib/containers", "/var/lib/kubelet", "/var/lib/containerd", "/proc", "/sys", "/run",
        "/tmp", "/var/tmp", "/dev/shm",
    ];
    let prune = |p: &str| PRUNE.contains(&p) || SNAPSHOT_ROOTS.contains(&p);
    let mut roots: Vec<String> = all.iter().filter(|m| LOCAL.contains(&m.fstype.as_str())).map(|m| m.target.clone()).collect();
    if roots.is_empty() {
        roots.push("/".into());
    }
    roots.sort();
    roots.dedup();
    let uids: HashSet<u32> = passwd.iter().filter_map(|p| p.uid).collect();
    let gids: HashSet<u32> = read(ctx, "/etc/group")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.split(':').nth(2)?.parse().ok())
        .collect();

    let (mut wwsys, mut wwoth, mut wwdir, mut orphan, mut sugid) = (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let mut seen = HashSet::new();
    for root in &roots {
        let opts = WalkOpts { xdev: true, prune: Some(&prune), deadline: Some(Instant::now() + scan_timeout()), ..Default::default() };
        walk(ctx, root, &opts, &mut |e| {
            let (mode, file, dir) = (e.mode(), e.is_file(), e.is_dir());
            // cada predicado se calcula una vez: decide si la entrada interesa y en qué lista cae
            let ww_file = file && mode & 0o002 != 0;
            let ww_dir = dir && mode & 0o002 != 0 && mode & 0o1000 == 0;
            let sugid_file = file && mode & 0o6000 != 0;
            let orphaned = !uids.contains(&e.meta.uid()) || !gids.contains(&e.meta.gid());
            if !(ww_file || ww_dir || sugid_file || orphaned) || !seen.insert(e.path.to_string()) {
                return;
            }
            let p = e.path.to_string();
            if orphaned {
                orphan.push((p.clone(), e.meta.uid(), e.meta.gid()));
            }
            if ww_file && !p.contains("/.cache/") && !p.contains("/.local/share/") {
                let system =
                    ["/etc/", "/usr/", "/bin/", "/sbin/", "/boot/", "/opt/"].iter().any(|d| p.starts_with(d)) || p.starts_with("/lib");
                if system { wwsys.push(p.clone()) } else { wwoth.push(p.clone()) }
            }
            if sugid_file {
                sugid.push((mode, p.clone()));
            }
            if ww_dir {
                wwdir.push(p);
            }
        });
    }
    for v in [&mut wwsys, &mut wwoth, &mut wwdir] {
        v.sort();
    }
    orphan.sort();
    sugid.sort_by(|a, b| a.1.cmp(&b.1));

    // FS-013: SUID en binarios que permiten escalar (GTFOBins)
    let x: Vec<&str> = sugid
        .iter()
        .filter(|(m, p)| m & 0o4000 != 0 && gtfo(p.rsplit('/').next().unwrap_or("")))
        .map(|(_, p)| p.as_str())
        .collect();
    if x.is_empty() {
        em.pass("FS-013", Critical, tr!("No SUID on dangerous binaries (GTFOBins)"));
    } else {
        em.fail("FS-013", Critical, tr!("SUID on binaries that allow escalating to root")).with_detail(x.join(" ")).with_fix(tr!("chmod u-s <binary>"));
    }

    // FS-014: SUID/SGID que no vienen de ningún paquete
    // Con el índice de dpkg revisar todos es barato; rpm -qf recibe las rutas como argumentos y se acota.
    // Un tope fijo en Debian dejaba afuera rutas que ordenan tarde (/usr/...) si había muchas antes.
    let limit = if ctx.os.family == OsFamily::Rhel { 150 } else { usize::MAX };
    let checked: Vec<&str> = sugid.iter().take(limit).map(|(_, p)| p.as_str()).collect();
    let orphans: Option<Vec<String>> = match ctx.os.family {
        OsFamily::Debian => {
            let index = if checked.is_empty() { HashSet::new() } else { dpkg_files(ctx) };
            Some(checked.iter().filter(|p| !owned_by_dpkg(&index, p)).map(|p| p.to_string()).collect())
        }
        OsFamily::Rhel => {
            let mut args = vec!["-qf", "--"];
            args.extend(checked.iter().copied());
            let out = if checked.is_empty() {
                String::new()
            } else {
                live_command_full(ctx, "rpm", &args, &[]).map(|o| o.stdout).unwrap_or_default()
            };
            Some(
                out.lines()
                    .filter(|l| l.contains("is not owned by any package"))
                    .filter_map(|l| l.strip_prefix("file ").and_then(|r| r.split(" is not owned").next()))
                    .map(str::to_string)
                    .collect(),
            )
        }
        OsFamily::Unknown => None,
    };
    match orphans {
        None => {
            em.na("FS-014", High, tr!("SUID/SGID not provided by packages")).with_detail(tr!("unrecognized distro"));
        }
        Some(o) if o.is_empty() => {
            em.pass("FS-014", High, &tr!("All SUID/SGID files belong to packages ({n} checked)", n = checked.len()));
        }
        Some(o) => {
            em.fail("FS-014", High, tr!("SUID/SGID files that belong to no package"))
                .with_detail(short(&o))
                .with_fix(tr!("Verify the origin; if not legitimate: chmod u-s,g-s and investigate"));
        }
    }

    // FS-015..018
    if wwsys.is_empty() {
        em.pass("FS-015", High, tr!("No world-writable files in system paths"));
    } else {
        em.fail("FS-015", High, &tr!("World-writable files in system paths ({n})", n = wwsys.len()))
            .with_detail(short(&wwsys))
            .with_fix(tr!("chmod o-w <file>"));
    }
    if wwoth.is_empty() {
        em.pass("FS-016", Medium, tr!("No world-writable files outside system paths"));
    } else {
        em.warn("FS-016", Medium, &tr!("World-writable files ({n})", n = wwoth.len())).with_detail(short(&wwoth)).with_fix(tr!("chmod o-w <file>"));
    }
    if wwdir.is_empty() {
        em.pass("FS-017", Medium, tr!("World-writable directories have the sticky bit"));
    } else {
        em.fail("FS-017", Medium, &tr!("World-writable directories without the sticky bit ({n})", n = wwdir.len()))
            .with_detail(short(&wwdir))
            .with_fix(tr!("chmod +t <dir>  (or remove o+w)"));
    }
    if orphan.is_empty() {
        em.pass("FS-018", Medium, tr!("No orphaned files (without owner/group)"));
    } else {
        em.warn("FS-018", Medium, &tr!("Files without an owner or group ({n})", n = orphan.len()))
            .with_detail(short(&group_orphans(&orphan)))
            .with_fix(tr!("Assign a valid owner or delete them"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::fixture::Fixture;
    use crate::model::Status;

    const MOUNTINFO: &str = "\
29 1 254:2 / / rw,relatime shared:1 - ext4 /dev/mapper/root rw,errors=remount-ro
31 26 0:26 / /dev/shm rw,nosuid,nodev shared:4 - tmpfs tmpfs rw,inode64
48 29 0:35 / /tmp rw,nosuid,nodev,noexec shared:88 - tmpfs tmpfs rw,nr_inodes=1048576,inode64
51 29 254:0 / /home/con\\040espacio rw,relatime shared:91 - ext4 /dev/mapper/home rw
";

    #[test]
    fn opciones_como_findmnt() {
        let m = parse_mountinfo(MOUNTINFO);
        assert_eq!(m[0].options, "rw,relatime,errors=remount-ro");
        assert_eq!(m[2].options, "rw,nosuid,nodev,noexec,nr_inodes=1048576,inode64");
        assert_eq!(m[3].target, "/home/con espacio");
        assert_eq!(mount_of(&m, "/var/tmp").unwrap().target, "/");
        assert_eq!(mount_of(&m, "/tmp").unwrap().target, "/tmp");
        assert_eq!(mount_of(&m, "/tmpx").unwrap().target, "/");
    }

    #[test]
    fn controles_de_montaje() {
        let f = Fixture::new();
        f.file("/proc/self/mountinfo", MOUNTINFO);
        let r = f.run(run);
        assert_eq!(r["FS-006"].status, Status::Pass);
        assert_eq!(r["FS-007"].detail, "/var/tmp no es un filesystem separado");
        assert_eq!(r["FS-008"].detail, "faltan: noexec (opciones actuales: rw,nosuid,nodev,inode64)");
    }

    #[test]
    fn barrido_completo() {
        let mut f = Fixture::new();
        f.fast = false;
        // los archivos del fixture son del usuario que corre los tests: que exista en passwd/group
        f.file("/marca", "");
        let m = std::fs::metadata(f.ctx().path("/marca")).unwrap();
        let (uid, gid) = (m.uid(), m.gid());
        f.file("/etc/passwd", &format!("root:x:0:0::/root:/bin/bash\nyo:x:{uid}:{gid}::/home/yo:/bin/bash\n"))
            .file("/etc/group", &format!("root:x:0:\nyo:x:{gid}:\n"))
            .file("/usr/bin/find", "")
            .mode("/usr/bin/find", 0o4755)
            .file("/usr/bin/legit", "")
            .mode("/usr/bin/legit", 0o4755)
            .file("/usr/local/bin/yt", "")
            .mode("/usr/local/bin/yt", 0o666)
            .file("/home/yo/foto.jpg", "")
            .mode("/home/yo/foto.jpg", 0o666)
            .file("/home/yo/.cache/x", "")
            .mode("/home/yo/.cache/x", 0o666)
            .dir("/srv/abierto")
            .mode("/srv/abierto", 0o777)
            .file("/var/lib/dpkg/info/legit.list", "/bin/legit\n");
        let r = f.run(run);
        assert_eq!(r["FS-013"].detail, "/usr/bin/find");
        // /usr/bin/legit está en dpkg como /bin/legit (usr unificado): no es huérfano
        assert_eq!(r["FS-014"].detail, "/usr/bin/find");
        assert_eq!(r["FS-015"].title, "Archivos world-writable en rutas del sistema (1)");
        assert_eq!(r["FS-016"].detail, "/home/yo/foto.jpg", ".cache no cuenta");
        assert_eq!(r["FS-017"].detail, "/srv/abierto");
    }

    #[test]
    fn directorio_huerfano_no_es_world_writable() {
        let mut f = Fixture::new();
        f.fast = false;
        // passwd/group sin el usuario que corre los tests: todo el fixture queda huérfano,
        // como el pg_data de un contenedor con uid 26 inexistente en el host
        f.file("/etc/passwd", "root:x:0:0::/root:/bin/bash\n")
            .file("/etc/group", "root:x:0:\n")
            .dir("/srv/pg_data")
            .mode("/srv/pg_data", 0o700)
            .dir("/srv/tmpcomun")
            .mode("/srv/tmpcomun", 0o1777);
        let r = f.run(run);
        assert_eq!(r["FS-017"].status, Status::Pass, "{}", r["FS-017"].detail);
        assert!(r["FS-018"].detail.contains("/srv("), "pg_data queda agrupado bajo /srv: {}", r["FS-018"].detail);
    }

    #[test]
    fn snapshots_fuera_del_barrido() {
        let mut f = Fixture::new();
        f.fast = false;
        f.file("/marca", "");
        let m = std::fs::metadata(f.ctx().path("/marca")).unwrap();
        let (uid, gid) = (m.uid(), m.gid());
        f.file("/etc/passwd", &format!("root:x:0:0::/root:/bin/bash\nyo:x:{uid}:{gid}::/home/yo:/bin/bash\n"))
            .file("/etc/group", &format!("root:x:0:\nyo:x:{gid}:\n"))
            .file("/var/lib/dpkg/info/login.list", "/usr/bin/chfn\n")
            .file("/usr/bin/chfn", "")
            .mode("/usr/bin/chfn", 0o4755)
            .file("/usr/local/bin/rogue", "")
            .mode("/usr/local/bin/rogue", 0o4755)
            .dir("/timeshift")
            .mode("/timeshift", 0o755);
        // más copias que el viejo tope de 150, todas ordenadas antes que /usr
        for i in 0..160 {
            let p = format!("/timeshift/snapshots/{i:03}/localhost/usr/bin/chfn");
            f.file(&p, "").mode(&p, 0o4755);
        }
        let r = f.run(run);
        assert_eq!(r["FS-014"].detail, "/usr/local/bin/rogue");
        assert_eq!(r["FS-019"].status, Status::Fail);
        assert_eq!(r["FS-019"].detail, "/timeshift(755)");

        f.mode("/timeshift", 0o700);
        assert_eq!(f.run(run)["FS-019"].status, Status::Pass);
    }

    #[test]
    fn huerfanos_agrupados_por_directorio() {
        let o = |p: &str| (p.to_string(), 26, 26);
        let mut v = vec![o("/h/pg_data"), o("/h/pg_data/base"), o("/h/pg_data/base/1"), o("/h/pg_data-old"), o("/srv/x")];
        v.sort();
        let g = group_orphans(&v);
        assert_eq!(g, ["/h/pg_data(26:26, 3 entradas)", "/h/pg_data-old(26:26)", "/srv/x(26:26)"]);
    }

    #[test]
    fn rapido_omite_el_barrido() {
        let f = Fixture::new();
        f.file("/proc/self/mountinfo", MOUNTINFO);
        let mut ctx = f.ctx();
        ctx.fast = true;
        let mut em = Emitter::new("filesystem");
        run(&ctx, &mut em);
        let r = em.into_results();
        assert!(r.iter().filter(|x| x.id.as_str() >= "FS-013").all(|x| x.status == Status::Na));
    }

    #[test]
    fn gtfobins() {
        assert!(gtfo("python3.12"));
        assert!(gtfo("bash"));
        assert!(!gtfo("passwd"));
        assert!(!gtfo("pythonx"));
    }
}
