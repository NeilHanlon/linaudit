//! category: network — port de checks.d/50-network.sh.
//! Firewall, puertos en escucha, parámetros de red del kernel, servicios heredados.

use super::Context;
use super::util::{active_services, check_sysctl, live_command, read, sysctl_get};
use crate::model::{Emitter, ResultExt, Severity::*};
use crate::tr;

/// Lo que se pudo averiguar de cada firewall. `None` = no instalado / no consultado.
#[derive(Debug, Default, Clone)]
pub struct FirewallProbe {
    /// firewalld activo, con su zona por defecto (si se pudo leer).
    pub firewalld_zone: Option<String>,
    pub ufw_status: Option<String>,
    pub iptables_input: Option<String>,
    pub nft_ruleset: Option<String>,
}

/// Devuelve (firewalls con reglas activas, hay política restrictiva).
pub fn firewall_state(p: &FirewallProbe) -> (Vec<&'static str>, bool) {
    let mut active = Vec::new();
    let mut deny = false;
    if let Some(zone) = &p.firewalld_zone {
        active.push("firewalld");
        if !zone.is_empty() && zone != "trusted" {
            deny = true;
        }
    }
    if let Some(s) = &p.ufw_status {
        let low = s.to_lowercase();
        if low.lines().any(|l| l.starts_with("status: active")) {
            active.push("ufw");
            if low.contains("default: deny (incoming)") || low.contains("default: reject (incoming)") {
                deny = true;
            }
        }
    }
    if let Some(r) = &p.iptables_input {
        let drops = r.lines().any(|l| {
            l.starts_with("-P INPUT DROP")
                || l.starts_with("-P INPUT REJECT")
                || l.contains("-j DROP")
                || l.contains("-j REJECT")
        });
        if drops {
            active.push("iptables");
            deny = true;
        }
    }
    if let Some(r) = &p.nft_ruleset {
        if input_hook_lines(r).iter().any(|l| nft_line_denies(l)) {
            active.push("nftables");
            deny = true;
        }
    }
    (active, deny)
}

/// Equivalente a `grep -A25 'hook input'`: cada línea con "hook input" y las 25 siguientes.
fn input_hook_lines(ruleset: &str) -> Vec<&str> {
    let lines: Vec<&str> = ruleset.lines().collect();
    let mut keep = vec![false; lines.len()];
    for (i, l) in lines.iter().enumerate() {
        if l.contains("hook input") {
            for k in keep.iter_mut().skip(i).take(26) {
                *k = true;
            }
        }
    }
    lines.into_iter().zip(keep).filter(|(_, k)| *k).map(|(l, _)| l).collect()
}

/// `policy drop` o la palabra `drop`/`reject` precedida por un espacio.
fn nft_line_denies(line: &str) -> bool {
    let l = line.to_lowercase();
    if l.contains("policy drop") {
        return true;
    }
    ["drop", "reject"].iter().any(|w| {
        l.match_indices(w).any(|(i, _)| {
            let before = l[..i].chars().next_back();
            let after = l[i + w.len()..].chars().next();
            before.is_some_and(char::is_whitespace) && after.is_none_or(char::is_whitespace)
        })
    })
}

fn probe_firewall(ctx: &Context) -> FirewallProbe {
    let mut p = FirewallProbe::default();
    if active_services(ctx, &["firewalld"]).contains("firewalld") {
        p.firewalld_zone =
            Some(live_command(ctx, "firewall-cmd", &["--get-default-zone"]).unwrap_or_default().trim().to_string());
    }
    // ufw, iptables y nft necesitan root para mostrar reglas: sin root ni se consultan
    if ctx.root {
        p.ufw_status = live_command(ctx, "ufw", &["status", "verbose"]);
        p.iptables_input = live_command(ctx, "iptables", &["-S", "INPUT"]);
        p.nft_ruleset = live_command(ctx, "nft", &["list", "ruleset"]);
    }
    p
}

/// Un socket en escucha, de la salida de `ss -tulnp`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listener {
    pub udp: bool,
    pub addr: String,
    pub port: String,
    pub process: String,
}

impl Listener {
    /// `22/tcp(sshd)`
    fn label(&self) -> String {
        let proto = if self.udp { "udp" } else { "tcp" };
        if self.process.is_empty() {
            format!("{}/{proto}", self.port)
        } else {
            format!("{}/{proto}({})", self.port, self.process)
        }
    }

    fn is_loopback(&self) -> bool {
        self.addr.starts_with("127.") || self.addr == "::1"
    }
}

pub fn parse_ss(out: &str) -> Vec<Listener> {
    out.lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            let local = *f.get(4)?;
            let (addr, port) = local.rsplit_once(':')?;
            let addr = addr.replace(['[', ']'], "");
            let addr = addr.split('%').next().unwrap_or("").to_string();
            let process = line
                .find("users:((\"")
                .and_then(|i| {
                    let rest = &line[i + 9..];
                    rest.find('"').map(|j| rest[..j].to_string())
                })
                .unwrap_or_default();
            Some(Listener { udp: f[0].contains("udp"), addr, port: port.to_string(), process })
        })
        .collect()
}

const INSECURE_TCP: &[&str] = &["21", "23", "79", "512", "513", "514", "5900", "6000"];
const DATASTORES: &[&str] = &[
    "6379", "11211", "27017", "9200", "9300", "2379", "5984", "9042", "3306", "5432", "1433", "61616", "9092", "2181",
    "5672", "8161", "5601",
];

/// NET-003..006 a partir de los sockets en escucha.
pub fn evaluate_listeners(em: &mut Emitter, listeners: &[Listener]) {
    let exposed: Vec<&Listener> = listeners.iter().filter(|l| !l.is_loopback()).collect();
    let on_ports = |ports: &[&str]| -> String {
        exposed.iter().filter(|l| ports.contains(&l.port.as_str())).map(|l| l.label()).collect::<Vec<_>>().join(" ")
    };

    let x: Vec<String> = exposed
        .iter()
        .filter(|l| (!l.udp && INSECURE_TCP.contains(&l.port.as_str())) || (l.udp && l.port == "69"))
        .map(|l| l.label())
        .collect();
    if x.is_empty() {
        em.pass("NET-003", High, tr!("No insecure cleartext services exposed (telnet/ftp/rsh/tftp/vnc)"));
    } else {
        em.fail("NET-003", High, tr!("Insecure services listening on the network"))
            .with_detail(x.join(" "))
            .with_fix(tr!("Disable the service or replace it (SSH/SFTP)"));
    }

    let x = on_ports(&["2375"]);
    if x.is_empty() {
        em.pass("NET-004", Critical, tr!("Docker API without TLS not exposed"));
    } else {
        em.fail("NET-004", Critical, tr!("Docker API (2375) exposed without TLS: equivalent to remote root"))
            .with_detail(x)
            .with_fix(tr!("Remove the tcp:// listener or use TLS with client certificates (2376)"));
    }

    let x = on_ports(DATASTORES);
    if x.is_empty() {
        em.pass("NET-005", Medium, tr!("Databases/queues only on loopback"));
    } else {
        em.warn("NET-005", Medium, tr!("Databases or queues listening on network interfaces"))
            .with_detail(x)
            .with_fix(tr!("Confirm authentication + firewall (or bind to 127.0.0.1); if intentional, add a waiver"));
    }

    let mut labels: Vec<String> = exposed.iter().map(|l| l.label()).collect();
    labels.sort();
    labels.dedup();
    em.pass(
        "NET-006",
        Info,
        &tr!("Network surface: {n} sockets listening outside loopback", n = exposed.len()),
    )
    .with_detail(labels.join(" "));
}

pub fn run(ctx: &Context, em: &mut Emitter) {
    // NET-001 / NET-002: firewall
    let (fw, deny) = firewall_state(&probe_firewall(ctx));
    if !fw.is_empty() {
        em.pass("NET-001", High, tr!("Local firewall active")).with_detail(fw.join(" "));
    } else if !ctx.root {
        em.error("NET-001", High, tr!("Local firewall active")).with_detail(tr!("root is required to inspect iptables/nft"));
    } else {
        em.fail("NET-001", High, tr!("No active local firewall detected"))
            .with_detail(tr!("no DROP/REJECT rules in iptables/nft/ufw/firewalld"))
            .with_fix(tr!("Enable firewalld/ufw/nftables with a restrictive default policy (or a waiver if there is a dedicated perimeter firewall)"));
    }
    if fw.is_empty() {
        em.na("NET-002", Medium, tr!("Restrictive default policy")).with_detail(tr!("no firewall detected"));
    } else if deny {
        em.pass("NET-002", Medium, tr!("Firewall with a restrictive default policy"));
    } else {
        em.warn("NET-002", Medium, tr!("Firewall without a restrictive default policy"))
            .with_detail(fw.join(" "))
            .with_fix(tr!("INPUT DROP/deny policy, allowing only what is needed"));
    }

    // NET-003..006: puertos en escucha
    match live_command(ctx, "ss", &["-tulnp"]) {
        Some(out) => evaluate_listeners(em, &parse_ss(&out)),
        None => {
            for (id, sev) in [("NET-003", High), ("NET-004", Critical), ("NET-005", Medium)] {
                em.na(id, sev, tr!("Listening ports")).with_detail(tr!("ss unavailable"));
            }
        }
    }

    // NET-007: reenvío IP (normal con contenedores o virtualización)
    if sysctl_get(ctx, "net.ipv4.ip_forward").as_deref() == Some("1") {
        let runtimes = active_services(ctx, &["docker", "containerd", "kubelet", "libvirtd", "crio"]);
        if runtimes.is_empty() {
            em.fail("NET-007", Medium, tr!("IP forwarding enabled on a host that is not a router"))
                .with_detail("net.ipv4.ip_forward = 1")
                .with_fix("sysctl -w net.ipv4.ip_forward=0");
        } else {
            em.na("NET-007", Medium, tr!("ip_forward disabled"))
                .with_detail(tr!("enabled, but a container/virtualization runtime is active"));
        }
    } else {
        em.pass("NET-007", Medium, tr!("ip_forward disabled"));
    }

    check_sysctl(em, ctx, "NET-008", Medium, tr!("Rejects ICMP redirects"), "net.ipv4.conf.all.accept_redirects", &["0"]);
    check_sysctl(em, ctx, "NET-009", Low, tr!("Does not send ICMP redirects"), "net.ipv4.conf.all.send_redirects", &["0"]);
    check_sysctl(em, ctx, "NET-010", Medium, tr!("Rejects source routing"), "net.ipv4.conf.all.accept_source_route", &["0"]);
    check_sysctl(em, ctx, "NET-011", Medium, tr!("Reverse path filtering enabled"), "net.ipv4.conf.all.rp_filter", &["1", "2"]);
    check_sysctl(em, ctx, "NET-012", Medium, tr!("SYN cookies enabled"), "net.ipv4.tcp_syncookies", &["1"]);
    check_sysctl(em, ctx, "NET-013", Low, tr!("Ignores broadcast ICMP echo"), "net.ipv4.icmp_echo_ignore_broadcasts", &["1"]);
    check_sysctl(em, ctx, "NET-014", Low, tr!("Logs martian packets"), "net.ipv4.conf.all.log_martians", &["1"]);

    // NET-015: exports NFS
    match read(ctx, "/etc/exports") {
        Some(t) => {
            let x = risky_exports(&t);
            if x.is_empty() {
                em.pass("NET-015", High, tr!("NFS exports without no_root_squash or wildcards"));
            } else {
                em.fail("NET-015", High, tr!("Risky NFS exports (no_root_squash or open to *)"))
                    .with_detail(x.join(" "))
                    .with_fix(tr!("Restrict clients and use root_squash"));
            }
        }
        None => {
            em.na("NET-015", High, tr!("NFS exports")).with_detail(tr!("no /etc/exports"));
        }
    }

    // NET-016: SNMP con communities por defecto
    match read(ctx, "/etc/snmp/snmpd.conf") {
        Some(t) if t.lines().any(snmp_default_community) => {
            em.fail("NET-016", High, tr!("SNMP with a default community (public/private)"))
                .with_detail("/etc/snmp/snmpd.conf")
                .with_fix(tr!("Use SNMPv3 or a non-trivial community with a source ACL"));
        }
        Some(_) => {
            em.pass("NET-016", High, tr!("SNMP without default communities"));
        }
        None => {
            em.na("NET-016", High, "SNMP").with_detail(tr!("snmpd not configured"));
        }
    }

    // NET-017: confianza r-commands
    let mut x: Vec<String> = ["/etc/hosts.equiv", "/root/.rhosts"]
        .iter()
        .map(|s| s.to_string())
        .chain(
            std::fs::read_dir(ctx.path("/home"))
                .map(|d| d.flatten().map(|e| format!("/home/{}/.rhosts", e.file_name().to_string_lossy())).collect())
                .unwrap_or_else(|_| Vec::new()),
        )
        .filter(|p| ctx.path(p).exists())
        .collect();
    x.sort();
    if x.is_empty() {
        em.pass("NET-017", High, tr!("No r-commands trust (hosts.equiv / .rhosts)"));
    } else {
        em.fail("NET-017", High, tr!("r-commands trust files present")).with_detail(x.join(" ")).with_fix("Eliminarlos");
    }
}

/// Rutas exportadas con `no_root_squash` o abiertas a `*`.
pub fn risky_exports(text: &str) -> Vec<String> {
    let mut v: Vec<String> = text
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split('#').next().unwrap_or("").split_whitespace().collect();
            (f.len() >= 2 && f[1..].iter().any(|c| c.starts_with('*') || c.contains("no_root_squash")))
                .then(|| f[0].to_string())
        })
        .collect();
    v.sort();
    v.dedup();
    v
}

/// `rocommunity|rwcommunity|com2sec ... public|private` (sin distinguir mayúsculas).
pub fn snmp_default_community(line: &str) -> bool {
    let l = line.split('#').next().unwrap_or("").to_lowercase();
    ["rocommunity", "rwcommunity", "com2sec"].iter().any(|k| {
        l.match_indices(k).any(|(i, _)| {
            let rest = &l[i + k.len()..];
            rest.char_indices().any(|(j, c)| {
                c.is_whitespace()
                    && ["public", "private"].iter().any(|w| {
                        rest[j + c.len_utf8()..].strip_prefix(w).is_some_and(|a| a.is_empty() || a.starts_with(char::is_whitespace))
                    })
            })
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::fixture::Fixture;
    use crate::model::Status;
    use std::collections::HashMap;

    const SS: &str = "\
Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
udp   UNCONN 0      0            0.0.0.0:5353       0.0.0.0:*     users:((\"avahi-daemon\",pid=600,fd=12))
udp   UNCONN 0      0      127.0.0.53%lo:53         0.0.0.0:*
tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*     users:((\"sshd\",pid=800,fd=3))
tcp   LISTEN 0      511        127.0.0.1:6379       0.0.0.0:*
tcp   LISTEN 0      128             [::]:23            [::]:*     users:((\"inetd\",pid=900,fd=5))
tcp   LISTEN 0      128                *:5432             *:*
tcp   LISTEN 0      128            [::1]:631           [::]:*
";

    fn listeners() -> HashMap<String, crate::model::CheckResult> {
        let mut em = Emitter::new("network");
        evaluate_listeners(&mut em, &parse_ss(SS));
        em.into_results().into_iter().map(|r| (r.id.clone(), r)).collect()
    }

    #[test]
    fn parsea_ss() {
        let l = parse_ss(SS);
        assert_eq!(l.len(), 7);
        assert_eq!(l[0], Listener { udp: true, addr: "0.0.0.0".into(), port: "5353".into(), process: "avahi-daemon".into() });
        assert_eq!(l[1].addr, "127.0.0.53");
        assert_eq!(l[4].addr, "::");
        assert_eq!(l[6].addr, "::1");
    }

    #[test]
    fn evalua_puertos_expuestos() {
        let r = listeners();
        assert_eq!(r["NET-003"].detail, "23/tcp(inetd)");
        assert_eq!(r["NET-004"].status, Status::Pass);
        // 6379 está en loopback: no cuenta; 5432 en * sí
        assert_eq!(r["NET-005"].detail, "5432/tcp");
        assert_eq!(r["NET-006"].title, "Superficie de red: 4 sockets en escucha fuera de loopback");
        assert_eq!(r["NET-006"].detail, "22/tcp(sshd) 23/tcp(inetd) 5353/udp(avahi-daemon) 5432/tcp");
    }

    #[test]
    fn detecta_firewalls() {
        let p = FirewallProbe {
            ufw_status: Some("Status: active\nDefault: deny (incoming), allow (outgoing)\n".into()),
            ..Default::default()
        };
        assert_eq!(firewall_state(&p), (vec!["ufw"], true));

        let p = FirewallProbe { firewalld_zone: Some("trusted".into()), ..Default::default() };
        assert_eq!(firewall_state(&p), (vec!["firewalld"], false));

        let p = FirewallProbe { iptables_input: Some("-P INPUT ACCEPT\n".into()), ..Default::default() };
        assert_eq!(firewall_state(&p), (vec![], false));

        let nft = "table inet filter {\n  chain input {\n    type filter hook input priority filter; policy drop;\n  }\n}\n";
        let p = FirewallProbe { nft_ruleset: Some(nft.into()), ..Default::default() };
        assert_eq!(firewall_state(&p), (vec!["nftables"], true));

        // un "drop" en otra cadena, lejos del hook input, no cuenta
        let nft = format!("chain input {{\n type filter hook input priority 0; policy accept;\n}}\n{}chain fwd {{ ct state invalid drop\n}}\n", "\n".repeat(30));
        let p = FirewallProbe { nft_ruleset: Some(nft), ..Default::default() };
        assert_eq!(firewall_state(&p), (vec![], false));
    }

    #[test]
    fn sin_root_y_sin_firewalld_no_se_evalua() {
        let mut f = Fixture::new();
        f.is_root = false;
        let r = f.run(run);
        assert_eq!(r["NET-001"].status, Status::Error);
        assert_eq!(r["NET-002"].status, Status::Na);
        // en fixtures no se ejecuta ss
        assert_eq!(r["NET-003"].status, Status::Na);
    }

    #[test]
    fn ip_forward_con_y_sin_contenedores() {
        let f = Fixture::new();
        f.file("/proc/sys/net/ipv4/ip_forward", "1\n");
        assert_eq!(f.run(run)["NET-007"].status, Status::Fail);
        let mut f2 = Fixture::new();
        f2.service("docker");
        f2.file("/proc/sys/net/ipv4/ip_forward", "1\n");
        assert_eq!(f2.run(run)["NET-007"].status, Status::Na);
    }

    #[test]
    fn exports_snmp_y_rhosts() {
        assert_eq!(
            risky_exports("/srv/a 10.0.0.0/8(rw)\n/srv/b *(ro)\n/srv/c host(rw,no_root_squash)\n# /srv/d *(rw)\n/srv/b *.lan(ro)\n"),
            ["/srv/b", "/srv/c"]
        );
        assert!(snmp_default_community("rocommunity public default"));
        assert!(snmp_default_community("com2sec notConfigUser  default       PUBLIC"));
        assert!(!snmp_default_community("rocommunity s3cr3t-public 10.0.0.0/8"));
        assert!(!snmp_default_community("# rocommunity public"));

        let f = Fixture::new();
        f.file("/home/ana/.rhosts", "+ +\n").file("/etc/hosts.equiv", "+\n").dir("/home/beto");
        assert_eq!(f.run(run)["NET-017"].detail, "/etc/hosts.equiv /home/ana/.rhosts");
    }
}
