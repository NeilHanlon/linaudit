//! category: ssh — port de checks.d/20-ssh.sh.
//! Configuración efectiva de OpenSSH (`sshd -T`). Si `sshd -T` no funciona (típicamente sin root),
//! cae a un parseo estático de los archivos, sin defaults y sin bloques Match.

use std::collections::HashMap;

use super::Context;
use super::util::{check_file_perm, command_output, file_mode, find_command, glob, mode_within};
use crate::model::{Emitter, ResultExt, Severity::*};
use crate::tr;

/// Configuración de sshd: clave en minúsculas -> valor.
#[derive(Debug, Default, Clone)]
pub struct SshdConfig {
    values: HashMap<String, String>,
    /// true si salió del parseo estático (sin defaults de sshd ni Match).
    pub is_static: bool,
}

impl SshdConfig {
    /// Salida de `sshd -T`: una línea `clave valor` por opción, claves ya en minúsculas.
    pub fn from_sshd_t(out: &str) -> Self {
        let mut values = HashMap::new();
        for line in out.lines() {
            let mut it = line.splitn(2, ' ');
            if let (Some(k), Some(v)) = (it.next(), it.next()) {
                values.entry(k.to_ascii_lowercase()).or_insert_with(|| v.trim().to_string());
            }
        }
        SshdConfig { values, is_static: false }
    }

    /// Parseo estático: los archivos en el orden en que sshd los lee; gana la primera aparición
    /// de cada clave (como sshd) y se corta en el primer `Match`.
    pub fn from_files(texts: &[String]) -> Self {
        let mut values = HashMap::new();
        'outer: for text in texts {
            for line in text.lines() {
                let mut words = line.split_whitespace();
                let Some(k) = words.next() else { continue };
                if k.starts_with('#') {
                    continue;
                }
                let k = k.to_ascii_lowercase();
                if k == "match" {
                    break 'outer;
                }
                values.entry(k).or_insert_with(|| words.collect::<Vec<_>>().join(" "));
            }
        }
        SshdConfig { values, is_static: true }
    }

    pub fn get<'a>(&'a self, key: &str, default: &'a str) -> &'a str {
        self.values.get(key).map(String::as_str).filter(|v| !v.is_empty()).unwrap_or(default)
    }

    fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

/// Archivos de configuración en el orden de lectura de sshd (los drop-in primero, por el Include de Debian).
fn config_files(ctx: &Context) -> Vec<String> {
    let mut paths = glob(&ctx.path("/etc/ssh/sshd_config.d"), "", ".conf");
    paths.push(ctx.path("/etc/ssh/sshd_config"));
    paths.iter().filter_map(|p| std::fs::read_to_string(p).ok()).collect()
}

pub fn run(ctx: &Context, em: &mut Emitter) {
    let sshd = if ctx.is_live() {
        find_command("sshd")
    } else {
        Some(ctx.path("/usr/sbin/sshd")).filter(|p| p.exists())
    };
    let Some(sshd) = sshd else {
        em.na("SSH-000", Info, tr!("OpenSSH server")).with_detail(tr!("sshd is not installed"));
        return;
    };

    let from_t = if ctx.is_live() { command_output(&sshd, &["-T"]).map(|o| SshdConfig::from_sshd_t(&o)) } else { None };
    let cfg = match from_t {
        Some(c) if !c.is_empty() => c,
        _ => {
            let c = SshdConfig::from_files(&config_files(ctx));
            if c.is_empty() {
                em.error("SSH-000", High, tr!("sshd configuration"))
                    .with_detail(tr!("could not read or evaluate the configuration (not root?)"));
                return;
            }
            c
        }
    };

    evaluate_config(em, &cfg);
    check_match_blocks(ctx, em);
    check_files(ctx, em);
}

/// SSH-001..009, 011..013: opciones de la configuración efectiva.
pub fn evaluate_config(em: &mut Emitter, cfg: &SshdConfig) {
    let note = if cfg.is_static { tr!(" (static config, no defaults: sshd -T unavailable)") } else { "" };

    let v = cfg.get("permitrootlogin", "prohibit-password");
    match v {
        "no" => {
            em.pass("SSH-001", High, tr!("Direct root login disabled"));
        }
        "prohibit-password" | "without-password" | "forced-commands-only" => {
            em.warn("SSH-001", High, tr!("Root can log in over SSH with a key only"))
                .with_detail(format!("PermitRootLogin {v}{note}"))
                .with_fix(tr!("PermitRootLogin no and use sudo"));
        }
        _ => {
            em.fail("SSH-001", High, tr!("Root can log in over SSH with a password"))
                .with_detail(format!("PermitRootLogin {v}{note}"))
                .with_fix("PermitRootLogin no");
        }
    }

    let v = cfg.get("passwordauthentication", "yes");
    if v == "no" {
        em.pass("SSH-002", Medium, tr!("Password authentication disabled"));
    } else {
        em.fail("SSH-002", Medium, tr!("SSH accepts password authentication"))
            .with_detail(format!("PasswordAuthentication {v}{note}"))
            .with_fix(tr!("Use keys (or a waiver if there is SSO/IPA)"));
    }

    let v = cfg.get("permitemptypasswords", "no");
    if v == "no" {
        em.pass("SSH-003", Critical, tr!("PermitEmptyPasswords disabled"));
    } else {
        em.fail("SSH-003", Critical, tr!("SSH allows empty passwords"))
            .with_detail(format!("PermitEmptyPasswords {v}"))
            .with_fix("PermitEmptyPasswords no");
    }

    let v = cfg.get("maxauthtries", "6");
    if v.parse::<i64>().is_ok_and(|n| n <= 6) {
        em.pass("SSH-004", Low, tr!("MaxAuthTries is reasonable")).with_detail(format!("MaxAuthTries {v}"));
    } else {
        em.warn("SSH-004", Low, tr!("MaxAuthTries is high")).with_detail(format!("MaxAuthTries {v}")).with_fix("MaxAuthTries 4");
    }

    let v = cfg.get("x11forwarding", "no");
    if v == "no" {
        em.pass("SSH-005", Low, tr!("X11Forwarding disabled"));
    } else {
        em.warn("SSH-005", Low, tr!("X11Forwarding enabled"))
            .with_detail(format!("X11Forwarding {v}{note}"))
            .with_fix("X11Forwarding no");
    }

    if cfg.is_static {
        em.na("SSH-006", Medium, tr!("Weak cryptographic algorithms")).with_detail(tr!("requires sshd -T"));
    } else {
        let weak = |key: &str, is_weak: fn(&str) -> bool| {
            cfg.get(key, "").split(',').filter(|a| is_weak(a)).collect::<Vec<_>>().join(",")
        };
        let c = weak("ciphers", |a| {
            ["3des", "arcfour", "blowfish", "cast128"].iter().any(|w| a.contains(w)) || a.ends_with("-cbc")
        });
        let m = weak("macs", |a| a.starts_with("hmac-md5") || a.starts_with("umac-64") || a.contains("hmac-sha1-96"));
        let k = weak("kexalgorithms", |a| {
            ["group1-sha1", "group14-sha1", "group-exchange-sha1"].iter().any(|w| a.contains(w))
        });
        if c.is_empty() && m.is_empty() && k.is_empty() {
            em.pass("SSH-006", Medium, tr!("No weak cryptographic algorithms"));
        } else {
            let mut d = Vec::new();
            if !c.is_empty() {
                d.push(format!("ciphers: {c}"));
            }
            if !m.is_empty() {
                d.push(format!("macs: {m}"));
            }
            if !k.is_empty() {
                d.push(format!("kex: {k}"));
            }
            em.fail("SSH-006", Medium, tr!("Weak SSH algorithms enabled"))
                .with_detail(d.join(" "))
                .with_fix(tr!("Set explicit Ciphers/MACs/KexAlgorithms (e.g. crypto-policies on RHEL)"));
        }
    }

    let v = cfg.get("logingracetime", "120");
    let v = v.strip_suffix('s').unwrap_or(v);
    if v.parse::<i64>().is_ok_and(|n| n <= 60) {
        em.pass("SSH-007", Low, "LoginGraceTime <= 60s").with_detail(format!("{v} s"));
    } else {
        em.warn("SSH-007", Low, tr!("LoginGraceTime is high")).with_detail(format!("{v}s")).with_fix("LoginGraceTime 30");
    }

    let v = cfg.get("clientaliveinterval", "0");
    if v.parse::<i64>().is_ok_and(|n| n > 0) {
        em.pass("SSH-008", Low, tr!("Idle session timeout")).with_detail(format!("ClientAliveInterval {v}"));
    } else {
        em.warn("SSH-008", Low, tr!("No timeout for idle SSH sessions"))
            .with_detail(format!("ClientAliveInterval {v}"))
            .with_fix(tr!("ClientAliveInterval 300 / ClientAliveCountMax 0 (or TMOUT)"));
    }

    let v = cfg.get("gatewayports", "no");
    if v == "no" {
        em.pass("SSH-009", Medium, tr!("GatewayPorts disabled"));
    } else {
        em.warn("SSH-009", Medium, tr!("GatewayPorts enabled")).with_detail(format!("GatewayPorts {v}")).with_fix("GatewayPorts no");
    }

    let v = cfg.get("banner", "none");
    if v != "none" {
        em.pass("SSH-011", Low, tr!("Legal banner configured")).with_detail(v);
    } else {
        em.warn("SSH-011", Low, tr!("No legal banner on SSH"))
            .with_detail("Banner none")
            .with_fix(tr!("Set Banner /etc/issue.net"));
    }

    let v = cfg.get("hostbasedauthentication", "no");
    if v == "no" {
        em.pass("SSH-012", High, tr!("HostbasedAuthentication disabled"));
    } else {
        em.fail("SSH-012", High, tr!("HostbasedAuthentication enabled")).with_detail(v).with_fix("HostbasedAuthentication no");
    }

    let v = cfg.get("permituserenvironment", "no");
    if v == "no" {
        em.pass("SSH-013", Medium, tr!("PermitUserEnvironment disabled"));
    } else {
        em.fail("SSH-013", Medium, tr!("PermitUserEnvironment enabled")).with_detail(v).with_fix("PermitUserEnvironment no");
    }
}

/// Líneas dentro de bloques Match que reabren root o passwords vacíos.
pub fn weakening_match_lines(file: &str, text: &str) -> Vec<String> {
    let mut in_match = false;
    let mut out = Vec::new();
    for line in text.lines() {
        let mut w = line.split_whitespace();
        let Some(k) = w.next().map(str::to_ascii_lowercase) else { continue };
        if k == "match" {
            in_match = true;
            continue;
        }
        let v = w.next().unwrap_or("").to_ascii_lowercase();
        if in_match && (k == "permitrootlogin" || k == "permitemptypasswords") && v == "yes" {
            out.push(format!("{file}: {line}"));
        }
    }
    out
}

/// SSH-010
fn check_match_blocks(ctx: &Context, em: &mut Emitter) {
    let mut files = vec!["/etc/ssh/sshd_config".to_string()];
    files.extend(
        glob(&ctx.path("/etc/ssh/sshd_config.d"), "", ".conf")
            .iter()
            .filter_map(|p| p.file_name().map(|n| format!("/etc/ssh/sshd_config.d/{}", n.to_string_lossy()))),
    );
    let found: Vec<String> = files
        .iter()
        .filter_map(|f| std::fs::read_to_string(ctx.path(f)).ok().map(|t| weakening_match_lines(f, &t)))
        .flatten()
        .collect();
    if found.is_empty() {
        em.pass("SSH-010", Medium, tr!("No Match block re-enables root/empty passwords"));
    } else {
        em.fail("SSH-010", Medium, tr!("Match block weakens security"))
            .with_detail(found.join(" "))
            .with_fix(tr!("Review the Match blocks"));
    }
}

/// SSH-014..016: permisos y claves de host.
fn check_files(ctx: &Context, em: &mut Emitter) {
    check_file_perm(em, ctx, "SSH-014", Medium, tr!("sshd_config permissions"), "/etc/ssh/sshd_config", 0o644, Some(0));

    let bad: Vec<String> = glob(&ctx.path("/etc/ssh"), "ssh_host_", "_key")
        .iter()
        .filter_map(|p| {
            let m = file_mode(p)?;
            (!mode_within(m, 0o640)).then(|| {
                let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                format!("/etc/ssh/{name}({m:o})")
            })
        })
        .collect();
    if bad.is_empty() {
        em.pass("SSH-015", High, tr!("Host private keys have correct permissions"));
    } else {
        em.fail("SSH-015", High, tr!("Host private keys readable by others"))
            .with_detail(bad.join(" "))
            .with_fix("chmod 600 /etc/ssh/ssh_host_*_key");
    }

    if ctx.path("/etc/ssh/ssh_host_dsa_key").exists() {
        em.warn("SSH-016", Medium, tr!("DSA host key present (obsolete)"))
            .with_detail("/etc/ssh/ssh_host_dsa_key")
            .with_fix(tr!("Remove it and drop the DSA HostKey"));
    } else {
        em.pass("SSH-016", Medium, tr!("No DSA host key"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CheckResult, Status};

    fn eval(cfg: &SshdConfig) -> HashMap<String, CheckResult> {
        let mut em = Emitter::new("ssh");
        evaluate_config(&mut em, cfg);
        em.into_results().into_iter().map(|r| (r.id.clone(), r)).collect()
    }

    #[test]
    fn defaults_de_sshd_t_endurecido() {
        let out = "permitrootlogin no\npasswordauthentication no\npermitemptypasswords no\nmaxauthtries 3\n\
                   x11forwarding no\nciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com\n\
                   macs hmac-sha2-256-etm@openssh.com\nkexalgorithms curve25519-sha256\nlogingracetime 30\n\
                   clientaliveinterval 300\ngatewayports no\nbanner /etc/issue.net\nhostbasedauthentication no\n\
                   permituserenvironment no\n";
        let r = eval(&SshdConfig::from_sshd_t(out));
        for (id, res) in &r {
            assert_eq!(res.status, Status::Pass, "{id}: {res:?}");
        }
        assert_eq!(r.len(), 12); // 001..009 y 011..013 (010 y 014..016 leen archivos)
    }

    #[test]
    fn detecta_algoritmos_debiles_y_root_con_password() {
        let out = "permitrootlogin yes\nciphers aes128-ctr,aes256-cbc,3des-cbc\nmacs hmac-md5,hmac-sha2-256\n\
                   kexalgorithms diffie-hellman-group14-sha1\n";
        let r = eval(&SshdConfig::from_sshd_t(out));
        assert_eq!(r["SSH-001"].status, Status::Fail);
        assert_eq!(r["SSH-006"].status, Status::Fail);
        assert_eq!(r["SSH-006"].detail, "ciphers: aes256-cbc,3des-cbc macs: hmac-md5 kex: diffie-hellman-group14-sha1");
    }

    #[test]
    fn parseo_estatico_respeta_primera_aparicion_y_corta_en_match() {
        let dropin = "PasswordAuthentication no\n".to_string();
        let main = "# comentario\nPasswordAuthentication yes\nPermitRootLogin no\nMatch User x\nPermitRootLogin yes\n"
            .to_string();
        let cfg = SshdConfig::from_files(&[dropin, main]);
        assert!(cfg.is_static);
        assert_eq!(cfg.get("passwordauthentication", "?"), "no");
        assert_eq!(cfg.get("permitrootlogin", "?"), "no");
        let r = eval(&cfg);
        assert_eq!(r["SSH-006"].status, Status::Na);
        // sin defaults: X11Forwarding usa el default asumido y no lleva nota
        assert_eq!(r["SSH-005"].status, Status::Pass);
    }

    #[test]
    fn match_que_reabre_root() {
        let t = "PermitRootLogin no\nMatch Address 10.0.0.0/8\n  PermitRootLogin yes\n";
        assert_eq!(weakening_match_lines("/etc/ssh/sshd_config", t), vec![
            "/etc/ssh/sshd_config:   PermitRootLogin yes".to_string()
        ]);
        assert!(weakening_match_lines("f", "PermitRootLogin yes\n").is_empty());
    }

    #[test]
    fn logingracetime_con_sufijo() {
        let r = eval(&SshdConfig::from_sshd_t("logingracetime 30s\n"));
        assert_eq!(r["SSH-007"].status, Status::Pass);
        let r = eval(&SshdConfig::from_sshd_t("logingracetime 2m\n"));
        assert_eq!(r["SSH-007"].status, Status::Warn);
    }
}
