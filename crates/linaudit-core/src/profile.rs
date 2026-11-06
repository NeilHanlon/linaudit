//! Perfiles de sistema (servidor, escritorio, contenedor) y su autodetección.
//!
//! Un perfil nunca esconde controles: o les cambia la severidad o los marca N/A,
//! y en ambos casos lo deja escrito en el detalle. Así el puntaje se puede explicar.

use std::path::Path;

use serde::Serialize;

use crate::model::{CheckResult, Severity, Status};
use crate::{N_, tr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    Server,
    Desktop,
    Container,
}

impl Profile {
    pub const ALL: [Profile; 3] = [Profile::Server, Profile::Desktop, Profile::Container];

    /// Nombre estable (CLI, JSON, config).
    pub fn id(self) -> &'static str {
        match self {
            Profile::Server => "server",
            Profile::Desktop => "desktop",
            Profile::Container => "container",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Profile::Server => tr!("Server"),
            Profile::Desktop => tr!("Desktop / laptop"),
            Profile::Container => tr!("Container / ephemeral VM"),
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Profile::Server => tr!("Full criteria: every check with its original severity."),
            Profile::Desktop => tr!(
                "Personal machine: relaxes checks meant for corporate servers (legal banner, \
                 password expiry, log forwarding, fail2ban, services such as cups or avahi) and lowers \
                 the firewall from HIGH to MEDIUM."
            ),
            Profile::Container => tr!(
                "What the host or the runtime manages (clock, AppArmor, auditd, firewall, logs, \
                 kernel parameters) is N/A."
            ),
        }
    }

    /// Descripción corta, para tarjetas.
    pub fn summary(self) -> &'static str {
        match self {
            Profile::Server => tr!("Full criteria, no concessions. For servers, VPSs and exposed machines."),
            Profile::Desktop => tr!("Relaxes what only matters on corporate servers: banner, password expiry, SIEM, cups/avahi."),
            Profile::Container => tr!("What the host or the runtime manages (kernel, clock, firewall, logs) is not evaluated."),
        }
    }

    /// IDs de los controles que este perfil ajusta (severidad o N/A).
    pub fn adjusted_ids(self) -> Vec<&'static str> {
        ADJUSTMENTS.iter().filter(|(p, _, _)| *p == self).map(|(_, id, _)| *id).collect()
    }

    pub fn from_id(s: &str) -> Option<Profile> {
        Profile::ALL.into_iter().find(|p| p.id() == s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Adjust {
    /// Cambia la severidad del control.
    Severity(Severity),
    /// El control no aplica con este perfil.
    NotApplicable(&'static str),
}

/// Ajustes por perfil. Los IDs son los de docs/CHECKS.md; un test verifica que existan.
/// Mientras una categoría no esté portada a Rust, su ajuste simplemente no encuentra resultados.
const ADJUSTMENTS: &[(Profile, &str, Adjust)] = &[
    // Escritorio: equipo personal, no un servidor corporativo
    (Profile::Desktop, "NET-001", Adjust::Severity(Severity::Medium)),
    (Profile::Desktop, "SSH-011", Adjust::NotApplicable(N_!("a legal banner is a requirement for corporate servers"))),
    (Profile::Desktop, "ACC-009", Adjust::NotApplicable(N_!("periodic password expiry does not apply to personal machines"))),
    (Profile::Desktop, "HRD-006", Adjust::NotApplicable(N_!("a personal machine does not usually forward logs to a SIEM"))),
    (Profile::Desktop, "HRD-014", Adjust::NotApplicable(N_!("cups, avahi, bluetooth and ModemManager are normal on a desktop"))),
    (Profile::Desktop, "HRD-015", Adjust::NotApplicable(N_!("fail2ban protects exposed services; it does not apply to a desktop"))),
    // Contenedor: lo gestiona el host o el runtime
    (Profile::Container, "NET-001", Adjust::NotApplicable(N_!("the firewall is enforced by the host or the orchestrator"))),
    (Profile::Container, "NET-002", Adjust::NotApplicable(N_!("the firewall is enforced by the host or the orchestrator"))),
    (Profile::Container, "HRD-001", Adjust::NotApplicable(N_!("AppArmor/SELinux is enforced by the host"))),
    (Profile::Container, "HRD-002", Adjust::NotApplicable(N_!("auditd runs on the host"))),
    (Profile::Container, "HRD-003", Adjust::NotApplicable(N_!("auditd runs on the host"))),
    (Profile::Container, "HRD-004", Adjust::NotApplicable(N_!("the clock is synchronized by the host"))),
    (Profile::Container, "HRD-005", Adjust::NotApplicable(N_!("logs are collected by the container runtime"))),
    (Profile::Container, "HRD-006", Adjust::NotApplicable(N_!("logs are collected by the container runtime"))),
    (Profile::Container, "PAT-004", Adjust::NotApplicable(N_!("a container is not rebooted: the image is rebuilt"))),
    (Profile::Container, "HRD-007", Adjust::NotApplicable(N_!("host kernel parameter"))),
    (Profile::Container, "HRD-008", Adjust::NotApplicable(N_!("host kernel parameter"))),
    (Profile::Container, "HRD-009", Adjust::NotApplicable(N_!("host kernel parameter"))),
    (Profile::Container, "HRD-010", Adjust::NotApplicable(N_!("host kernel parameter"))),
    (Profile::Container, "HRD-011", Adjust::NotApplicable(N_!("host kernel parameter"))),
    (Profile::Container, "HRD-012", Adjust::NotApplicable(N_!("host kernel parameter"))),
    (Profile::Container, "HRD-013", Adjust::NotApplicable(N_!("host kernel parameter"))),
];

/// Aplica los ajustes del perfil. Va antes de las excepciones (waivers).
pub fn apply(profile: Profile, results: &mut [CheckResult]) {
    for r in results.iter_mut() {
        let Some(&(_, _, adj)) = ADJUSTMENTS.iter().find(|(p, id, _)| *p == profile && *id == r.id) else {
            continue;
        };
        match adj {
            Adjust::NotApplicable(why) => {
                if r.status != Status::Na {
                    r.status = Status::Na;
                    let d = tr!("profile {profile}: {why}", profile = profile.id(), why = crate::i18n::tr(why));
                    r.set_detail(&d);
                }
            }
            Adjust::Severity(sev) if sev != r.severity => {
                let note = tr!(
                    "profile {profile}: severity {from} → {to}",
                    profile = profile.id(),
                    from = r.severity.label(),
                    to = sev.label()
                );
                let d = if r.detail.is_empty() { note } else { format!("{} ({note})", r.detail) };
                r.set_detail(&d);
                r.severity = sev;
            }
            Adjust::Severity(_) => {}
        }
    }
}

/// Resultado de la autodetección, con las señales que la justifican (se muestran en el menú).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    pub profile: Profile,
    pub reasons: Vec<String>,
}

/// Señales del sistema. Separadas de la lectura del disco para poder testear la decisión.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Signals {
    pub container: Option<String>,
    pub graphical: Option<String>,
    pub battery: bool,
    pub sshd_running: bool,
}

impl Signals {
    pub fn probe() -> Self {
        Signals {
            container: probe_container(),
            graphical: probe_graphical(),
            battery: dir_has_prefix("/sys/class/power_supply", "BAT"),
            sshd_running: Path::new("/run/sshd.pid").exists() || process_running("sshd"),
        }
    }

    pub fn decide(&self) -> Detection {
        let mut reasons = Vec::new();
        if let Some(c) = &self.container {
            reasons.push(tr!("container detected ({c})", c = c));
            return Detection { profile: Profile::Container, reasons };
        }
        if let Some(g) = &self.graphical {
            reasons.push(tr!("graphical environment ({g})", g = g));
        }
        if self.battery {
            reasons.push(tr!("has a battery").into());
        }
        if !reasons.is_empty() {
            return Detection { profile: Profile::Desktop, reasons };
        }
        reasons.push(tr!("no graphical environment").into());
        if self.sshd_running {
            reasons.push(tr!("sshd running").into());
        }
        Detection { profile: Profile::Server, reasons }
    }
}

pub fn detect() -> Detection {
    Signals::probe().decide()
}

fn probe_container() -> Option<String> {
    if Path::new("/.dockerenv").exists() {
        return Some("docker".into());
    }
    if Path::new("/run/.containerenv").exists() {
        return Some("podman".into());
    }
    // systemd y la mayoría de los runtimes exportan container= al PID 1
    if let Ok(env) = std::fs::read("/proc/1/environ") {
        for kv in env.split(|&b| b == 0) {
            if let Some(v) = kv.strip_prefix(b"container=") {
                return Some(String::from_utf8_lossy(v).into_owned());
            }
        }
    }
    if let Ok(v) = std::fs::read_to_string("/run/systemd/container") {
        let v = v.trim();
        if !v.is_empty() {
            return Some(v.to_string());
        }
    }
    None
}

fn probe_graphical() -> Option<String> {
    if Path::new("/etc/systemd/system/display-manager.service").exists() {
        return Some(tr!("display manager enabled").into());
    }
    if let Ok(t) = std::fs::read_link("/etc/systemd/system/default.target") {
        if t.to_string_lossy().ends_with("graphical.target") {
            return Some(tr!("boots into graphical.target").into());
        }
    }
    for dir in ["/usr/share/wayland-sessions", "/usr/share/xsessions"] {
        if std::fs::read_dir(dir).map(|mut d| d.next().is_some()).unwrap_or(false) {
            return Some(tr!("graphical sessions installed").into());
        }
    }
    None
}

fn dir_has_prefix(dir: &str, prefix: &str) -> bool {
    std::fs::read_dir(dir)
        .map(|d| d.flatten().any(|e| e.file_name().to_string_lossy().starts_with(prefix)))
        .unwrap_or(false)
}

/// Busca un proceso por nombre exacto en /proc/*/comm.
pub fn process_running(name: &str) -> bool {
    let Ok(dir) = std::fs::read_dir("/proc") else { return false };
    dir.flatten()
        .filter(|e| e.file_name().to_string_lossy().bytes().all(|b| b.is_ascii_digit()))
        .any(|e| {
            std::fs::read_to_string(e.path().join("comm")).map(|c| c.trim_end() == name).unwrap_or(false)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decide_contenedor_antes_que_escritorio() {
        let s = Signals { container: Some("docker".into()), battery: true, ..Default::default() };
        assert_eq!(s.decide().profile, Profile::Container);
    }

    #[test]
    fn decide_escritorio_por_bateria_o_grafico() {
        let s = Signals { battery: true, ..Default::default() };
        assert_eq!(s.decide().profile, Profile::Desktop);
        let s = Signals { graphical: Some("x".into()), ..Default::default() };
        assert_eq!(s.decide().profile, Profile::Desktop);
    }

    #[test]
    fn decide_servidor_por_defecto() {
        let s = Signals { sshd_running: true, ..Default::default() };
        let d = s.decide();
        assert_eq!(d.profile, Profile::Server);
        assert!(d.reasons.iter().any(|r| r == "sshd activo"));
    }

    #[test]
    fn ajuste_de_severidad_y_na() {
        let mut v = vec![
            CheckResult::new("NET-001", Severity::High, Status::Fail, "network", "t").detail("sin reglas"),
            CheckResult::new("SSH-011", Severity::Low, Status::Warn, "ssh", "t"),
            CheckResult::new("SSH-001", Severity::High, Status::Fail, "ssh", "t"),
        ];
        apply(Profile::Desktop, &mut v);
        assert_eq!(v[0].severity, Severity::Medium);
        assert_eq!(v[0].detail, "sin reglas (perfil desktop: severidad ALTO → MEDIO)");
        assert_eq!(v[1].status, Status::Na);
        assert_eq!(v[2].severity, Severity::High);
        assert_eq!(v[2].status, Status::Fail);
    }

    #[test]
    fn servidor_no_ajusta_nada() {
        let orig = vec![CheckResult::new("NET-001", Severity::High, Status::Fail, "network", "t")];
        let mut v = orig.clone();
        apply(Profile::Server, &mut v);
        assert_eq!(v, orig);
    }

    /// Evita ajustes "muertos" por un ID mal escrito.
    #[test]
    fn ids_de_ajustes_existen_en_checks_md() {
        let doc = include_str!("../../../docs/CHECKS.md");
        for (_, id, _) in ADJUSTMENTS {
            assert!(doc.contains(&format!("| {id} |")), "{id} no está en docs/CHECKS.md");
        }
    }
}
