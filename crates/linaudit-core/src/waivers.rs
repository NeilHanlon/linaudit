//! Excepciones documentadas (waivers.conf). Formato: una línea por excepción, `ID   # motivo`.

use std::collections::HashMap;
use std::path::Path;

use crate::model::{CheckResult, Status};
use crate::tr;

#[derive(Debug, Default, Clone)]
pub struct Waivers {
    by_id: HashMap<String, String>,
}

impl Waivers {
    /// Carga los archivos que existan y sean legibles; los demás se ignoran (igual que en bash).
    pub fn load<P: AsRef<Path>>(paths: &[P]) -> Self {
        let mut w = Waivers::default();
        for p in paths {
            if let Ok(text) = std::fs::read_to_string(p) {
                w.parse_into(&text);
            }
        }
        w
    }

    pub fn parse(text: &str) -> Self {
        let mut w = Waivers::default();
        w.parse_into(text);
        w
    }

    fn parse_into(&mut self, text: &str) {
        for line in text.lines() {
            let line = line.trim_end_matches('\r');
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let end = line.find(|c: char| c.is_whitespace() || c == '#').unwrap_or(line.len());
            let (id, rest) = line.split_at(end);
            if id.is_empty() {
                continue;
            }
            let reason = rest.trim_start_matches(|c: char| c.is_whitespace() || c == '#').trim_end();
            let reason = if reason.is_empty() { tr!("no documented reason") } else { reason };
            self.by_id.insert(id.to_string(), reason.to_string());
        }
    }

    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    /// Marca como WAIVED los resultados con excepción. PASS y N/A no se tocan:
    /// si el control ya cumple, la excepción no hace falta.
    pub fn apply(&self, results: &mut [CheckResult]) {
        for r in results.iter_mut() {
            if matches!(r.status, Status::Pass | Status::Na) {
                continue;
            }
            if let Some(reason) = self.by_id.get(&r.id) {
                let detail = if r.detail.is_empty() {
                    tr!("waiver: {reason}", reason = reason)
                } else {
                    tr!("waiver: {reason} — {detail}", reason = reason, detail = r.detail)
                };
                r.set_detail(&detail);
                r.status = Status::Waived;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;

    #[test]
    fn parsea_formato_de_waivers_conf() {
        let w = Waivers::parse(
            "# comentario\n\nNET-001   # Firewall perimetral. Ticket INF-1234\r\nPAT-003\nSSH-002#pegado\n",
        );
        assert_eq!(w.by_id["NET-001"], "Firewall perimetral. Ticket INF-1234");
        assert_eq!(w.by_id["PAT-003"], "sin motivo documentado");
        assert_eq!(w.by_id["SSH-002"], "pegado");
        assert_eq!(w.len(), 3);
    }

    #[test]
    fn aplica_solo_a_hallazgos() {
        let w = Waivers::parse("A-1 # motivo\nB-1 # motivo\n");
        let mut v = vec![
            CheckResult::new("A-1", Severity::High, Status::Fail, "c", "t").detail("algo"),
            CheckResult::new("B-1", Severity::High, Status::Pass, "c", "t"),
        ];
        w.apply(&mut v);
        assert_eq!(v[0].status, Status::Waived);
        assert_eq!(v[0].detail, "excepción: motivo — algo");
        assert_eq!(v[1].status, Status::Pass);
    }
}
