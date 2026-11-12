//! Puntaje de 1 a 10. Port directo de `lib/score.awk`; los tests replican `tests/test_score.sh`.
//!
//! Modelo:
//!   1) Cada control cuenta según su severidad: CRITICAL=10 HIGH=6 MEDIUM=3 LOW=1 INFO=0
//!   2) PASS suma todo el peso, WARN la mitad, FAIL nada. NA/ERROR/WAIVED no cuentan.
//!   3) pct = pesos obtenidos / pesos posibles  ->  escala lineal 1..10
//!   4) Cobertura: si no se pudo evaluar >10% del peso (ej. sin root) el tope es 6.
//!   5) Techos por gravedad (un 9 con un crítico abierto sería mentira):
//!        >=3 críticos -> máx 3 | 2 críticos -> máx 4 | 1 crítico -> máx 6
//!        >=5 altos    -> máx 6 | >=1 alto    -> máx 8

use std::collections::BTreeMap;

use serde::Serialize;

use crate::model::{CheckResult, Severity, Status};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CapReason {
    /// Techo por hallazgos críticos/altos abiertos.
    Hallazgos,
    /// Techo por cobertura insuficiente (controles que no se pudieron evaluar).
    Cobertura,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Counts {
    pub pass: u32,
    pub fail: u32,
    pub warn: u32,
    pub na: u32,
    pub error: u32,
    pub waived: u32,
    pub open_critical: u32,
    pub open_high: u32,
    pub open_medium: u32,
    pub open_low: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CategoryScore {
    pub name: String,
    pub pct: f64,
    pub fails: u32,
    pub checks: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Score {
    /// Puntaje entero 1..10. `None` si no hubo ningún control evaluable.
    pub score: Option<u8>,
    /// Puntaje con un decimal (después de techos).
    pub score_raw: Option<f64>,
    /// Cumplimiento ponderado, 0..100.
    pub pct: f64,
    /// Techo que efectivamente bajó el puntaje (0 si ninguno).
    pub cap: u8,
    pub cap_reason: CapReason,
    /// Porcentaje del peso que se pudo evaluar.
    pub coverage: f64,
    pub incomplete: bool,
    /// true si el techo de cobertura lo forzó un módulo que entró en pánico (se
    /// perdió una categoría entera), no una cobertura baja por falta de root.
    /// Permite que el reporte muestre el motivo correcto (ver text.rs / tui/ui.rs).
    pub module_panic: bool,
    pub counts: Counts,
    /// Ordenadas por nombre.
    pub categories: Vec<CategoryScore>,
}

impl Score {
    pub fn nodata(&self) -> bool {
        self.score.is_none()
    }
}

/// Redondea a un decimal, como el `printf "%.1f"` de awk.
fn round1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

pub fn compute(results: &[CheckResult]) -> Score {
    let mut counts = Counts::default();
    let (mut poss, mut earn, mut errw) = (0.0_f64, 0.0_f64, 0.0_f64);
    // Un módulo entero entró en pánico (RUN-<categoría>): se perdió una categoría
    // completa, cuyo peso real es desconocido.
    let mut module_error = false;
    // categoría -> (posible, obtenido, fallas, controles)
    let mut cats: BTreeMap<&str, (f64, f64, u32, u32)> = BTreeMap::new();

    for r in results {
        let w = r.severity.weight();
        match r.status {
            Status::Pass => counts.pass += 1,
            Status::Fail => counts.fail += 1,
            Status::Warn => counts.warn += 1,
            Status::Na => counts.na += 1,
            Status::Error => {
                counts.error += 1;
                errw += w;
                // Marcador explícito que deja checks::run_all al atrapar un pánico;
                // no se infiere del prefijo "RUN-" del id.
                if r.module_panic {
                    module_error = true;
                }
            }
            Status::Waived => counts.waived += 1,
        }
        if !r.status.is_scored() {
            continue;
        }
        let c = cats.entry(r.category.as_str()).or_default();
        c.3 += 1;
        c.0 += w;
        poss += w;
        match r.status {
            Status::Pass => {
                c.1 += w;
                earn += w;
            }
            Status::Warn => {
                c.1 += w / 2.0;
                earn += w / 2.0;
            }
            _ => {
                c.2 += 1;
                match r.severity {
                    Severity::Critical => counts.open_critical += 1,
                    Severity::High => counts.open_high += 1,
                    Severity::Medium => counts.open_medium += 1,
                    Severity::Low => counts.open_low += 1,
                    Severity::Info => {}
                }
            }
        }
    }

    let categories = cats
        .into_iter()
        .map(|(name, (p, e, fails, checks))| CategoryScore {
            name: name.to_string(),
            pct: if p > 0.0 { round1(100.0 * e / p) } else { 100.0 },
            fails,
            checks,
        })
        .collect();

    if poss == 0.0 {
        return Score {
            score: None,
            score_raw: None,
            pct: 0.0,
            cap: 0,
            cap_reason: CapReason::Cobertura,
            coverage: 0.0,
            incomplete: true,
            module_panic: module_error,
            counts,
            categories,
        };
    }

    let pct = 100.0 * earn / poss;
    let raw = 1.0 + 9.0 * pct / 100.0;

    let mut cap: u8 = match counts.open_critical {
        0 => 10,
        1 => 6,
        2 => 4,
        _ => 3,
    };
    if counts.open_high >= 5 && cap > 6 {
        cap = 6;
    } else if counts.open_high >= 1 && cap > 8 {
        cap = 8;
    }

    let coverage = 100.0 * poss / (poss + errw);
    // Si un módulo entró en pánico se perdió una categoría entera: su peso real
    // es desconocido, por lo que la cobertura calculada lo subestima (el error
    // RUN-<cat> solo aporta peso LOW=1). Tratamos todo fallo de módulo como
    // cobertura insuficiente: se fuerza "incompleto" y se aplica el techo de
    // cobertura, para que una categoría que falló en silencio no pueda reportar
    // un puntaje alto y "completo".
    let incomplete = coverage < 90.0 || module_error;
    let mut reason = CapReason::Hallazgos;
    if incomplete && cap > 6 {
        cap = 6;
        reason = CapReason::Cobertura;
    }

    let fin = raw.min(f64::from(cap)).clamp(1.0, 10.0);
    Score {
        score: Some((fin + 0.5).floor() as u8),
        score_raw: Some(round1(fin)),
        pct: round1(pct),
        cap: if cap < 10 && raw > f64::from(cap) { cap } else { 0 },
        cap_reason: reason,
        coverage: round1(coverage),
        incomplete,
        module_panic: module_error,
        counts,
        categories,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Severity::*;
    use Status::*;

    /// Equivalente a `mk N ESTADO SEV` de tests/test_score.sh.
    fn mk(out: &mut Vec<CheckResult>, n: usize, st: Status, sev: Severity) {
        for i in 0..n {
            out.push(CheckResult::new(format!("T-{i}"), sev, st, "test", "titulo"));
        }
    }

    fn score(spec: &[(usize, Status, Severity)]) -> Option<u8> {
        let mut v = Vec::new();
        for &(n, st, sev) in spec {
            mk(&mut v, n, st, sev);
        }
        compute(&v).score
    }

    #[test]
    fn casos_de_test_score_sh() {
        let cases: &[(&str, &[(usize, Status, Severity)], u8)] = &[
            ("todo PASS = 10", &[(20, Pass, Critical), (20, Pass, High), (20, Pass, Medium)], 10),
            ("todo FAIL = 1", &[(10, Fail, High), (10, Fail, Medium), (5, Fail, Critical)], 1),
            ("99% pero 1 crítico -> tope 6", &[(30, Pass, High), (30, Pass, Medium), (1, Fail, Critical)], 6),
            ("2 críticos -> tope 4", &[(30, Pass, High), (30, Pass, Medium), (2, Fail, Critical)], 4),
            ("3 críticos -> tope 3", &[(30, Pass, High), (30, Pass, Medium), (3, Fail, Critical)], 3),
            ("1 alto -> tope 8", &[(60, Pass, High), (60, Pass, Medium), (1, Fail, High)], 8),
            ("5 altos -> tope 6", &[(60, Pass, High), (60, Pass, Medium), (5, Fail, High)], 6),
            ("solo bajos fallando = 10", &[(50, Pass, High), (50, Pass, Medium), (3, Fail, Low)], 10),
            ("NA y WAIVED no cuentan", &[(10, Pass, High), (10, Na, High), (10, Waived, High)], 10),
            ("30%+ sin evaluar -> tope 6", &[(10, Pass, High), (10, Error, Critical)], 6),
            ("WARN cuenta la mitad", &[(10, Pass, High), (20, Warn, High)], 7),
        ];
        for (desc, spec, want) in cases {
            assert_eq!(score(spec), Some(*want), "{desc}");
        }
    }

    #[test]
    fn sin_controles_evaluables_es_nodata() {
        assert_eq!(score(&[]), None);
        let mut v = Vec::new();
        mk(&mut v, 3, Na, Info);
        assert!(compute(&v).nodata());
        let mut v = Vec::new();
        mk(&mut v, 3, Pass, High);
        assert!(!compute(&v).nodata());
    }

    #[test]
    fn categorias_y_techo_informado() {
        let mut v = Vec::new();
        mk(&mut v, 30, Pass, High);
        mk(&mut v, 1, Fail, Critical);
        let s = compute(&v);
        assert_eq!(s.cap, 6);
        assert_eq!(s.cap_reason, CapReason::Hallazgos);
        assert_eq!(s.counts.open_critical, 1);
        assert_eq!(s.categories.len(), 1);
        assert_eq!(s.categories[0].fails, 1);
        assert_eq!(s.categories[0].checks, 31);
    }

    #[test]
    fn cobertura_marca_incompleto() {
        let mut v = Vec::new();
        mk(&mut v, 10, Pass, High);
        mk(&mut v, 10, Error, Critical);
        let s = compute(&v);
        assert!(s.incomplete);
        assert_eq!(s.cap_reason, CapReason::Cobertura);
    }

    /// Un módulo que entra en pánico emite un error RUN-<categoría> de peso LOW.
    /// Ese error borra una categoría entera del denominador: sin la correccion la
    /// cobertura apenas baja (99%+) y el puntaje se reporta alto y "completo",
    /// ocultando que una categoria fallo. Debe forzar "incompleto" y techo de cobertura.
    #[test]
    fn modulo_en_panico_no_puntua_como_completo() {
        let mut v = Vec::new();
        mk(&mut v, 50, Pass, High);
        // Simula el pánico del módulo ssh: checks/mod.rs marca el ERROR con module_panic().
        v.push(
            CheckResult::new("RUN-ssh", Severity::Low, Status::Error, "ssh", "modulo con error").module_panic(),
        );
        let s = compute(&v);
        assert!(s.incomplete, "un módulo en pánico debe dejar la corrida incompleta");
        assert!(s.module_panic, "el puntaje debe marcar que la causa fue un módulo caído");
        assert_eq!(s.cap_reason, CapReason::Cobertura);
        // Sin la corrección esto daría 10; el techo de cobertura lo baja a 6.
        assert_eq!(s.score, Some(6), "no debe reportar un puntaje alto con una categoría caída");
    }

    /// El marcador es explícito: un ERROR con id "RUN-" pero SIN module_panic (p. ej.
    /// baja cobertura por falta de root) no debe tratarse como módulo caído.
    #[test]
    fn error_sin_marcador_no_es_modulo_en_panico() {
        let mut v = Vec::new();
        mk(&mut v, 10, Pass, High);
        mk(&mut v, 10, Error, Critical);
        let s = compute(&v);
        assert!(s.incomplete, "baja cobertura deja la corrida incompleta");
        assert!(!s.module_panic, "sin el marcador no es un pánico de módulo");
        assert_eq!(s.cap_reason, CapReason::Cobertura);
    }
}
