//! Reporte de texto. Port de render_text (lib/report.sh).

use std::fmt::Write;

use linaudit_core::score::CapReason;
use linaudit_core::{CheckResult, ProfileSource, Report, Severity, Status, tr};

pub struct Style {
    color: bool,
    utf8: bool,
}

impl Style {
    pub fn detect(color: bool) -> Self {
        let locale = ["LC_ALL", "LC_CTYPE", "LANG"]
            .iter()
            .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
            .unwrap_or_default()
            .to_ascii_lowercase();
        Style { color, utf8: locale.contains("utf-8") || locale.contains("utf8") }
    }

    fn c(&self, code: &'static str) -> &'static str {
        if self.color { code } else { "" }
    }
    fn red(&self) -> &'static str {
        self.c("\x1b[31m")
    }
    fn yel(&self) -> &'static str {
        self.c("\x1b[33m")
    }
    fn grn(&self) -> &'static str {
        self.c("\x1b[32m")
    }
    fn cyn(&self) -> &'static str {
        self.c("\x1b[36m")
    }
    fn dim(&self) -> &'static str {
        self.c("\x1b[2m")
    }
    fn bld(&self) -> &'static str {
        self.c("\x1b[1m")
    }
    fn rst(&self) -> &'static str {
        self.c("\x1b[0m")
    }
    fn sym(&self, utf8: &'static str, ascii: &'static str) -> &'static str {
        if self.utf8 { utf8 } else { ascii }
    }
    fn sev(&self, s: Severity) -> &'static str {
        match s {
            Severity::Critical | Severity::High => self.red(),
            Severity::Medium => self.yel(),
            _ => self.cyn(),
        }
    }
}

pub fn verdict(score: u8) -> &'static str {
    match score {
        9.. => tr!("Well hardened"),
        7..=8 => tr!("Acceptable, with details to fix"),
        5..=6 => tr!("Needs work: there are relevant gaps"),
        3..=4 => tr!("Weak: fix soon"),
        _ => tr!("Critical: act now"),
    }
}

fn bar(st: &Style, pct: f64) -> String {
    let n = (((pct as u32) + 5) / 10).min(10) as usize;
    st.sym("█", "#").repeat(n) + &st.sym("░", ".").repeat(10 - n)
}

/// Hallazgos con un estado dado, ordenados por gravedad, FAIL antes que WARN, y por ID.
fn sorted<'a>(r: &'a Report, pred: impl Fn(Status) -> bool) -> Vec<&'a CheckResult> {
    let mut v: Vec<_> = r.results.iter().filter(|x| pred(x.status)).collect();
    v.sort_by(|a, b| {
        let st = |s: Status| u8::from(s != Status::Fail);
        (a.severity, st(a.status), &a.id).cmp(&(b.severity, st(b.status), &b.id))
    });
    v
}

pub fn render(r: &Report, st: &Style, show_all: bool, user: &str, date: &str) -> String {
    let mut o = String::new();
    let s = &r.score;
    let n = &s.counts;
    let (b, rst, dim, yel, red, grn) = (st.bld(), st.rst(), st.dim(), st.yel(), st.red(), st.grn());
    let line = st.sym("━", "=").repeat(66);

    let _ = writeln!(o, "{line}");
    let _ = writeln!(o, " {b}linaudit {}{rst} — {}  ({})", r.version, r.host, r.os);
    let no_root = if r.root { "" } else { tr!(" (NOT root: some checks cannot run)") };
    let source = match r.profile_source {
        ProfileSource::Argument => tr!("argument"),
        ProfileSource::Config => tr!("config"),
        ProfileSource::Menu => tr!("chosen"),
        ProfileSource::Auto => tr!("auto-detected"),
    };
    let _ = writeln!(o, " {dim}{}{rst}", tr!("{date} · user: {user}{no_root}", date = date, user = user, no_root = no_root));
    let _ = writeln!(o, " {dim}{}{rst}", tr!("profile: {profile} ({source})", profile = r.profile.label(), source = source));
    let _ = writeln!(o, "{line}\n");

    let score_label = tr!("SCORE:");
    match (s.score, s.incomplete) {
        (None, _) => {
            let _ = writeln!(
                o,
                "  {b}{score_label} {}{rst}   {}",
                tr!("no data"),
                tr!("no check could be evaluated (unknown category, or none applies to this system?)")
            );
        }
        (Some(sc), true) => {
            let _ = writeln!(o, "  {b}{score_label} {yel}{sc}/10{rst}   {yel}{}{rst}", tr!("INCOMPLETE evaluation"));
        }
        (Some(sc), false) => {
            let col = if sc < 5 { red } else if sc < 7 { yel } else { grn };
            let _ = writeln!(o, "  {b}{score_label} {col}{sc}/10{rst}   {}", verdict(sc));
        }
    }
    if let Some(raw) = s.score_raw {
        let line = tr!(
            "weighted compliance {pct}% · fine score {raw}",
            pct = format!("{:.1}", s.pct),
            raw = format!("{raw:.1}")
        );
        let _ = writeln!(o, "  {dim}{line}{rst}");
    }
    if !r.partial_categories.is_empty() {
        let line = tr!(
            "PARTIAL SCORE: only the categories {categories} were evaluated; this is not the system score.",
            categories = r.partial_categories.join(",")
        );
        let _ = writeln!(o, "  {yel}{line}{rst}");
    }
    if s.score.is_some() {
        if s.incomplete {
            // Un módulo caído tapa una categoría entera: el techo no es por "falta
            // de cobertura/root" sino por una categoría que no se pudo evaluar.
            let line = if s.module_panic {
                tr!("A check module crashed: a whole category was lost. Until it is evaluated again, the score cannot exceed 6/10.").to_string()
            } else {
                tr!(
                    "Coverage {pct}%: {n} checks could not be evaluated (missing root?). Until they are, the score cannot exceed 6/10.",
                    pct = format!("{:.1}", s.coverage),
                    n = n.error
                )
            };
            let _ = writeln!(o, "  {yel}{line}{rst}");
        } else if s.cap > 0 && s.cap_reason == CapReason::Hallazgos {
            let line = tr!("Cap applied: {cap}/10 due to open critical/high findings", cap = s.cap);
            let _ = writeln!(o, "  {yel}{line}{rst}");
        }
    }
    let _ = writeln!(
        o,
        "\n  {}",
        tr!(
            "Open findings:  {red}{critical} critical{rst} · {red}{high} high{rst} · {medium} medium · {low} low",
            red = red,
            rst = rst,
            critical = n.open_critical,
            high = n.open_high,
            medium = n.open_medium,
            low = n.open_low
        )
    );
    let _ = writeln!(
        o,
        "  {}\n",
        tr!(
            "Checks:  {pass} ok · {fail} failing · {warn} warn · {na} n/a · {error} error · {waived} waived",
            pass = n.pass,
            fail = n.fail,
            warn = n.warn,
            na = n.na,
            error = n.error,
            waived = n.waived
        )
    );

    if !s.categories.is_empty() {
        let _ = writeln!(o, "  {b}{}{rst}", tr!("By category"));
        for c in &s.categories {
            let col = if c.pct < 50.0 { red } else if c.pct < 80.0 { yel } else { grn };
            let _ = writeln!(
                o,
                "    {:<14} {col}{}{rst} {:>5.1}%   {}",
                c.name,
                bar(st, c.pct),
                c.pct,
                tr!("{fails} failing out of {checks}", fails = c.fails, checks = c.checks)
            );
        }
        o.push('\n');
    }

    let open = sorted(r, Status::is_open);
    if open.is_empty() {
        let _ = writeln!(o, "  {grn}{}{rst}\n", tr!("No open findings."));
    } else {
        let _ = writeln!(o, "  {b}{}{rst} {}\n", tr!("FINDINGS"), tr!("(sorted by severity)"));
        let arrow = st.sym("↳", ">");
        let fix = tr!("fix:");
        for f in open {
            let sym = if f.status == Status::Warn { st.sym("▲", "!") } else { st.sym("✖", "x") };
            let _ = writeln!(
                o,
                "  {}{sym} {:<8}{rst} {:<9} {}",
                st.sev(f.severity),
                f.severity.label(),
                f.id,
                f.title
            );
            if !f.detail.is_empty() {
                let _ = writeln!(o, "      {dim}{arrow} {}{rst}", f.detail);
            }
            if !f.fix.is_empty() {
                let _ = writeln!(o, "      {grn}{arrow} {fix}{rst} {}", f.fix);
            }
        }
        o.push('\n');
    }

    let section = |o: &mut String, title: &str, status: Status| {
        let v = sorted(r, |s| s == status);
        if v.is_empty() {
            return;
        }
        let _ = writeln!(o, "  {b}{title}{rst}");
        for f in v {
            let _ = writeln!(o, "    {} {} — {}", f.id, f.title, f.detail);
        }
        o.push('\n');
    };
    section(&mut o, tr!("DOCUMENTED WAIVERS (not scored)"), Status::Waived);
    section(&mut o, tr!("COULD NOT BE EVALUATED (count neither as PASS nor as FAIL)"), Status::Error);

    if show_all {
        let _ = writeln!(o, "  {b}{}{rst}", tr!("PASSED CHECKS"));
        for f in sorted(r, |s| s == Status::Pass) {
            let _ = writeln!(o, "    {grn}{}{rst} {:<9} {}", st.sym("✓", "+"), f.id, f.title);
        }
        o.push('\n');
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use linaudit_core::Profile;
    use linaudit_core::score;

    fn report(results: Vec<CheckResult>) -> Report {
        linaudit_core::i18n::set_lang(linaudit_core::i18n::Lang::Es);
        Report {
            schema: 1,
            tool: "linaudit",
            version: "test",
            host: "h".into(),
            os: "Debian".into(),
            timestamp: "t".into(),
            root: true,
            profile: Profile::Server,
            profile_source: ProfileSource::Argument,
            partial_categories: vec![],
            score: score::compute(&results),
            results,
        }
    }

    fn pass(n: usize) -> Vec<CheckResult> {
        (0..n).map(|i| CheckResult::new(format!("OK-{i}"), Severity::High, Status::Pass, "accounts", "ok")).collect()
    }

    /// Un módulo en pánico muestra el mensaje de "módulo caído", no el de cobertura/root.
    #[test]
    fn modulo_en_panico_muestra_mensaje_propio() {
        let mut results = pass(50);
        results.push(
            CheckResult::new("RUN-ssh", Severity::Low, Status::Error, "ssh", "modulo con error").module_panic(),
        );
        let r = report(results);
        let out = render(&r, &Style { color: false, utf8: true }, false, "ana", "hoy");
        assert!(out.contains("Un módulo de control se cayó"), "{out}");
        assert!(!out.contains("¿falta root?"), "no debe mostrar el texto de cobertura:\n{out}");
    }

    /// Baja cobertura genuina (sin pánico) conserva el mensaje de cobertura/root.
    #[test]
    fn baja_cobertura_muestra_mensaje_de_cobertura() {
        let mut results = pass(10);
        results.extend(
            (0..10).map(|i| CheckResult::new(format!("ERR-{i}"), Severity::Critical, Status::Error, "ssh", "sin evaluar")),
        );
        let r = report(results);
        assert!(r.score.incomplete && !r.score.module_panic);
        let out = render(&r, &Style { color: false, utf8: true }, false, "ana", "hoy");
        assert!(out.contains("¿falta root?"), "{out}");
        assert!(!out.contains("Un módulo de control se cayó"), "{out}");
    }
}
