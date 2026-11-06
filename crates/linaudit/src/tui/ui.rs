//! Dibujo de la TUI: encabezado con pestañas, Resumen, Hallazgos, Categorías, progreso y ventanas emergentes.

use linaudit_core::score::CapReason;
use linaudit_core::i18n::tr_dyn;
use linaudit_core::{CheckResult, ProfileSource, Report, Severity, Status, checks, tr, trc};
use ratatui::layout::{Alignment, Constraint, Direction, Flex, Layout, Margin, Rect};
use ratatui::prelude::*;
use ratatui::symbols;
use ratatui::widgets::{
    Bar, BarChart, BarGroup, Block, BorderType, Cell, Clear, LineGauge, Padding, Paragraph, Row, Scrollbar,
    ScrollbarOrientation, ScrollbarState, Table, Tabs, Wrap,
};

use super::app::{App, ModuleState, Tab, View};
use super::theme::Theme;
use super::widgets::{SPINNER, ScoreRing, key_hint, sev_pill};
use crate::text::verdict;

pub const MIN_W: u16 = 50;
pub const MIN_H: u16 = 16;

pub fn draw(f: &mut Frame, app: &mut App, theme: &Theme) {
    let area = f.area();
    if area.width < MIN_W || area.height < MIN_H {
        let msg = tr!(
            "Terminal too small ({w}×{h}). Minimum {min_w}×{min_h}. q to quit.",
            w = area.width,
            h = area.height,
            min_w = MIN_W,
            min_h = MIN_H
        );
        f.render_widget(Paragraph::new(msg).wrap(Wrap { trim: true }), area);
        return;
    }
    if app.welcome.is_some() {
        super::welcome::draw(f, area, app, theme);
        if let Some((msg, _)) = &app.toast {
            draw_toast(f, area.inner(Margin::new(2, 1)), msg, theme);
        }
        return;
    }
    let [header, tabs, body, footer] =
        Layout::vertical([Constraint::Length(1), Constraint::Length(1), Constraint::Fill(1), Constraint::Length(1)])
            .areas(area);

    let Some(report) = app.report.take() else {
        draw_header(f, header, theme, None, app);
        draw_progress(f, tabs.union(body), app, theme);
        draw_footer(f, footer, app, theme);
        return;
    };
    draw_header(f, header, theme, Some(&report), app);
    draw_tabs(f, tabs, app, theme, &report);
    let body = body.inner(Margin::new(1, 0));
    match app.tab {
        Tab::Summary => draw_summary(f, body, app, theme, &report),
        Tab::Findings => draw_findings(f, body, app, theme, &report),
        Tab::Categories => draw_categories_tab(f, body, app, theme, &report),
    }
    app.report = Some(report);
    draw_footer(f, footer, app, theme);
    if let Some((msg, _)) = &app.toast {
        draw_toast(f, body, msg, theme);
    }
    if app.show_help {
        draw_help(f, area, theme);
    }
}

// ───────────────────────────────────────────────────────────── encabezado

fn chip<'a>(text: impl Into<String>, fg: Color, theme: &Theme) -> Span<'a> {
    let style =
        if theme.mono() { Style::new().add_modifier(Modifier::BOLD) } else { Style::new().fg(fg).add_modifier(Modifier::BOLD) };
    Span::styled(text.into(), style)
}

fn draw_header(f: &mut Frame, area: Rect, theme: &Theme, r: Option<&Report>, app: &App) {
    let brand = if theme.mono() {
        Style::new().add_modifier(Modifier::REVERSED | Modifier::BOLD)
    } else {
        Style::new().bg(theme.accent).fg(theme.on_color).add_modifier(Modifier::BOLD)
    };
    let mut spans = vec![Span::styled(" ◆ linaudit ", brand), Span::raw(" ")];
    let sep = || Span::styled("  ·  ", theme.text_muted());
    match r {
        Some(r) => {
            let src = match r.profile_source {
                ProfileSource::Argument => tr!("argument"),
                ProfileSource::Config => tr!("config"),
                ProfileSource::Menu => tr!("chosen"),
                ProfileSource::Auto => "auto",
            };
            spans.push(Span::styled(r.host.clone(), Style::new().add_modifier(Modifier::BOLD)));
            spans.push(sep());
            spans.push(Span::styled(r.os.clone(), theme.text_muted()));
            spans.push(sep());
            spans.push(chip(format!("⬢ {}", r.profile.label()), theme.accent2, theme));
            spans.push(Span::styled(format!(" ({src})"), theme.text_muted()));
            if !r.root {
                spans.push(sep());
                spans.push(chip(format!("▲ {}", tr!("not root")), theme.warn, theme));
            }
        }
        None => {
            spans.push(Span::styled(linaudit_core::system::hostname(), Style::new().add_modifier(Modifier::BOLD)));
        }
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);

    if area.width > 110 {
        let elapsed = app.finished_at.unwrap_or_else(std::time::Instant::now).duration_since(app.started);
        let right = Line::styled(
            format!("v{} · {:.1} s ", env!("CARGO_PKG_VERSION"), elapsed.as_secs_f64()),
            theme.text_muted(),
        )
        .right_aligned();
        f.render_widget(Paragraph::new(right), area);
    }
}

fn draw_tabs(f: &mut Frame, area: Rect, app: &App, theme: &Theme, r: &Report) {
    let open = r.score.counts.fail + r.score.counts.warn;
    let titles: Vec<Line> = Tab::ALL
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let badge = match t {
                Tab::Findings if open > 0 => format!(" {open}"),
                Tab::Categories => format!(" {}", r.score.categories.len()),
                _ => String::new(),
            };
            Line::from(vec![
                Span::styled(format!("{} ", i + 1), theme.text_muted()),
                Span::raw(t.title()),
                Span::styled(badge, Style::new().fg(theme.warn)),
            ])
        })
        .collect();
    let selected = if theme.mono() {
        Style::new().add_modifier(Modifier::REVERSED | Modifier::BOLD)
    } else {
        Style::new().fg(theme.accent).add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
    };
    let tabs = Tabs::new(titles)
        .select(Tab::ALL.iter().position(|t| *t == app.tab).unwrap_or(0))
        .highlight_style(selected)
        .divider(Span::styled("│", theme.border()))
        .padding("  ", "  ");
    f.render_widget(tabs, area);
}

// ───────────────────────────────────────────────────────────── progreso

fn draw_progress(f: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let n = app.modules.len() as u16;
    let [card] = Layout::vertical([Constraint::Length(n + 7)]).flex(Flex::Center).areas(area);
    let [card] =
        Layout::horizontal([Constraint::Length(68.min(area.width.saturating_sub(4)))]).flex(Flex::Center).areas(card);
    let frame = (app.started.elapsed().as_millis() / 80) as usize % SPINNER.len();
    let block = rounded(theme, true)
        .title(Line::from(vec![
            Span::styled(format!(" {} ", tr!("Auditing")), theme.title()),
            Span::styled(linaudit_core::system::hostname(), Style::new().add_modifier(Modifier::BOLD)),
            Span::raw(" "),
        ]))
        .title_bottom(Line::styled(format!(" {:.1} s ", app.started.elapsed().as_secs_f64()), theme.text_muted()).right_aligned())
        .padding(Padding::new(2, 2, 1, 0));
    let inner = block.inner(card);
    f.render_widget(Clear, card);
    f.render_widget(block, card);

    let done = app.modules.iter().filter(|m| m.state == ModuleState::Done).count();
    let current = app.modules.iter().find(|m| m.state == ModuleState::Running);
    let [status, gauge, _, list] =
        Layout::vertical([Constraint::Length(1), Constraint::Length(1), Constraint::Length(1), Constraint::Fill(1)])
            .areas(inner);
    let label = current.map_or(tr!("Preparing…").to_string(), |m| format!("{}…", tr_dyn(m.description)));
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(format!("{} ", SPINNER[frame]), Style::new().fg(theme.accent)),
            Span::raw(label),
        ])),
        status,
    );
    let ratio = if app.modules.is_empty() { 0.0 } else { done as f64 / app.modules.len() as f64 };
    f.render_widget(
        LineGauge::default()
            .filled_style(Style::new().fg(theme.accent))
            .unfilled_style(Style::new().fg(theme.track))
            .thick()
            .label(Span::styled(format!("{done}/{} ", app.modules.len()), theme.text_muted()))
            .ratio(ratio),
        gauge,
    );
    let rows: Vec<Line> = app
        .modules
        .iter()
        .map(|m| {
            let (sym, style) = match m.state {
                ModuleState::Done => ("✓".to_string(), Style::new().fg(theme.ok)),
                ModuleState::Running => {
                    (SPINNER[frame].to_string(), Style::new().fg(theme.accent).add_modifier(Modifier::BOLD))
                }
                ModuleState::Pending => ("·".to_string(), theme.text_muted()),
            };
            let name_style = if m.state == ModuleState::Pending { theme.text_muted() } else { Style::new() };
            Line::from(vec![
                Span::styled(format!("{sym} "), style),
                Span::styled(format!("{:<12}", m.category), name_style.add_modifier(Modifier::BOLD)),
                Span::styled(tr_dyn(m.description), theme.text_muted()),
            ])
        })
        .collect();
    f.render_widget(Paragraph::new(rows), list);
}

// ───────────────────────────────────────────────────────────── resumen

fn rounded<'a>(theme: &Theme, focus: bool) -> Block<'a> {
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(if focus { theme.border_focus() } else { theme.border() })
}

fn card_title<'a>(text: &'a str, theme: &Theme) -> Line<'a> {
    Line::from(vec![Span::raw(" "), Span::styled(text, theme.title()), Span::raw(" ")])
}

fn draw_summary(f: &mut Frame, area: Rect, app: &mut App, theme: &Theme, r: &Report) {
    let top_h = if area.height >= 30 {
        16
    } else if area.height >= 22 {
        13
    } else {
        9
    };
    let [top, bottom] = Layout::vertical([Constraint::Length(top_h), Constraint::Fill(1)]).areas(area);

    if area.width >= 110 {
        let [score, sev, cats] =
            Layout::horizontal([Constraint::Length(38), Constraint::Length(34), Constraint::Fill(1)]).areas(top);
        draw_score_card(f, score, app, theme, r);
        draw_severity_card(f, sev, theme, r);
        draw_category_card(f, cats, theme, r);
    } else if area.width >= 72 {
        let [score, cats] = Layout::horizontal([Constraint::Length(36), Constraint::Fill(1)]).areas(top);
        draw_score_card(f, score, app, theme, r);
        draw_category_card(f, cats, theme, r);
    } else {
        draw_score_card(f, top, app, theme, r);
    }
    draw_urgent(f, bottom, app, theme, r);
}

fn score_note(r: &Report) -> Option<(String, bool)> {
    let s = &r.score;
    s.score?;
    if s.incomplete {
        Some((tr!("Coverage {pct}% · capped at 6/10", pct = format!("{:.0}", s.coverage)), true))
    } else if s.cap > 0 && s.cap_reason == CapReason::Hallazgos {
        Some((tr!("Capped at {cap}/10 by serious findings", cap = s.cap), true))
    } else if !r.partial_categories.is_empty() {
        Some((tr!("Partial: only {categories}", categories = r.partial_categories.join(",")), true))
    } else {
        Some((tr!("Weighted compliance {pct}%", pct = format!("{:.1}", s.pct)), false))
    }
}

fn draw_score_card(f: &mut Frame, area: Rect, app: &App, theme: &Theme, r: &Report) {
    let block = rounded(theme, false).title(card_title(tr!("Score"), theme));
    let inner = block.inner(area);
    f.render_widget(block, area);
    let [ring, verdict_area, note_area] =
        Layout::vertical([Constraint::Fill(1), Constraint::Length(1), Constraint::Length(1)]).areas(inner);
    f.render_widget(ScoreRing { theme, score: r.score.score, progress: app.score_progress() }, ring);

    let (text, color) = match r.score.score {
        Some(_) if r.score.incomplete => (tr!("Incomplete evaluation").to_string(), theme.warn),
        Some(s) => (verdict(s).to_string(), theme.score_color(f64::from(s))),
        None => (tr!("No check could be evaluated").to_string(), theme.muted),
    };
    f.render_widget(
        Paragraph::new(Span::styled(text, Style::new().fg(color).add_modifier(Modifier::BOLD)))
            .alignment(Alignment::Center),
        verdict_area,
    );
    if let Some((note, warn)) = score_note(r) {
        let style = if warn { Style::new().fg(theme.warn) } else { theme.text_muted() };
        f.render_widget(Paragraph::new(Span::styled(note, style)).alignment(Alignment::Center), note_area);
    }
}

fn draw_severity_card(f: &mut Frame, area: Rect, theme: &Theme, r: &Report) {
    let n = &r.score.counts;
    let block = rounded(theme, false).title(card_title(tr!("Open by severity"), theme)).title_bottom(
        Line::from(vec![
            Span::styled(format!(" ✓ {} ", n.pass), Style::new().fg(theme.ok)),
            Span::styled(format!("– {} ", n.na), theme.text_muted()),
            Span::styled(format!("? {} ", n.error), Style::new().fg(theme.warn)),
            Span::styled(format!("≈ {} ", n.waived), Style::new().fg(theme.waived)),
        ])
        .centered(),
    );
    // FAIL y WARN son hallazgos abiertos: se cuentan los dos, por severidad
    let open_by = |s: Severity| r.results.iter().filter(|x| x.status.is_open() && x.severity == s).count() as u64;
    let bars: Vec<Bar> = [
        (Severity::Critical, trc!("severity, short", "CRIT")),
        (Severity::High, Severity::High.label()),
        (Severity::Medium, Severity::Medium.label()),
        (Severity::Low, Severity::Low.label()),
    ]
    .iter()
    .map(|(s, label)| {
        let v = open_by(*s);
        let c = theme.sev_color(*s);
        let value_style = if theme.mono() {
            Style::new().add_modifier(Modifier::BOLD)
        } else {
            Style::new().fg(theme.on_color).bg(c).add_modifier(Modifier::BOLD)
        };
        Bar::default()
            .value(v)
            .text_value(v.to_string())
            .label(Line::styled(*label, Style::new().fg(c)))
            .style(Style::new().fg(c))
            .value_style(value_style)
    })
    .collect();
    let inner_w = area.width.saturating_sub(4);
    let bar_w = (inner_w.saturating_sub(3 * 2) / 4).clamp(3, 6);
    let chart = BarChart::default()
        .block(block.padding(Padding::new(1, 1, 1, 0)))
        .data(BarGroup::default().bars(&bars))
        .bar_width(bar_w)
        .bar_gap(2)
        .bar_set(symbols::bar::NINE_LEVELS);
    f.render_widget(chart, area);
}

/// Línea gruesa para los LineGauge. `line_set` está deprecado desde ratatui 0.30, pero su reemplazo
/// no existe en 0.29 (la de Debian 13): se usa el que anda en las dos.
trait ThickGauge {
    fn thick(self) -> Self;
}

impl ThickGauge for LineGauge<'_> {
    #[allow(deprecated)]
    fn thick(self) -> Self {
        self.line_set(symbols::line::THICK)
    }
}

/// Barra fina hecha de texto, para usar dentro de tablas.
fn text_bar<'a>(theme: &Theme, ratio: f64, width: usize) -> Vec<Span<'a>> {
    let filled = ((ratio.clamp(0.0, 1.0) * width as f64).round() as usize).min(width);
    vec![
        Span::styled("━".repeat(filled), Style::new().fg(theme.grade(ratio))),
        Span::styled("━".repeat(width - filled), Style::new().fg(theme.track)),
    ]
}

fn draw_category_card(f: &mut Frame, area: Rect, theme: &Theme, r: &Report) {
    let block = rounded(theme, false).title(card_title(tr!("Categories"), theme)).padding(Padding::new(1, 1, 1, 0));
    let inner = block.inner(area);
    f.render_widget(block, area);
    let rows = Layout::vertical(vec![Constraint::Length(1); r.score.categories.len()]).split(inner);
    for (c, row) in r.score.categories.iter().zip(rows.iter()) {
        let [name, gauge, pct, fails] = Layout::horizontal([
            Constraint::Length(12),
            Constraint::Fill(1),
            Constraint::Length(6),
            Constraint::Length(if row.width > 40 { 6 } else { 0 }),
        ])
        .areas(*row);
        let ratio = c.pct / 100.0;
        f.render_widget(Paragraph::new(Span::styled(c.name.as_str(), Style::new().add_modifier(Modifier::BOLD))), name);
        f.render_widget(
            LineGauge::default()
                .filled_style(Style::new().fg(theme.grade(ratio)))
                .unfilled_style(Style::new().fg(theme.track))
                .thick()
                .label("")
                .ratio(ratio.clamp(0.0, 1.0)),
            gauge,
        );
        f.render_widget(
            Paragraph::new(Span::styled(format!("{:>4.0}%", c.pct), Style::new().fg(theme.grade(ratio))))
                .alignment(Alignment::Right),
            pct,
        );
        if c.fails > 0 {
            f.render_widget(
                Paragraph::new(Span::styled(format!("✖ {}", c.fails), Style::new().fg(theme.bad)))
                    .alignment(Alignment::Right),
                fails,
            );
        }
    }
}

fn status_icon(theme: &Theme, s: Status) -> Span<'static> {
    let sym = match s {
        Status::Fail => "✖",
        Status::Warn => "▲",
        Status::Pass => "✓",
        Status::Na => "–",
        Status::Waived => "≈",
        Status::Error => "?",
    };
    Span::styled(sym, Style::new().fg(theme.status_color(s)).add_modifier(Modifier::BOLD))
}

fn status_label(s: Status) -> &'static str {
    match s {
        Status::Fail => tr!("Fails"),
        Status::Warn => tr!("Warning"),
        Status::Pass => tr!("Passes"),
        Status::Na => tr!("Not applicable"),
        Status::Waived => tr!("Documented waiver"),
        Status::Error => tr!("Could not be evaluated"),
    }
}

fn finding_row<'a>(theme: &Theme, x: &'a CheckResult, show_cat: bool) -> Row<'a> {
    let mut cells = vec![
        Cell::from(status_icon(theme, x.status)),
        Cell::from(sev_pill(theme, x.severity)),
        Cell::from(Span::styled(x.id.as_str(), theme.text_muted())),
        Cell::from(x.title.as_str()),
    ];
    if show_cat {
        cells.push(Cell::from(Span::styled(x.category.as_str(), theme.text_muted())));
    }
    Row::new(cells)
}

fn finding_widths(show_cat: bool) -> Vec<Constraint> {
    let mut w = vec![Constraint::Length(1), Constraint::Length(8), Constraint::Length(7), Constraint::Fill(1)];
    if show_cat {
        w.push(Constraint::Length(11));
    }
    w
}

fn draw_urgent(f: &mut Frame, area: Rect, app: &mut App, theme: &Theme, r: &Report) {
    let block = rounded(theme, true)
        .title(card_title(tr!("Most urgent"), theme))
        .title_bottom(Line::from(key_hint(theme, "Enter", tr!("details"))).right_aligned())
        .padding(Padding::horizontal(1));
    if app.urgent.is_empty() {
        let msg = Paragraph::new(vec![
            Line::raw(""),
            Line::styled(format!("✓ {}", tr!("No open findings")), Style::new().fg(theme.ok).add_modifier(Modifier::BOLD)),
            Line::styled(tr!("Press 2 to see every evaluated check."), theme.text_muted()),
        ])
        .alignment(Alignment::Center)
        .block(block);
        f.render_widget(msg, area);
        return;
    }
    let show_cat = area.width > 70;
    let rows: Vec<Row> = app.urgent.iter().map(|&i| finding_row(theme, &r.results[i], show_cat)).collect();
    let table = Table::new(rows, finding_widths(show_cat))
        .block(block)
        .column_spacing(2)
        .row_highlight_style(theme.selected())
        .highlight_symbol("▌");
    f.render_stateful_widget(table, area, &mut app.urgent_state);
}

// ───────────────────────────────────────────────────────────── hallazgos

fn draw_findings(f: &mut Frame, area: Rect, app: &mut App, theme: &Theme, r: &Report) {
    let [filters, content] = Layout::vertical([Constraint::Length(1), Constraint::Fill(1)]).areas(area);
    draw_filter_bar(f, filters, app, theme, r);
    if area.width >= 110 {
        let [list, detail] =
            Layout::horizontal([Constraint::Percentage(58), Constraint::Percentage(42)]).areas(content);
        draw_findings_table(f, list, app, theme, r);
        draw_detail(f, detail, app, theme, r);
    } else {
        let detail_h = (content.height / 2).clamp(6, 14);
        let [list, detail] = Layout::vertical([Constraint::Fill(1), Constraint::Length(detail_h)]).areas(content);
        draw_findings_table(f, list, app, theme, r);
        draw_detail(f, detail, app, theme, r);
    }
}

fn draw_filter_bar(f: &mut Frame, area: Rect, app: &App, theme: &Theme, r: &Report) {
    let active = Style::new().fg(theme.accent).add_modifier(Modifier::BOLD);
    let value = |v: String, on: bool| Span::styled(v, if on { active } else { theme.text_muted() });
    let key = |k: &'static str| key_hint(theme, k, "").into_iter().next().unwrap_or_default();
    let sev = match app.min_severity {
        None => tr!("any severity").to_string(),
        Some(Severity::Critical) => tr!("only {severity}", severity = Severity::Critical.label()),
        Some(s) => format!("≥ {}", s.label()),
    };
    let search = if app.searching {
        Span::styled(format!(" {}▏", app.search), active)
    } else if app.search.is_empty() {
        value(format!(" {}", tr!("search")), false)
    } else {
        value(format!(" \"{}\"", app.search), true)
    };
    let spans = vec![
        key("a"),
        value(format!(" {}   ", if app.view == View::Open { tr!("open") } else { tr!("all") }), app.view == View::All),
        key("s"),
        value(format!(" {sev}   "), app.min_severity.is_some()),
        key("c"),
        value(format!(" {}   ", app.category.as_deref().unwrap_or(tr!("any category"))), app.category.is_some()),
        key("/"),
        search,
    ];
    f.render_widget(Paragraph::new(Line::from(spans)), area);
    if area.width > 100 {
        let count = Line::styled(format!("{} ", tr!("{shown} of {total}", shown = app.visible.len(), total = r.results.len())), theme.text_muted())
            .right_aligned();
        f.render_widget(Paragraph::new(count), area);
    }
}

fn draw_findings_table(f: &mut Frame, area: Rect, app: &mut App, theme: &Theme, r: &Report) {
    let title = if app.view == View::Open { tr!("Open findings") } else { tr!("All checks") };
    let block = rounded(theme, true).title(card_title(title, theme));
    if app.visible.is_empty() {
        let msg = if !app.filtered() && app.view == View::Open {
            vec![
                Line::raw(""),
                Line::styled(format!("✓ {}", tr!("No open findings")), Style::new().fg(theme.ok).add_modifier(Modifier::BOLD)),
                Line::styled(tr!("a shows every check"), theme.text_muted()),
            ]
        } else {
            vec![
                Line::raw(""),
                Line::styled(tr!("Nothing matches the filters"), theme.text_muted()),
                Line::styled(tr!("x clears them"), theme.text_muted()),
            ]
        };
        f.render_widget(Paragraph::new(msg).alignment(Alignment::Center).block(block), area);
        return;
    }
    let show_cat = area.width > 80;
    let all_names = ["", tr!("SEVERITY"), "ID", tr!("CHECK"), tr!("CATEGORY")];
    let names: &[&str] = if show_cat { &all_names } else { &all_names[..4] };
    let header = Row::new(names.iter().map(|h| Cell::from(Span::styled(*h, theme.text_muted().add_modifier(Modifier::BOLD)))));
    let rows: Vec<Row> = app.visible.iter().map(|&i| finding_row(theme, &r.results[i], show_cat)).collect();
    let table = Table::new(rows, finding_widths(show_cat))
        .header(header)
        .block(block.padding(Padding::horizontal(1)))
        .column_spacing(2)
        .row_highlight_style(theme.selected())
        .highlight_symbol("▌");
    f.render_stateful_widget(table, area, &mut app.findings);

    let visible_rows = area.height.saturating_sub(3) as usize;
    if app.visible.len() > visible_rows {
        let mut sb = ScrollbarState::new(app.visible.len()).position(app.findings.selected().unwrap_or(0));
        f.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(None)
                .end_symbol(None)
                .track_symbol(Some("│"))
                .track_style(theme.border())
                .thumb_style(Style::new().fg(theme.accent)),
            area.inner(Margin::new(0, 1)),
            &mut sb,
        );
    }
}

fn section<'a>(title: &'a str, theme: &Theme) -> Line<'a> {
    Line::styled(title, theme.text_muted().add_modifier(Modifier::BOLD))
}

fn draw_detail(f: &mut Frame, area: Rect, app: &App, theme: &Theme, r: &Report) {
    // durante el dibujo el reporte está fuera de `app`, así que se busca en `r`
    let Some(x) = app.findings.selected().and_then(|i| app.visible.get(i)).map(|&i| &r.results[i]) else {
        let block = rounded(theme, false).title(card_title(tr!("Details"), theme));
        f.render_widget(
            Paragraph::new(Span::styled(tr!("Pick a check from the list"), theme.text_muted())).block(block),
            area,
        );
        return;
    };
    let mut block = rounded(theme, false)
        .title(Line::from(vec![Span::raw(" "), Span::styled(x.id.as_str(), theme.title()), Span::raw(" ")]))
        .padding(Padding::new(1, 1, 0, 0));
    if !x.fix.is_empty() {
        block = block.title_bottom(Line::from(key_hint(theme, "y", tr!("copy fix"))).right_aligned());
    }
    let mut lines = vec![
        Line::from(vec![
            sev_pill(theme, x.severity),
            Span::raw("  "),
            status_icon(theme, x.status),
            Span::styled(format!(" {}", status_label(x.status)), Style::new().fg(theme.status_color(x.status))),
            Span::styled(format!("  ·  {}", x.category), theme.text_muted()),
        ]),
        Line::raw(""),
        Line::styled(x.title.as_str(), Style::new().add_modifier(Modifier::BOLD)),
    ];
    if !x.detail.is_empty() {
        lines.push(Line::raw(""));
        lines.push(section(tr!("WHAT WAS FOUND"), theme));
        lines.push(Line::raw(x.detail.as_str()));
    }
    if !x.fix.is_empty() {
        lines.push(Line::raw(""));
        lines.push(section(tr!("HOW TO FIX IT"), theme));
        lines.push(Line::from(vec![
            Span::styled("› ", Style::new().fg(theme.ok)),
            Span::styled(x.fix.as_str(), Style::new().fg(theme.ok)),
        ]));
    }
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }).block(block), area);
}

// ───────────────────────────────────────────────────────────── categorías

fn draw_categories_tab(f: &mut Frame, area: Rect, app: &mut App, theme: &Theme, r: &Report) {
    let (list, detail) = if area.width >= 100 {
        let [l, d] = Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)]).areas(area);
        (l, Some(d))
    } else if area.height >= 24 {
        let [l, d] = Layout::vertical([Constraint::Fill(1), Constraint::Length(11)]).areas(area);
        (l, Some(d))
    } else {
        (area, None)
    };

    let bar_w = (list.width.saturating_sub(48) as usize).clamp(8, 30);
    let rows: Vec<Row> = r
        .score
        .categories
        .iter()
        .map(|c| {
            let ratio = c.pct / 100.0;
            let fails = if c.fails > 0 { format!("✖ {}", c.fails) } else { String::new() };
            Row::new(vec![
                Cell::from(Span::styled(c.name.as_str(), Style::new().add_modifier(Modifier::BOLD))),
                Cell::from(Line::from(text_bar(theme, ratio, bar_w))),
                Cell::from(Line::styled(format!("{:.0}%", c.pct), Style::new().fg(theme.grade(ratio))).right_aligned()),
                Cell::from(Line::styled(fails, Style::new().fg(theme.bad)).right_aligned()),
                Cell::from(Line::styled(c.checks.to_string(), theme.text_muted()).right_aligned()),
            ])
        })
        .collect();
    let header = Row::new(
        [tr!("CATEGORY"), tr!("COMPLIANCE"), "", tr!("FAILING"), tr!("CHECKS")]
            .map(|h| Cell::from(Line::styled(h, theme.text_muted().add_modifier(Modifier::BOLD)))),
    );
    let widths = [
        Constraint::Length(12),
        Constraint::Length(bar_w as u16),
        Constraint::Length(5),
        Constraint::Length(7),
        Constraint::Length(9),
    ];
    let table = Table::new(rows, widths)
        .header(header)
        .block(
            rounded(theme, true)
                .title(card_title(tr!("Categories"), theme))
                .title_bottom(Line::from(key_hint(theme, "Enter", tr!("see checks"))).right_aligned())
                .padding(Padding::new(1, 1, 1, 0)),
        )
        .column_spacing(2)
        .row_highlight_style(theme.selected())
        .highlight_symbol("▌");
    f.render_stateful_widget(table, list, &mut app.categories_state);

    let (Some(detail), Some(sel)) = (detail, app.categories_state.selected().and_then(|i| r.score.categories.get(i)))
    else {
        return;
    };
    let desc = checks::MODULES.iter().find(|m| m.category == sel.name).map_or("", |m| m.label());
    let count = |s: Status| r.results.iter().filter(|x| x.category == sel.name && x.status == s).count() as u64;
    let block = rounded(theme, false)
        .title(Line::from(vec![Span::raw(" "), Span::styled(sel.name.as_str(), theme.title()), Span::raw(" ")]))
        .padding(Padding::new(1, 1, 0, 0));
    let inner = block.inner(detail);
    f.render_widget(block, detail);
    let [d, _, chart, _, open_area] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Length(1),
        Constraint::Length(6),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .areas(inner);
    let mut open: Vec<&CheckResult> = r.results.iter().filter(|x| x.category == sel.name && x.status.is_open()).collect();
    open.sort_by_key(|x| super::app::sort_key(x));
    let mut lines = vec![section(if open.is_empty() { tr!("NO OPEN FINDINGS") } else { tr!("OPEN FINDINGS") }, theme)];
    lines.extend(open.iter().map(|x| {
        Line::from(vec![
            status_icon(theme, x.status),
            Span::raw(" "),
            Span::styled(format!("{:<8}", x.id), Style::new().fg(theme.sev_color(x.severity))),
            Span::raw(x.title.as_str()),
        ])
    }));
    f.render_widget(Paragraph::new(lines), open_area);
    f.render_widget(Paragraph::new(Span::styled(desc, theme.text_muted())).wrap(Wrap { trim: true }), d);
    let bars: Vec<Bar> = [
        (Status::Pass, trc!("category chart", "pass")),
        (Status::Fail, trc!("category chart", "fail")),
        (Status::Warn, trc!("category chart", "warn")),
        (Status::Na, trc!("category chart", "n/a")),
        (Status::Error, trc!("category chart", "not evaluated")),
        (Status::Waived, trc!("category chart", "waived")),
    ]
    .iter()
    .map(|(s, label)| {
        let v = count(*s);
        let c = theme.status_color(*s);
        Bar::default()
            .value(v)
            .text_value(format!("{v} {label}"))
            .style(Style::new().fg(c))
            .value_style(Style::new().fg(if theme.mono() { Color::Reset } else { theme.on_color }).bg(c))
    })
    .collect();
    f.render_widget(
        BarChart::default()
            .direction(Direction::Horizontal)
            .data(BarGroup::default().bars(&bars))
            .bar_width(1)
            .bar_gap(0)
            .bar_set(symbols::bar::NINE_LEVELS),
        chart,
    );
}

// ───────────────────────────────────────────────────────────── pie y ventanas

fn draw_footer(f: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let hints: Vec<(&str, &str)> = if app.searching {
        vec![("Enter", tr!("accept")), ("Esc", tr!("clear")), ("⌫", tr!("delete"))]
    } else if app.report.is_none() {
        vec![("q", tr!("cancel"))]
    } else {
        let mut h = vec![("↑↓", tr!("move")), ("Tab", tr!("tab"))];
        match app.tab {
            Tab::Summary | Tab::Categories => h.push(("Enter", trc!("action", "open"))),
            Tab::Findings => h.extend([
                ("a", tr!("view")),
                ("s", tr!("severity")),
                ("c", tr!("category")),
                ("/", tr!("search")),
                ("y", tr!("copy")),
                ("x", tr!("clear filters")),
            ]),
        }
        h.extend([("p", tr!("profile")), ("?", tr!("help")), ("q", tr!("quit"))]);
        h
    };
    // si no entra todo, se recortan desde el final (pero "q" siempre queda)
    let width = |h: &[(&str, &str)]| h.iter().map(|(k, l)| k.chars().count() + l.chars().count() + 5).sum::<usize>();
    let mut h = hints;
    while width(&h) + 1 > area.width as usize && h.len() > 2 {
        let last = h.pop();
        h.pop();
        h.extend(last);
    }
    let spans: Vec<Span> =
        std::iter::once(Span::raw(" ")).chain(h.iter().flat_map(|(k, l)| key_hint(theme, k, l))).collect();
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_toast(f: &mut Frame, area: Rect, msg: &str, theme: &Theme) {
    let w = (msg.chars().count() as u16 + 8).min(area.width);
    let [_, row] = Layout::vertical([Constraint::Fill(1), Constraint::Length(3)]).areas(area);
    let [_, cell] = Layout::horizontal([Constraint::Fill(1), Constraint::Length(w)]).areas(row);
    f.render_widget(Clear, cell);
    f.render_widget(
        Paragraph::new(Line::from(vec![Span::styled("✓ ", Style::new().fg(theme.ok)), Span::raw(msg)])).block(
            Block::bordered()
                .border_type(BorderType::Rounded)
                .border_style(Style::new().fg(theme.ok))
                .padding(Padding::horizontal(1)),
        ),
        cell,
    );
}

fn draw_help(f: &mut Frame, area: Rect, theme: &Theme) {
    type Group<'a> = (&'a str, &'a [(&'a str, &'a str)]);
    let groups: &[Group] = &[
        (
            tr!("General"),
            &[
                ("1 2 3", tr!("go to Summary / Findings / Categories")),
                ("Tab ⇧Tab", tr!("next / previous tab")),
                ("↑↓ j k", tr!("move")),
                ("PgUp PgDn", tr!("by 10")),
                ("g G", tr!("first / last")),
                ("Enter", tr!("open the selected item")),
                ("p", tr!("change profile and audit again")),
                ("q Esc", tr!("quit")),
            ],
        ),
        (
            tr!("Findings"),
            &[
                ("a", tr!("open ↔ all checks")),
                ("s", tr!("minimum severity")),
                ("c", tr!("category")),
                ("/", tr!("search in ID, title, details and fix")),
                ("x", tr!("clear the filters")),
                ("y", tr!("copy the fix (OSC 52, works over SSH)")),
            ],
        ),
    ];
    let mut lines = Vec::new();
    for (g, rows) in groups {
        lines.push(Line::styled(*g, theme.title()));
        for (k, d) in *rows {
            lines.push(Line::from(vec![
                Span::styled(format!("  {k:<12}"), Style::new().add_modifier(Modifier::BOLD)),
                Span::styled(*d, theme.text_muted()),
            ]));
        }
        lines.push(Line::raw(""));
    }
    lines.push(Line::from(vec![
        Span::styled(format!("{}  ", tr!("Symbols")), theme.title()),
        status_icon(theme, Status::Fail),
        Span::raw(format!(" {}  ", trc!("legend", "fails"))),
        status_icon(theme, Status::Warn),
        Span::raw(format!(" {}  ", trc!("legend", "warning"))),
        status_icon(theme, Status::Pass),
        Span::raw(format!(" {}  ", trc!("legend", "passes"))),
        status_icon(theme, Status::Na),
        Span::raw(format!(" {}  ", trc!("legend", "not applicable"))),
        status_icon(theme, Status::Waived),
        Span::raw(format!(" {}  ", trc!("legend", "waived"))),
        status_icon(theme, Status::Error),
        Span::raw(format!(" {}", trc!("legend", "not evaluated"))),
    ]));
    let h = (lines.len() as u16 + 3).min(area.height);
    let [v] = Layout::vertical([Constraint::Length(h)]).flex(Flex::Center).areas(area);
    let [cell] = Layout::horizontal([Constraint::Length(84.min(area.width))]).flex(Flex::Center).areas(v);
    f.render_widget(Clear, cell);
    f.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            rounded(theme, true)
                .title(card_title(tr!("Shortcuts"), theme))
                .title_bottom(Line::styled(format!(" {} ", tr!("any key closes")), theme.text_muted()).right_aligned())
                .padding(Padding::horizontal(2)),
        ),
        cell,
    );
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::tui::app::tests::{app, new_app};
    use crate::tui::theme::ColorMode;
    use ratatui::backend::TestBackend;
    use ratatui::crossterm::event::{KeyCode, KeyEvent};

    pub(crate) fn render(w: u16, h: u16, app: &mut App, mode: ColorMode) -> String {
        let theme = Theme::new(mode);
        let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
        t.draw(|f| draw(f, app, &theme)).unwrap();
        let buf = t.backend().buffer().clone();
        (0..h)
            .map(|y| (0..w).map(|x| buf[(x, y)].symbol().to_string()).collect::<String>().trim_end().to_string())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn todas_las_pestanas_en_varios_tamanos() {
        for mode in [ColorMode::TrueColor, ColorMode::Ansi, ColorMode::Mono] {
            for (w, h) in [(30, 10), (50, 16), (80, 24), (120, 40), (200, 60)] {
                for tab in ['1', '2', '3'] {
                    let mut a = app();
                    a.on_key(KeyEvent::from(KeyCode::Char(tab)));
                    let out = render(w, h, &mut a, mode);
                    if w < MIN_W || h < MIN_H {
                        assert!(out.contains("Terminal muy chica"));
                        continue;
                    }
                    assert!(out.contains("linaudit"), "{w}×{h} pestaña {tab}:\n{out}");
                    match tab {
                        '1' => assert!(out.contains("Lo más urgente"), "{w}×{h}:\n{out}"),
                        '2' => assert!(out.contains("ACC-004"), "{w}×{h}:\n{out}"),
                        _ => assert!(out.contains("accounts"), "{w}×{h}:\n{out}"),
                    }
                    a.show_help = true;
                    assert!(render(w, h, &mut a, mode).contains("Atajos"), "{w}×{h}");
                }
            }
        }
    }

    #[test]
    fn bienvenida_en_varios_tamanos() {
        for mode in [ColorMode::TrueColor, ColorMode::Ansi, ColorMode::Mono] {
            for (w, h) in [(50, 16), (80, 24), (100, 40), (140, 45), (200, 60)] {
                let mut a = new_app(true);
                let out = render(w, h, &mut a, mode);
                assert!(out.contains("Escritorio"), "{w}×{h}:\n{out}");
                assert!(out.contains("Enter"), "{w}×{h}:\n{out}");
                if h >= 24 {
                    assert!(out.contains("detectado"), "{w}×{h}:\n{out}");
                }
                if w >= 100 && h >= 40 {
                    assert!(out.contains("██╗"), "logo grande en {w}×{h}:\n{out}");
                    assert!(out.contains("Alexia Michelle"), "{w}×{h}:\n{out}");
                }
            }
        }
    }

    #[test]
    fn selector_de_idioma_con_vista_previa() {
        use linaudit_core::i18n::Lang;
        for (w, h) in [(50, 16), (80, 24), (120, 40)] {
            let mut a = new_app(true);
            a.prefs_path = Some("~/.config/linaudit/config.toml".into());
            a.open_lang_picker(true);
            a.lang_picker = Some(Lang::ALL.iter().position(|l| *l == Lang::En).unwrap());
            let out = render(w, h, &mut a, ColorMode::TrueColor);
            assert!(out.contains("Español") && out.contains("English"), "{w}×{h}:\n{out}");
            // la pregunta va en los dos idiomas y el resto de la pantalla, en el resaltado
            assert!(out.contains("Elegí el idioma · Choose the language"), "{w}×{h}:\n{out}");
            if h >= 24 {
                assert!(out.contains("This system"), "{w}×{h}:\n{out}");
                assert!(out.contains("config.toml"), "{w}×{h}:\n{out}");
            }
            assert!(!out.contains("Este sistema"), "{w}×{h}:\n{out}");
        }
    }

    #[test]
    fn interfaz_en_ingles() {
        use linaudit_core::i18n::{Lang, with_lang};
        let mut a = app();
        let out = with_lang(Lang::En, || render(120, 40, &mut a, ColorMode::TrueColor));
        assert!(out.contains("Most urgent") && out.contains("Summary"), "{out}");
        assert!(!out.contains("Lo más urgente"), "{out}");
        let mut w = new_app(true);
        let out = with_lang(Lang::En, || render(120, 40, &mut w, ColorMode::TrueColor));
        assert!(out.contains("What kind of system is this?") && out.contains("language"), "{out}");
        assert!(out.contains("License AGPL v3.0 or later"), "{out}");
    }

    #[test]
    fn progreso_muestra_los_modulos() {
        let mut a = new_app(false);
        a.module_started("accounts");
        a.module_started("ssh");
        let out = render(100, 30, &mut a, ColorMode::TrueColor);
        assert!(out.contains("Auditando"), "{out}");
        assert!(out.contains("✓ accounts"), "{out}");
        assert!(out.contains("SSH…"), "{out}");
    }

    #[test]
    fn progreso_con_todos_los_modulos_reales() {
        let modules: Vec<_> = linaudit_core::checks::MODULES.iter().map(|m| (m.category, m.description)).collect();
        let mut a = App::new(&modules, false, crate::tui::app::tests::detection(), crate::tui::app::tests::system(), false);
        a.module_started(modules[0].0);
        let out = render(80, 24, &mut a, ColorMode::TrueColor);
        for (cat, _) in &modules {
            assert!(out.contains(cat), "falta {cat} en 80×24:\n{out}");
        }
    }

    #[test]
    fn detalle_del_hallazgo() {
        let mut a = app();
        a.on_key(KeyEvent::from(KeyCode::Char('2')));
        let out = render(140, 40, &mut a, ColorMode::TrueColor);
        assert!(out.contains("CÓMO ARREGLARLO"), "{out}");
        assert!(out.contains("Exigir password"), "{out}");
    }
}

/// Vista previa sin terminal: `cargo test -p linaudit preview -- --ignored --nocapture`
#[cfg(test)]
mod preview {
    use super::tests::render;
    use crate::tui::app::tests::app;
    use crate::tui::theme::ColorMode;
    use ratatui::crossterm::event::{KeyCode, KeyEvent};

    #[test]
    #[ignore]
    fn preview_bienvenida() {
        for (w, h) in [(140, 42), (90, 30)] {
            let mut a = crate::tui::app::tests::new_app(true);
            println!("── bienvenida {w}×{h}\n{}", render(w, h, &mut a, ColorMode::TrueColor));
        }
    }

    #[test]
    #[ignore]
    fn preview() {
        for (w, h) in [(140, 40), (90, 28)] {
            for tab in ['1', '2', '3'] {
                let mut a = app();
                a.finished_at = Some(std::time::Instant::now() - std::time::Duration::from_secs(5));
                a.on_key(KeyEvent::from(KeyCode::Char(tab)));
                println!("── {w}×{h} pestaña {tab}\n{}", render(w, h, &mut a, ColorMode::TrueColor));
            }
        }
    }
}
