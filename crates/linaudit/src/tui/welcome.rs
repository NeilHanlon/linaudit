//! Pantalla de bienvenida: logo, datos del sistema y elección del perfil.

use linaudit_core::i18n::{self, Lang};
use linaudit_core::{Profile, checks, tr};
use ratatui::layout::{Alignment, Constraint, Flex, Layout, Margin, Rect};
use ratatui::prelude::*;
use ratatui::widgets::{Block, BorderType, Padding, Paragraph, Wrap};

use super::app::App;
use super::theme::{ColorMode, Theme};
use super::widgets::key_hint;

fn no_root() -> &'static str {
    tr!("Without root some checks cannot be evaluated (capped at 6/10). Full audit: sudo linaudit")
}

pub const AUTHOR: &str = "Alexia Michelle";
pub const HOMEPAGE: &str = "https://lexiworks.dev/linaudit";

pub fn license() -> &'static str {
    tr!("AGPL v3.0 or later")
}

/// Letras del logo (estilo "ANSI Shadow"), 6 filas cada una.
const LETTERS: &[[&str; 6]] = &[
    ["██╗     ", "██║     ", "██║     ", "██║     ", "███████╗", "╚══════╝"],
    ["██╗", "██║", "██║", "██║", "██║", "╚═╝"],
    ["███╗   ██╗", "████╗  ██║", "██╔██╗ ██║", "██║╚██╗██║", "██║ ╚████║", "╚═╝  ╚═══╝"],
    [" █████╗ ", "██╔══██╗", "███████║", "██╔══██║", "██║  ██║", "╚═╝  ╚═╝"],
    ["██╗   ██╗", "██║   ██║", "██║   ██║", "██║   ██║", "╚██████╔╝", " ╚═════╝ "],
    ["██████╗ ", "██╔══██╗", "██║  ██║", "██║  ██║", "██████╔╝", "╚═════╝ "],
    ["██╗", "██║", "██║", "██║", "██║", "╚═╝"],
    ["████████╗", "╚══██╔══╝", "   ██║   ", "   ██║   ", "   ██║   ", "   ╚═╝   "],
];

pub fn logo_rows() -> [String; 6] {
    let mut rows: [String; 6] = Default::default();
    for letter in LETTERS {
        for (r, part) in letter.iter().enumerate() {
            rows[r].push_str(part);
        }
    }
    rows
}

/// Logo con degradé horizontal (truecolor) o en el color de acento.
fn logo<'a>(theme: &Theme) -> Vec<Line<'a>> {
    let rows = logo_rows();
    let width = rows[0].chars().count().max(1);
    rows.iter()
        .map(|row| {
            if theme.mode != ColorMode::TrueColor {
                return Line::styled(row.clone(), Style::new().fg(theme.accent).add_modifier(Modifier::BOLD));
            }
            let spans: Vec<Span> = row
                .chars()
                .enumerate()
                .map(|(i, c)| {
                    let t = i as f64 / width as f64;
                    Span::styled(c.to_string(), Style::new().fg(mix(theme.accent, theme.accent2, t)))
                })
                .collect();
            Line::from(spans)
        })
        .collect()
}

fn mix(a: Color, b: Color, t: f64) -> Color {
    match (a, b) {
        (Color::Rgb(r1, g1, b1), Color::Rgb(r2, g2, b2)) => {
            let m = |x: u8, y: u8| (f64::from(x) + (f64::from(y) - f64::from(x)) * t).round() as u8;
            Color::Rgb(m(r1, r2), m(g1, g2), m(b1, b2))
        }
        _ => a,
    }
}

fn icon(p: Profile) -> &'static str {
    match p {
        Profile::Server => "▤",
        Profile::Desktop => "▭",
        Profile::Container => "⬡",
    }
}

pub fn draw(f: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    match app.lang_picker {
        // vista previa: toda la pantalla en el idioma resaltado
        Some(i) => i18n::with_lang(Lang::ALL[i], || draw_screen(f, area, app, theme)),
        None => draw_screen(f, area, app, theme),
    }
}

fn draw_screen(f: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let sel = app.welcome.unwrap_or(0);
    let [body, footer] = Layout::vertical([Constraint::Fill(1), Constraint::Length(1)]).areas(area);
    let [col] = Layout::horizontal([Constraint::Max(108)]).flex(Flex::Center).areas(body.inner(Margin::new(2, 0)));

    let big_logo = col.width >= 62 && body.height >= 34;
    let wide_cards = col.width >= 96;
    let logo_h = if big_logo { 6 } else { 1 };
    let cards_h = if wide_cards { 9 } else { 3 * 4 };
    // la tarjeta del sistema crece si el aviso de "sin root" no entra en una línea
    let inner_w = col.width.saturating_sub(4).max(1) as usize;
    let sys_h = if app.system.root { 4 } else { 4 + no_root().chars().count().div_ceil(inner_w) as u16 };
    let credits_text = credits_line(theme, col.width);
    let credits_h = credits_text.width().div_ceil(col.width.max(1) as usize) as u16;
    let [logo_area, tagline, _, sys, _, question, cards, reasons, _, credits] = Layout::vertical([
        Constraint::Length(logo_h),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(sys_h),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(cards_h),
        Constraint::Length(2),
        Constraint::Length(1),
        Constraint::Length(credits_h),
    ])
    .flex(Flex::Center)
    .areas(col);

    if big_logo {
        f.render_widget(Paragraph::new(logo(theme)).alignment(Alignment::Center), logo_area);
    } else {
        let brand = if theme.mono() {
            Style::new().add_modifier(Modifier::REVERSED | Modifier::BOLD)
        } else {
            Style::new().bg(theme.accent).fg(theme.on_color).add_modifier(Modifier::BOLD)
        };
        f.render_widget(Paragraph::new(Span::styled(" ◆ linaudit ", brand)).alignment(Alignment::Center), logo_area);
    }
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(tr!("Read-only security audit for Linux"), theme.text_muted()),
            Span::styled("  ·  ", Style::new().fg(theme.border)),
            Span::styled(format!("v{}", env!("CARGO_PKG_VERSION")), theme.text_muted()),
        ]))
        .alignment(Alignment::Center),
        tagline,
    );

    draw_system(f, sys, app, theme);

    if let Some(lang_sel) = app.lang_picker {
        draw_language(f, [question, cards, reasons, footer], app, theme, lang_sel, wide_cards);
        f.render_widget(Paragraph::new(credits_text).alignment(Alignment::Center).wrap(Wrap { trim: true }), credits);
        return;
    }

    f.render_widget(
        Paragraph::new(Span::styled(tr!("What kind of system is this?"), Style::new().add_modifier(Modifier::BOLD))),
        question,
    );
    draw_cards(f, cards, app, theme, sel, wide_cards);
    f.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                Span::styled(format!("{} ", tr!("Auto-detection:")), theme.text_muted()),
                Span::raw(app.detection.reasons.join(", ")),
            ]),
            Line::styled(
                tr!("To skip this screen (cron, scripts): linaudit --profile {id}", id = Profile::ALL[sel].id()),
                theme.text_muted(),
            ),
        ])
        .wrap(Wrap { trim: true }),
        reasons,
    );

    f.render_widget(Paragraph::new(credits_text).alignment(Alignment::Center).wrap(Wrap { trim: true }), credits);

    let mut spans = vec![Span::raw(" ")];
    let back = if app.report.is_some() { ("Esc", tr!("back")) } else { ("q", tr!("quit")) };
    for (k, l) in [("←→", tr!("choose")), ("Enter", tr!("audit")), ("i", tr!("language")), back] {
        spans.extend(key_hint(theme, k, l));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), footer);
}

/// Selector de idioma: ocupa el lugar de la pregunta, las tarjetas de perfil y el pie.
fn draw_language(f: &mut Frame, [question, cards, note, footer]: [Rect; 4], app: &App, theme: &Theme, sel: usize, wide: bool) {
    // la pregunta va en los dos idiomas: todavía no se sabe cuál lee la persona
    let both: Vec<&str> = Lang::ALL.iter().map(|l| i18n::with_lang(*l, || tr!("Choose the language"))).collect();
    f.render_widget(Paragraph::new(Span::styled(both.join(" · "), Style::new().add_modifier(Modifier::BOLD))), question);

    // tarjetas bajas (una línea de texto) y la nota justo debajo
    let n = Lang::ALL.len();
    let cards_h = if wide { 3 } else { 3 * n as u16 };
    let [cards, _, note] =
        Layout::vertical([Constraint::Length(cards_h), Constraint::Length(1), Constraint::Length(2)]).areas(cards.union(note));
    let areas = if wide {
        Layout::horizontal(vec![Constraint::Ratio(1, n as u32); n]).spacing(2).split(cards)
    } else {
        Layout::vertical(vec![Constraint::Length(3); n]).split(cards)
    };
    for (i, (l, cell)) in Lang::ALL.iter().zip(areas.iter()).enumerate() {
        let selected = i == sel;
        let accent = Style::new().fg(theme.accent).add_modifier(Modifier::BOLD);
        let mut title = vec![
            Span::raw(" "),
            Span::styled(l.native_name(), if selected { accent } else { Style::new().add_modifier(Modifier::BOLD) }),
            Span::raw(" "),
        ];
        if selected {
            title.insert(0, Span::styled(" ▸", Style::new().fg(theme.accent)));
        }
        let mut block = Block::bordered()
            .border_type(if selected { BorderType::Thick } else { BorderType::Rounded })
            .border_style(if selected { accent } else { theme.border() })
            .title(Line::from(title))
            .padding(Padding::horizontal(1));
        if *l == i18n::lang() {
            block = block.title_bottom(Line::styled(format!(" {} ", tr!("preview")), Style::new().fg(theme.ok)).right_aligned());
        }
        let sample = i18n::with_lang(*l, || tr!("Interface, reports and help in this language."));
        let style = if selected { Style::new() } else { theme.text_muted() };
        f.render_widget(Paragraph::new(Line::styled(sample, style)).wrap(Wrap { trim: true }).block(block), *cell);
    }

    let lines = match &app.prefs_path {
        Some(p) => vec![
            Line::styled(tr!("You choose this only once: it is saved in {path}.", path = p), theme.text_muted()),
            Line::styled(tr!("To choose again, delete that file (or use --lang / LINAUDIT_LANG)."), theme.text_muted()),
        ],
        None => vec![Line::styled(tr!("It cannot be saved (no HOME): use --lang or LINAUDIT_LANG."), theme.text_muted())],
    };
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), note);

    let mut spans = vec![Span::raw(" ")];
    let back = if app.lang_required { ("q", tr!("quit")) } else { ("Esc", tr!("back")) };
    for (k, l) in [("←→", tr!("choose")), ("Enter", tr!("confirm")), back] {
        spans.extend(key_hint(theme, k, l));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), footer);
}

/// "Desarrollado por …". En terminales angostas la dirección va sin `https://`.
fn credits_line<'a>(theme: &Theme, width: u16) -> Line<'a> {
    let url = if width >= 96 { HOMEPAGE } else { HOMEPAGE.trim_start_matches("https://") };
    let dot = || Span::styled("  ·  ", Style::new().fg(theme.border));
    Line::from(vec![
        Span::styled(format!("{} ", tr!("Developed by")), theme.text_muted()),
        Span::styled(AUTHOR, Style::new().add_modifier(Modifier::BOLD)),
        dot(),
        Span::styled(url, Style::new().fg(theme.accent).add_modifier(Modifier::UNDERLINED)),
        dot(),
        Span::styled(tr!("License {license}", license = license()), theme.text_muted()),
    ])
}

fn draw_system(f: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let s = &app.system;
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(theme.border())
        .title(Line::from(vec![Span::raw(" "), Span::styled(tr!("This system"), theme.title()), Span::raw(" ")]))
        .padding(Padding::horizontal(1));
    // etiquetas alineadas en dos columnas, sea cual sea el idioma
    let (host, system, kernel, user_l) = (tr!("Host"), tr!("System"), tr!("Kernel"), tr!("User"));
    let w1 = host.chars().count().max(kernel.chars().count()) + 3;
    let w2 = system.chars().count().max(user_l.chars().count()) + 2;
    let label = |t: String| Span::styled(t, theme.text_muted());
    let col1 = |t: &str| label(format!("{t:<w1$}"));
    let col2 = |t: &str| label(format!("      {t:<w2$}"));
    let value = |t: String| Span::styled(t, Style::new().add_modifier(Modifier::BOLD));
    let user = if s.root {
        Span::styled(format!("{} (root)", s.user), Style::new().fg(theme.ok).add_modifier(Modifier::BOLD))
    } else {
        Span::styled(format!("{} ▲ {}", s.user, tr!("not root")), Style::new().fg(theme.warn).add_modifier(Modifier::BOLD))
    };
    let mut lines = vec![
        Line::from(vec![col1(host), value(s.host.clone()), col2(system), value(s.os.clone())]),
        Line::from(vec![
            col1(kernel),
            value(s.kernel.clone()),
            col2(user_l),
            user,
            Span::styled(format!("      {}", tr!("{n} categories", n = checks::MODULES.len())), theme.text_muted()),
        ]),
    ];
    if !s.root {
        lines.push(Line::styled(
            no_root(),
            Style::new().fg(theme.warn),
        ));
    }
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }).block(block), area);
}

fn draw_cards(f: &mut Frame, area: Rect, app: &App, theme: &Theme, sel: usize, wide: bool) {
    let n = Profile::ALL.len();
    let areas = if wide {
        Layout::horizontal(vec![Constraint::Ratio(1, n as u32); n]).spacing(2).split(area)
    } else {
        Layout::vertical(vec![Constraint::Length(4); n]).split(area)
    };
    for (i, (p, cell)) in Profile::ALL.iter().zip(areas.iter()).enumerate() {
        let selected = i == sel;
        let detected = *p == app.detection.profile;
        let border = if selected {
            Style::new().fg(theme.accent).add_modifier(Modifier::BOLD)
        } else {
            theme.border()
        };
        let name_style = if selected {
            Style::new().fg(theme.accent).add_modifier(Modifier::BOLD)
        } else {
            Style::new().add_modifier(Modifier::BOLD)
        };
        let mut title = vec![
            Span::raw(" "),
            Span::styled(format!("{} {}", icon(*p), p.label()), name_style),
            Span::raw(" "),
        ];
        if selected {
            title.insert(0, Span::styled(" ▸", Style::new().fg(theme.accent)));
        }
        let mut block = Block::bordered()
            .border_type(if selected { BorderType::Thick } else { BorderType::Rounded })
            .border_style(border)
            .title(Line::from(title))
            .padding(Padding::horizontal(1));
        if detected {
            block = block.title_bottom(Line::styled(format!(" ✓ {} ", tr!("detected")), Style::new().fg(theme.ok)).right_aligned());
        }
        let adjusted = p.adjusted_ids().len();
        let tail = if adjusted == 0 {
            tr!("No adjustments: original severity.").to_string()
        } else {
            tr!("Adjusts {adjusted} checks.", adjusted = adjusted)
        };
        let text = if wide {
            vec![
                Line::styled(p.summary(), if selected { Style::new() } else { theme.text_muted() }),
                Line::raw(""),
                Line::styled(tail, theme.text_muted()),
            ]
        } else {
            vec![Line::from(vec![
                Span::styled(p.summary(), if selected { Style::new() } else { theme.text_muted() }),
                Span::styled(format!(" {tail}"), theme.text_muted()),
            ])]
        };
        f.render_widget(Paragraph::new(text).wrap(Wrap { trim: true }).block(block), *cell);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logo_rectangular() {
        let rows = logo_rows();
        let w = rows[0].chars().count();
        assert!(rows.iter().all(|r| r.chars().count() == w), "todas las filas del mismo ancho");
        assert_eq!(w, 58);
    }
}
