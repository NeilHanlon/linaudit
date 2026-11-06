//! Menú interactivo para elegir el perfil (↑↓ + Enter), dibujado en línea con ratatui:
//! no ocupa la pantalla completa y al terminar deja una sola línea con la elección.

use std::io::{self, Write};

use linaudit_core::{Profile, tr};
use linaudit_core::profile::Detection;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use ratatui::layout::{Constraint, Layout};
use ratatui::prelude::*;
use ratatui::widgets::{List, ListItem, ListState, Paragraph, Wrap};
use ratatui::{TerminalOptions, Viewport};

const HEIGHT: u16 = 14;

/// Devuelve el perfil elegido, o `None` si la persona canceló (q, Esc, Ctrl-C).
pub fn choose_profile(det: &Detection, header: &str) -> io::Result<Option<Profile>> {
    enable_raw_mode()?;
    // si algo falla a mitad de camino, la terminal no debe quedar en modo raw
    struct RawGuard;
    impl Drop for RawGuard {
        fn drop(&mut self) {
            let _ = disable_raw_mode();
        }
    }
    let _guard = RawGuard;

    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::with_options(backend, TerminalOptions { viewport: Viewport::Inline(HEIGHT) })?;

    let detected = Profile::ALL.iter().position(|p| *p == det.profile).unwrap_or(0);
    let mut state = ListState::default().with_selected(Some(detected));

    let choice = loop {
        terminal.draw(|f| draw(f, det, header, detected, &mut state))?;
        let Event::Key(k) = event::read()? else { continue };
        if k.kind != KeyEventKind::Press {
            continue;
        }
        let n = Profile::ALL.len();
        let i = state.selected().unwrap_or(0);
        match k.code {
            KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => break None,
            KeyCode::Char('q') | KeyCode::Esc => break None,
            KeyCode::Up | KeyCode::Char('k') => state.select(Some((i + n - 1) % n)),
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => state.select(Some((i + 1) % n)),
            KeyCode::Char(c @ '1'..='9') => {
                let idx = c as usize - '1' as usize;
                if idx < n {
                    state.select(Some(idx));
                }
            }
            KeyCode::Enter => break Some(Profile::ALL[i]),
            _ => {}
        }
    };

    terminal.clear()?;
    drop(terminal);
    drop(_guard);
    let mut out = io::stdout();
    match choice {
        Some(p) => {
            let how = if p == det.profile { tr!("detected") } else { tr!("chosen") };
            let msg = tr!(
                "Profile: {profile} ({how}) · to automate: --profile {id}",
                profile = p.label(),
                how = how,
                id = p.id()
            );
            writeln!(out, " {msg}")?;
        }
        None => writeln!(out, " {}", tr!("Cancelled."))?,
    }
    out.flush()?;
    Ok(choice)
}

fn draw(f: &mut Frame, det: &Detection, header: &str, detected: usize, state: &mut ListState) {
    let area = f.area();
    let [head, question, list, desc, why, keys, tip] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Length(2),
        Constraint::Length(Profile::ALL.len() as u16 + 1),
        Constraint::Length(3),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .horizontal_margin(1)
    .areas(area);

    f.render_widget(Paragraph::new(Line::from(header.to_string()).bold()), head);
    f.render_widget(Paragraph::new(tr!("What kind of system is this?")), question);

    let items: Vec<ListItem> = Profile::ALL
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let mut spans = vec![Span::raw(format!("{:<26}", p.label()))];
            if i == detected {
                spans.push(Span::styled(tr!("(detected)"), Style::new().fg(Color::Green)));
            }
            ListItem::new(Line::from(spans))
        })
        .collect();
    let list_widget = List::new(items)
        .highlight_symbol(" ▸ ")
        .highlight_spacing(ratatui::widgets::HighlightSpacing::Always)
        .highlight_style(Style::new().fg(Color::Cyan).bold());
    f.render_stateful_widget(list_widget, list, state);

    let sel = Profile::ALL[state.selected().unwrap_or(0)];
    f.render_widget(
        Paragraph::new(sel.description()).wrap(Wrap { trim: true }).style(Style::new().dim()),
        desc,
    );
    f.render_widget(
        Paragraph::new(tr!("Auto-detection: {reasons}", reasons = det.reasons.join(", "))).style(Style::new().dim()),
        why,
    );
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("↑↓", Style::new().bold()),
            Span::raw(format!(" {} · ", tr!("choose"))),
            Span::styled("Enter", Style::new().bold()),
            Span::raw(format!(" {} · ", tr!("confirm"))),
            Span::styled("q", Style::new().bold()),
            Span::raw(format!(" {}", tr!("quit"))),
        ])),
        keys,
    );
    f.render_widget(
        Paragraph::new(tr!("Tip: for cron or scripts use --profile {id}", id = sel.id())).style(Style::new().dim()),
        tip,
    );
}
