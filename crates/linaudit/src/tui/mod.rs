//! Interfaz interactiva a pantalla completa. La auditoría corre en otro hilo y
//! le avisa a la interfaz qué módulo está corriendo, para mostrar el progreso en vivo.

mod app;
mod theme;
mod ui;
mod welcome;
mod widgets;

pub use theme::ColorMode;

use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use linaudit_core::profile::Detection;
use linaudit_core::{AuditOptions, ProfileSource, Report, checks, i18n, profile, tr};
use ratatui::crossterm::event::{self, Event, KeyEventKind};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode};
use ratatui::prelude::*;

use app::{Action, App, SystemInfo};

/// Nombre del hilo de la auditoría: el hook de pánico lo usa para no ensuciar la pantalla
/// con los pánicos de módulos, que ya quedan registrados como ERROR en el reporte.
pub const AUDIT_THREAD: &str = "linaudit-audit";

/// true mientras la terminal está en modo raw + pantalla alternativa.
pub static ACTIVE: AtomicBool = AtomicBool::new(false);

/// Deja la terminal como estaba. Se puede llamar más de una vez.
pub fn restore_terminal() {
    if ACTIVE.swap(false, Ordering::SeqCst) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen, ratatui::crossterm::cursor::Show);
    }
}

struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        restore_terminal();
    }
}

enum Msg {
    Module(&'static str),
    Done(Box<Report>),
}

/// Cómo arranca la TUI.
pub struct Start {
    pub opts: AuditOptions,
    pub timestamp: String,
    pub start_all: bool,
    pub color: ColorMode,
    /// Autodetección (para la pantalla de bienvenida y para preseleccionar el perfil).
    pub detection: Detection,
    /// Mostrar la bienvenida para elegir el perfil antes de auditar.
    pub welcome: bool,
    /// Empezar la bienvenida preguntando el idioma (primera vez).
    pub ask_language: bool,
}

fn spawn_audit(opts: AuditOptions, timestamp: String) -> io::Result<mpsc::Receiver<Msg>> {
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new().name(AUDIT_THREAD.into()).spawn(move || {
        let progress = tx.clone();
        let report = linaudit_core::audit(&opts, timestamp, |m| {
            let _ = progress.send(Msg::Module(m.category));
        });
        let _ = tx.send(Msg::Done(Box::new(report)));
    })?;
    Ok(rx)
}

/// Corre la TUI (bienvenida → análisis → resultados). Devuelve el último reporte,
/// o `None` si se salió antes de que terminara alguno.
pub fn run(start: Start) -> io::Result<Option<Report>> {
    let Start { mut opts, timestamp, start_all, color, detection, welcome, ask_language } = start;
    let modules: Vec<(&'static str, &'static str)> = checks::MODULES
        .iter()
        .filter(|m| opts.categories.is_empty() || opts.categories.iter().any(|c| c == m.category))
        .map(|m| (m.category, m.description))
        .collect();

    let mut rx = if welcome { None } else { Some(spawn_audit(opts.clone(), timestamp.clone())?) };

    enable_raw_mode()?;
    ACTIVE.store(true, Ordering::SeqCst);
    let _guard = Guard;
    execute!(io::stdout(), EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;

    let theme = theme::Theme::new(color);
    let mut app = App::new(&modules, start_all, detection, SystemInfo::probe(), welcome);
    app.prefs_path = crate::lang::prefs_path().map(|p| crate::lang::display_path(&p));
    if ask_language {
        app.open_lang_picker(true);
    }
    let mut dirty = true;
    loop {
        if let Some(r) = &rx {
            while let Ok(msg) = r.try_recv() {
                match msg {
                    Msg::Module(c) => app.module_started(c),
                    Msg::Done(r) => app.finished(*r),
                }
                dirty = true;
            }
        }
        app.expire_toast();
        // se redibuja si cambió algo o mientras haya una animación en curso (~30 fps)
        let animating = if app.welcome.is_some() { app.toast.is_some() } else { app.animating() };
        if dirty || animating {
            terminal.draw(|f| ui::draw(f, &mut app, &theme))?;
            dirty = false;
        }
        let wait = if animating { Duration::from_millis(33) } else { Duration::from_millis(250) };
        if !event::poll(wait)? {
            continue;
        }
        dirty = true;
        match event::read()? {
            Event::Key(k) if k.kind == KeyEventKind::Press => match app.on_key(k) {
                Action::Quit => break,
                Action::Copy(text) => copy_osc52(&text)?,
                Action::Start(profile) => {
                    opts.profile = profile;
                    opts.profile_source = ProfileSource::Menu;
                    app.start_audit();
                    rx = Some(spawn_audit(opts.clone(), timestamp.clone())?);
                }
                Action::SetLanguage(lang) => {
                    i18n::set_lang(lang);
                    // las razones de la autodetección son texto: se recalculan en el idioma nuevo
                    app.detection = profile::detect();
                    match crate::lang::save(lang) {
                        Ok(p) => app.notify_long(tr!(
                            "Language saved in {path}. Delete that file to choose again.",
                            path = crate::lang::display_path(&p)
                        )),
                        Err(e) => app.notify(tr!("Could not save the language: {e}", e = e)),
                    }
                }
                Action::None => {}
            },
            _ => {}
        }
    }
    Ok(app.report)
}

/// Copia al portapapeles con la secuencia OSC 52 (la soportan la mayoría de las terminales,
/// también a través de SSH y tmux con `set-clipboard on`).
fn copy_osc52(text: &str) -> io::Result<()> {
    let mut out = io::stdout();
    write!(out, "\x1b]52;c;{}\x07", base64(text.as_bytes()))?;
    out.flush()
}

fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                s.push(T[(n >> (18 - 6 * i)) as usize & 63] as char);
            } else {
                s.push('=');
            }
        }
    }
    s
}

#[cfg(test)]
mod tests {
    #[test]
    fn base64_rfc4648() {
        for (i, o) in [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foobar", "Zm9vYmFy"), ("ñ", "w7E=")] {
            assert_eq!(super::base64(i.as_bytes()), o);
        }
    }
}
