//! Componentes visuales propios: anillo de puntaje (Canvas braille), dígitos grandes, etiquetas, spinner.

use std::f64::consts::PI;

use linaudit_core::{Severity, tr};
use ratatui::buffer::Buffer;
use ratatui::layout::{Alignment, Constraint, Flex, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::symbols::Marker;
use ratatui::text::{Line, Span};
use ratatui::widgets::canvas::{Canvas, Points};
use ratatui::widgets::{Paragraph, Widget};

use super::theme::Theme;

pub const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// Dígitos de 3×3 celdas con medios bloques.
fn glyph(c: char) -> [&'static str; 3] {
    match c {
        '0' => ["█▀█", "█ █", "▀▀▀"],
        '1' => ["▀█ ", " █ ", "▀▀▀"],
        '2' => ["▀▀█", "█▀▀", "▀▀▀"],
        '3' => ["▀▀█", " ▀█", "▀▀▀"],
        '4' => ["█ █", "▀▀█", "  ▀"],
        '5' => ["█▀▀", "▀▀█", "▀▀▀"],
        '6' => ["█▀▀", "█▀█", "▀▀▀"],
        '7' => ["▀▀█", "  █", "  ▀"],
        '8' => ["█▀█", "█▀█", "▀▀▀"],
        '9' => ["█▀█", "▀▀█", "▀▀▀"],
        '?' => ["▀▀█", " ▀ ", " ▀ "],
        _ => ["   ", "   ", "   "],
    }
}

/// Texto grande de 3 filas (solo dígitos y '?').
pub fn big_text(s: &str) -> [String; 3] {
    let mut rows = [String::new(), String::new(), String::new()];
    for (i, c) in s.chars().enumerate() {
        for (r, part) in glyph(c).iter().enumerate() {
            if i > 0 {
                rows[r].push(' ');
            }
            rows[r].push_str(part);
        }
    }
    rows
}

/// Anillo de puntaje con degradé, y el número grande en el centro.
pub struct ScoreRing<'a> {
    pub theme: &'a Theme,
    /// Puntaje final (None = sin datos).
    pub score: Option<u8>,
    /// Avance de la animación, 0..1.
    pub progress: f64,
}

impl Widget for ScoreRing<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.height < 7 || area.width < 14 {
            return self.render_compact(area, buf);
        }
        // el círculo tiene que ser redondo: con braille cada celda es 2×4 puntos
        // y una celda mide ~1×2, así que el ancho útil es 2× el alto
        let h = area.height;
        let w = (h * 2).min(area.width);
        let [ring] = Layout::horizontal([Constraint::Length(w)]).flex(Flex::Center).areas(area);
        let ax = f64::from(ring.width) / (2.0 * f64::from(ring.height));
        let target = self.score.map_or(0.0, |s| f64::from(s) / 10.0);
        let filled = target * ease_out(self.progress);
        let theme = self.theme;
        let samples = (f64::from(h) * 30.0) as usize;
        let radii: Vec<f64> = (0..6).map(|i| 0.80 + f64::from(i) * 0.034).collect();

        let canvas = Canvas::default()
            .marker(Marker::Braille)
            .x_bounds([-ax, ax])
            .y_bounds([-1.0, 1.0])
            .paint(move |ctx| {
                let point = |t: f64, r: f64| {
                    let a = PI / 2.0 - 2.0 * PI * t;
                    (r * a.cos(), r * a.sin())
                };
                // pista de fondo
                let track: Vec<(f64, f64)> = (0..samples)
                    .map(|i| i as f64 / samples as f64)
                    .filter(|t| *t >= filled)
                    .flat_map(|t| radii.iter().map(move |r| point(t, *r)))
                    .collect();
                // misma capa para pista y arco: en la celda donde se juntan, los puntos braille
                // se combinan (con capas separadas la de arriba tapa a la otra y queda un hueco)
                ctx.draw(&Points { coords: &track, color: theme.track });
                // arco lleno, en tramos con su color del degradé
                const SEGMENTS: usize = 48;
                for seg in 0..SEGMENTS {
                    let t0 = seg as f64 / SEGMENTS as f64;
                    if t0 >= filled {
                        break;
                    }
                    let t1 = ((seg + 1) as f64 / SEGMENTS as f64).min(filled);
                    let n = ((t1 - t0) * samples as f64).ceil().max(1.0) as usize;
                    let pts: Vec<(f64, f64)> = (0..=n)
                        .map(|i| t0 + (t1 - t0) * i as f64 / n as f64)
                        .flat_map(|t| radii.iter().map(move |r| point(t, *r)))
                        .collect();
                    ctx.draw(&Points { coords: &pts, color: theme.grade(t1) });
                }
            });
        canvas.render(ring, buf);

        // número grande + "de 10" en el centro
        let shown = self.score.map(|s| ((f64::from(s) * ease_out(self.progress)).round() as u8).max(1));
        let digits = shown.map_or("?".to_string(), |s| s.to_string());
        let color = shown.map_or(theme.muted, |s| theme.score_color(f64::from(s)));
        let big = big_text(&digits);
        let mut lines: Vec<Line> = big
            .iter()
            .map(|r| Line::styled(r.clone(), Style::new().fg(color).add_modifier(Modifier::BOLD)))
            .collect();
        lines.push(Line::styled(if self.score.is_some() { tr!("out of 10") } else { tr!("no data") }, theme.text_muted()));
        let [mid] = Layout::vertical([Constraint::Length(4)]).flex(Flex::Center).areas(ring);
        Paragraph::new(lines).alignment(Alignment::Center).render(mid, buf);
    }
}

impl ScoreRing<'_> {
    /// Sin lugar para el anillo: número grande y nada más.
    fn render_compact(self, area: Rect, buf: &mut Buffer) {
        let shown = self.score.map(|s| ((f64::from(s) * ease_out(self.progress)).round() as u8).max(1));
        let color = shown.map_or(self.theme.muted, |s| self.theme.score_color(f64::from(s)));
        let text = shown.map_or("?".into(), |s| s.to_string());
        let lines: Vec<Line> = if area.height >= 3 {
            big_text(&text).into_iter().map(|r| Line::styled(r, Style::new().fg(color).add_modifier(Modifier::BOLD))).collect()
        } else {
            vec![Line::styled(format!("{text}/10"), Style::new().fg(color).add_modifier(Modifier::BOLD))]
        };
        Paragraph::new(lines).alignment(Alignment::Center).render(area, buf);
    }
}

/// Curva de animación: rápida al principio, suave al final.
pub fn ease_out(t: f64) -> f64 {
    let t = t.clamp(0.0, 1.0);
    1.0 - (1.0 - t).powi(3)
}

/// ` ALTO ` con fondo del color de la severidad.
pub fn sev_pill(theme: &Theme, s: Severity) -> Span<'static> {
    Span::styled(format!(" {:<7}", s.label()), theme.sev_pill(s))
}

/// Ayuda de teclado: la tecla como etiqueta y la descripción en gris.
pub fn key_hint<'a>(theme: &Theme, key: &'a str, label: &'a str) -> Vec<Span<'a>> {
    let key_style = if theme.mono() {
        Style::new().add_modifier(Modifier::REVERSED)
    } else {
        Style::new().bg(theme.border).fg(ratatui::style::Color::White).add_modifier(Modifier::BOLD)
    };
    vec![Span::styled(format!(" {key} "), key_style), Span::styled(format!(" {label}  "), theme.text_muted())]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digitos_grandes() {
        let t = big_text("10");
        assert_eq!(t[0], "▀█  █▀█");
        assert_eq!(t[2], "▀▀▀ ▀▀▀");
        assert!(t.iter().all(|r| r.chars().count() == 7));
    }

    #[test]
    fn easing() {
        assert_eq!(ease_out(0.0), 0.0);
        assert_eq!(ease_out(1.0), 1.0);
        assert!(ease_out(0.5) > 0.5);
    }
}
