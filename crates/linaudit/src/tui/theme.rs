//! Paleta de colores. Tres variantes según lo que soporte la terminal:
//! truecolor (COLORTERM=truecolor/24bit), 16 colores ANSI, o monocromo (NO_COLOR / --no-color).
//! El fondo nunca se pinta salvo en etiquetas y selección, así funciona en terminales claras y oscuras.

use linaudit_core::{Severity, Status};
use ratatui::style::{Color, Modifier, Style};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorMode {
    TrueColor,
    Ansi,
    Mono,
}

impl ColorMode {
    pub fn detect(no_color: bool) -> Self {
        if no_color || std::env::var_os("NO_COLOR").is_some() {
            return ColorMode::Mono;
        }
        let ct = std::env::var("COLORTERM").unwrap_or_default().to_lowercase();
        if ct.contains("truecolor") || ct.contains("24bit") { ColorMode::TrueColor } else { ColorMode::Ansi }
    }
}

#[derive(Debug, Clone)]
pub struct Theme {
    pub mode: ColorMode,
    pub accent: Color,
    pub accent2: Color,
    pub muted: Color,
    pub border: Color,
    pub track: Color,
    pub ok: Color,
    pub warn: Color,
    pub bad: Color,
    pub critical: Color,
    pub info: Color,
    pub waived: Color,
    /// Texto sobre fondos de color (etiquetas, selección).
    pub on_color: Color,
    pub selection: Color,
}

const fn rgb(r: u8, g: u8, b: u8) -> Color {
    Color::Rgb(r, g, b)
}

impl Theme {
    pub fn new(mode: ColorMode) -> Self {
        match mode {
            // inspirada en Tokyo Night: saturación media, se lee sobre fondos claros y oscuros
            ColorMode::TrueColor => Theme {
                mode,
                accent: rgb(122, 162, 247),
                accent2: rgb(187, 154, 247),
                muted: rgb(120, 128, 155),
                border: rgb(86, 95, 137),
                track: rgb(59, 66, 97),
                ok: rgb(115, 218, 140),
                warn: rgb(224, 175, 104),
                bad: rgb(247, 118, 142),
                critical: rgb(255, 77, 109),
                info: rgb(125, 207, 255),
                waived: rgb(187, 154, 247),
                on_color: rgb(26, 27, 38),
                selection: rgb(61, 89, 161),
            },
            ColorMode::Ansi => Theme {
                mode,
                accent: Color::Blue,
                accent2: Color::Magenta,
                muted: Color::DarkGray,
                border: Color::DarkGray,
                track: Color::DarkGray,
                ok: Color::Green,
                warn: Color::Yellow,
                bad: Color::LightRed,
                critical: Color::Red,
                info: Color::Cyan,
                waived: Color::Magenta,
                on_color: Color::Black,
                selection: Color::Blue,
            },
            ColorMode::Mono => Theme {
                mode,
                accent: Color::Reset,
                accent2: Color::Reset,
                muted: Color::Reset,
                border: Color::Reset,
                track: Color::Reset,
                ok: Color::Reset,
                warn: Color::Reset,
                bad: Color::Reset,
                critical: Color::Reset,
                info: Color::Reset,
                waived: Color::Reset,
                on_color: Color::Reset,
                selection: Color::Reset,
            },
        }
    }

    pub fn mono(&self) -> bool {
        self.mode == ColorMode::Mono
    }

    pub fn text_muted(&self) -> Style {
        if self.mono() { Style::new().add_modifier(Modifier::DIM) } else { Style::new().fg(self.muted) }
    }

    pub fn border(&self) -> Style {
        Style::new().fg(self.border)
    }

    pub fn border_focus(&self) -> Style {
        Style::new().fg(self.accent)
    }

    pub fn title(&self) -> Style {
        Style::new().fg(self.accent).add_modifier(Modifier::BOLD)
    }

    pub fn selected(&self) -> Style {
        if self.mono() {
            Style::new().add_modifier(Modifier::REVERSED)
        } else {
            Style::new().bg(self.selection).fg(Color::White).add_modifier(Modifier::BOLD)
        }
    }

    pub fn sev_color(&self, s: Severity) -> Color {
        match s {
            Severity::Critical => self.critical,
            Severity::High => self.bad,
            Severity::Medium => self.warn,
            Severity::Low => self.info,
            Severity::Info => self.muted,
        }
    }

    /// Etiqueta de severidad: texto oscuro sobre el color de la severidad.
    pub fn sev_pill(&self, s: Severity) -> Style {
        if self.mono() {
            Style::new().add_modifier(Modifier::BOLD)
        } else {
            Style::new().bg(self.sev_color(s)).fg(self.on_color).add_modifier(Modifier::BOLD)
        }
    }

    pub fn status_color(&self, s: Status) -> Color {
        match s {
            Status::Fail => self.bad,
            Status::Warn => self.warn,
            Status::Pass => self.ok,
            Status::Na => self.muted,
            Status::Waived => self.waived,
            Status::Error => self.warn,
        }
    }

    /// Color para un porcentaje de cumplimiento (0..1), con degradé en truecolor.
    pub fn grade(&self, f: f64) -> Color {
        match self.mode {
            ColorMode::Mono => Color::Reset,
            ColorMode::Ansi => {
                if f >= 0.8 {
                    self.ok
                } else if f >= 0.5 {
                    self.warn
                } else {
                    self.bad
                }
            }
            ColorMode::TrueColor => {
                // rojo -> ámbar -> verde
                let stops = [(0.0, self.critical), (0.5, self.warn), (1.0, self.ok)];
                let f = f.clamp(0.0, 1.0);
                let (a, b) = if f <= 0.5 { (stops[0], stops[1]) } else { (stops[1], stops[2]) };
                let t = (f - a.0) / (b.0 - a.0);
                lerp(a.1, b.1, t)
            }
        }
    }

    /// Color del puntaje 1..10.
    pub fn score_color(&self, score: f64) -> Color {
        self.grade((score - 1.0) / 9.0)
    }
}

fn lerp(a: Color, b: Color, t: f64) -> Color {
    match (a, b) {
        (Color::Rgb(r1, g1, b1), Color::Rgb(r2, g2, b2)) => {
            let m = |x: u8, y: u8| (f64::from(x) + (f64::from(y) - f64::from(x)) * t).round() as u8;
            Color::Rgb(m(r1, r2), m(g1, g2), m(b1, b2))
        }
        _ => a,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn degrade_va_de_rojo_a_verde() {
        let t = Theme::new(ColorMode::TrueColor);
        assert_eq!(t.grade(0.0), t.critical);
        assert_eq!(t.grade(0.5), t.warn);
        assert_eq!(t.grade(1.0), t.ok);
        assert_eq!(Theme::new(ColorMode::Ansi).grade(0.9), Color::Green);
    }
}
