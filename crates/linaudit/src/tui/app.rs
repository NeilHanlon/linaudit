//! Estado de la TUI y manejo de teclas. Sin nada de dibujo, para poder testearlo.

use std::time::{Duration, Instant};

use linaudit_core::profile::Detection;
use linaudit_core::i18n::{self, Lang};
use linaudit_core::{CheckResult, Profile, Report, Severity, Status, system, tr};
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::widgets::TableState;

/// Duración de la animación del puntaje al terminar el análisis.
pub const SCORE_ANIMATION: Duration = Duration::from_millis(900);
const TOAST_TTL: Duration = Duration::from_millis(2500);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Summary,
    Findings,
    Categories,
}

impl Tab {
    pub const ALL: [Tab; 3] = [Tab::Summary, Tab::Findings, Tab::Categories];

    pub fn title(self) -> &'static str {
        match self {
            Tab::Summary => tr!("Summary"),
            Tab::Findings => tr!("Findings"),
            Tab::Categories => tr!("Categories"),
        }
    }

    fn index(self) -> usize {
        Tab::ALL.iter().position(|t| *t == self).unwrap_or(0)
    }
}

/// Qué controles muestra la lista de hallazgos.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    /// FAIL y WARN.
    Open,
    /// Todos, incluidos aprobados, N/A, excepciones y errores.
    All,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    None,
    Quit,
    /// Copiar texto al portapapeles (OSC 52; funciona también por SSH).
    Copy(String),
    /// Arrancar (o repetir) la auditoría con este perfil.
    Start(Profile),
    /// Cambiar el idioma de la interfaz y guardarlo como preferencia.
    SetLanguage(Lang),
}

/// Lo que la pantalla de bienvenida muestra del sistema.
#[derive(Debug, Clone)]
pub struct SystemInfo {
    pub host: String,
    pub os: String,
    pub kernel: String,
    pub user: String,
    pub root: bool,
}

impl SystemInfo {
    pub fn probe() -> Self {
        SystemInfo {
            host: system::hostname(),
            os: linaudit_core::OsInfo::detect().pretty,
            kernel: std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default().trim().to_string(),
            user: system::effective_uid().and_then(system::user_name).unwrap_or_else(|| "?".into()),
            root: system::is_root(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleState {
    Pending,
    Running,
    Done,
}

pub struct ModuleInfo {
    pub category: &'static str,
    pub description: &'static str,
    pub state: ModuleState,
}

pub struct App {
    /// Pantalla de bienvenida visible, con el índice del perfil elegido en `Profile::ALL`.
    pub welcome: Option<usize>,
    /// Selector de idioma abierto (dentro de la bienvenida), con el índice en `Lang::ALL`.
    pub lang_picker: Option<usize>,
    /// Primera vez: todavía no hay idioma elegido, así que Esc no cierra el selector.
    pub lang_required: bool,
    /// Dónde se guarda la preferencia (para decirle a la persona cómo volver a elegir).
    pub prefs_path: Option<String>,
    pub detection: Detection,
    pub system: SystemInfo,
    pub report: Option<Report>,
    pub modules: Vec<ModuleInfo>,
    pub started: Instant,
    pub finished_at: Option<Instant>,
    pub tab: Tab,
    pub view: View,
    /// Severidad mínima a mostrar (`None` = todas).
    pub min_severity: Option<Severity>,
    /// Categoría filtrada (`None` = todas).
    pub category: Option<String>,
    pub search: String,
    pub searching: bool,
    pub show_help: bool,
    /// Aviso flotante temporal.
    pub toast: Option<(String, Instant)>,
    /// Índices de `report.results` visibles en Hallazgos, ya ordenados.
    pub visible: Vec<usize>,
    pub findings: TableState,
    /// Índices de los hallazgos abiertos, del más grave al menos grave (resumen).
    pub urgent: Vec<usize>,
    pub urgent_state: TableState,
    pub categories_state: TableState,
}

impl App {
    pub fn new(
        modules: &[(&'static str, &'static str)],
        start_all: bool,
        detection: Detection,
        system: SystemInfo,
        show_welcome: bool,
    ) -> Self {
        let detected = Profile::ALL.iter().position(|p| *p == detection.profile).unwrap_or(0);
        App {
            welcome: show_welcome.then_some(detected),
            lang_picker: None,
            lang_required: false,
            prefs_path: None,
            detection,
            system,
            report: None,
            modules: modules
                .iter()
                .map(|(c, d)| ModuleInfo { category: c, description: d, state: ModuleState::Pending })
                .collect(),
            started: Instant::now(),
            finished_at: None,
            tab: Tab::Summary,
            view: if start_all { View::All } else { View::Open },
            min_severity: None,
            category: None,
            search: String::new(),
            searching: false,
            show_help: false,
            toast: None,
            visible: Vec::new(),
            findings: TableState::default(),
            urgent: Vec::new(),
            urgent_state: TableState::default(),
            categories_state: TableState::default(),
        }
    }

    /// Empieza (o reinicia) un análisis: vuelve a la pantalla de progreso.
    pub fn start_audit(&mut self) {
        self.welcome = None;
        self.report = None;
        self.finished_at = None;
        self.started = Instant::now();
        self.tab = Tab::Summary;
        self.visible.clear();
        self.urgent.clear();
        for m in &mut self.modules {
            m.state = ModuleState::Pending;
        }
    }

    /// Abre el selector de idioma con el idioma actual elegido.
    pub fn open_lang_picker(&mut self, required: bool) {
        self.lang_picker = Some(Lang::ALL.iter().position(|l| *l == i18n::lang()).unwrap_or(0));
        self.lang_required = required;
    }

    fn on_lang_key(&mut self, k: KeyEvent, sel: usize) -> Action {
        let n = Lang::ALL.len();
        match k.code {
            KeyCode::Left | KeyCode::Up | KeyCode::Char('h' | 'k') | KeyCode::BackTab => {
                self.lang_picker = Some((sel + n - 1) % n);
            }
            KeyCode::Right | KeyCode::Down | KeyCode::Char('l' | 'j') | KeyCode::Tab => {
                self.lang_picker = Some((sel + 1) % n);
            }
            KeyCode::Char(c @ '1'..='9') if (c as usize - '1' as usize) < n => {
                self.lang_picker = Some(c as usize - '1' as usize);
            }
            KeyCode::Enter => {
                self.lang_picker = None;
                self.lang_required = false;
                return Action::SetLanguage(Lang::ALL[sel]);
            }
            KeyCode::Esc if !self.lang_required => self.lang_picker = None,
            KeyCode::Char('q') | KeyCode::Esc => return Action::Quit,
            _ => {}
        }
        Action::None
    }

    fn on_welcome_key(&mut self, k: KeyEvent, sel: usize) -> Action {
        if let Some(i) = self.lang_picker {
            return self.on_lang_key(k, i);
        }
        let n = Profile::ALL.len();
        match k.code {
            KeyCode::Left | KeyCode::Up | KeyCode::Char('h' | 'k') | KeyCode::BackTab => {
                self.welcome = Some((sel + n - 1) % n);
            }
            KeyCode::Right | KeyCode::Down | KeyCode::Char('l' | 'j') | KeyCode::Tab => {
                self.welcome = Some((sel + 1) % n);
            }
            KeyCode::Char(c @ '1'..='3') => self.welcome = Some(c as usize - '1' as usize),
            KeyCode::Enter => return Action::Start(Profile::ALL[sel]),
            KeyCode::Char('i') => self.open_lang_picker(false),
            // si ya hay resultados, Esc vuelve a ellos en vez de salir
            KeyCode::Esc if self.report.is_some() => self.welcome = None,
            KeyCode::Char('q') | KeyCode::Esc => return Action::Quit,
            _ => {}
        }
        Action::None
    }

    pub fn module_started(&mut self, category: &str) {
        for m in &mut self.modules {
            if m.state == ModuleState::Running {
                m.state = ModuleState::Done;
            }
            if m.category == category {
                m.state = ModuleState::Running;
            }
        }
    }

    pub fn finished(&mut self, report: Report) {
        for m in &mut self.modules {
            m.state = ModuleState::Done;
        }
        let mut urgent: Vec<usize> = (0..report.results.len()).filter(|&i| report.results[i].status.is_open()).collect();
        urgent.sort_by_key(|&i| sort_key(&report.results[i]));
        self.urgent_state.select(if urgent.is_empty() { None } else { Some(0) });
        self.urgent = urgent;
        self.categories_state.select(if report.score.categories.is_empty() { None } else { Some(0) });
        self.report = Some(report);
        self.finished_at = Some(Instant::now());
        self.refilter();
    }

    /// Avance de la animación del puntaje (0..1).
    pub fn score_progress(&self) -> f64 {
        self.finished_at.map_or(0.0, |t| (t.elapsed().as_secs_f64() / SCORE_ANIMATION.as_secs_f64()).min(1.0))
    }

    /// true mientras haya algo animándose (para redibujar seguido solo cuando hace falta).
    pub fn animating(&self) -> bool {
        self.report.is_none() || self.score_progress() < 1.0 || self.toast.is_some()
    }

    pub fn expire_toast(&mut self) {
        if self.toast.as_ref().is_some_and(|(_, t)| t.elapsed() > TOAST_TTL) {
            self.toast = None;
        }
    }

    pub fn notify(&mut self, msg: impl Into<String>) {
        self.toast = Some((msg.into(), Instant::now()));
    }

    /// Aviso que queda más tiempo en pantalla (para mensajes largos que hay que poder leer).
    pub fn notify_long(&mut self, msg: impl Into<String>) {
        let start = Instant::now().checked_add(Duration::from_secs(4)).unwrap_or_else(Instant::now);
        self.toast = Some((msg.into(), start));
    }

    pub fn result(&self, i: usize) -> Option<&CheckResult> {
        self.report.as_ref().and_then(|r| r.results.get(i))
    }

    pub fn selected(&self) -> Option<&CheckResult> {
        self.findings.selected().and_then(|i| self.visible.get(i)).and_then(|&i| self.result(i))
    }

    pub fn categories(&self) -> Vec<String> {
        self.report.as_ref().map(|r| r.score.categories.iter().map(|c| c.name.clone()).collect()).unwrap_or_default()
    }

    /// Recalcula la lista visible conservando, si se puede, el control seleccionado.
    pub fn refilter(&mut self) {
        let prev = self.selected().map(|x| x.id.clone());
        self.refilter_selecting(prev);
    }

    fn refilter_selecting(&mut self, want: Option<String>) {
        let Some(r) = &self.report else { return };
        let needle = self.search.to_lowercase();
        let mut v: Vec<usize> = r
            .results
            .iter()
            .enumerate()
            .filter(|(_, x)| self.view == View::All || x.status.is_open())
            .filter(|(_, x)| self.min_severity.is_none_or(|m| x.severity <= m))
            .filter(|(_, x)| self.category.as_ref().is_none_or(|c| &x.category == c))
            .filter(|(_, x)| {
                needle.is_empty()
                    || [&x.id, &x.title, &x.detail, &x.fix].iter().any(|f| f.to_lowercase().contains(&needle))
            })
            .map(|(i, _)| i)
            .collect();
        v.sort_by_key(|&i| sort_key(&r.results[i]));
        let idx = want
            .and_then(|id| v.iter().position(|&i| r.results[i].id == id))
            .or(if v.is_empty() { None } else { Some(0) });
        self.visible = v;
        self.findings.select(idx);
    }

    fn move_in(state: &mut TableState, len: usize, delta: isize) {
        if len == 0 {
            return;
        }
        let cur = state.selected().unwrap_or(0) as isize;
        state.select(Some((cur + delta).clamp(0, len as isize - 1) as usize));
    }

    fn move_by(&mut self, delta: isize) {
        match self.tab {
            Tab::Summary => Self::move_in(&mut self.urgent_state, self.urgent.len(), delta),
            Tab::Findings => Self::move_in(&mut self.findings, self.visible.len(), delta),
            Tab::Categories => {
                let n = self.categories().len();
                Self::move_in(&mut self.categories_state, n, delta)
            }
        }
    }

    /// Ir a Hallazgos sin filtros, con un control seleccionado.
    fn open_finding(&mut self, id: String) {
        self.tab = Tab::Findings;
        self.min_severity = None;
        self.category = None;
        self.search.clear();
        if self.view == View::Open && self.report.as_ref().is_some_and(|r| r.results.iter().any(|x| x.id == id && !x.status.is_open())) {
            self.view = View::All;
        }
        self.refilter_selecting(Some(id));
    }

    pub fn on_key(&mut self, k: KeyEvent) -> Action {
        if k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL) {
            return Action::Quit;
        }
        if let Some(sel) = self.welcome {
            return self.on_welcome_key(k, sel);
        }
        if self.show_help {
            self.show_help = false;
            return Action::None;
        }
        if self.searching {
            match k.code {
                KeyCode::Enter => self.searching = false,
                KeyCode::Esc => {
                    self.searching = false;
                    self.search.clear();
                }
                KeyCode::Backspace => {
                    self.search.pop();
                }
                KeyCode::Char(c) => self.search.push(c),
                _ => return Action::None,
            }
            self.refilter();
            return Action::None;
        }
        if self.report.is_none() {
            // durante el análisis solo se puede salir
            return if matches!(k.code, KeyCode::Char('q') | KeyCode::Esc) { Action::Quit } else { Action::None };
        }

        // teclas globales
        match k.code {
            KeyCode::Char('q') => return Action::Quit,
            KeyCode::Esc if !self.search.is_empty() => {
                self.search.clear();
                self.refilter();
                return Action::None;
            }
            KeyCode::Esc => return Action::Quit,
            KeyCode::Char('?') => {
                self.show_help = true;
                return Action::None;
            }
            KeyCode::Char('p') => {
                let current = self.report.as_ref().map_or(self.detection.profile, |r| r.profile);
                self.welcome = Profile::ALL.iter().position(|p| *p == current);
                return Action::None;
            }
            KeyCode::Char(c @ '1'..='3') => {
                self.tab = Tab::ALL[c as usize - '1' as usize];
                return Action::None;
            }
            KeyCode::Tab | KeyCode::Right if k.code == KeyCode::Tab || self.tab != Tab::Findings => {
                self.tab = Tab::ALL[(self.tab.index() + 1) % Tab::ALL.len()];
                return Action::None;
            }
            KeyCode::BackTab | KeyCode::Left if k.code == KeyCode::BackTab || self.tab != Tab::Findings => {
                self.tab = Tab::ALL[(self.tab.index() + Tab::ALL.len() - 1) % Tab::ALL.len()];
                return Action::None;
            }
            KeyCode::Char('/') => {
                self.tab = Tab::Findings;
                self.searching = true;
                return Action::None;
            }
            KeyCode::Down | KeyCode::Char('j') => self.move_by(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_by(-1),
            KeyCode::PageDown => self.move_by(10),
            KeyCode::PageUp => self.move_by(-10),
            KeyCode::Home | KeyCode::Char('g') => self.move_by(isize::MIN / 2),
            KeyCode::End | KeyCode::Char('G') => self.move_by(isize::MAX / 2),
            _ => {}
        }

        match (self.tab, k.code) {
            (Tab::Summary, KeyCode::Enter) => {
                if let Some(id) = self.urgent_state.selected().and_then(|i| self.urgent.get(i)).and_then(|&i| self.result(i)).map(|x| x.id.clone()) {
                    self.open_finding(id);
                }
            }
            (Tab::Categories, KeyCode::Enter) => {
                if let Some(c) = self.categories_state.selected().and_then(|i| self.categories().get(i).cloned()) {
                    self.tab = Tab::Findings;
                    self.category = Some(c);
                    self.min_severity = None;
                    self.search.clear();
                    self.view = View::All;
                    self.refilter_selecting(None);
                }
            }
            (Tab::Findings, KeyCode::Char('a')) => {
                self.view = if self.view == View::Open { View::All } else { View::Open };
                self.refilter();
            }
            (Tab::Findings, KeyCode::Char('s')) => {
                self.min_severity = match self.min_severity {
                    None => Some(Severity::Medium),
                    Some(Severity::Medium) => Some(Severity::High),
                    Some(Severity::High) => Some(Severity::Critical),
                    _ => None,
                };
                self.refilter();
            }
            (Tab::Findings, KeyCode::Char('c')) => {
                let cats = self.categories();
                self.category = match &self.category {
                    None => cats.first().cloned(),
                    Some(c) => cats.iter().position(|x| x == c).and_then(|i| cats.get(i + 1)).cloned(),
                };
                self.refilter();
            }
            (Tab::Findings, KeyCode::Char('x')) => {
                self.min_severity = None;
                self.category = None;
                self.search.clear();
                self.view = View::Open;
                self.refilter();
            }
            (Tab::Findings, KeyCode::Char('y')) => {
                let found = self.selected().map(|x| (x.id.clone(), x.fix.clone()));
                return match found {
                    Some((id, fix)) if !fix.is_empty() => {
                        self.notify(tr!("Fix for {id} copied to the clipboard", id = id));
                        Action::Copy(fix)
                    }
                    _ => {
                        self.notify(tr!("This check has no fix to copy"));
                        Action::None
                    }
                };
            }
            _ => {}
        }
        Action::None
    }

    /// true si hay algún filtro activo además de la vista.
    pub fn filtered(&self) -> bool {
        self.min_severity.is_some() || self.category.is_some() || !self.search.is_empty()
    }
}

/// Orden: primero lo abierto (más grave primero, FAIL antes que WARN), después lo que hay que
/// revisar (errores, excepciones), y al final lo que está bien.
pub fn sort_key(x: &CheckResult) -> (u8, Severity, u8, String) {
    let group = match x.status {
        Status::Fail | Status::Warn => 0,
        Status::Error => 1,
        Status::Waived => 2,
        Status::Na => 3,
        Status::Pass => 4,
    };
    (group, x.severity, u8::from(x.status == Status::Warn), x.id.clone())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use linaudit_core::{Profile, ProfileSource, score};

    pub(crate) const MODULES: &[(&str, &str)] = &[("accounts", "Cuentas"), ("ssh", "SSH")];

    /// Los tests verifican los textos en castellano (el idioma es global; todos los tests usan el mismo).
    pub(crate) fn es() {
        linaudit_core::i18n::set_lang(linaudit_core::i18n::Lang::Es);
    }

    pub(crate) fn sample_report() -> Report {
        es();
        use Severity::*;
        use Status::*;
        let results = vec![
            CheckResult::new("SSH-002", Medium, Fail, "ssh", "SSH acepta password").fix("PasswordAuthentication no"),
            CheckResult::new("SSH-001", High, Warn, "ssh", "Root solo con clave").detail("PermitRootLogin prohibit-password"),
            CheckResult::new("SSH-003", Critical, Pass, "ssh", "Sin passwords vacíos"),
            CheckResult::new("ACC-004", High, Fail, "accounts", "sudo NOPASSWD:ALL").fix("Exigir password"),
            CheckResult::new("SSH-011", Low, Na, "ssh", "Banner"),
        ];
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

    fn key(c: KeyCode) -> KeyEvent {
        KeyEvent::new(c, KeyModifiers::NONE)
    }

    fn ids(app: &App) -> Vec<&str> {
        app.visible.iter().map(|&i| app.result(i).unwrap().id.as_str()).collect()
    }

    pub(crate) fn system() -> SystemInfo {
        SystemInfo { host: "h".into(), os: "Debian".into(), kernel: "6.12".into(), user: "ana".into(), root: false }
    }

    pub(crate) fn detection() -> Detection {
        Detection { profile: Profile::Desktop, reasons: vec!["tiene batería".into()] }
    }

    pub(crate) fn new_app(welcome: bool) -> App {
        es();
        App::new(MODULES, false, detection(), system(), welcome)
    }

    pub(crate) fn app() -> App {
        let mut a = new_app(false);
        a.finished(sample_report());
        a
    }

    #[test]
    fn selector_de_idioma() {
        use linaudit_core::i18n::Lang;
        let mut a = new_app(true);
        a.open_lang_picker(true);
        let first = a.lang_picker.unwrap();
        a.on_key(key(KeyCode::Right));
        assert_ne!(a.lang_picker, Some(first));
        // la primera vez Esc no saltea la elección: sale
        assert_eq!(a.on_key(key(KeyCode::Esc)), Action::Quit);
        let chosen = Lang::ALL[a.lang_picker.unwrap()];
        assert_eq!(a.on_key(key(KeyCode::Enter)), Action::SetLanguage(chosen));
        assert_eq!(a.lang_picker, None);
        assert!(a.welcome.is_some(), "después del idioma sigue la elección de perfil");
        // después, `i` lo vuelve a abrir y Esc lo cierra sin cambiar nada
        a.on_key(key(KeyCode::Char('i')));
        assert!(a.lang_picker.is_some());
        assert_eq!(a.on_key(key(KeyCode::Esc)), Action::None);
        assert_eq!(a.lang_picker, None);
    }

    fn findings() -> App {
        let mut a = app();
        a.on_key(key(KeyCode::Char('2')));
        assert_eq!(a.tab, Tab::Findings);
        a
    }

    #[test]
    fn progreso_por_modulo() {
        let mut a = new_app(false);
        a.module_started("accounts");
        assert_eq!(a.modules[0].state, ModuleState::Running);
        a.module_started("ssh");
        assert_eq!(a.modules[0].state, ModuleState::Done);
        assert_eq!(a.modules[1].state, ModuleState::Running);
        a.finished(sample_report());
        assert!(a.modules.iter().all(|m| m.state == ModuleState::Done));
    }

    #[test]
    fn abiertos_ordenados_por_gravedad() {
        let a = findings();
        assert_eq!(ids(&a), ["ACC-004", "SSH-001", "SSH-002"]);
        assert_eq!(a.selected().unwrap().id, "ACC-004");
        assert_eq!(a.urgent.len(), 3);
    }

    #[test]
    fn vista_todos_deja_aprobados_al_final() {
        let mut a = findings();
        a.on_key(key(KeyCode::Char('a')));
        assert_eq!(ids(&a), ["ACC-004", "SSH-001", "SSH-002", "SSH-011", "SSH-003"]);
    }

    #[test]
    fn filtros_de_severidad_categoria_y_busqueda() {
        let mut a = findings();
        a.on_key(key(KeyCode::Char('s'))); // ≥ MEDIO
        a.on_key(key(KeyCode::Char('s'))); // ≥ ALTO
        assert_eq!(ids(&a), ["ACC-004", "SSH-001"]);
        a.on_key(key(KeyCode::Char('c'))); // accounts
        assert_eq!(ids(&a), ["ACC-004"]);
        a.on_key(key(KeyCode::Char('c'))); // ssh
        assert_eq!(ids(&a), ["SSH-001"]);
        a.on_key(key(KeyCode::Char('x'))); // limpiar
        assert!(!a.filtered());
        for c in "/root".chars() {
            a.on_key(key(KeyCode::Char(c)));
        }
        assert_eq!(ids(&a), ["SSH-001"]);
        a.on_key(key(KeyCode::Esc));
        assert_eq!(ids(&a).len(), 3);
    }

    #[test]
    fn la_seleccion_se_conserva_al_filtrar() {
        let mut a = findings();
        a.on_key(key(KeyCode::Down));
        assert_eq!(a.selected().unwrap().id, "SSH-001");
        a.on_key(key(KeyCode::Char('a')));
        assert_eq!(a.selected().unwrap().id, "SSH-001");
    }

    #[test]
    fn enter_en_resumen_abre_el_hallazgo() {
        let mut a = app();
        a.on_key(key(KeyCode::Down));
        a.on_key(key(KeyCode::Enter));
        assert_eq!(a.tab, Tab::Findings);
        assert_eq!(a.selected().unwrap().id, "SSH-001");
    }

    #[test]
    fn enter_en_categorias_filtra() {
        let mut a = app();
        a.on_key(key(KeyCode::Char('3')));
        a.on_key(key(KeyCode::Down)); // ssh
        a.on_key(key(KeyCode::Enter));
        assert_eq!(a.tab, Tab::Findings);
        assert_eq!(a.category.as_deref(), Some("ssh"));
        assert_eq!(ids(&a), ["SSH-001", "SSH-002", "SSH-011", "SSH-003"]);
    }

    #[test]
    fn tab_y_flechas_cambian_de_pestana() {
        let mut a = app();
        a.on_key(key(KeyCode::Tab));
        assert_eq!(a.tab, Tab::Findings);
        a.on_key(key(KeyCode::Right)); // en Hallazgos las flechas no cambian de pestaña
        assert_eq!(a.tab, Tab::Findings);
        a.on_key(key(KeyCode::Tab));
        assert_eq!(a.tab, Tab::Categories);
        a.on_key(key(KeyCode::Right));
        assert_eq!(a.tab, Tab::Summary);
        a.on_key(key(KeyCode::BackTab));
        assert_eq!(a.tab, Tab::Categories);
    }

    #[test]
    fn copiar_arreglo() {
        let mut a = findings();
        assert_eq!(a.on_key(key(KeyCode::Char('y'))), Action::Copy("Exigir password".into()));
        assert!(a.toast.is_some());
        a.on_key(key(KeyCode::Down));
        assert_eq!(a.on_key(key(KeyCode::Char('y'))), Action::None);
    }

    #[test]
    fn bienvenida_elige_perfil_y_arranca() {
        let mut a = new_app(true);
        assert_eq!(a.welcome, Some(1), "arranca en el perfil detectado");
        a.on_key(key(KeyCode::Right));
        assert_eq!(a.welcome, Some(2));
        a.on_key(key(KeyCode::Right));
        assert_eq!(a.welcome, Some(0), "da la vuelta");
        assert_eq!(a.on_key(key(KeyCode::Char('2'))), Action::None);
        assert_eq!(a.on_key(key(KeyCode::Enter)), Action::Start(Profile::Desktop));
        assert_eq!(a.on_key(key(KeyCode::Esc)), Action::Quit, "sin resultados, Esc sale");
    }

    #[test]
    fn p_vuelve_a_la_bienvenida_y_esc_regresa() {
        let mut a = app();
        a.on_key(key(KeyCode::Char('p')));
        assert_eq!(a.welcome, Some(0), "preselecciona el perfil del reporte (Servidor)");
        a.on_key(key(KeyCode::Esc));
        assert_eq!(a.welcome, None);
        assert!(a.report.is_some());
        a.on_key(key(KeyCode::Char('p')));
        a.on_key(key(KeyCode::Down));
        assert_eq!(a.on_key(key(KeyCode::Enter)), Action::Start(Profile::Desktop));
        a.start_audit();
        assert!(a.report.is_none() && a.welcome.is_none());
        assert!(a.modules.iter().all(|m| m.state == ModuleState::Pending));
    }

    #[test]
    fn q_sale_pero_no_mientras_se_busca() {
        let mut a = findings();
        a.on_key(key(KeyCode::Char('/')));
        assert_eq!(a.on_key(key(KeyCode::Char('q'))), Action::None);
        assert_eq!(a.search, "q");
        a.on_key(key(KeyCode::Enter));
        assert_eq!(a.on_key(key(KeyCode::Char('q'))), Action::Quit);
    }
}
