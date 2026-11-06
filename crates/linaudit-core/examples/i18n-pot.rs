//! Genera po/linaudit.pot desde el código. Lo llama contrib/i18n-update.sh.
use std::path::Path;

fn main() {
    let root = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."));
    let msgs = linaudit_core::i18n::extract::scan_workspace(root).expect("leer fuentes");
    let pot = linaudit_core::i18n::extract::render_pot(&msgs, env!("CARGO_PKG_VERSION"));
    std::fs::write(root.join("po/linaudit.pot"), pot).expect("escribir po/linaudit.pot");
    eprintln!("po/linaudit.pot: {} textos", msgs.len());
}
