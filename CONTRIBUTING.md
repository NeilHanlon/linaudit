# Contributing to linaudit

Thanks for helping! Bug reports, new checks, translations and packaging fixes are all welcome.
Issues: <https://github.com/alexiarstein/linaudit/issues>

## The golden rule

**linaudit is read-only.** No check may modify the system, and no output may contain the value of a secret (only the
file and line where it was found). Pull requests that break this will not be merged.

## Building and testing

You need Rust 1.85 or newer (the version in Debian 13).

```bash
cargo build --release      # binary in target/release/linaudit
cargo test                 # unit tests, filesystem fixtures, TUI rendering and translation coverage
```

```
crates/linaudit-core   engine: checks, profiles, waivers, score and i18n (no user interface)
crates/linaudit        binary: command line, interactive interface (ratatui), text and JSON reports
po/                    translations (gettext)
doc/                   man pages
etc/                   default /etc/linaudit files
contrib/               systemd units and maintenance scripts
debian/                Debian packaging
```

## Adding or changing a check

Checks live in `crates/linaudit-core/src/checks/`, one module per category. Each check has a stable ID (`SSH-001`)
that never changes meaning, because waivers and collectors depend on it. Add new IDs to `docs/CHECKS.md`, and cover
the check with a test using the filesystem fixture (`checks/fixture.rs`) so it can be tested without root.

## Translations

The texts in the code are in English and are the keys (msgid) of the gettext catalogs in `po/`, which are embedded in
the binary. Every user-facing text goes through `tr!("...")`; values are inserted by name, as in
`tr!("{n} files", n = count)`, and translations must keep the same `{names}`.

```bash
contrib/i18n-update.sh     # regenerates po/linaudit.pot from the code and updates every po/*.po
```

A test fails if a text in the code is missing from `po/es.po`. To add a language, copy `po/linaudit.pot` to
`po/<code>.po`, translate it, and add the language to `Lang` in `crates/linaudit-core/src/i18n.rs`.

## Debian packaging

`debian/` builds against the Rust crates packaged in Debian (`librust-*-dev`) with the Debian cargo wrapper. The code
works with the crate versions in Debian 13 (ratatui 0.29, toml 0.8) and in unstable (ratatui 0.30, toml 1.x); keep
both building when you update dependencies.

## License

By contributing you agree that your work is distributed under the GNU AGPL v3.0 or later.
