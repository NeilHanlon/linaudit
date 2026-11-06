#!/usr/bin/env bash
# Regenera po/linaudit.pot desde el código y actualiza los catálogos po/*.po con msgmerge.
# Los textos nuevos quedan sin traducir (msgstr "") y los que ya no existen, como obsoletos (#~).
# Requiere gettext (msgmerge, msgfmt).
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
cargo run -q -p linaudit-core --example i18n-pot
for po in po/*.po; do
  msgmerge --quiet --update --backup=none --no-fuzzy-matching --no-wrap "$po" po/linaudit.pot
  msgfmt --check-format --statistics -o /dev/null "$po"
done
