#!/usr/bin/env bash
# Copies the web app into the APK assets and vendors its libraries so the app works offline.
set -euo pipefail
cd "$(dirname "$0")"
A=app/src/main/assets
sed -e 's#https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js#jszip.min.js#' \
    -e 's#https://cdn.jsdelivr.net/npm/pptxgenjs@3.12.0/dist/pptxgen.bundle.js#pptxgen.bundle.js#' \
    ../pptx-mobile.html > "$A/index.html"
tmp=$(mktemp -d); (cd "$tmp" && npm i -s --no-save jszip@3.10.1 pptxgenjs@3.12.0 >/dev/null)
cp "$tmp/node_modules/jszip/dist/jszip.min.js" "$tmp/node_modules/pptxgenjs/dist/pptxgen.bundle.js" "$A/"
rm -rf "$tmp"
