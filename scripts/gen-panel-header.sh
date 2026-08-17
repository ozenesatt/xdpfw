#!/usr/bin/env bash
# panel.html -> panel.h (C string sabiti)
set -euo pipefail
cd "$(dirname "$0")/.."

{
    echo '/* OTOMATIK URETILDI - src/panel.html dosyasini duzenleyin */'
    echo '#ifndef __PANEL_H'
    echo '#define __PANEL_H'
    echo 'static const char PANEL_HTML[] ='
    sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/^/"/' -e 's/$/\\n"/' src/panel.html
    echo ';'
    echo '#endif'
} > src/panel.h

echo "src/panel.h uretildi ($(wc -l < src/panel.h) satir)"
