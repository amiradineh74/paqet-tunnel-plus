#!/usr/bin/env bash
set -Eeuo pipefail
DEST="/opt/paqet-tunnel-plus"
URL="https://raw.githubusercontent.com/amiradineh74/paqet-tunnel-plus/main/deploy.sh"
mkdir -p "$DEST"
curl -fsSL --retry 3 "$URL" -o "$DEST/deploy.sh"
chmod +x "$DEST/deploy.sh"
cd "$DEST"
exec ./deploy.sh "$@"
