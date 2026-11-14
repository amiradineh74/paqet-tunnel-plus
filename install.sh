#!/usr/bin/env bash
set -Eeuo pipefail

DEST="/opt/paqet-tunnel-plus"
BASE="https://raw.githubusercontent.com/amiradineh74/paqet-tunnel-plus/main"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Fetch and validate all components before replacing the local launcher.
curl -fsSL --retry 3 --connect-timeout 10 "$BASE/deploy.sh" -o "$tmp/deploy.sh"
curl -fsSL --retry 3 --connect-timeout 10 "$BASE/synced_flag_lab.py" -o "$tmp/synced_flag_lab.py"
curl -fsSL --retry 3 --connect-timeout 10 "$BASE/cleanup.py" -o "$tmp/cleanup.py"
bash -n "$tmp/deploy.sh"
if command -v python3 >/dev/null 2>&1; then
  python3 -m py_compile "$tmp/synced_flag_lab.py" "$tmp/cleanup.py"
else
  echo "[ERROR] Python3 is required for safe cleanup and Flag Auto-Test." >&2
  exit 1
fi

mkdir -p "$DEST"
if [ -f "$DEST/deploy.sh" ]; then
  cp -p "$DEST/deploy.sh" "$DEST/deploy.sh.before-update-$(date -u +%Y%m%dT%H%M%SZ)"
fi
if [ -f "$DEST/cleanup.py" ]; then
  cp -p "$DEST/cleanup.py" "$DEST/cleanup.py.before-update-$(date -u +%Y%m%dT%H%M%SZ)"
fi
install -m 0755 "$tmp/synced_flag_lab.py" "$DEST/synced_flag_lab.py"
install -m 0755 "$tmp/cleanup.py" "$DEST/cleanup.py"
install -m 0755 "$tmp/deploy.sh" "$DEST/deploy.sh"
echo "[OK] Paqet Tunnel Plus management script, Flag Auto-Test and cleanup component updated."
echo "[INFO] Existing services and YAML configurations have not been changed."
rm -rf "$tmp"
trap - EXIT
cd "$DEST"
exec ./deploy.sh "$@"
