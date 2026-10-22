#!/usr/bin/env bash
set -Eeuo pipefail

DEST="/opt/paqet-tunnel-plus"
BASE="https://raw.githubusercontent.com/amiradineh74/paqet-tunnel-plus/main"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Fetch and validate both components before replacing the local launcher.
curl -fsSL --retry 3 --connect-timeout 10 "$BASE/deploy.sh" -o "$tmp/deploy.sh"
curl -fsSL --retry 3 --connect-timeout 10 "$BASE/synced_flag_lab.py" -o "$tmp/synced_flag_lab.py"
bash -n "$tmp/deploy.sh"
if command -v python3 >/dev/null 2>&1; then
  python3 -m py_compile "$tmp/synced_flag_lab.py"
else
  echo "[WARN] python3 not installed; Flag Auto-Test will need python3." >&2
fi

mkdir -p "$DEST"
if [ -f "$DEST/deploy.sh" ]; then
  cp -p "$DEST/deploy.sh" "$DEST/deploy.sh.before-update-$(date -u +%Y%m%dT%H%M%SZ)"
fi
install -m 0755 "$tmp/synced_flag_lab.py" "$DEST/synced_flag_lab.py"
install -m 0755 "$tmp/deploy.sh" "$DEST/deploy.sh"
echo "[OK] Paqet Tunnel Plus management script and Flag Auto-Test updated."
echo "[INFO] Existing services and YAML configurations have not been changed."
rm -rf "$tmp"
trap - EXIT
cd "$DEST"
exec ./deploy.sh "$@"
