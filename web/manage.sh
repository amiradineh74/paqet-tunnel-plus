#!/usr/bin/env bash
# Paqet Tunnel Plus optional read-only Web Panel
set -Eeuo pipefail
[[ "$(id -u)" == "0" ]] || { echo "[ERROR] Run as root."; exit 1; }

BASE_URL="https://raw.githubusercontent.com/amiradineh74/paqet-tunnel-plus/main/web"
DEST="/opt/paqet-tunnel-plus/web"
UNIT="/etc/systemd/system/paqet-plus-web.service"
SERVICE="paqet-plus-web.service"

show_access(){
  echo
  echo "Panel only listens on 127.0.0.1:8792 (NOT public)."
  echo "Windows/Linux computer: ssh -L 8792:127.0.0.1:8792 root@SERVER_IP"
  echo "Browser: http://127.0.0.1:8792"
  echo "Token on server: sudo cat /opt/paqet-tunnel-plus/web-panel.token"
  echo "Never share the token or expose 8792 without HTTPS and stronger access controls."
}
install_panel() (
  command -v python3 >/dev/null || { echo "[ERROR] Python3 is required."; return 1; }
  command -v curl >/dev/null || { echo "[ERROR] curl is required."; return 1; }
  local tmp file stamp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  for file in web_panel.py index.html app.js; do
    echo "[*] Downloading web/$file..."
    curl -fsSL --retry 3 --connect-timeout 10 "$BASE_URL/$file" -o "$tmp/$file" || return 1
    test -s "$tmp/$file" || { echo "[ERROR] Empty file: $file"; return 1; }
  done
  python3 -m py_compile "$tmp/web_panel.py" || { echo "[ERROR] Python syntax invalid."; return 1; }
  if [[ -e "$UNIT" ]] && ! grep -q '/opt/paqet-tunnel-plus/web/web_panel.py' "$UNIT"; then
    echo "[ERROR] Service name collision, refusing to overwrite $UNIT"
    return 1
  fi
  mkdir -p "$DEST"
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  for file in web_panel.py index.html app.js; do
    [[ ! -f "$DEST/$file" ]] || cp -p "$DEST/$file" "$DEST/$file.backup-$stamp"
    install -m 0644 "$tmp/$file" "$DEST/$file"
  done
  chmod 0755 "$DEST/web_panel.py"
  if [[ ! -e "$UNIT" ]]; then
    cat >"$UNIT" <<'EOF'
[Unit]
Description=Paqet Tunnel Plus Web (local read-only dashboard)
After=network.target
[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/bin/python3 /opt/paqet-tunnel-plus/web/web_panel.py --assets /opt/paqet-tunnel-plus/web --port 8792 --token-file /opt/paqet-tunnel-plus/web-panel.token
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
ProtectControlGroups=true
ProtectKernelTunables=true
ProtectKernelModules=true
RestrictAddressFamilies=AF_INET AF_UNIX
[Install]
WantedBy=multi-user.target
EOF
  fi
  systemctl daemon-reload
  systemctl enable "$SERVICE" >/dev/null
  systemctl restart "$SERVICE"
  if systemctl is-active --quiet "$SERVICE"; then
    echo "[OK] Web panel started. Other Paqet services and firewall untouched."
    show_access
  else
    echo "[ERROR] Panel failed. Run: journalctl -u $SERVICE -n 50 --no-pager"
    return 1
  fi
)
owned_unit(){
  [[ -f "$UNIT" ]] && grep -qF 'ExecStart=/usr/bin/python3 /opt/paqet-tunnel-plus/web/web_panel.py' "$UNIT"
}
remove_panel(){
  if ! owned_unit; then
    echo "[ERROR] Web unit missing or belongs to another application. No changes made."
    return 1
  fi
  read -r -p "Remove ONLY Paqet web panel service/files? [type REMOVE]: " answer
  [[ "$answer" == "REMOVE" ]] || { echo "Cancelled."; return 0; }
  systemctl disable --now "$SERVICE" 2>/dev/null || true
  if [[ -f "$UNIT" ]] && grep -q '/opt/paqet-tunnel-plus/web/web_panel.py' "$UNIT"; then
    rm -f "$UNIT"
    systemctl daemon-reload
  fi
  # Preserve token and backups for safety. Remove only our published runtime assets.
  rm -f "$DEST/web_panel.py" "$DEST/index.html" "$DEST/app.js"
  echo "[OK] Web service removed. Token, existing backups and all Paqet tunnels preserved."
}
menu(){
  while true; do
    echo
    echo "Paqet Web Panel (OPTIONAL / READ-ONLY / LOCALHOST)"
    echo "  1) Install or update and start panel"
    echo "  2) Status / access instructions"
    echo "  3) Restart web panel only"
    echo "  4) Stop web panel only"
    echo "  5) Uninstall web panel only"
    echo "  0) Back"
    read -r -p "Choose: " option
    case "$option" in
      1) install_panel ;;
      2) systemctl status "$SERVICE" --no-pager -l || true; show_access ;;
      3) if owned_unit; then systemctl restart "$SERVICE" && echo "[OK] Web restarted."; else echo "[ERROR] Web unit is not ours."; fi ;;
      4) if owned_unit; then systemctl stop "$SERVICE" && echo "[OK] Web stopped."; else echo "[ERROR] Web unit is not ours."; fi ;;
      5) remove_panel ;;
      0) return 0 ;;
      *) echo "Invalid choice" ;;
    esac
  done
}
case "$*" in
  --install) install_panel ;;
  --status) systemctl status "$SERVICE" --no-pager -l || true; show_access ;;
  --stop) owned_unit && systemctl stop "$SERVICE" ;;
  --uninstall) remove_panel ;;
  "") menu ;;
  *) echo "Usage: manage.sh [--install|--status|--stop|--uninstall]"; exit 2 ;;
esac
