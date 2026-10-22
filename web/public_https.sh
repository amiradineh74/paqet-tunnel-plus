#!/usr/bin/env bash
# HTTPS proxy for Paqet Web; opt-in, requires DNS domain & Caddy 2.8+
set -Eeuo pipefail
umask 077
[[ $EUID == 0 ]] || { echo "Run as root"; exit 1; }
site=/etc/caddy/paqet-panel.caddy
main=/etc/caddy/Caddyfile
token_file=/opt/paqet-tunnel-plus/web-panel.token
case "$*" in
--install|"")
  systemctl is-active --quiet paqet-plus-web || { echo "Install local web panel first (menu 9)"; exit 1; }
  command -v caddy >/dev/null || { echo "Install Caddy 2.8+ first"; exit 1; }
  [[ -f $main && -f $token_file ]] || { echo "Caddyfile or token missing"; exit 1; }
  read -r -p "Panel domain, DNS A pointed to server: " domain
  [[ $domain =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]+$ && $domain != *..* ]] || { echo "Invalid domain"; exit 1; }
  read -r -s -p "Administrator password (14+ chars): " password; echo
  read -r -s -p "Repeat password: " again; echo
  [[ $(printf %s "$password" | wc -c) -ge 14 && "$password" == "$again" ]] || { echo "Password mismatch/short"; exit 1; }
  hashed="$(printf %s "$password" | caddy hash-password)"
  unset password again
  secret="$(tr -d '\r\n' < "$token_file")"
  [[ $secret =~ ^[A-Za-z0-9_-]+$ && $(printf %s "$secret" | wc -c) -ge 32 ]] || { echo "Invalid token"; exit 1; }
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  cp -p "$main" "$main.backup-$stamp"
  [[ ! -f "$site" ]] || cp -p "$site" "$site.backup-$stamp"
  cat > "$site" <<EOF
$domain {
    encode gzip
    basic_auth {
        admin $hashed
    }
    reverse_proxy 127.0.0.1:8792 {
        header_up Authorization "Bearer $secret"
    }
    header Strict-Transport-Security "max-age=31536000"
}
EOF
  if id caddy >/dev/null; then chown root:caddy "$site"; fi
  chmod 0640 "$site"
  grep -qFx 'import /etc/caddy/paqet-panel.caddy' "$main" || printf '\nimport /etc/caddy/paqet-panel.caddy\n' >> "$main"
  if ! caddy validate --config "$main" --adapter caddyfile || ! systemctl reload caddy; then
    cp -p "$main.backup-$stamp" "$main"
    if [[ -f "$site.backup-$stamp" ]]; then cp -p "$site.backup-$stamp" "$site"; else rm -f "$site"; fi
    systemctl reload caddy || true
    echo "Validation/reload failed; files restored"; exit 1
  fi
  echo "HTTPS panel: https://$domain"
  echo "DNS A record and inbound ports 80/443 must be reachable for valid TLS."
  echo "Paqet tunnel services/firewall were not touched."
  ;;
--status)
  [[ -f "$site" ]] && echo "Proxy installed: $site" || echo "Proxy not installed"
  systemctl is-active caddy || true
  ;;
*)
  echo "Usage: public_https.sh [--install|--status]"; exit 2 ;;
esac
