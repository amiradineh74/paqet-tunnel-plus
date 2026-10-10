#!/usr/bin/env bash
set -Eeuo pipefail

APP="Paqet Tunnel Plus"
VERSION="0.1.0"
PAQET_VERSION="v1.0.0-alpha.21"
PAQET_BIN="/usr/local/bin/paqet"
BASE_DIR="/etc/paqet-tunnel-plus"
SYSTEMD_DIR="/etc/systemd/system"

C_RESET='\033[0m'; C_RED='\033[0;31m'; C_GREEN='\033[0;32m'; C_YELLOW='\033[1;33m'; C_CYAN='\033[0;36m'

say(){ echo -e "${C_CYAN}[*]${C_RESET} $*"; }
ok(){ echo -e "${C_GREEN}[✓]${C_RESET} $*"; }
warn(){ echo -e "${C_YELLOW}[!]${C_RESET} $*"; }
die(){ echo -e "${C_RED}[x]${C_RESET} $*" >&2; exit 1; }
pause(){ read -r -p "Press Enter to continue..." _ || true; }

need_root(){ [ "${EUID}" -eq 0 ] || die "Run as root."; }

valid_port(){ [[ "${1:-}" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }
valid_flag(){ [[ "${1:-}" =~ ^[FSRPAUECN]+$ ]]; }
sanitize_name(){
  local n="${1:-tunnel}"
  n="${n// /-}"
  n="$(echo "$n" | tr -cd '[:alnum:]_.-')"
  [ -n "$n" ] || n="tunnel"
  echo "$n"
}

install_deps(){
  say "Installing required packages..."
  export DEBIAN_FRONTEND=noninteractive
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y >/dev/null
    apt-get install -y curl ca-certificates tar iproute2 iptables iptables-persistent libpcap0.8 >/dev/null
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y curl ca-certificates tar iproute iptables libpcap >/dev/null
  elif command -v yum >/dev/null 2>&1; then
    yum install -y curl ca-certificates tar iproute iptables libpcap >/dev/null
  else
    die "Unsupported package manager."
  fi
  ok "Dependencies ready."
}

arch_name(){
  case "$(uname -m)" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    armv7l|armv6l) echo "arm32" ;;
    *) die "Unsupported CPU architecture: $(uname -m)" ;;
  esac
}

install_paqet(){
  if [ -x "$PAQET_BIN" ]; then
    local have
    have="$("$PAQET_BIN" version 2>/dev/null | head -n1 || true)"
    say "Existing Paqet: ${have:-unknown version}"
    read -r -p "Reinstall tested core $PAQET_VERSION? [y/N]: " ans
    [[ "${ans,,}" == "y" ]] || return 0
  fi

  local arch asset url tmp
  arch="$(arch_name)"
  asset="paqet-linux-${arch}-${PAQET_VERSION}.tar.gz"
  url="https://github.com/hanselime/paqet/releases/download/${PAQET_VERSION}/${asset}"
  tmp="$(mktemp -d)"
  say "Downloading official Paqet $PAQET_VERSION ($arch)..."
  curl -fL --retry 3 "$url" -o "$tmp/paqet.tar.gz"
  tar -xzf "$tmp/paqet.tar.gz" -C "$tmp"
  local found
  found="$(find "$tmp" -maxdepth 2 -type f -name 'paqet*' ! -name '*.tar.gz' | head -n1)"
  [ -n "$found" ] || die "Paqet binary not found in release archive."
  install -m 0755 "$found" "$PAQET_BIN"
  rm -rf "$tmp"
  ok "Installed $("$PAQET_BIN" version 2>/dev/null | head -n1 || echo "$PAQET_VERSION")."
}

detect_network(){
  local route
  route="$(ip -4 route get 1.1.1.1 2>/dev/null | head -n1)" || true
  IFACE="$(awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1);exit}}' <<<"$route")"
  LOCAL_IP="$(awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1);exit}}' <<<"$route")"
  GATEWAY="$(awk '{for(i=1;i<=NF;i++) if($i=="via"){print $(i+1);exit}}' <<<"$route")"

  [ -n "${IFACE:-}" ] || die "Could not detect network interface."
  [ -n "${LOCAL_IP:-}" ] || die "Could not detect local IPv4."

  if [ -z "${GATEWAY:-}" ]; then
    GATEWAY="$(ip -4 route show default dev "$IFACE" | awk '/default/{print $3;exit}')"
  fi
  [ -n "${GATEWAY:-}" ] || die "Could not detect gateway."

  ping -c1 -W1 "$GATEWAY" >/dev/null 2>&1 || true
  GATEWAY_MAC="$(ip neigh show "$GATEWAY" dev "$IFACE" | awk '/lladdr/{print $5;exit}')"
  if [ -z "${GATEWAY_MAC:-}" ]; then
    ip neigh replace "$GATEWAY" dev "$IFACE" nud probe >/dev/null 2>&1 || true
    sleep 1
    GATEWAY_MAC="$(ip neigh show "$GATEWAY" dev "$IFACE" | awk '/lladdr/{print $5;exit}')"
  fi

  if [ -z "${GATEWAY_MAC:-}" ]; then
    warn "Gateway MAC was not detected automatically."
    read -r -p "Gateway MAC: " GATEWAY_MAC
  fi

  echo
  say "Detected network"
  echo "  Interface : $IFACE"
  echo "  Local IPv4: $LOCAL_IP"
  echo "  Gateway   : $GATEWAY"
  echo "  Router MAC: $GATEWAY_MAC"
}

choose_network_profile(){
  echo
  echo "Network / TCP camouflage profile:"
  echo "  1) Iran Restrictive (TESTED)  Client S/SA, Server SA"
  echo "  2) Standard                   PA/PA"
  echo "  3) Custom flags"
  read -r -p "Choose [1]: " p
  case "${p:-1}" in
    1)
      PROFILE_NAME="iran-restrictive"
      CLIENT_LOCAL_FLAG="S"
      CLIENT_REMOTE_FLAG="SA"
      SERVER_LOCAL_FLAG="SA"
      SERVER_REMOTE_FLAG="PA"
      ;;
    2)
      PROFILE_NAME="standard"
      CLIENT_LOCAL_FLAG="PA"
      CLIENT_REMOTE_FLAG="PA"
      SERVER_LOCAL_FLAG="PA"
      SERVER_REMOTE_FLAG="PA"
      ;;
    3)
      PROFILE_NAME="custom"
      if [ "$ROLE" = "client" ]; then
        read -r -p "Client local_flag [S]: " CLIENT_LOCAL_FLAG
        CLIENT_LOCAL_FLAG="${CLIENT_LOCAL_FLAG:-S}"
        valid_flag "$CLIENT_LOCAL_FLAG" || die "Invalid TCP flag."
        read -r -p "Client remote_flag [SA]: " CLIENT_REMOTE_FLAG
        CLIENT_REMOTE_FLAG="${CLIENT_REMOTE_FLAG:-SA}"
        valid_flag "$CLIENT_REMOTE_FLAG" || die "Invalid TCP flag."
        SERVER_LOCAL_FLAG="SA"; SERVER_REMOTE_FLAG="PA"
      else
        read -r -p "Server local_flag [SA]: " SERVER_LOCAL_FLAG
        SERVER_LOCAL_FLAG="${SERVER_LOCAL_FLAG:-SA}"
        valid_flag "$SERVER_LOCAL_FLAG" || die "Invalid TCP flag."
        read -r -p "Server remote_flag [PA]: " SERVER_REMOTE_FLAG
        SERVER_REMOTE_FLAG="${SERVER_REMOTE_FLAG:-PA}"
        valid_flag "$SERVER_REMOTE_FLAG" || die "Invalid TCP flag."
        CLIENT_LOCAL_FLAG="S"; CLIENT_REMOTE_FLAG="SA"
      fi
      ;;
    *) die "Invalid profile choice." ;;
  esac

  echo
  echo "Kernel raw-packet protection:"
  echo "  1) Enable NOTRACK + RST DROP (recommended)"
  echo "  2) Disable"
  read -r -p "Choose [1]: " fw
  [ "${fw:-1}" = "2" ] && APPLY_FW="no" || APPLY_FW="yes"
}

choose_performance_profile(){
  echo
  echo "Performance profile:"
  echo "  1) Stable Tested  conn=1, fast2, MTU=1200, SMUX 2/30"
  echo "  2) Default        conn=3, fast,  MTU=1350, SMUX 2/8"
  echo "  3) Custom"
  read -r -p "Choose [1]: " p
  case "${p:-1}" in
    1)
      PERF_NAME="stable-tested"
      CONN=1; KCP_MODE="fast2"; MTU=1200
      SMUX_KEEPALIVE=2; SMUX_TIMEOUT=30
      ;;
    2)
      PERF_NAME="default"
      CONN=3; KCP_MODE="fast"; MTU=1350
      SMUX_KEEPALIVE=2; SMUX_TIMEOUT=8
      ;;
    3)
      PERF_NAME="custom"
      read -r -p "Parallel connections [1]: " CONN; CONN="${CONN:-1}"
      [[ "$CONN" =~ ^[0-9]+$ ]] && [ "$CONN" -ge 1 ] || die "Invalid connection count."
      echo "KCP mode: 1) fast  2) fast2  3) fast3  4) normal"
      read -r -p "Choose [2]: " km
      case "${km:-2}" in
        1) KCP_MODE="fast" ;; 2) KCP_MODE="fast2" ;; 3) KCP_MODE="fast3" ;; 4) KCP_MODE="normal" ;; *) die "Invalid KCP mode." ;;
      esac
      read -r -p "MTU [1200]: " MTU; MTU="${MTU:-1200}"
      [[ "$MTU" =~ ^[0-9]+$ ]] && [ "$MTU" -ge 500 ] && [ "$MTU" -le 1500 ] || die "Invalid MTU."
      read -r -p "SMUX keepalive seconds [2]: " SMUX_KEEPALIVE; SMUX_KEEPALIVE="${SMUX_KEEPALIVE:-2}"
      read -r -p "SMUX timeout seconds [30]: " SMUX_TIMEOUT; SMUX_TIMEOUT="${SMUX_TIMEOUT:-30}"
      ;;
    *) die "Invalid performance choice." ;;
  esac
}

generate_key(){
  openssl rand -base64 32 2>/dev/null || head -c 32 /dev/urandom | base64
}

ask_common(){
  read -r -p "Tunnel name (e.g. germany): " TUNNEL_NAME
  TUNNEL_NAME="$(sanitize_name "${TUNNEL_NAME:-tunnel}")"
  read -r -p "Paqet transport port [29999]: " PAQET_PORT
  PAQET_PORT="${PAQET_PORT:-29999}"
  valid_port "$PAQET_PORT" || die "Invalid port."
  choose_network_profile
  choose_performance_profile
}

ask_server(){
  ROLE="server"
  ask_common
  echo
  KEY="$(generate_key)"
  echo "Encryption key (copy this to the Iran client):"
  echo "$KEY"
  echo
  read -r -p "Press Enter after you saved the key..." _
}

ask_client(){
  ROLE="client"
  read -r -p "Kharej server IPv4: " SERVER_IP
  [[ "$SERVER_IP" =~ ^[0-9a-fA-F:.]+$ ]] || die "Invalid server address."
  ask_common
  echo
  read -r -p "Encryption key from Kharej server: " KEY
  [ -n "$KEY" ] || die "Encryption key is required."

  echo
  echo "Client exposure:"
  echo "  1) Port forwarding (recommended for Xray/Reality)"
  echo "  2) SOCKS5 on 127.0.0.1:1080"
  read -r -p "Choose [1]: " e
  if [ "${e:-1}" = "2" ]; then
    EXPOSURE="socks5"
    FORWARDS=""
  else
    EXPOSURE="forward"
    echo "Enter mappings local=remote separated by commas."
    echo "Example: 8443=8443,8080=8080"
    read -r -p "Mappings: " maps
    maps="${maps// /}"
    [ -n "$maps" ] || die "At least one mapping is required."
    FORWARDS=""
    IFS=',' read -ra pairs <<<"$maps"
    for pair in "${pairs[@]}"; do
      localp="${pair%%=*}"; remotep="${pair#*=}"
      valid_port "$localp" || die "Invalid local port: $localp"
      valid_port "$remotep" || die "Invalid remote port: $remotep"
      if [ -n "$FORWARDS" ]; then FORWARDS+=";"; fi
      FORWARDS+="${localp}=${remotep}"
    done
  fi
}

write_transport(){
  cat <<EOF
transport:
  protocol: "kcp"
  conn: $CONN
  kcp:
    mode: "$KCP_MODE"
    mtu: $MTU
    nodelay: 1
    interval: 10
    resend: 2
    nc: 1
    rcvwnd: 1024
    sndwnd: 1024
    block: "aes"
    key: "$KEY"
    smuxbuf: 4194304
    streambuf: 2097152
    smuxkalive: $SMUX_KEEPALIVE
    smuxktimeout: $SMUX_TIMEOUT
EOF
}

write_server_config(){
  CONFIG="$BASE_DIR/${TUNNEL_NAME}-server.yaml"
  {
    cat <<EOF
role: "server"
log:
  level: "info"
listen:
  addr: ":$PAQET_PORT"
network:
  interface: "$IFACE"
  ipv4:
    addr: "$LOCAL_IP:$PAQET_PORT"
    router_mac: "$GATEWAY_MAC"
  tcp:
    local_flag: ["$SERVER_LOCAL_FLAG"]
    remote_flag: ["$SERVER_REMOTE_FLAG"]
  pcap:
    sockbuf: 8388608
EOF
    write_transport
  } >"$CONFIG"
  chmod 600 "$CONFIG"
}

write_client_config(){
  CONFIG="$BASE_DIR/${TUNNEL_NAME}-client.yaml"
  {
    cat <<EOF
role: "client"
log:
  level: "info"
EOF
    if [ "$EXPOSURE" = "socks5" ]; then
      cat <<EOF
socks5:
  - listen: "127.0.0.1:1080"
    username: ""
    password: ""
EOF
    else
      echo "forward:"
      IFS=';' read -ra rules <<<"$FORWARDS"
      for r in "${rules[@]}"; do
        lp="${r%%=*}"; rp="${r#*=}"
        cat <<EOF
  - listen: ":$lp"
    target: "$SERVER_IP:$rp"
    protocol: "tcp"
EOF
      done
    fi
    cat <<EOF
network:
  interface: "$IFACE"
  ipv4:
    addr: "$LOCAL_IP:0"
    router_mac: "$GATEWAY_MAC"
  tcp:
    local_flag: ["$CLIENT_LOCAL_FLAG"]
    remote_flag: ["$CLIENT_REMOTE_FLAG"]
  pcap:
    sockbuf: 4194304
server:
  addr: "$SERVER_IP:$PAQET_PORT"
EOF
    write_transport
  } >"$CONFIG"
  chmod 600 "$CONFIG"
}

ipt_add(){
  local table="$1"
  local chain="$2"
  local pos="$3"
  shift 3
  if ! iptables -t "$table" -C "$chain" "$@" >/dev/null 2>&1; then
    iptables -t "$table" -I "$chain" "$pos" "$@" >/dev/null
  fi
}

save_firewall(){
  mkdir -p /etc/iptables
  iptables-save > /etc/iptables/rules.v4
  if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save >/dev/null 2>&1 || true
  fi
}

apply_firewall(){
  [ "$APPLY_FW" = "yes" ] || { warn "NOTRACK/RST protection disabled by user."; return; }
  say "Applying role-aware NOTRACK/RST protection..."
  if [ "$ROLE" = "server" ]; then
    ipt_add raw PREROUTING 1 -p tcp --dport "$PAQET_PORT" -j NOTRACK
    ipt_add raw OUTPUT 1 -p tcp --sport "$PAQET_PORT" -j NOTRACK
    ipt_add mangle OUTPUT 1 -p tcp --sport "$PAQET_PORT" --tcp-flags RST RST -j DROP
  else
    ipt_add raw PREROUTING 1 -p tcp -s "$SERVER_IP" --sport "$PAQET_PORT" -j NOTRACK
    ipt_add raw OUTPUT 1 -p tcp -d "$SERVER_IP" --dport "$PAQET_PORT" -j NOTRACK
    ipt_add mangle OUTPUT 1 -p tcp -d "$SERVER_IP" --dport "$PAQET_PORT" --tcp-flags RST RST -j DROP
  fi
  save_firewall
  ok "Firewall protection applied and saved."
}

write_meta(){
  META="$BASE_DIR/${SERVICE}.meta"
  {
    echo "ROLE=$ROLE"
    echo "TUNNEL_NAME=$TUNNEL_NAME"
    echo "PAQET_PORT=$PAQET_PORT"
    echo "SERVER_IP=${SERVER_IP:-}"
    echo "PROFILE_NAME=$PROFILE_NAME"
    echo "PERF_NAME=$PERF_NAME"
    echo "EXPOSURE=${EXPOSURE:-}"
    echo "FORWARDS=${FORWARDS:-}"
    echo "CONFIG=$CONFIG"
  } >"$META"
  chmod 600 "$META"
}

create_service(){
  SERVICE="paqet-plus-${ROLE}-${TUNNEL_NAME}"
  local unit="$SYSTEMD_DIR/${SERVICE}.service"
  cat >"$unit" <<EOF
[Unit]
Description=Paqet Tunnel Plus ($ROLE/$TUNNEL_NAME)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$PAQET_BIN run -c $CONFIG
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable "$SERVICE" >/dev/null
  systemctl restart "$SERVICE"
  sleep 2
  if systemctl is-active --quiet "$SERVICE"; then
    ok "$SERVICE is running."
  else
    systemctl status "$SERVICE" --no-pager -l || true
    die "Service failed to start."
  fi
}

deployment_summary(){
  echo
  echo "=============================================="
  echo " $APP deployment complete"
  echo "=============================================="
  echo " Service : $SERVICE"
  echo " Config  : $CONFIG"
  echo " Profile : $PROFILE_NAME"
  echo " Tuning  : $PERF_NAME"
  echo " Paqet   : $PAQET_VERSION / port $PAQET_PORT"
  if [ "$ROLE" = "client" ]; then
    echo " Server  : $SERVER_IP:$PAQET_PORT"
    [ "${EXPOSURE:-}" = "forward" ] && echo " Forwards: $FORWARDS"
  else
    echo " KEY     : $KEY"
    warn "Save the key securely; it is stored in the root-only config."
  fi
  echo
  echo "Logs: journalctl -u $SERVICE -f"
}

deploy(){
  need_root
  install_deps
  install_paqet
  mkdir -p "$BASE_DIR"
  detect_network

  echo
  echo "Deploy role:"
  echo "  1) SERVER (Kharej / Germany-Turkey)"
  echo "  2) CLIENT (Iran)"
  read -r -p "Choose: " r
  case "$r" in
    1) ask_server; write_server_config ;;
    2) ask_client; write_client_config ;;
    *) die "Invalid role." ;;
  esac

  apply_firewall
  create_service
  write_meta
  deployment_summary
}

list_tunnels(){
  echo
  systemctl list-unit-files --type=service 'paqet-plus-*' --no-legend 2>/dev/null || true
  echo
  systemctl list-units --type=service 'paqet-plus-*' --no-legend 2>/dev/null || true
}

choose_service(){
  mapfile -t svcs < <(systemctl list-unit-files --type=service 'paqet-plus-*' --no-legend 2>/dev/null | awk '{sub(/\.service$/,"",$1); print $1}')
  [ "${#svcs[@]}" -gt 0 ] || { warn "No Paqet Tunnel Plus services found."; return 1; }
  local i=1
  for s in "${svcs[@]}"; do echo "  $i) $s"; i=$((i+1)); done
  read -r -p "Choose service: " n
  [[ "$n" =~ ^[0-9]+$ ]] && [ "$n" -ge 1 ] && [ "$n" -le "${#svcs[@]}" ] || return 1
  SELECTED_SERVICE="${svcs[$((n-1))]}"
  return 0
}

diag_firewall(){
  choose_service || return
  local m="$BASE_DIR/${SELECTED_SERVICE}.meta"
  [ -f "$m" ] || { warn "Metadata missing."; return; }
  # shellcheck disable=SC1090
  source "$m"
  echo "--- RAW ---"
  iptables -t raw -L -n -v --line-numbers | grep -E "Chain|$PAQET_PORT|${SERVER_IP:-NO_MATCH}" || true
  echo "--- MANGLE ---"
  iptables -t mangle -L OUTPUT -n -v --line-numbers | grep -E "Chain|$PAQET_PORT|${SERVER_IP:-NO_MATCH}" || true
}

diag_rst(){
  choose_service || return
  local m="$BASE_DIR/${SELECTED_SERVICE}.meta"
  [ -f "$m" ] || { warn "Metadata missing."; return; }
  # shellcheck disable=SC1090
  source "$m"
  echo "Capturing RST packets for 20 seconds..."
  if [ "$ROLE" = "client" ] && [ -n "${SERVER_IP:-}" ]; then
    timeout 20 tcpdump -ni any -nn "host $SERVER_IP and tcp port $PAQET_PORT and tcp[tcpflags] & tcp-rst != 0" || true
  else
    timeout 20 tcpdump -ni any -nn "tcp port $PAQET_PORT and tcp[tcpflags] & tcp-rst != 0" || true
  fi
}

manage(){
  need_root
  while true; do
    echo
    echo "Management / Diagnostics"
    echo "  1) List tunnels"
    echo "  2) Live logs"
    echo "  3) Restart tunnel"
    echo "  4) Show status"
    echo "  5) Firewall counters"
    echo "  6) RST monitor (20 sec)"
    echo "  7) Show redacted config"
    echo "  0) Back"
    read -r -p "Choose: " x
    case "$x" in
      1) list_tunnels ;;
      2) choose_service && journalctl -u "$SELECTED_SERVICE" -f ;;
      3) choose_service && systemctl restart "$SELECTED_SERVICE" && ok "Restarted." ;;
      4) choose_service && systemctl status "$SELECTED_SERVICE" --no-pager -l ;;
      5) diag_firewall ;;
      6) diag_rst ;;
      7)
        choose_service || continue
        m="$BASE_DIR/${SELECTED_SERVICE}.meta"
        [ -f "$m" ] || { warn "Metadata missing."; continue; }
        # shellcheck disable=SC1090
        source "$m"
        sed -E 's/(^[[:space:]]*key:[[:space:]]*).*/\1"<REDACTED>"/' "$CONFIG"
        ;;
      0) return ;;
      *) warn "Invalid choice." ;;
    esac
  done
}

main_menu(){
  need_root
  while true; do
    clear || true
    echo "=============================================="
    echo " $APP v$VERSION"
    echo "=============================================="
    echo "  1) Deploy new tunnel"
    echo "  2) Manage / Diagnostics"
    echo "  3) Install/Reinstall tested Paqet core"
    echo "  0) Exit"
    echo
    read -r -p "Choose: " c
    case "$c" in
      1) deploy; pause ;;
      2) manage ;;
      3) install_deps; install_paqet; pause ;;
      0) exit 0 ;;
      *) warn "Invalid choice."; sleep 1 ;;
    esac
  done
}

case "${1:-}" in
  --deploy) deploy ;;
  --manage) manage ;;
  --list) list_tunnels ;;
  --version) echo "$APP v$VERSION" ;;
  *) main_menu ;;
esac
