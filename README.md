# Paqet Tunnel Plus

A menu-driven installer/manager for the official [hanselime/paqet](https://github.com/hanselime/paqet) core.

This project was written independently and focuses on practical deployment profiles, role-aware firewall rules, multiple forwards, and diagnostics.

## Tested profile

The **Iran Restrictive / Stable Tested** profile uses:

- Client (Iran): `local_flag: ["S"]`, `remote_flag: ["SA"]`
- Server (Kharej): `local_flag: ["SA"]`
- `conn: 1`
- KCP `fast2`
- MTU `1200`
- SMUX keepalive `2` sec
- SMUX timeout `30` sec
- Role-aware `NOTRACK` + kernel `RST` drop rules

The default core is pinned to **Paqet v1.0.0-alpha.21**, the version used for the tested profile.

## One-line run

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/amiradineh74/paqet-tunnel-plus/main/install.sh)
```

Run the **Kharej server first**, save the generated encryption key, then run the **Iran client** and enter the same key.

## Menu options

- Deploy Server or Client
- Standard / Iran Restrictive / Custom TCP flag profiles
- Stable / Default / Custom KCP tuning
- Multiple TCP forwards, e.g. `8443=8443,8080=8080`
- Optional SOCKS5
- Automatic role-aware NOTRACK/RST protection
- Systemd service creation
- Status, live logs, restart
- Firewall counters
- 20-second RST monitor
- Redacted config display

## Notes

- Secrets are never stored in this repository. Encryption keys are generated or entered at install time.
- Generated configs are stored under `/etc/paqet-tunnel-plus/` with mode 600.
- Services are named `paqet-plus-<role>-<name>`.
- Do not run two Paqet servers on the same raw transport port simultaneously.


## Gateway MAC troubleshooting

The script tries to detect the gateway MAC automatically. If that fails, it prints the detected interface and gateway and shows these commands:

```bash
ping -c 1 GATEWAY_IP
ip neigh show GATEWAY_IP dev INTERFACE
```

If the neighbour table still has no MAC, try:

```bash
arping -c 2 -I INTERFACE GATEWAY_IP
```

Copy the MAC address shown in the output (format: `00:11:22:33:44:55`) and paste it into the script.
