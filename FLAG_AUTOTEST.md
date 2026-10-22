# Synchronized Flag Auto-Test (without SSH between servers)

Experimental diagnostics for Paqet Tunnel Plus v0.1.3. **Not a guarantee of connectivity.** Use only on systems you are authorized to administer. This feature repeatedly restarts **the selected Paqet service**. Do not select other tunnels.

## Install/update on each server

Run the existing install.sh from the main branch with --manage on **both** servers. The updater fetches deploy.sh and synced_flag_lab.py and checks syntax before installation. It does not modify YAML or restart running services merely to update the management script. Select **8 — Synchronized Flag Auto-Test**.

If raw.githubusercontent.com cannot be reached from a server, transfer the two published scripts using your existing secure management workflow rather than running partial downloads.

## Prerequisites

1. Both hosts must have synchronized UTC/NTP clocks. Check timedatectl and date -u.
2. Select only the matching client and server Paqet units; YAML is expected at /etc/paqet-tunnel-plus/<tunnel>-client.yaml or <tunnel>-server.yaml.
3. Server host should offer a normal local SSH banner on TCP port 22, which is a test target. No inter-server management SSH is used.
4. Start server console first, then client console. Use the **same future Unix epoch**, mode, and stability profile index on both sides. Allow a few minutes to enter prompts.
5. The client must enter the **actual numeric IPv4** of its matching foreign server.

## Built-in hypotheses

Profile 1 historic-s-sa: client S/SA ; server SA/PA.
Profile 2 current-s-pa: client S/PA ; server PA/PA.
Profile 3 standard-pa-pa: client PA/PA ; server PA/PA.
Profile 4 pa-sa: client PA/SA ; server SA/PA.
Profile 5 s-a: client S/A ; server A/PA.
Profile 6 pa-a: client PA/A ; server A/PA.

These are six configurations, not an exhaustive space. The tool does not vary encryption, MTU, KCP mode, transmission port, routes or firewall rules.

## How a run works

Each scan profile has a 75-second slot. The server applies its flags first; the client applies corresponding flags 10 seconds later, temporarily adding a **127.0.0.1-only** forward. The client attempts eight SSH-banner reads via Paqet. Direct SSH connectivity to the foreign server does not count.

Results:
- PROBE_PASS 8/8: eight loopback-forward banner probes succeeded; this is not proof of application stability.
- UNSTABLE: at least one but not all probes succeeded.
- PROBE_FAIL: none succeeded. Check clocks, both logs, and test target before interpreting as blocked flags.
- SERVER_READY: only confirms server-side restart, not functional success.
- ERROR / SERVER_ERROR: inconclusive, inspect the reported reason.

For any promising result, choose mode 2 on both endpoints using the **same profile number** and a new common epoch. Stability mode attempts 40 probes over about six minutes. Afterwards, test your actual client application.

Both modes restore the starting YAML and restart the selected service at completion or on a normal interruption. A private timestamped copy of the original remains on disk. After a hard crash or power loss, manually inspect YAML against this copy: automated cleanup cannot run then.

Reports (compare both):
/var/log/paqet-tunnel-plus/flag-lab/synced-client-*.csv
/var/log/paqet-tunnel-plus/flag-lab/synced-server-*.csv

The tool deliberately does not permanently adopt a winning profile based on short probing. First compare both reports, verify stability, and apply a selected profile to both roles as a separate, explicit action.

## Limits

Six failed profiles do not prove that *no possible tunnel method* can work. They establish only failure of these combinations under observed conditions. Check synchronization, key agreement, test-target availability, packet captures, routing and firewall/service health before concluding where the fault lies.

Do not publish YAML files, encryption keys, or unredacted logs.
