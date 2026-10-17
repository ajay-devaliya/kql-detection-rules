# FW-004 — Firewall - ICMP ping sweep (host discovery)

Detects one source IP sending ICMP traffic to 20 or more different destination hosts within one hour. A ping sweep is usually the first step of network discovery, used to find which hosts are alive before port scanning them.

| Property | Value |
| --- | --- |
| Rule type | Scheduled (not NRT) |
| Runs every | 1h |
| Looks back | 1h |
| Severity | Low |
| MITRE tactics | Reconnaissance, Discovery |
| MITRE techniques | T1595, T1018, T1595.001 |
| Data | `CommonSecurityLog` (FortiGate / Palo Alto via CEF) |
| Rule file | [`rules/firewall/FW-004-icmp-ping-sweep.yaml`](../../rules/firewall/FW-004-icmp-ping-sweep.yaml) |
| Query only | [`queries/firewall/FW-004-icmp-ping-sweep.kql`](../../queries/firewall/FW-004-icmp-ping-sweep.kql) |
| Deploy (ARM) | [`deploy/firewall/FW-004-icmp-ping-sweep.json`](../../deploy/firewall/FW-004-icmp-ping-sweep.json) |

## Tuning knobs

| Variable | Default | Notes |
| --- | --- | --- |
| `lookback` | `1h` |  |
| `HostThreshold` | `20` |  |
| `ExcludedSources` | `dynamic([])` | monitoring tools (PRTG, Zabbix, Nagios, SolarWinds) |

## Known false positives

- Network monitoring tools that ping devices for uptime.
- Load balancer health checks.
- IT admins running troubleshooting tools.

## Triage steps

1. Confirm whether the source is a monitoring server.
2. Check for port-scan alerts (FW-001/002/003) from the same source shortly after; sweep followed by scan is a stronger signal.
3. For internal sources that are user workstations, investigate the host.
