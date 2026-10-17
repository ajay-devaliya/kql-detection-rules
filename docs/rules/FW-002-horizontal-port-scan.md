# FW-002 — Firewall - Horizontal port scan (one source, one port across many hosts)

Detects one source IP connecting to the same destination port on 20 or more different hosts within one hour. This is a horizontal scan (a port sweep), typically used to find every machine running a particular service, such as SMB (445), RDP (3389) or SSH (22).

| Property | Value |
| --- | --- |
| Rule type | Scheduled (not NRT) |
| Runs every | 1h |
| Looks back | 1h |
| Severity | Medium |
| MITRE tactics | Reconnaissance, Discovery |
| MITRE techniques | T1595, T1046, T1595.001 |
| Data | `CommonSecurityLog` (FortiGate / Palo Alto via CEF) |
| Rule file | [`rules/firewall/FW-002-horizontal-port-scan.yaml`](../../rules/firewall/FW-002-horizontal-port-scan.yaml) |
| Query only | [`queries/firewall/FW-002-horizontal-port-scan.kql`](../../queries/firewall/FW-002-horizontal-port-scan.kql) |
| Deploy (ARM) | [`deploy/firewall/FW-002-horizontal-port-scan.json`](../../deploy/firewall/FW-002-horizontal-port-scan.json) |

## Tuning knobs

| Variable | Default | Notes |
| --- | --- | --- |
| `lookback` | `1h` |  |
| `HostThreshold` | `20` | distinct destination hosts on the same port |
| `ExcludedSources` | `dynamic([])` | approved scanners, monitoring servers, domain controllers |
| `ExcludedPorts` | `dynamic([53, 123])` | DNS and NTP fan out by design; adjust to your network |

## Known false positives

- Vulnerability scanners and asset-discovery tools.
- Domain controllers, SCCM/Intune, backup or patching servers that talk to many hosts on one port.
- Network monitoring (SNMP 161, ICMP-based tools on some firewalls).

## Triage steps

1. Identify the port: 445, 3389, 22, 5985 sweeps from an internal host suggest lateral-movement preparation.
2. Confirm whether the source is a server that legitimately talks to many hosts.
3. For internal sources, check the host for a new process or user that started the connections.
4. For external sources, check if any connection was allowed and whether the port is exposed on purpose.
