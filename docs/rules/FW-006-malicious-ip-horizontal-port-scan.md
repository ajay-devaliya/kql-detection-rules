# FW-006 — Firewall - Horizontal port scan from a threat-intelligence IP

Detects a horizontal scan (the same port on 10 or more hosts within one hour) where the source IP is an active indicator in Microsoft Sentinel threat intelligence.

| Property | Value |
| --- | --- |
| Rule type | Scheduled (not NRT) |
| Runs every | 1h |
| Looks back | 14d |
| Severity | High |
| MITRE tactics | Reconnaissance, Discovery |
| MITRE techniques | T1595, T1046, T1595.001 |
| Data | `CommonSecurityLog` (FortiGate / Palo Alto via CEF) + `ThreatIntelIndicators` |
| Rule file | [`rules/firewall/FW-006-malicious-ip-horizontal-port-scan.yaml`](../../rules/firewall/FW-006-malicious-ip-horizontal-port-scan.yaml) |
| Query only | [`queries/firewall/FW-006-malicious-ip-horizontal-port-scan.kql`](../../queries/firewall/FW-006-malicious-ip-horizontal-port-scan.kql) |
| Deploy (ARM) | [`deploy/firewall/FW-006-malicious-ip-horizontal-port-scan.json`](../../deploy/firewall/FW-006-malicious-ip-horizontal-port-scan.json) |

## Tuning knobs

| Variable | Default | Notes |
| --- | --- | --- |
| `dt_lookBack` | `1h` |  |
| `ioc_lookBack` | `14d` |  |
| `HostThreshold` | `10` |  |

## Known false positives

- Stale or low-confidence indicators.
- Internet-wide research scanners listed in some feeds (Shodan, Censys); decide per customer whether to suppress them.

## Triage steps

1. Review the indicator and the targeted port.
2. List which hosts allowed the connection and check those services for exploitation attempts.
3. Block at the perimeter and add to the customer report.
