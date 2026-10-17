# FW-005 — Firewall - Vertical port scan from a threat-intelligence IP

Detects a vertical port scan (10 or more ports on one host within one hour) where the source IP is an active indicator in Microsoft Sentinel threat intelligence. The threshold is lower than FW-001 because the source is already known to be malicious.

| Property | Value |
| --- | --- |
| Rule type | Scheduled (not NRT) |
| Runs every | 1h |
| Looks back | 14d |
| Severity | High |
| MITRE tactics | Reconnaissance, Discovery |
| MITRE techniques | T1595, T1046, T1595.001 |
| Data | `CommonSecurityLog` (FortiGate / Palo Alto via CEF) + `ThreatIntelIndicators` |
| Rule file | [`rules/firewall/FW-005-malicious-ip-vertical-port-scan.yaml`](../../rules/firewall/FW-005-malicious-ip-vertical-port-scan.yaml) |
| Query only | [`queries/firewall/FW-005-malicious-ip-vertical-port-scan.kql`](../../queries/firewall/FW-005-malicious-ip-vertical-port-scan.kql) |
| Deploy (ARM) | [`deploy/firewall/FW-005-malicious-ip-vertical-port-scan.json`](../../deploy/firewall/FW-005-malicious-ip-vertical-port-scan.json) |

## Tuning knobs

| Variable | Default | Notes |
| --- | --- | --- |
| `dt_lookBack` | `1h` | firewall data window |
| `ioc_lookBack` | `14d` | threat-intel window |
| `PortThreshold` | `10` |  |

## Known false positives

- Stale or low-confidence indicators: raise the minimum TI_Confidence if this is noisy.
- Shared hosting or cloud IPs that were malicious in the past and have since been reassigned.

## Triage steps

1. Review the indicator (TI_Description, confidence, source feed).
2. Check whether any connection was allowed (Actions). Allowed + open service = high priority.
3. Block the IP at the perimeter if not already blocked, and check other logs for the same IP.
