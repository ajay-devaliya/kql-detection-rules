# FW-010 — Firewall - Outbound connection allowed to a threat-intelligence IP

Detects internal hosts making outbound connections to IPs that are active indicators in Microsoft Sentinel threat intelligence, where the firewall allowed the session. This can indicate malware calling its command-and-control server or data being sent to attacker infrastructure.

| Property | Value |
| --- | --- |
| Rule type | Scheduled (not NRT) |
| Runs every | 1h |
| Looks back | 14d |
| Severity | High |
| MITRE tactics | CommandAndControl, Exfiltration |
| MITRE techniques | T1071, T1041 |
| Data | `CommonSecurityLog` (FortiGate / Palo Alto via CEF) + `ThreatIntelIndicators` |
| Rule file | [`rules/firewall/FW-010-outbound-allowed-to-malicious-ip.yaml`](../../rules/firewall/FW-010-outbound-allowed-to-malicious-ip.yaml) |
| Query only | [`queries/firewall/FW-010-outbound-allowed-to-malicious-ip.kql`](../../queries/firewall/FW-010-outbound-allowed-to-malicious-ip.kql) |
| Deploy (ARM) | [`deploy/firewall/FW-010-outbound-allowed-to-malicious-ip.json`](../../deploy/firewall/FW-010-outbound-allowed-to-malicious-ip.json) |

## Tuning knobs

| Variable | Default | Notes |
| --- | --- | --- |
| `dt_lookBack` | `1h` |  |
| `ioc_lookBack` | `14d` |  |
| `MinConfidence` | `0` | raise (for example to 50) if low-confidence indicators are noisy |
| `AllowedActions` | `dynamic(["accept", "allow", "close", "timeout", "server-rst"` |  |

## Known false positives

- Shared CDN or cloud IPs listed in a feed while also hosting legitimate services.
- Security tools (sandboxes, TI enrichment servers) that contact malicious IPs on purpose: exclude their source IPs.
- Expired or low-confidence indicators.

## Triage steps

1. Identify the internal host and its user.
2. Check BytesSent: large uploads suggest exfiltration.
3. Look at the process that made the connection (EDR / Sysmon event ID 3) and DNS queries around the same time.
4. Isolate the host if C2 is confirmed and block the IP at the firewall.
