# KQL Detection Rules: Firewall

Microsoft Sentinel scheduled analytics rules written in KQL (Kusto Query Language) for **FortiGate and Palo Alto** firewalls. They cover port scans, ping sweeps, threat-intel matches, configuration changes and traffic allowed to or from restricted countries. Windows and Linux rules are next.

Each rule is available in two forms:

- `rules/firewall/` holds the rules as Sentinel analytics rule YAML (query, schedule, severity, MITRE mapping, entity mapping).
- `queries/firewall/` holds the same queries as plain `.kql`, ready to paste into Log Analytics.

All rules are **Scheduled** rules, not NRT.

## Rules

| ID | Detection | Severity | Runs / looks back | MITRE ATT&CK |
| --- | --- | --- | --- | --- |
| [FW-001](rules/firewall/FW-001-vertical-port-scan.yaml) | Vertical port scan: one source, many ports on one host | Medium | 1h / 1h | T1595.001, T1046 |
| [FW-002](rules/firewall/FW-002-horizontal-port-scan.yaml) | Horizontal port scan: one source, one port across many hosts | Medium | 1h / 1h | T1595.001, T1046 |
| [FW-003](rules/firewall/FW-003-slow-port-scan.yaml) | Slow port scan spread over 24 hours | Medium | 1h / 1d | T1595.001, T1046 |
| [FW-004](rules/firewall/FW-004-icmp-ping-sweep.yaml) | ICMP ping sweep (host discovery) | Low | 1h / 1h | T1595.001, T1018 |
| [FW-005](rules/firewall/FW-005-malicious-ip-vertical-port-scan.yaml) | Vertical port scan from a threat-intel IP | High | 1h / 14d | T1595.001, T1046 |
| [FW-006](rules/firewall/FW-006-malicious-ip-horizontal-port-scan.yaml) | Horizontal port scan from a threat-intel IP | High | 1h / 14d | T1595.001, T1046 |
| [FW-007](rules/firewall/FW-007-fortigate-configuration-change.yaml) | FortiGate configuration change by an administrator | Medium | 15m / 15m | T1562.004, T1098 |
| [FW-008](rules/firewall/FW-008-paloalto-configuration-change.yaml) | Palo Alto configuration change or commit | Medium | 15m / 15m | T1562.004, T1098 |
| [FW-009](rules/firewall/FW-009-inbound-allowed-from-restricted-country.yaml) | Inbound connection **allowed** from a restricted country | High | 1h / 1h | T1190, T1133 |
| [FW-010](rules/firewall/FW-010-outbound-allowed-to-malicious-ip.yaml) | Outbound connection **allowed** to a threat-intel IP | High | 1h / 14d | T1071, T1041 |
| [FW-011](rules/firewall/FW-011-outbound-allowed-to-restricted-country.yaml) | Outbound connection **allowed** to a restricted country | Medium | 1h / 1h | T1071, T1041 |

## Data sources

| Table | Source | Used by |
| --- | --- | --- |
| `CommonSecurityLog` | FortiGate and Palo Alto logs in CEF format (CEF via AMA connector) | All rules |
| `ThreatIntelIndicators` | Any Sentinel threat-intelligence connector | FW-005, FW-006, FW-010 |

## Notes

- Thresholds and exclusion lists are `let` variables at the top of each query, so they're easy to tune.
- The `RestrictedCountries` list in FW-009 and FW-011 is an example only. Replace it with your organisation's policy.
- Test each query against your own data before enabling it as a rule.

## Author

**Ajay Devaliya**, SOC Analyst
[LinkedIn](https://www.linkedin.com/in/ajay-devaliya-867075257) · [GitHub](https://github.com/ajay-devaliya)

Licensed under the [MIT License](LICENSE).
