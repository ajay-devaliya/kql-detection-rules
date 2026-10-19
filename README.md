# KQL Detection Rules: Firewall and Windows

Microsoft Sentinel scheduled analytics rules written in KQL (Kusto Query Language).

- **Firewall (11 rules):** FortiGate and Palo Alto: port scans, ping sweeps, threat-intel matches, configuration changes and traffic allowed to or from restricted countries.
- **Windows (23 rules):** credential dumping, brute force, Kerberos attacks, suspicious PowerShell and process activity, defence evasion, persistence and remote access tools.

Linux rules are next.

The repo has two folders:

- `rules/` holds the rules as Sentinel analytics rule YAML (query, schedule, severity, MITRE mapping, entity mapping).
- `queries/` holds the same queries as plain `.kql`, ready to paste into Log Analytics.

All rules are **Scheduled** rules, not NRT.

## Firewall rules

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

## Windows rules

| ID | Detection | Severity | Runs / looks back | MITRE ATT&CK |
| --- | --- | --- | --- | --- |
| [WIN-001](rules/windows/WIN-001-mimikatz-execution.yaml) | Mimikatz execution or command-line usage | High | 1h / 1h | T1003.001 |
| [WIN-002](rules/windows/WIN-002-lsass-memory-access.yaml) | Suspicious access to LSASS memory (credential dumping) | High | 1h / 1h | T1003.001 |
| [WIN-003](rules/windows/WIN-003-suspicious-parent-child-process.yaml) | Office, browser or web server spawning a shell or script host | Medium | 1h / 1h | T1204.002, T1505.003 |
| [WIN-004](rules/windows/WIN-004-rdp-brute-force.yaml) | RDP brute force (with success check) | Medium | 1h / 1h | T1110.001 |
| [WIN-005](rules/windows/WIN-005-rdp-logon-from-malicious-ip.yaml) | RDP or network logon attempt from a threat-intelligence IP | High | 1h / 14d | T1133, T1110, T1078 |
| [WIN-006](rules/windows/WIN-006-authentication-failures-by-logon-type.yaml) | Repeated authentication failures by logon type (3, 4, 5, 10, 11) | Medium | 1h / 1h | T1110.001 |
| [WIN-007](rules/windows/WIN-007-internal-host-brute-forcing-devices.yaml) | Internal host brute forcing or password spraying other devices | High | 1h / 1h | T1110.003 |
| [WIN-008](rules/windows/WIN-008-suspicious-powershell-command.yaml) | Suspicious PowerShell command line (encoded, download cradle, AMSI bypass) | Medium | 1h / 1h | T1059.001 |
| [WIN-009](rules/windows/WIN-009-discovery-command-chain.yaml) | Chain of discovery commands from one user (whoami, net, nltest, ipconfig...) | Medium | 1h / 1h | T1087, T1016, T1082, T1033, T1069 |
| [WIN-010](rules/windows/WIN-010-defender-disabled-or-tampered.yaml) | Microsoft Defender disabled, stopped or exclusions added | High | 15m / 15m | T1562.001 |
| [WIN-011](rules/windows/WIN-011-event-log-cleared.yaml) | Security or System event log cleared | High | 15m / 15m | T1070.001 |
| [WIN-012](rules/windows/WIN-012-audit-policy-or-logging-disabled.yaml) | Audit policy weakened or log collection stopped | High | 15m / 15m | T1562.002, T1562.006 |
| [WIN-013](rules/windows/WIN-013-suspicious-file-created.yaml) | Executable or script dropped by a script host, Office or LOLBin | Medium | 1h / 1h | T1547.001 |
| [WIN-014](rules/windows/WIN-014-suspicious-process-created.yaml) | Process started from a suspicious folder or LOLBin used to download/execute | Medium | 1h / 1h | T1218.005, T1218.010, T1218.011 |
| [WIN-015](rules/windows/WIN-015-reverse-shell-command.yaml) | Reverse shell command line | High | 1h / 1h | T1059.001, T1059.003 |
| [WIN-016](rules/windows/WIN-016-network-connection-from-unusual-process.yaml) | Outbound connection from a process in a suspicious folder or a LOLBin | Medium | 1h / 1h | T1071, T1218 |
| [WIN-017](rules/windows/WIN-017-remote-access-tool-or-tunnel.yaml) | Remote access tool or tunnelling tool executed (possible RAT) | Medium | 1h / 1h | T1219, T1572 |
| [WIN-018](rules/windows/WIN-018-kerberoasting-rc4-service-tickets.yaml) | Kerberoasting: RC4 service tickets requested for several services | High | 1h / 1h | T1558.003 |
| [WIN-019](rules/windows/WIN-019-asrep-roasting.yaml) | AS-REP roasting: ticket issued without Kerberos pre-authentication | Medium | 1h / 1h | T1558.004 |
| [WIN-020](rules/windows/WIN-020-kerberos-password-spray.yaml) | Kerberos password spray or user enumeration | High | 1h / 1h | T1110.003, T1087.002 |
| [WIN-021](rules/windows/WIN-021-suspicious-service-installed.yaml) | Suspicious service installed | High | 1h / 1h | T1543.003, T1569.002 |
| [WIN-022](rules/windows/WIN-022-suspicious-scheduled-task.yaml) | Scheduled task created that runs a script host or a file from a suspicious folder | Medium | 1h / 1h | T1053.005 |
| [WIN-023](rules/windows/WIN-023-user-added-to-privileged-group.yaml) | Account added to a privileged group | High | 15m / 15m | T1098.007 |

## Data sources

| Table | Source | Used by |
| --- | --- | --- |
| `CommonSecurityLog` | FortiGate and Palo Alto logs in CEF format (CEF via AMA connector) | All rules |
| `SecurityEvent` | Windows Security log via the Windows Security Events connector (AMA) | WIN rules using 4624/4625, 4688, 4698, 4719, 4728/4732/4756, 4768/4769/4771, 1102 |
| `Event` | Sysmon, System and Defender logs collected through a Data Collection Rule | WIN-002, 010–013, 016, 021 and the Sysmon part of process rules |
| `ThreatIntelIndicators` | Any Sentinel threat-intelligence connector | FW-005, FW-006, FW-010, WIN-005 |

## Notes

- Thresholds and exclusion lists are `let` variables at the top of each query, so they're easy to tune.
- The `RestrictedCountries` list in FW-009 and FW-011 is an example only. Replace it with your organisation's policy.
- Process rules read both Security 4688 (with command-line auditing on) and Sysmon Event ID 1, so they work with either.
- Sysmon-based rules need Sysmon installed and its log collected into the `Event` table.
- Test each query against your own data before enabling it as a rule.

## Author

**Ajay Devaliya**, SOC Analyst
[LinkedIn](https://www.linkedin.com/in/ajay-devaliya-867075257) · [GitHub](https://github.com/ajay-devaliya)

Licensed under the [MIT License](LICENSE).
