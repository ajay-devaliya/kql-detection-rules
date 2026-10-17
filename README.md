# KQL Detection Rules: Firewall, Windows and Linux

Microsoft Sentinel scheduled analytics rules written in KQL (Kusto Query Language). The first pack covers **FortiGate and Palo Alto firewalls**: port scans, ping sweeps, threat-intel matches, configuration changes and geo-policy violations. Windows and Linux packs are next.

Every rule ships in three forms:

- **Sentinel YAML** (`rules/`): the format Microsoft uses in the Azure-Sentinel GitHub repo
- **Plain KQL** (`queries/`): paste it into Log Analytics to hunt or test
- **ARM template** (`deploy/`): import it straight into Sentinel

All rules are **Scheduled** (not NRT). They aggregate over a time window, which near-real-time rules can't do.

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

Each rule has its own page in [`docs/rules/`](docs/rules/) with tuning variables, known false positives and triage steps.

## How the scan rules fit together

| Pattern | Rule | Grouped by | Default threshold |
| --- | --- | --- | --- |
| Many ports, one host, fast | FW-001 | source + destination | 25 ports in 1 hour |
| One port, many hosts, fast | FW-002 | source + port | 20 hosts in 1 hour |
| Many targets, slow | FW-003 | source | 50 host:port targets over 24 hours, at least 6 active hours, under 20 per hour |
| ICMP to many hosts | FW-004 | source | 20 hosts in 1 hour |
| Same as FW-001/002, known-bad source | FW-005 / FW-006 | as above | 10 ports / 10 hosts |

FW-003 only fires when the hourly rate stays under the fast-scan thresholds, so a fast scan and a slow scan don't double-alert.

## Data sources

| Table | Source | Used by |
| --- | --- | --- |
| `CommonSecurityLog` | FortiGate and Palo Alto logs in CEF format through the Azure Monitor Agent (CEF via AMA connector) | All rules |
| `ThreatIntelIndicators` | Any Sentinel threat-intelligence connector (TAXII, Defender Threat Intelligence, upload) | FW-005, FW-006, FW-010 |

The threat-intel rules use the current `ThreatIntelIndicators` table. Microsoft stopped writing to the older `ThreatIntelligenceIndicator` table on 31 July 2025.

Firewall logging settings, field mapping and the queries to check your data before enabling the rules are in [docs/data-sources.md](docs/data-sources.md).

## Deploy

**Option 1: Sentinel portal.** Go to *Microsoft Sentinel → Analytics → Import*, then choose a file from `deploy/firewall/`, or `deploy/firewall-rules-all.json` to import all 11 at once.

**Option 2: Azure CLI.**

```bash
az deployment group create \
  --resource-group <resource-group> \
  --template-file deploy/firewall-rules-all.json \
  --parameters workspace=<log-analytics-workspace-name>
```

**Option 3: Test the query first.** Copy a file from `queries/firewall/` into *Logs* and run it over the last 7 days. This shows how noisy the rule will be before you enable it.

The ARM templates create incidents and group alerts that share the same entities into one incident (5 hours, or 1 day for the daily-lookback rules).

## Before enabling in production

1. Run the checks in [docs/data-sources.md](docs/data-sources.md) to confirm your field values match (actions, log IDs, country names).
2. Replace the example `RestrictedCountries` list in FW-009 and FW-011 with your organisation's policy.
3. Add vulnerability scanners and monitoring servers to `ExcludedSources` in FW-001 to FW-004.
4. Run each query over 7–14 days of history and adjust the thresholds.
5. Test in a lab using [docs/testing.md](docs/testing.md).

## Validation

Every push runs two checks in GitHub Actions ([`.github/workflows/validate.yml`](.github/workflows/validate.yml)):

- `tools/validate_rules.py` checks required fields, unique GUIDs, Sentinel limits, that mapped columns exist in the final `project`, and that each YAML query matches its `.kql` file.
- `tools/kql-check/check.js` parses and analyses every query with Microsoft's Kusto language service against the table columns the rules use.

Run them locally:

```bash
pip install pyyaml && python tools/validate_rules.py
npm install && npm run check:kql
```

## Repository layout

```
rules/firewall/       Sentinel analytics rule YAML (source of truth)
queries/firewall/     the same queries as plain .kql
deploy/firewall/      one ARM template per rule
deploy/               firewall-rules-all.json, every firewall rule in one template
docs/rules/           one page per rule: tuning, false positives, triage
docs/data-sources.md  log onboarding and field checks
docs/testing.md       how to trigger each rule in a lab
tools/                validation scripts
rules/windows/        next
rules/linux/          next
```

## Roadmap

- [x] Firewall pack: FortiGate and Palo Alto (11 rules)
- [ ] Windows pack: Security event log and Sysmon
- [ ] Linux pack: Syslog and auditd

## Author

**Ajay Devaliya**, SOC Analyst. I onboard log sources into SIEM and build the detections, dashboards and reports on top of them.
[LinkedIn](https://www.linkedin.com/in/ajay-devaliya-867075257) · [GitHub](https://github.com/ajay-devaliya)

## Disclaimer

These rules are a starting point. Test them against your own data, and tune the thresholds and exclusions for your environment before you rely on them. Run scan tests only against systems you own or are authorised to test.

Licensed under the [MIT License](LICENSE).
