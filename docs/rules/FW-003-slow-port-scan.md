# FW-003 — Firewall - Slow port scan over 24 hours

Detects a low-and-slow scan: one source IP touching 50 or more different host:port targets over 24 hours, spread across at least 6 separate hours, while never exceeding 20 targets in any single hour. Attackers scan slowly to stay under the one-hour thresholds used by FW-001 and FW-002; this rule catches what those miss.

| Property | Value |
| --- | --- |
| Rule type | Scheduled (not NRT) |
| Runs every | 1h |
| Looks back | 1d |
| Severity | Medium |
| MITRE tactics | Reconnaissance, Discovery |
| MITRE techniques | T1595, T1046, T1595.001 |
| Data | `CommonSecurityLog` (FortiGate / Palo Alto via CEF) |
| Rule file | [`rules/firewall/FW-003-slow-port-scan.yaml`](../../rules/firewall/FW-003-slow-port-scan.yaml) |
| Query only | [`queries/firewall/FW-003-slow-port-scan.kql`](../../queries/firewall/FW-003-slow-port-scan.kql) |
| Deploy (ARM) | [`deploy/firewall/FW-003-slow-port-scan.json`](../../deploy/firewall/FW-003-slow-port-scan.json) |

## Tuning knobs

| Variable | Default | Notes |
| --- | --- | --- |
| `lookback` | `1d` |  |
| `MinTotalTargets` | `50` | distinct host:port pairs over the whole day |
| `MinActiveHours` | `6` | the activity must be spread out |
| `MaxTargetsPerHour` | `20` | above this, the fast-scan rules (FW-001/FW-002) already fire |
| `ExcludedSources` | `dynamic([])` |  |

## Known false positives

- Busy servers with many legitimate clients-to-service connections (proxies, jump hosts). Tune by excluding them.
- Monitoring systems that poll many services slowly through the day.
- Peer-to-peer or VoIP applications using random high ports.

## Triage steps

1. Look at SampleTargets: random or sequential ports point to scanning; a fixed set of business ports points to normal traffic.
2. Check if the same source also triggered FW-001, FW-002 or a threat-intel match.
3. For external sources, check reputation and whether anything was allowed.
4. This rule runs hourly over 24 hours, so the same source can re-alert; incident grouping in the ARM template merges these.
