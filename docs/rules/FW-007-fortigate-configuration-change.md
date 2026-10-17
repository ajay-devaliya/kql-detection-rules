# FW-007 — FortiGate - Configuration change by administrator

Detects configuration changes on FortiGate firewalls using FortiOS configuration log IDs (32102, 32104, 44544-44547, 32565, 32566). Each alert shows who made the change, from where (GUI or CLI, source IP), and what was changed (configuration path, object and attributes). Changes to high-risk areas such as firewall policies, admin accounts, VPN and logging settings are flagged.

| Property | Value |
| --- | --- |
| Rule type | Scheduled (not NRT) |
| Runs every | 15m |
| Looks back | 15m |
| Severity | Medium |
| MITRE tactics | DefenseEvasion, Persistence |
| MITRE techniques | T1562, T1098, T1562.004 |
| Data | `CommonSecurityLog` (FortiGate / Palo Alto via CEF) |
| Rule file | [`rules/firewall/FW-007-fortigate-configuration-change.yaml`](../../rules/firewall/FW-007-fortigate-configuration-change.yaml) |
| Query only | [`queries/firewall/FW-007-fortigate-configuration-change.kql`](../../queries/firewall/FW-007-fortigate-configuration-change.kql) |
| Deploy (ARM) | [`deploy/firewall/FW-007-fortigate-configuration-change.json`](../../deploy/firewall/FW-007-fortigate-configuration-change.json) |

## Tuning knobs

| Variable | Default | Notes |
| --- | --- | --- |
| `lookback` | `15m` | FortiOS log IDs for configuration activity (CEF carries the last 5 digits, e.g. 0100044546 -> 44546) |
| `ConfigLogIds` | `dynamic(["32102", "32104", "44544", "44545", "44546", "44547` | Paths where a change deserves extra attention |
| `HighRiskPaths` | `dynamic(["firewall.policy", "system.admin", "user.local", "u` |  |
| `ApprovedAdmins` | `dynamic([])` | optional: change-managed service accounts to exclude |

## Known false positives

- Planned changes under an approved change request: confirm the ticket and close as benign.
- FortiManager or automation accounts pushing configuration: add them to ApprovedAdmins only if change-managed.

## Triage steps

1. Match the change to a change request. No ticket = escalate.
2. Check AdminSourceIP: is it a known admin workstation or jump host? A public IP or VPN pool address raises the priority.
3. Review ConfigPaths: new allow-all policies, new admin users, disabled logging or VPN changes are the most dangerous.
4. If unauthorised, disable the admin account, revert the change and review FortiGate login events (log ID 32001/32002) for that user.
