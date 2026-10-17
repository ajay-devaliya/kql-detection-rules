# FW-008 — Palo Alto - Configuration change or commit by administrator

Detects configuration changes on Palo Alto Networks firewalls (PAN-OS CONFIG logs): add, delete, edit, set, move, rename, clone and commit commands. Each alert shows the administrator, the client used (Web or CLI), the configuration path and the result. Changes to security rules, admin accounts, NAT, VPN and log forwarding are flagged as high risk.

| Property | Value |
| --- | --- |
| Rule type | Scheduled (not NRT) |
| Runs every | 15m |
| Looks back | 15m |
| Severity | Medium |
| MITRE tactics | DefenseEvasion, Persistence |
| MITRE techniques | T1562, T1098, T1562.004 |
| Data | `CommonSecurityLog` (FortiGate / Palo Alto via CEF) |
| Rule file | [`rules/firewall/FW-008-paloalto-configuration-change.yaml`](../../rules/firewall/FW-008-paloalto-configuration-change.yaml) |
| Query only | [`queries/firewall/FW-008-paloalto-configuration-change.kql`](../../queries/firewall/FW-008-paloalto-configuration-change.kql) |
| Deploy (ARM) | [`deploy/firewall/FW-008-paloalto-configuration-change.json`](../../deploy/firewall/FW-008-paloalto-configuration-change.json) |

## Tuning knobs

| Variable | Default | Notes |
| --- | --- | --- |
| `lookback` | `15m` |  |
| `HighRiskPaths` | `dynamic(["rulebase", "security", "nat", "mgt-config", "users` |  |
| `ApprovedAdmins` | `dynamic([])` | optional: Panorama or automation accounts under change management |

## Known false positives

- Approved change windows: match to the change ticket.
- Panorama pushes and automation (Ansible, Terraform) service accounts.

## Triage steps

1. Match the change to a change request.
2. Check the admin's source IP and client (Web or CLI).
3. Review ConfigPaths for security rulebase, NAT, admin users and log-forwarding changes.
4. If the change was committed without approval, revert and review admin authentication logs (SYSTEM logs, subtype auth).
