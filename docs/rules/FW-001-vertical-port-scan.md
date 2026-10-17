# FW-001 — Firewall - Vertical port scan (one source, many ports on one host)

Detects one source IP connecting to 25 or more different destination ports on a single destination host within one hour, as seen by FortiGate or Palo Alto firewalls. This is the pattern of a vertical port scan, where an attacker probes one machine to find which services are open. Denied and allowed connections are both counted, because most scan traffic is blocked.

| Property | Value |
| --- | --- |
| Rule type | Scheduled (not NRT) |
| Runs every | 1h |
| Looks back | 1h |
| Severity | Medium |
| MITRE tactics | Reconnaissance, Discovery |
| MITRE techniques | T1595, T1046, T1595.001 |
| Data | `CommonSecurityLog` (FortiGate / Palo Alto via CEF) |
| Rule file | [`rules/firewall/FW-001-vertical-port-scan.yaml`](../../rules/firewall/FW-001-vertical-port-scan.yaml) |
| Query only | [`queries/firewall/FW-001-vertical-port-scan.kql`](../../queries/firewall/FW-001-vertical-port-scan.kql) |
| Deploy (ARM) | [`deploy/firewall/FW-001-vertical-port-scan.json`](../../deploy/firewall/FW-001-vertical-port-scan.json) |

## Tuning knobs

| Variable | Default | Notes |
| --- | --- | --- |
| `lookback` | `1h` |  |
| `PortThreshold` | `25` | distinct destination ports from one source to one host |
| `ExcludedSources` | `dynamic([])` | approved scanners, e.g. vulnerability scanner IPs |

## Known false positives

- Authorised vulnerability scanners (Nessus, Qualys, OpenVAS): add their IPs to ExcludedSources.
- Monitoring or asset-discovery tools that check many ports on a server.
- Load balancers or proxies that open many short-lived sessions to backend ports.

## Triage steps

1. Check if the source IP is a known scanner or monitoring tool in your environment.
2. Look at SamplePorts and Actions: were any connections allowed? An allowed connection on a sensitive port (22, 3389, 445, 1433) raises the priority.
3. If the source is internal, check the host for compromise (EDR, process creation around the start time).
4. If the source is external and nothing was allowed, block the IP at the perimeter and close as a true positive with low impact.
