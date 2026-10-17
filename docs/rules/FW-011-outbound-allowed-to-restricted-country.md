# FW-011 — Firewall - Outbound connection allowed to a restricted country

Detects internal hosts making outbound connections to public IPs in a restricted country that the firewall allowed. Outbound traffic to countries the organisation has no business with can indicate malware command-and-control, data exfiltration or policy violations.

| Property | Value |
| --- | --- |
| Rule type | Scheduled (not NRT) |
| Runs every | 1h |
| Looks back | 1h |
| Severity | Medium |
| MITRE tactics | CommandAndControl, Exfiltration |
| MITRE techniques | T1071, T1041 |
| Data | `CommonSecurityLog` (FortiGate / Palo Alto via CEF) |
| Rule file | [`rules/firewall/FW-011-outbound-allowed-to-restricted-country.yaml`](../../rules/firewall/FW-011-outbound-allowed-to-restricted-country.yaml) |
| Query only | [`queries/firewall/FW-011-outbound-allowed-to-restricted-country.kql`](../../queries/firewall/FW-011-outbound-allowed-to-restricted-country.kql) |
| Deploy (ARM) | [`deploy/firewall/FW-011-outbound-allowed-to-restricted-country.json`](../../deploy/firewall/FW-011-outbound-allowed-to-restricted-country.json) |

## Tuning knobs

| Variable | Default | Notes |
| --- | --- | --- |
| `lookback` | `1h` | EXAMPLE list only. Replace with your organisation's or customer's restricted-country policy. |
| `RestrictedCountries` | `dynamic([
    "North Korea", "Korea, Democratic People's Rep` | FortiGate logs allowed sessions as accept/close/timeout/*-rst; Palo Alto uses allow |
| `AllowedActions` | `dynamic(["accept", "allow", "close", "timeout", "server-rst"` |  |

## Known false positives

- Software updates or CDNs served from that country.
- Geo-IP mistakes for cloud and anycast IPs.
- Business travel or partners: update the policy list.

## Triage steps

1. Identify the internal host, user and process making the connection.
2. Check BytesSent for possible exfiltration.
3. Check the destination IPs in threat intelligence and the DNS names they resolved from.
4. Block the destination if it is not business-justified and report the policy gap.
