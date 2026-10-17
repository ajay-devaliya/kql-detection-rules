# FW-009 — Firewall - Inbound connection allowed from a restricted country

Detects inbound connections from public IPs located in a restricted country that the firewall allowed (FortiGate accept/close/timeout, Palo Alto allow). If your policy is to block these countries, any allowed session means a geo-blocking gap or a misconfigured rule. Country comes from the FortiGate srccountry field when present, otherwise from Sentinel's geo_info_from_ip_address().

| Property | Value |
| --- | --- |
| Rule type | Scheduled (not NRT) |
| Runs every | 1h |
| Looks back | 1h |
| Severity | High |
| MITRE tactics | InitialAccess, CommandAndControl |
| MITRE techniques | T1190, T1133 |
| Data | `CommonSecurityLog` (FortiGate / Palo Alto via CEF) |
| Rule file | [`rules/firewall/FW-009-inbound-allowed-from-restricted-country.yaml`](../../rules/firewall/FW-009-inbound-allowed-from-restricted-country.yaml) |
| Query only | [`queries/firewall/FW-009-inbound-allowed-from-restricted-country.kql`](../../queries/firewall/FW-009-inbound-allowed-from-restricted-country.kql) |
| Deploy (ARM) | [`deploy/firewall/FW-009-inbound-allowed-from-restricted-country.json`](../../deploy/firewall/FW-009-inbound-allowed-from-restricted-country.json) |

## Tuning knobs

| Variable | Default | Notes |
| --- | --- | --- |
| `lookback` | `1h` | EXAMPLE list only. Replace with your organisation's or customer's restricted-country policy. |
| `RestrictedCountries` | `dynamic([
    "North Korea", "Korea, Democratic People's Rep` | FortiGate logs allowed sessions as accept/close/timeout/*-rst; Palo Alto uses allow |
| `AllowedActions` | `dynamic(["accept", "allow", "close", "timeout", "server-rst"` |  |

## Known false positives

- The organisation does business in that country and the list is out of date.
- Geo-IP errors for VPN, CDN or cloud IPs. Verify the country with a second geo-IP source.
- Published services (web, mail) that are intentionally open to all countries; decide per customer whether to exclude their ports.

## Triage steps

1. Confirm the restricted-country policy for this customer.
2. Find the firewall policy that allowed the traffic and why geo-blocking did not apply.
3. Check DestinationPorts and the destination hosts for signs of exploitation or login attempts.
4. Block the IP or country and report the policy gap.
