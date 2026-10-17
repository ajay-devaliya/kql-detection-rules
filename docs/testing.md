# Testing the rules in a lab

Run these only against systems you own or have written permission to test. Each test should produce one alert from the matching rule on its next scheduled run. To see results immediately, run the query from `queries/firewall/` in *Logs*.

Set the lab up so that the "attacker" machine's traffic crosses the firewall, and the firewall is logging denied traffic (see [data-sources.md](data-sources.md)).

| Rule | How to trigger it | What should appear |
| --- | --- | --- |
| FW-001 Vertical scan | `nmap -Pn -p 1-100 <target-ip>` | One alert: attacker IP → target, about 100 ports |
| FW-002 Horizontal scan | `nmap -Pn -p 445 <lab-subnet>/24` | One alert: attacker IP, port 445, 20+ hosts |
| FW-003 Slow scan | `nmap -Pn --max-retries 0 --scan-delay 10m -p 1-60 <target-ip>` (runs about 10 hours) | One alert after 6+ active hours; FW-001 must **not** fire |
| FW-004 Ping sweep | `nmap -sn -PE <lab-subnet>/24` | One alert: attacker IP, 20+ hosts |
| FW-005 / FW-006 TI scans | Add the attacker's IP as a test indicator (*Sentinel → Threat intelligence → Add new*, short expiry), then repeat the FW-001 or FW-002 test with a smaller range (`-p 1-20`) | High-severity alert with the TI description; delete the indicator afterwards |
| FW-007 FortiGate change | Create or edit a test address object in the GUI or CLI | Alert showing your admin user, GUI/CLI, and `firewall.address` |
| FW-008 Palo Alto change | Edit a test address object and commit | Alert with commands `edit`/`set` and `commit`, `Committed = Yes` |
| FW-009 Inbound restricted country | Temporarily add the country of a test public IP to `RestrictedCountries`, then allow and generate inbound traffic from it | Alert with that country; remove it from the list afterwards |
| FW-010 Outbound to TI IP | Add a harmless public test IP you control as an indicator, then `curl http://<that-ip>` from an internal host | Alert: internal host → indicator IP |
| FW-011 Outbound restricted country | Temporarily add the country of a test destination to `RestrictedCountries`, then browse to it from an internal host | Alert with the destination country |

## After testing

- Remove test indicators and test countries.
- Note the alert delay you observed (log forwarding plus the rule schedule). It belongs in your SOC runbook.
- Record any field differences you found and update the rule and [data-sources.md](data-sources.md).
