# Data sources and field checks

All firewall rules read the `CommonSecurityLog` table. Logs arrive as CEF over syslog on a Linux log forwarder that runs the Azure Monitor Agent. Sentinel's **Common Event Format (CEF) via AMA** connector and a data collection rule (DCR) send them to the workspace.

```
FortiGate / Palo Alto  --syslog CEF (514)-->  Linux forwarder (AMA)  --DCR-->  Log Analytics: CommonSecurityLog
```

## 1. FortiGate

Send logs as CEF:

```
config log syslogd setting
    set status enable
    set server "<forwarder-ip>"
    set port 514
    set format cef
end
```

Make sure the logs the rules need are generated:

```
# Configuration-change events (FW-007)
config log eventfilter
    set system enable
end

# Log denied traffic hitting the implicit deny (most scan traffic is denied)
config log setting
    set fwpolicy-implicit-log enable
end
```

On each firewall policy, set `set logtraffic all` (not just `utm`). Otherwise allowed sessions are missing and FW-009 to FW-011 stay silent.

## 2. Palo Alto (PAN-OS)

1. *Device → Server Profiles → Syslog*: add the forwarder. Set the custom log format to Palo Alto's published **CEF format** for Traffic, Threat, Config and System logs.
2. *Objects → Log Forwarding*: forward Traffic logs to that profile, and attach the profile to your security rules, including the interzone/intrazone default rules if you want denied traffic.
3. *Device → Log Settings*: forward **Configuration** and **System** logs to the same profile (FW-008).

## 3. Check your data before enabling the rules

Run these in *Logs*. Each one confirms an assumption the rules make.

**Is firewall data arriving, and under which vendor and product names?**

```kql
CommonSecurityLog
| where TimeGenerated > ago(1d)
| summarize Events = count() by DeviceVendor, DeviceProduct
```

Expected: `Fortinet / Fortigate` and `Palo Alto Networks / PAN-OS`. If yours differ, update the `DeviceVendor` filter in the rules.

**Which action values does your firewall use?** (FW-009, FW-010, FW-011 use `AllowedActions`)

```kql
CommonSecurityLog
| where TimeGenerated > ago(1d)
| where DeviceVendor in ("Fortinet", "Palo Alto Networks")
| summarize Events = count() by DeviceVendor, DeviceAction
| order by Events desc
```

**Are FortiGate configuration events present, and how is the log ID stored?** (FW-007)

```kql
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor == "Fortinet"
| where DeviceEventClassID endswith "44546" or DeviceEventClassID endswith "44547" or Message has "configured"
| project TimeGenerated, DeviceName, DeviceEventClassID, Activity, Message, DestinationUserName, AdditionalExtensions
| take 20
```

Check that `AdditionalExtensions` contains `FTNTFGTcfgpath`, `FTNTFGTcfgobj`, `FTNTFGTcfgattr` and `FTNTFGTui`.

**Are Palo Alto config logs present, and where are admin and command stored?** (FW-008)

```kql
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor == "Palo Alto Networks"
| where Activity =~ "CONFIG" or DeviceEventClassID =~ "CONFIG"
| project TimeGenerated, DeviceName, Activity, DeviceEventClassID, DeviceAction, DestinationUserName, SourceUserName, DestinationServiceName, Message
| take 20
```

**What do country names look like in your data?** (FW-009, FW-011: names in `RestrictedCountries` must match exactly)

```kql
CommonSecurityLog
| where TimeGenerated > ago(1d)
| where DeviceVendor in ("Fortinet", "Palo Alto Networks")
| where isnotempty(SourceIP) and not(ipv4_is_private(SourceIP))
| take 5000
| extend Country = coalesce(
    extract(@"FTNTFGTsrccountry=([^;]+)", 1, AdditionalExtensions),
    tostring(geo_info_from_ip_address(SourceIP).country))
| summarize Events = count() by Country
| order by Events desc
```

**Is threat intelligence loaded?** (FW-005, FW-006, FW-010)

```kql
ThreatIntelIndicators
| where TimeGenerated > ago(14d)
| where ObservableKey in ("ipv4-addr:value", "ipv6-addr:value", "network-traffic:src_ref.value", "network-traffic:dst_ref.value")
| summarize arg_max(TimeGenerated, *) by Id
| where IsDeleted == false and (isnull(ValidUntil) or ValidUntil > now())
| summarize ActiveIPIndicators = dcount(ObservableValue)
```

**How is ICMP stored?** (FW-004)

```kql
CommonSecurityLog
| where TimeGenerated > ago(1d)
| where DeviceVendor in ("Fortinet", "Palo Alto Networks")
| summarize Events = count() by Protocol, ApplicationProtocol, DestinationServiceName
| where Protocol in~ ("icmp", "1") or ApplicationProtocol has "icmp" or DestinationServiceName has_any ("ping", "icmp")
```

## Field reference

| Column | FortiGate (CEF) | Palo Alto (CEF) |
| --- | --- | --- |
| `DeviceAction` | `accept`, `deny`, `close`, `timeout`, `server-rst`, `client-rst` | `allow`, `deny`, `drop`, `reset-*` |
| `DeviceEventClassID` | Log ID (last 5 digits, e.g. `44546`) | Log subtype or result |
| `Activity` | `type:subtype action` text | Log type: `TRAFFIC`, `THREAT`, `CONFIG`, `SYSTEM` |
| Admin user | `DestinationUserName` / `FTNTFGTuser` | `DestinationUserName` (duser) |
| Config details | `FTNTFGTcfgpath`, `FTNTFGTcfgobj`, `FTNTFGTcfgattr` | `Message` (path), `DeviceAction` (command) |
| Country | `FTNTFGTsrccountry`, `FTNTFGTdstcountry` | not sent by default; rules fall back to `geo_info_from_ip_address()` |

Field placement can change with firmware and log format. The checks above are the source of truth for your environment.
