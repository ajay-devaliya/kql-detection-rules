"""Checks every rule YAML before it is merged.

- required fields are present and the rule is Scheduled (this repo has no NRT rules)
- rule IDs are unique GUIDs
- the query in the YAML matches the stand-alone .kql file
- Sentinel limits: at most 20 custom details, at most 3 parameters in the alert name
- every customDetails / entity column is produced by the query's final project

Usage: python tools/validate_rules.py
"""
import glob, os, re, sys, uuid
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REQUIRED = ["id", "name", "description", "severity", "requiredDataConnectors", "queryFrequency",
            "queryPeriod", "triggerOperator", "triggerThreshold", "tactics", "relevantTechniques",
            "query", "entityMappings", "version", "kind"]
errors, seen = [], {}

for path in sorted(glob.glob(os.path.join(ROOT, "rules", "**", "*.yaml"), recursive=True)):
    name = os.path.relpath(path, ROOT)
    with open(path) as f:
        rule = yaml.safe_load(f)
    for key in REQUIRED:
        if key not in rule:
            errors.append(f"{name}: missing '{key}'")
    if rule.get("kind") != "Scheduled":
        errors.append(f"{name}: kind must be Scheduled")
    try:
        uuid.UUID(str(rule.get("id")))
    except ValueError:
        errors.append(f"{name}: id is not a GUID")
    if rule.get("id") in seen:
        errors.append(f"{name}: duplicate id with {seen[rule['id']]}")
    seen[rule.get("id")] = name

    kql = path.replace(os.sep + "rules" + os.sep, os.sep + "queries" + os.sep).replace(".yaml", ".kql")
    if os.path.exists(kql):
        body = "\n".join(l for l in open(kql).read().splitlines() if not l.startswith("// FW-") and not l.startswith("// Severity") and not l.startswith("// MITRE") and not l.startswith("// Table")).strip()
        if body != rule["query"].strip():
            errors.append(f"{name}: query differs from {os.path.relpath(kql, ROOT)}")
    else:
        errors.append(f"{name}: no matching .kql file")

    details = rule.get("customDetails") or {}
    if len(details) > 20:
        errors.append(f"{name}: more than 20 custom details")
    fmt = (rule.get("alertDetailsOverride") or {}).get("alertDisplayNameFormat", "")
    if len(re.findall(r"{{\w+}}", fmt)) > 3:
        errors.append(f"{name}: alert name uses more than 3 parameters")

    last_project = re.findall(r"^\| project (.+)$", rule["query"], re.M)
    if last_project:
        cols = {c.strip() for c in last_project[-1].split(",")}
        used = set(details.values())
        for ent in rule.get("entityMappings", []):
            used |= {m["columnName"] for m in ent["fieldMappings"]}
        for c in sorted(used - cols):
            errors.append(f"{name}: column '{c}' is mapped but not in the final project")

if errors:
    print("\n".join(errors))
    sys.exit(1)
print(f"OK: {len(seen)} rules validated")
