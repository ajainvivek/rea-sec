#!/usr/bin/env python3
"""Turn an attack path (JSON) into an ATT&CK tagged markdown table and a mermaid diagram.

Input JSON: a list of steps, or {"title": ..., "steps": [...]}. Each step:
  {"tactic": "Initial Access", "technique": "T1190", "name": "Exploit Public-Facing Application",
   "detail": "JNDI lookup in logged header", "status": "CONFIRMED", "source": "https://..."}
Only "technique" and "detail" are required. Usage:
    python3 attack_map.py steps.json [--format md|mermaid|both]
"""
import argparse
import json
import re
import sys

TECH_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
TACTIC_ORDER = ["Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
                "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery",
                "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"]
# Small offline lookup so common IDs get names and tactics without network access.
KNOWN = {
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1078": ("Valid Accounts", "Initial Access"),
    "T1566": ("Phishing", "Initial Access"),
    "T1566.001": ("Spearphishing Attachment", "Initial Access"),
    "T1566.002": ("Spearphishing Link", "Initial Access"),
    "T1195": ("Supply Chain Compromise", "Initial Access"),
    "T1199": ("Trusted Relationship", "Initial Access"),
    "T1133": ("External Remote Services", "Initial Access"),
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1203": ("Exploitation for Client Execution", "Execution"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1071": ("Application Layer Protocol", "Command and Control"),
    "T1505.003": ("Web Shell", "Persistence"),
    "T1136": ("Create Account", "Persistence"),
    "T1068": ("Exploitation for Privilege Escalation", "Privilege Escalation"),
    "T1562": ("Impair Defenses", "Defense Evasion"),
    "T1027": ("Obfuscated Files or Information", "Defense Evasion"),
    "T1552": ("Unsecured Credentials", "Credential Access"),
    "T1528": ("Steal Application Access Token", "Credential Access"),
    "T1621": ("Multi-Factor Authentication Request Generation", "Credential Access"),
    "T1003": ("OS Credential Dumping", "Credential Access"),
    "T1082": ("System Information Discovery", "Discovery"),
    "T1021": ("Remote Services", "Lateral Movement"),
    "T1530": ("Data from Cloud Storage", "Collection"),
    "T1213": ("Data from Information Repositories", "Collection"),
    "T1041": ("Exfiltration Over C2 Channel", "Exfiltration"),
    "T1567": ("Exfiltration Over Web Service", "Exfiltration"),
    "T1486": ("Data Encrypted for Impact", "Impact"),
    "T1496": ("Resource Hijacking", "Impact"),
    "T1656": ("Impersonation", "Defense Evasion"),
}
STATUSES = {"CONFIRMED", "REPORTED", "INFERRED"}


def load(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, list):
        return "Attack path", data
    return data.get("title", "Attack path"), data.get("steps", [])


def normalise(steps):
    out = []
    for i, s in enumerate(steps, 1):
        tid = str(s.get("technique", "")).upper().strip()
        if not TECH_RE.match(tid):
            raise ValueError(f"step {i}: technique '{tid}' is not an ATT&CK ID like T1190 or T1566.002")
        name, tactic = KNOWN.get(tid, KNOWN.get(tid.split(".")[0], (None, None)))
        status = str(s.get("status", "INFERRED")).upper()
        if status not in STATUSES:
            raise ValueError(f"step {i}: status must be one of {sorted(STATUSES)}")
        if not s.get("detail"):
            raise ValueError(f"step {i}: 'detail' is required")
        out.append({"n": i, "technique": tid, "name": s.get("name") or name or "unknown technique",
                    "tactic": s.get("tactic") or tactic or "Unmapped", "detail": s["detail"],
                    "status": status, "source": s.get("source", "")})
    return out


def link(tid):
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


def md_table(title, steps):
    rows = [f"### {title}", "", "| # | Tactic | Technique | What happened | Status | Source |",
            "|---|---|---|---|---|---|"]
    for s in steps:
        src = f"[link]({s['source']})" if s["source"] else "none"
        rows.append(f"| {s['n']} | {s['tactic']} | [{s['technique']}]({link(s['technique'])}) {s['name']} | "
                    f"{s['detail']} | {s['status']} | {src} |")
    missing = [s["n"] for s in steps if not s["source"] and s["status"] != "INFERRED"]
    if missing:
        rows += ["", f"> Warning: steps {missing} are marked confirmed or reported but have no source."]
    return "\n".join(rows)


def esc(text):
    return re.sub(r'["<>{}\[\]|]', "", text)


def short(text, limit=60):
    if len(text) <= limit:
        return text
    return text[:limit].rsplit(" ", 1)[0] + "..."


def mermaid(steps):
    lines = ["```mermaid", "flowchart LR"]
    for s in steps:
        style = {"CONFIRMED": ":::confirmed", "REPORTED": ":::reported", "INFERRED": ":::inferred"}[s["status"]]
        lines.append(f'  S{s["n"]}["{s["n"]}. {esc(s["tactic"])}<br/>{s["technique"]} {esc(s["name"])}<br/>'
                     f'<i>{short(esc(s["detail"]))}</i>"]{style}')
    for a, b in zip(steps, steps[1:]):
        lines.append(f'  S{a["n"]} --> S{b["n"]}')
    lines += ["  classDef confirmed fill:#d4f7d4,stroke:#1a7f37",
              "  classDef reported fill:#fff4c2,stroke:#9a6700",
              "  classDef inferred fill:#eeeeee,stroke:#666,stroke-dasharray: 4 3", "```"]
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("steps_json")
    ap.add_argument("--format", choices=["md", "mermaid", "both"], default="both")
    a = ap.parse_args(argv)
    try:
        title, raw = load(a.steps_json)
        steps = normalise(raw)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    parts = []
    if a.format in ("md", "both"):
        parts.append(md_table(title, steps))
    if a.format in ("mermaid", "both"):
        parts.append(mermaid(steps))
    print("\n\n".join(parts))
    return 0


if __name__ == "__main__":
    sys.exit(main())
