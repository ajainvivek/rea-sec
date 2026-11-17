#!/usr/bin/env python3
"""Fetch public advisory data for a CVE: NVD, GitHub Advisory Database, CISA KEV.

Read only. Talks to public APIs, never to the affected product.
Stdlib only. Usage:
    python3 fetch_advisory.py CVE-2021-44228
    python3 fetch_advisory.py CVE-2021-44228 --format json
Set NVD_API_KEY or GITHUB_TOKEN to raise rate limits (optional).
"""
import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}"
GHSA = "https://api.github.com/advisories?cve_id={}"
KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
EXPLOIT_ARCHIVES = re.compile(r"packetstormsecurity|exploit-db\.com|/exploits?/|payload", re.I)
UA = "rea-sec/1.0 (+https://github.com/ajainvivek/rea-sec)"


def get_json(url, headers=None, timeout=30):
    h = {"User-Agent": UA, "Accept": "application/json"}
    h.update(headers or {})
    req = urllib.request.Request(url, headers=h)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def parse_nvd(data):
    vulns = data.get("vulnerabilities") or []
    if not vulns:
        return None
    c = vulns[0]["cve"]
    desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
    cvss = None
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        m = c.get("metrics", {}).get(key)
        if m:
            d = m[0]["cvssData"]
            cvss = {"version": d.get("version"), "score": d.get("baseScore"),
                    "severity": d.get("baseSeverity") or m[0].get("baseSeverity"),
                    "vector": d.get("vectorString")}
            break
    cwes = sorted({d["value"] for w in c.get("weaknesses", []) for d in w.get("description", [])
                   if d.get("value", "").startswith("CWE-")})
    refs = [{"url": r["url"], "tags": r.get("tags", [])} for r in c.get("references", [])]
    return {"id": c["id"], "published": c.get("published", "")[:10],
            "last_modified": c.get("lastModified", "")[:10], "description": desc,
            "cvss": cvss, "cwes": cwes, "references": refs}


def parse_ghsa(data):
    out = []
    for a in data or []:
        pkgs = []
        for v in a.get("vulnerabilities") or []:
            p = v.get("package") or {}
            pkgs.append({"ecosystem": p.get("ecosystem"), "name": p.get("name"),
                         "vulnerable": v.get("vulnerable_version_range"),
                         "patched": v.get("first_patched_version")})
        out.append({"ghsa_id": a.get("ghsa_id"), "url": a.get("html_url"),
                    "summary": a.get("summary"), "severity": a.get("severity"),
                    "published": (a.get("published_at") or "")[:10], "packages": pkgs})
    return out


def parse_kev(data, cve):
    for v in data.get("vulnerabilities", []):
        if v.get("cveID", "").upper() == cve:
            return {"date_added": v.get("dateAdded"), "due_date": v.get("dueDate"),
                    "ransomware": v.get("knownRansomwareCampaignUse"),
                    "action": v.get("requiredAction"), "name": v.get("vulnerabilityName")}
    return None


def fetch(cve):
    cve = cve.upper()
    result = {"cve": cve, "nvd": None, "ghsa": [], "kev": None, "errors": []}
    nvd_h = {"apiKey": os.environ["NVD_API_KEY"]} if os.environ.get("NVD_API_KEY") else {}
    gh_h = {"Accept": "application/vnd.github+json"}
    if os.environ.get("GITHUB_TOKEN"):
        gh_h["Authorization"] = "Bearer " + os.environ["GITHUB_TOKEN"]
    for name, url, hdr, parser in (
        ("nvd", NVD.format(cve), nvd_h, parse_nvd),
        ("ghsa", GHSA.format(cve), gh_h, parse_ghsa),
        ("kev", KEV, {}, lambda d: parse_kev(d, cve)),
    ):
        try:
            result[name] = parser(get_json(url, hdr))
        except (urllib.error.URLError, TimeoutError, ValueError, KeyError) as e:
            result["errors"].append(f"{name}: {e}")
    return result


def to_markdown(r):
    lines = [f"# {r['cve']}", ""]
    n = r.get("nvd")
    if n:
        c = n.get("cvss") or {}
        lines += [f"**Published (NVD):** {n['published']}  ",
                  f"**CVSS:** {c.get('score')} {c.get('severity')} (v{c.get('version')}) `{c.get('vector')}`  ",
                  f"**CWE:** {', '.join(n['cwes']) or 'not assigned'}", "", n["description"], ""]
    else:
        lines += ["NVD: no record found.", ""]
    k = r.get("kev")
    lines += ["## CISA KEV", (f"Listed {k['date_added']}, due {k['due_date']}, ransomware use: {k['ransomware']}. "
                              f"Action: {k['action']}" if k else "Not in the KEV catalog."), ""]
    if r.get("ghsa"):
        lines += ["## GitHub Advisory Database", "| GHSA | Package | Vulnerable | First patched |", "|---|---|---|---|"]
        for a in r["ghsa"]:
            for p in sorted(a["packages"] or [{}], key=lambda x: (str(x.get("ecosystem")), str(x.get("name")), str(x.get("patched")))):
                lines.append(f"| [{a['ghsa_id']}]({a['url']}) | {p.get('ecosystem')}:{p.get('name')} | "
                             f"{p.get('vulnerable')} | {p.get('patched')} |")
        lines.append("")
    if n and n["references"]:
        lines += ["## References"]
        seen, refs = set(), []
        for x in n["references"]:
            # Guardrail: skip links tagged as exploits; REA-Sec does not point readers at PoCs.
            if x["url"] in seen or "Exploit" in x["tags"] or EXPLOIT_ARCHIVES.search(x["url"]):
                continue
            seen.add(x["url"])
            refs.append(x)
        fixes = [x for x in refs if re.search(r"/commit/|/pull/|/releases/|/compare/", x["url"])
                 or "Patch" in x["tags"]]
        vendor = [x for x in refs if "Vendor Advisory" in x["tags"] and x not in fixes]
        rest = [x for x in refs if x not in fixes and x not in vendor]
        for x in fixes:
            lines.append(f"- FIX: {x['url']}")
        for x in vendor:
            lines.append(f"- VENDOR: {x['url']}")
        for x in rest[:15]:
            lines.append(f"- {x['url']}" + (f" ({', '.join(x['tags'])})" if x["tags"] else ""))
        skipped = len(n["references"]) - len(refs)
        if skipped:
            lines.append(f"- ({skipped} duplicate or exploit-tagged references omitted)")
        lines.append("")
    if r["errors"]:
        lines += ["## Fetch errors"] + [f"- {e}" for e in r["errors"]]
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("cve")
    ap.add_argument("--format", choices=["md", "json"], default="md")
    a = ap.parse_args(argv)
    if not CVE_RE.match(a.cve):
        ap.error("expected an ID like CVE-2021-44228")
    r = fetch(a.cve)
    print(json.dumps(r, indent=2) if a.format == "json" else to_markdown(r))
    return 0 if r["nvd"] or r["ghsa"] else 1


if __name__ == "__main__":
    sys.exit(main())
