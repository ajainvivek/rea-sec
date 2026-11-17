#!/usr/bin/env python3
"""Offline phishing triage for an .eml file or pasted raw headers.

Makes NO network calls and never opens links. Reports sender mismatches,
SPF/DKIM/DMARC results, the Received chain, lookalike hints, and defanged URLs.
Usage:
    python3 phish_headers.py message.eml [--json]
"""
import argparse
import email
import email.policy
import hashlib
import json
import re
import sys
from email.utils import parseaddr
from urllib.parse import urlsplit, parse_qs, unquote

URL_RE = re.compile(r"""https?://[^\s"'<>\)\]]+""", re.I)
REDIRECT_KEYS = {"url", "u", "redirect", "redirect_uri", "next", "target", "dest", "destination", "continue", "q", "r"}
SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "lnkd.in"}
BRANDS = ["microsoft", "office365", "outlook", "google", "apple", "paypal", "amazon", "docusign", "dropbox",
          "linkedin", "netflix", "dhl", "fedex", "ups", "auspost", "mygov", "ato", "commbank", "westpac", "anz", "nab"]


def brand_in(brand, text):
    """True when brand appears as its own token (label, word or hyphen part), so 'ups' does not match 'groups'."""
    return re.search(rf"(?<![a-z0-9]){re.escape(brand)}(?![a-z0-9])", text.lower()) is not None or (
        len(brand) >= 6 and brand in text.lower())


def defang(s):
    return s.replace("http", "hxxp", 1).replace(".", "[.]")


def domain_of(addr):
    return addr.rsplit("@", 1)[-1].lower().strip(">") if "@" in addr else ""


def org_domain(host):
    parts = host.lower().strip(".").split(".")
    return ".".join(parts[-3:]) if len(parts) > 2 and parts[-2] in {"co", "com", "net", "org", "gov", "edu", "ac"} else ".".join(parts[-2:])


def auth_results(msg):
    res = {}
    for h in msg.get_all("Authentication-Results", []) or []:
        for mech in ("spf", "dkim", "dmarc"):
            m = re.search(rf"\b{mech}=(\w+)", str(h), re.I)
            if m and mech not in res:
                res[mech] = m.group(1).lower()
    return res


def bodies(msg):
    texts, atts = [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        payload = part.get_payload(decode=True) or b""
        if part.get_filename():
            atts.append({"filename": part.get_filename(), "type": part.get_content_type(),
                         "sha256": hashlib.sha256(payload).hexdigest(), "bytes": len(payload)})
        elif part.get_content_type() in ("text/plain", "text/html"):
            texts.append(payload.decode(part.get_content_charset() or "utf-8", "replace"))
    return "\n".join(texts), atts


def analyse_url(u):
    u = u.rstrip(".,;")
    sp = urlsplit(u)
    host = (sp.hostname or "").lower()
    flags = []
    if host.startswith("xn--") or ".xn--" in host:
        flags.append("punycode host")
    if re.fullmatch(r"[\d.]+", host):
        flags.append("raw IP host")
    if host in SHORTENERS:
        flags.append("URL shortener")
    if "@" in sp.netloc:
        flags.append("userinfo @ trick")
    for b in BRANDS:
        if brand_in(b, host) and not org_domain(host).startswith(b + "."):
            flags.append(f"brand '{b}' in non-brand domain")
    nested = []
    for k, vals in parse_qs(sp.query).items():
        if k.lower() in REDIRECT_KEYS:
            for v in vals:
                v = unquote(v)
                if v.startswith("http"):
                    nested.append(defang(v))
                    flags.append(f"redirect parameter '{k}'")
    return {"url": defang(u), "host": host.replace(".", "[.]"), "flags": sorted(set(flags)), "redirects_to": nested}


def analyse(raw_bytes):
    msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)
    frm = parseaddr(str(msg.get("From", "")))
    reply = parseaddr(str(msg.get("Reply-To", "")))
    rpath = parseaddr(str(msg.get("Return-Path", "")))
    fd, rd, pd = domain_of(frm[1]), domain_of(reply[1]), domain_of(rpath[1])
    flags = []
    if rd and org_domain(rd) != org_domain(fd):
        flags.append(f"Reply-To domain ({rd}) differs from From domain ({fd})")
    if pd and fd and org_domain(pd) != org_domain(fd):
        flags.append(f"Return-Path domain ({pd}) differs from From domain ({fd})")
    if frm[0] and "@" in frm[0] and domain_of(frm[0]) != fd:
        flags.append(f"Display name contains a different address: {frm[0]}")
    for b in BRANDS:
        if brand_in(b, frm[0] or "") and not org_domain(fd).startswith(b + "."):
            flags.append(f"Display name mentions '{b}' but sending domain is {fd}")
    auth = auth_results(msg)
    for mech in ("spf", "dkim", "dmarc"):
        if auth.get(mech) and auth[mech] != "pass":
            flags.append(f"{mech.upper()} = {auth[mech]}")
    if not auth:
        flags.append("No Authentication-Results header (cannot verify SPF/DKIM/DMARC)")
    received = [re.sub(r"\s+", " ", str(h)) for h in (msg.get_all("Received", []) or [])]
    ips = []
    for h in received:
        ips += re.findall(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]", h)
    text, atts = bodies(msg)
    urls = sorted(set(URL_RE.findall(text)))
    for a in atts:
        if re.search(r"\.(html?|js|vbs|iso|img|lnk|exe|scr|zip|rar|7z|one|svg)$", a["filename"] or "", re.I):
            flags.append(f"Risky attachment type: {a['filename']}")
    return {
        "subject": str(msg.get("Subject", "")), "date": str(msg.get("Date", "")),
        "from": {"display": frm[0], "address": defang(frm[1]) if frm[1] else ""},
        "reply_to": defang(reply[1]) if reply[1] else "", "return_path": defang(rpath[1]) if rpath[1] else "",
        "auth": auth, "received_hops": len(received), "first_hop_ips": ips[-3:],
        "urls": [analyse_url(u) for u in urls], "attachments": atts, "flags": flags,
    }


def to_md(r):
    out = [f"# Phish triage: {r['subject']}", "", f"**Date:** {r['date']}  ",
           f"**From:** {r['from']['display']} <{r['from']['address']}>  ",
           f"**Reply-To:** {r['reply_to'] or 'none'}  ", f"**Return-Path:** {r['return_path'] or 'none'}  ",
           f"**Auth:** " + (", ".join(f"{k.upper()}={v}" for k, v in r["auth"].items()) or "none"),
           f"**Received hops:** {r['received_hops']}, earliest IPs: {', '.join(r['first_hop_ips']) or 'none'}",
           "", "## Red flags"] + ([f"- {f}" for f in r["flags"]] or ["- none found in headers"])
    out += ["", "## URLs (defanged, not visited)"]
    for u in r["urls"]:
        out.append(f"- `{u['url']}`" + (f" : {', '.join(u['flags'])}" if u["flags"] else ""))
        for n in u["redirects_to"]:
            out.append(f"  - redirects to `{n}`")
    if not r["urls"]:
        out.append("- none")
    out += ["", "## Attachments"] + ([f"- {a['filename']} ({a['type']}, {a['bytes']} bytes) sha256 `{a['sha256']}`"
                                      for a in r["attachments"]] or ["- none"])
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("eml")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    with open(a.eml, "rb") as f:
        r = analyse(f.read())
    print(json.dumps(r, indent=2) if a.json else to_md(r))
    return 0


if __name__ == "__main__":
    sys.exit(main())
