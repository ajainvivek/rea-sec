# Phish / lure mode

**Input:** a phishing email (.eml file or pasted raw headers), a screenshot, or a
URL the user received or owns.

## Steps
1. **Parse offline.** For .eml or raw headers run
   `python3 scripts/phish_headers.py message.eml`. It reads the file only and
   makes no network calls. It reports From / Reply-To / Return-Path mismatches,
   SPF, DKIM and DMARC results from `Authentication-Results`, the Received chain,
   lookalike domains, and every URL in defanged form.
2. **Decode the lure.** Name the pretext (invoice, shared doc, MFA reset,
   parcel, payroll, CEO request), the urgency trigger, and the call to action.
3. **URL analysis, passive only.** Do not click, curl, or render the link.
   Allowed: parse the string (real domain vs display text, punycode, URL
   shorteners, open redirect parameters such as `url=`, `redirect=`, `next=`),
   public reputation lookups, WHOIS creation date, certificate transparency
   (crt.sh), and archived snapshots. Name the redirect chain only as far as the
   string or a public sandbox report shows it.
4. **Spoofing verdict.** Display name spoof, lookalike domain, compromised
   legitimate sender, or authenticated but malicious. Cite the header lines.
5. **IOCs.** Defanged sender address, sending IP, domains, URLs, attachment
   hashes (SHA-256). Format as a table and as a plain list for blocklists.
6. **Red flags for users.** 3 to 5 plain English tells a non technical person
   could spot next time, tied to this exact email.
7. **Tonight.** Block the domain and sender, search the mail platform for other
   recipients, and reset credentials for anyone who submitted them.

## Privacy
Redact the recipient's name and address, and any other private person's
details, before the output is shared.
