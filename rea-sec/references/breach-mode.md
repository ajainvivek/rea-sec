# Breach mode

**Input:** a breach notice, regulator filing, advisory, news URL, or vendor post.

## Steps
1. **Find the primary source.** The victim's own notice beats press. Look for
   the newsroom, investor relations (8-K Item 1.05 in the US, ASX/TSE/KRX
   announcements in APAC), regulator notices (OAIC, PIPC, PPC Japan, ICO), and
   status pages. If the input is press, trace it back to the primary source.
2. **Extract facts into a table.** For each: what, when (event and disclosure
   date), who said it, URL, label (CONFIRMED / REPORTED / INFERRED).
3. **Entry point.** One of: stolen credentials, phishing, exploited public
   facing app (name the CVE), third party / supply chain (name the vendor),
   insider, misconfiguration, unknown. If unknown, say unknown. If the victim
   says "a vulnerability" without naming it, write "unnamed vulnerability, CVE
   not disclosed" and do not guess which CVE it was.
4. **Kill chain.** Walk the ATT&CK tactics in order and fill only the ones the
   evidence supports:
   Initial Access, Execution, Persistence, Privilege Escalation, Defense
   Evasion, Credential Access, Discovery, Lateral Movement, Collection,
   Command and Control, Exfiltration, Impact.
5. **What was hit.** Data categories and record counts exactly as the source
   states them ("up to 2.6M member records"). Note what was explicitly NOT hit
   (for example "no card data") and cite it.
6. **Third party angle.** If a vendor or SaaS was the entry point, add a
   Downstream disclosures table: customer, disclosure date, records, data
   types, what was not hit, source. List a customer only if it has disclosed
   publicly. Never guess, and never add up counts across companies as if they
   were unique people (members can overlap); say "up to" and keep each figure
   with its source. Check whether integration secrets (API keys, OAuth tokens,
   webhooks) stored in the SaaS leaked: that is the path to the *next* victim.
7. **Detection.** Translate each mapped technique into a log source and a
   Sigma draft or query. Focus on what a peer company could run today.
8. **Tonight.** Three fixes for peers, not for the victim: rotate the tokens
   that connect the affected SaaS, enforce phishing resistant MFA on the admin
   path, patch the named CVE, and so on.

## Common technique mappings
| Evidence phrase | Technique |
|---|---|
| "exploited a vulnerability in our internet facing ..." | T1190 Exploit Public-Facing Application |
| "compromised credentials", "valid account" | T1078 Valid Accounts |
| "phishing email to an employee" | T1566 Phishing |
| "through a third party vendor" | T1195 Supply Chain Compromise / T1199 Trusted Relationship |
| "ransomware encrypted systems" | T1486 Data Encrypted for Impact |
| "data was copied / exfiltrated" | T1041 Exfiltration Over C2 Channel or T1567 Exfiltration Over Web Service |
| "accessed cloud storage bucket" | T1530 Data from Cloud Storage |
| "API keys / tokens stolen" | T1552 Unsecured Credentials / T1528 Steal Application Access Token |
| "MFA fatigue / push bombing" | T1621 Multi-Factor Authentication Request Generation |
| "help desk social engineering" | T1656 Impersonation |
