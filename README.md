# REA-Sec: Reverse Engineer Any Breach

**Give your AI agent any breach notice, CVE patch or phishing email, and get back how the attack worked and the 3 fixes to ship tonight.**

REA-Sec is an [Agent Skill](https://docs.claude.com/en/docs/claude-code/skills) for Claude Code and other coding agents. It works backwards from public security artifacts to a cited timeline, a MITRE ATT&CK kill chain, the root cause, detection rules, and a short fix list. It is defensive by design: public sources only, no scanning, no exploit code.

## Modes

| Mode | You give it | You get |
|---|---|---|
| **Breach** | A breach notice, advisory, regulator filing or news URL | Dated timeline, entry point, kill chain with ATT&CK IDs, data hit, confirmed vs unconfirmed facts with citations, Sigma drafts, Tonight list |
| **Patch-diff** | A CVE ID plus the public fix commit or release | Vulnerable code path, root cause (CWE), how the fix closes it, am I affected checks, hunting queries. No PoC. |
| **Phish/lure** | An .eml, headers, screenshot or URL you received | Spoofing verdict, SPF/DKIM/DMARC, redirect chain from passive lookups, defanged IOCs, red flags for users |
| **Operator Ticket** | Any of the above | A blunt, shareable post: hook, "What is on the record:", "Tonight:" with 3 fixes, closer |

See a full sample: [examples/log4shell-patch-diff.md](examples/log4shell-patch-diff.md) (CVE-2021-44228, patched since 2021).

## Install

**Claude Code (all projects):**
```bash
git clone https://github.com/ajainvivek/rea-sec.git
mkdir -p ~/.claude/skills
cp -r rea-sec/rea-sec ~/.claude/skills/
```

**Claude Code (one project):** copy the `rea-sec/` folder into `.claude/skills/` in that repo and commit it.

**Other agents (Codex, Cursor, Gemini CLI, any LLM):** copy the folder anywhere (for example `.agents/skills/rea-sec/`) and tell the agent: *"Read rea-sec/SKILL.md and follow it."* The references and scripts are plain Markdown and Python, nothing is Claude specific.

Restart the agent after installing so it picks up the skill.

## Example prompts

```
Use rea-sec on this breach notice and give me the timeline, ATT&CK mapping and Tonight list: <URL>
```
```
rea-sec patch-diff CVE-2021-44228 using https://github.com/apache/logging-log4j2/commit/c77b3cb39312b83b053d23a2158b99ac7de44dd3. Am I affected and how do I hunt for it?
```
```
Run rea-sec phish mode on ./suspicious.eml and give me IOCs plus 3 red flags I can send to staff.
```

## Helper scripts

Python 3.9+, standard library only.

| Script | What it does |
|---|---|
| `scripts/fetch_advisory.py CVE-ID [--format md\|json]` | Pulls NVD, GitHub Advisory Database and CISA KEV data: CVSS, CWE, affected and patched versions, fix links. Skips exploit archive links. |
| `scripts/attack_map.py steps.json` | Turns an attack path into an ATT&CK tagged Markdown table and a mermaid diagram, coloured by CONFIRMED / REPORTED / INFERRED. |
| `scripts/phish_headers.py message.eml [--json]` | Offline header and body triage: sender mismatches, auth results, Received chain, lookalike brands, defanged URLs, attachment hashes. Makes no network calls. |

Run the tests: `python3 -m unittest discover tests` (the advisory test needs internet; set `REA_SEC_OFFLINE=1` to skip it).

## Guardrails

Baked into [SKILL.md](rea-sec/SKILL.md) and [references/guardrails.md](rea-sec/references/guardrails.md):

- Public sources or artifacts you own only.
- Never scan, probe or log in to systems you do not own. Phish links are analysed passively.
- Never publish unpatched vulnerabilities. Use coordinated disclosure.
- No exploit code or weaponised PoCs. Detection content only.
- Every fact is labelled CONFIRMED, REPORTED or INFERRED, and every claim is cited.
- Fact-check the claim, never the person. No speculation about individuals.

## Layout

```
rea-sec/                  <- the skill folder you copy
  SKILL.md
  references/             breach, patch-diff, phish, operator ticket, sigma, guardrails
  scripts/                fetch_advisory.py, attack_map.py, phish_headers.py
examples/                 sample Log4Shell report and attack path JSON
tests/                    unittest suite and a sample phishing .eml
```

## Credit

Inspired by REA-Video, the reverse-engineer-anything skill shared by [@rileybrown](https://x.com/rileybrown).

Built by [@hackerlogs](https://x.com/hackerlogs). MIT licensed.
