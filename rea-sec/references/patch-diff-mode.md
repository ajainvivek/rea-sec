# Patch-diff mode

**Input:** a CVE or GHSA ID, plus a published fix commit, PR, or release tag.

Defensive only. Explain the bug well enough to find it, patch it, and detect
attempts. Do not produce a working exploit or a weaponised request.

## Steps
1. **Gate.** Confirm a public fix or vendor advisory exists. If not, stop (see guardrails).
2. **Advisory.** `python3 scripts/fetch_advisory.py CVE-XXXX-YYYY --format md`
   gives CVSS, CWE, affected ranges, fixed versions, references, and KEV status.
3. **Diff.** Fetch the public fix: `https://github.com/<owner>/<repo>/commit/<sha>.diff`
   or the compare view between the last vulnerable and first fixed tag. Read
   only the files that change behaviour; skip tests and changelogs on first pass,
   then read the tests because they often show the bad input shape.
4. **Vulnerable code path.** In prose: entry point (where untrusted input
   enters), the sink (what dangerous operation it reaches), and the missing
   check. Quote at most a few lines of the diff for context.
5. **Root cause.** Name the CWE (for example CWE-502 Deserialization of
   Untrusted Data, CWE-917 Expression Language Injection, CWE-22 Path
   Traversal) and explain in one paragraph why the code was vulnerable.
6. **How the fix closes it.** What the patch adds or removes (allow list,
   default off, input validation, removed feature). Note if the first fix was
   incomplete and a follow up CVE exists.
7. **Am I affected?** A concrete check: dependency version command
   (`mvn dependency:tree`, `npm ls`, `pip show`), SBOM query, config flag, or
   file hash. Only against the user's own systems.
8. **Detection and hunting.** Log patterns for attempted exploitation (shape of
   the input, not a working payload), post exploitation indicators, and a Sigma
   draft. Note known evasions only at the level of "attackers obfuscate the
   string, normalise before matching".
9. **Tonight.** Upgrade target version, mitigation if you cannot upgrade, and
   the hunt to run.

## What not to write
- Full exploit requests, payload strings that work as is, gadget chains, or
  scripts that send anything to a host.
- "Bypass" variants of the patch that are not already public and fixed.
