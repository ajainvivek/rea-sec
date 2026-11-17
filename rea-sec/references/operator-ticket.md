# Operator Ticket template

A short, blunt write up for X, Slack, or a security channel. Built from the
full REA-Sec output. Every fact must already be CONFIRMED and cited in the full
report. No em dashes.

```
<Blunt hook: one line, what happened and why it matters to the reader.>

What is on the record:
- <YYYY-MM-DD> <Source org> said <fact>. (<CVE-ID if any>)
- <YYYY-MM-DD> <Source org> said <fact>.
- <YYYY-MM-DD> <Source org> said <fact>.

Tonight:
1. <Fix with a version, config key, or query>
2. <Fix>
3. <Fix>

<Closer: one natural question to the reader.>
```

Rules:
- Hook under 15 words. No hype words ("massive", "insane").
- "What is on the record" lists only primary source facts, each with a date and the speaker.
- "Tonight" fixes are things a peer company can do in an evening.
- Sources go in the first reply, not the main post.
- One question at the end.

## Example (Log4Shell)
```
One logging library put half the internet one string away from remote code execution.

What is on the record:
- 2021-12-10 NVD published CVE-2021-44228 (Log4Shell), CVSS 10.0.
- 2021-12-10 NVD notes the risky JNDI behaviour is disabled by default from Log4j 2.15.0.
- 2021-12-14 Apache issued 2.16.0 after CVE-2021-45046 showed the first fix was incomplete.

Tonight:
1. Run your SBOM or `mvn dependency:tree` and find every log4j-core below 2.17.1.
2. Upgrade to 2.17.1 or later (2.12.4 for Java 7, 2.3.2 for Java 6).
3. Hunt web and app logs for `${jndi:` and obfuscated variants since 2021-12-01.

Still finding log4j-core 2.14 in your containers?
```
