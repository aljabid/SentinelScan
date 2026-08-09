# Security Policy

SentinelScan is a security tool, which makes vulnerabilities in the tool
itself unusually important — a bug here could give a false sense of safety,
leak scan targets/credentials, or be abused against the person running it.
We take reports seriously and will credit reporters (unless you'd prefer to
stay anonymous).

## Reporting a Vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

Email the maintainers instead (see `CONTRIBUTING.md` for the current
contact). Include:

- A description of the vulnerability and its impact
- Steps to reproduce (a minimal example is ideal)
- The version/commit affected
- Whether you're aware of it being exploited in the wild

You should get an acknowledgment within **5 business days**. We'll keep you
updated as we investigate and fix the issue, and aim to have a fix or
mitigation within **90 days** of confirmation — faster for anything actively
exploitable. If you disagree with that timeline for a specific report, say
so; severity varies and we'll adjust.

## Scope

**In scope** — vulnerabilities in SentinelScan's own code:
- Anything that could compromise the machine *running* SentinelScan (e.g.
  a malicious target triggering RCE via a crafted response, a plugin-loading
  path traversal, unsafe deserialization)
- Credential/secret leakage (e.g. `-H`/`--cookie` values ending up in logs,
  reports, or third-party requests they shouldn't reach)
- SSRF or scope-escape issues that let a scan reach further than the
  specified target
- Supply-chain issues in the release/packaging pipeline (e.g. a compromised
  build artifact)

**Out of scope** — these are the tool working as designed, not vulnerabilities in it:
- Findings SentinelScan *reports* about a scanned target (that's the product
  working correctly)
- The fact that SentinelScan performs active probes against targets you
  point it at — that's inherent to what a security scanner does; see the
  authorized-use disclaimer it prints on first run
- Denial of service *against a target you scanned* by scanning too
  aggressively — tune `-T`/`--timing` down; this isn't a bug in the tool

## Supported Versions

Only the latest released version receives security fixes. Given the
project's current stage, there's no long-term-support branch yet.

## Coordinated Disclosure

We ask that you give us the window above to fix the issue before any public
disclosure. In return, we'll credit you in the fix's changelog entry (or
keep you anonymous, your choice) and won't pursue legal action against
good-faith security research conducted under this policy.
