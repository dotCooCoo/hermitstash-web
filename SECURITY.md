# Security Policy

## A note up front

HermitStash Web is the Cloudflare Worker that serves the landing page at `hermitstash.com` and gates browser access to `app.hermitstash.com` on post-quantum TLS support. It's a personal project maintained by one person in their spare time. The code has not been professionally audited.

The worker itself is a small, stateless request filter plus a static HTML response — the heavy security lifting (PQC TLS handshake, mTLS, payload encryption) happens on the HermitStash server, not here. But the filter chain, the served HTML, and the Content-Security-Policy are entirely my own work, and flaws in any of them can still cause real harm (open redirect, XSS, CSP bypass, bot-filter evasion that exposes the backend).

If you're evaluating HermitStash for a use case where the consequences of a security flaw matter — legal, medical, financial, journalistic, or anything else where being wrong has real stakes — please factor this into your decision.

## Reporting a vulnerability

If you find a security issue, **please do not open a public GitHub issue**. Public disclosure before a fix is in place puts users at risk.

Instead, please email me directly:

**security@hermitstash.com**

### What to include

A useful report usually has:

- A clear description of the issue
- Steps to reproduce, or a proof of concept
- The commit hash or deploy you tested against
- Your assessment of the impact (what could an attacker actually do?)
- Any suggested fix, if you have one

Don't worry about formatting it perfectly. I'd rather get a rough report than no report.

## What to expect from me

I want to be honest about response times: this is a side project, and I can't promise the kind of turnaround a funded security team would offer. Realistically:

- **Acknowledgment:** within a few days, usually faster
- **Initial assessment:** within a week or two
- **Fix and disclosure:** depends on severity and complexity

For critical issues (anything that breaks the core security promises — CSP bypass, filter bypass that routes malicious traffic to the backend, open redirect, XSS, header injection, PQC-gate bypass), I'll prioritize and try to ship a fix as quickly as I reasonably can. Because this is a Cloudflare Worker, fixes deploy in seconds once written — the bottleneck is always diagnosis and patch, not rollout.

For lower-severity issues, it may take longer.

I'll keep you updated as I work on it, and I'll credit you in the fix commit and release notes unless you'd prefer to stay anonymous.

## Scope

Things I consider in scope:

- Content-Security-Policy bypasses (nonce leakage, missing directive, unsafe-inline reintroduction)
- Cross-site scripting (reflected, stored, DOM) in the served HTML
- HTML or header injection via crafted request headers
- Open redirect via the `/` path normalization logic
- Bot / ASN / fingerprint filter bypasses that defeat the stated protections
- Rate-limit bypasses that allow unbounded request volume per IP
- Missing or weakened security headers (HSTS, COOP/COEP/CORP, X-Frame-Options, Referrer-Policy, Permissions-Policy)
- PQC-gate bypass — any way to reach `app.hermitstash.com` from the gateway without a successful `/health` fetch
- Session fixation or cache poisoning via the worker's `Cache-Control` / `Vary` behavior
- Supply-chain concerns in the inlined script (though the script has no external dependencies)
- Anything that contradicts a security claim made in the README or CLAUDE.md

Things that are probably out of scope:

- Issues in the HermitStash server or `app.hermitstash.com` — please report those to the [main repository](https://github.com/dotCooCoo/hermitstash)
- Issues in the HermitStash Sync client — please report those to the [sync repository](https://github.com/dotCooCoo/hermitstash-sync)
- Cloudflare platform issues (please report to Cloudflare directly)
- Theoretical attacks that require capabilities beyond a realistic threat model
- Self-XSS or social engineering attacks against the user
- Missing best-practice headers that don't correspond to a real attack (e.g. `X-Permitted-Cross-Domain-Policies`)
- DNS / domain configuration issues that aren't caused by the worker code

If you're not sure whether something is in scope, just send it. I'd rather decide together than have you not report something that matters.

## What I can't offer

To set expectations honestly:

- No bug bounty. I can't pay for findings — this is a personal project with no budget. I can offer credit, gratitude, and a genuine attempt to fix what you find.
- No SLA. I'll do my best, but I can't guarantee response times.
- No guarantees about backwards compatibility while I'm fixing things. If a fix requires breaking changes, I'll make them.

## Thank you

Security research is real work, and reporting issues responsibly takes time and care. If you take the time to look at HermitStash Web and tell me what you find, you have my genuine thanks — even if the finding turns out to be a false alarm or out of scope.
