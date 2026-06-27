# STRIDE Worksheet - `<system or feature name>`

> One row per threat. Fill in for every box and arrow in your DFD. "N/A - read-only static asset, no input" is a valid row; the discipline matters.

## STRIDE in one screen

| Letter | Threat | Counter via |
|---|---|---|
| **S**poofing | Pretending to be someone | Authentication |
| **T**ampering | Modifying data | Integrity (signatures, hashes, mTLS) |
| **R**epudiation | Denying an action | Non-repudiation (logs, audit trail) |
| **I**nformation disclosure | Exposing data | Confidentiality (encryption, ACLs) |
| **D**enial of service | Crashing / starving | Rate limits, scale, design |
| **E**levation of privilege | Getting more rights | Authorization, least privilege |

## Worksheet - one block per DFD component

### Component: `<App / DB / Cache / etc.>`

| ID | STRIDE | Threat (be concrete) | Severity (L/M/H/C) | Likelihood (L/M/H) | Disposition |
|---|---|---|---|---|---|
| `<APP-S-01>` | S | <e.g. stolen JWT replayed as user X> | H | M | <Mitigated by ... / Action: ... / Accept> |
| `<APP-T-01>` | T | <e.g. mass assignment lets user set is_admin> | C | M | <Action: explicit DTOs> |
| `<APP-R-01>` | R | <e.g. no audit log for role change> | M | M | <Action: emit event> |
| `<APP-I-01>` | I | <e.g. verbose error pages leak env vars> | H | L | <Mitigated: DEBUG=False in prod> |
| `<APP-D-01>` | D | <e.g. no rate limit on /login> | H | H | <Action: multi-dim limiter> |
| `<APP-E-01>` | E | <e.g. RCE via insecure pickle in queue> | C | L | <Action: switch to JSON> |

<!-- Repeat the block for every component. Sample components: API service, DB, Cache, Blob storage, Each third party. Sample flows: User→Edge, Edge→App, App→DB, App→Vendor. -->

### Component: `<next>`

| ID | STRIDE | Threat | Severity | Likelihood | Disposition |
|---|---|---|---|---|---|
| | | | | | |

## Severity guide

| Severity | Rough meaning |
|---|---|
| **Critical** | RCE, full data exfil, privilege escalation to admin, payment fraud |
| **High** | Account takeover, single-tenant data leak, prolonged outage |
| **Medium** | Limited info disclosure, short outage, fixable through ops |
| **Low** | Theoretical, requires multiple unlikely conditions |

## Likelihood guide

| Likelihood | Rough meaning |
|---|---|
| **High** | Common technique, public exploit code, no specific prerequisites |
| **Medium** | Real technique but requires some condition (specific user role, network position) |
| **Low** | Insider, supply-chain, novel research-level attack |

## Per-week pattern cheatsheet

When you're stuck on what's plausible per component, walk through these:

| Threat lens | Reference |
|---|---|
| Session theft / JWT issues | [Week 02](../../week-02-sessions-and-cookies/) |
| Access-control gaps | [Week 03](../../week-03-broken-access-control/), [Week 13](../../week-13-api-security/) |
| Auth brute force / credential stuffing | [Week 04](../../week-04-auth-failures/) |
| SQL injection | [Week 05](../../week-05-sql-injection/) |
| XSS | [Weeks 01, 06](../../week-06-xss-deep/) |
| Template / command injection | [Week 07](../../week-07-ssti-and-command-injection/) |
| SSRF | [Week 08](../../week-08-ssrf/) |
| CSRF / CORS / SOP | [Week 09](../../week-09-csrf-cors-sop/) |
| Crypto / secrets | [Week 10](../../week-10-crypto-failures/) |
| Insecure deserialization | [Week 11](../../week-11-insecure-deserialization/) |
| XXE / upload / path traversal | [Week 12](../../week-12-xxe-upload-traversal/) |
| API-level BOLA / BOPLA / mass assignment | [Week 13](../../week-13-api-security/) |
| Misconfig / unpatched components | [Week 14](../../week-14-security-misconfig/) |
| Logging gaps | [Week 15](../../week-15-logging-and-detection/) |

## Next

- For high-value flows, drill into [attack-tree-template.md](attack-tree-template.md).
- When done, fold into [threat-model-report.md](threat-model-report.md).
