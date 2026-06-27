# Threat Model - `<system or feature name>`

**Status:** `Draft | Active | Stale`
**Authors:** `<eng lead>, <security partner>, <reviewers>`
**Date created:** `YYYY-MM-DD`
**Last review:** `YYYY-MM-DD`
**Next review by:** `YYYY-MM-DD` (default: +90 days, or sooner on architecture change)

## 1. Scope

### What this models

<!-- One paragraph. What system or change. What triggered this model: new service, new auth flow, new third party, new data domain, post-incident, scheduled re-visit. -->

### Out of scope

<!-- Explicit. "Network-layer DDoS - covered by CDN vendor SLA." "Physical security of cloud DC - accepted." -->

### Owners on call for this model

| Role | Name |
|---|---|
| Engineering lead | |
| Security partner | |
| Product / domain SME | |
| On-call for incidents | |

## 2. Architecture (from [dfd-template.md](dfd-template.md))

### Diagram

<!-- Embed your Mermaid DFD here, or link to a draw.io / Excalidraw export. -->

```mermaid
flowchart LR
  %% paste your DFD here
```

### Trust boundaries

| Boundary | What changes across it | Auth carrying trust |
|---|---|---|
| | | |

## 3. Threats (from [stride-worksheet.md](stride-worksheet.md))

### Top threats

| ID | Component | Threat | STRIDE | Severity | Likelihood | Disposition | Owner | Due |
|---|---|---|---|---|---|---|---|---|
| | | | | | | | | |

### Attack trees for high-value flows

<!-- Link or paste from attack-tree-template.md. One tree per high-value goal. -->

- Goal: `<...>` - see `attack-tree-<goal>.md`

## 4. Decisions

### Top-N mitigations this cycle

| # | Threat ID | Mitigation | Owner | Due | Status |
|---|---|---|---|---|---|
| 1 | | | | | |
| 2 | | | | | |
| 3 | | | | | |
| 4 | | | | | |
| 5 | | | | | |

### Accepted risks

<!-- Be explicit. Every one needs a reason and a calendar to re-check. -->

| Threat ID | Reason for accepting | Compensating control | Re-check by |
|---|---|---|---|
| | | | |

### Open questions

<!-- Things the team couldn't decide in the session. Track here; resolve before next review. -->

- [ ] `<question 1>`
- [ ] `<question 2>`

## 5. Validation - did we do a good job?

Check at the end of the modeling session:

- [ ] Every DFD component appears in the STRIDE worksheet at least once (or has a written "N/A" reason).
- [ ] Every threat row has a concrete component, not "the system."
- [ ] Every Critical or High threat has a disposition (mitigated / action / accepted) - none are "TBD."
- [ ] Every action has an owner and a date.
- [ ] At least one attack tree exists for the highest-value goal.
- [ ] An engineer who didn't attend the session can read this report and understand the work.

## 6. Re-evaluate when

- Architecture changes (new component, removed component, new third party)
- Auth flow changes (new IDP, new permission model)
- New regulated data domain (PII, payment, health)
- After an incident - was the model right?
- 90 days, default

## 7. Change log

| Date | Author | Change |
|---|---|---|
| | | Initial model |
| | | |

---

## Appendix - bug-class reference

For pattern matching during STRIDE, see the curriculum's bug-class chapters:

| Class | Chapter |
|---|---|
| Sessions / cookies / JWT | [Week 02](../../week-02-sessions-and-cookies/) |
| Access control / IDOR | [Week 03](../../week-03-broken-access-control/) |
| Auth failures | [Week 04](../../week-04-auth-failures/) |
| SQL injection | [Week 05](../../week-05-sql-injection/) |
| XSS | [Week 06](../../week-06-xss-deep/) |
| SSTI / command injection | [Week 07](../../week-07-ssti-and-command-injection/) |
| SSRF | [Week 08](../../week-08-ssrf/) |
| CSRF / CORS / SOP | [Week 09](../../week-09-csrf-cors-sop/) |
| Crypto / secrets | [Week 10](../../week-10-crypto-failures/) |
| Insecure deserialization | [Week 11](../../week-11-insecure-deserialization/) |
| XXE / upload / path traversal | [Week 12](../../week-12-xxe-upload-traversal/) |
| API security (BOLA, GraphQL) | [Week 13](../../week-13-api-security/) |
| Misconfig / unpatched | [Week 14](../../week-14-security-misconfig/) |
| Logging / detection | [Week 15](../../week-15-logging-and-detection/) |
