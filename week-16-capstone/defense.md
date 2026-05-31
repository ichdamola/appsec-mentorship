# Week 16: Defense — Embedding Threat Modeling in the SDLC

You worked the four questions in [attack.md](attack.md). This file is about making that practice happen continuously, with the right people, at the right cadence — without becoming theater.

---

## The single rule

> **Threat modeling is design review, not a deliverable. It happens when you change the design, runs as a discussion, and outputs a tracked decision per threat.**

A threat model in a PDF that lives in SharePoint is a document. A threat model in your project's `docs/security/` that gets re-opened on every significant change is a practice.

## When to threat-model

Not every commit. Specifically:

| Trigger | Granularity | Time budget |
|---|---|---|
| New service | Full STRIDE pass on the whole service | 4-8 hours over 1-2 sessions |
| New third-party integration | Focused — what crosses the new boundary? | 1-2 hours |
| New auth flow (SSO, SAML, OAuth provider) | Focused on the new flow + adjacent | 2-4 hours |
| New data domain (PII, health, financial) | Focused on the data + retention/access | 2-4 hours |
| Architecture change (split / merge service, new deployment region) | Re-visit affected components | 1-3 hours |
| Major incident | Post-incident: "did our model predict this? if not, why?" | 2-4 hours, baked into postmortem |
| Quarterly | Re-skim existing models for staleness | 1 hour per service |

**Don't threat-model bug fixes, refactors that preserve behavior, or feature flag flips.** The bar is "did the trust boundary or the data flow change?"

## Who's in the room

| Role | Why |
|---|---|
| Lead engineer for the change | They know the design |
| Another engineer (PR-reviewer equivalent) | Catches blind spots |
| Security partner (1 person per session, max) | Pattern matches, asks the STRIDE questions |
| Product / domain SME (optional but useful) | Knows what data matters |

Notably absent: large security teams, ICs from other teams, leadership. Those venues are for the *output*, not the modeling.

## The session shape (90 minutes max)

1. **(5 min)** Whoever proposed the change describes it. Whiteboard / Miro / draw.io / Excalidraw.
2. **(15 min)** Draw the DFD. Mark trust boundaries.
3. **(45 min)** Walk STRIDE per component. Capture threats in real-time — one row per threat.
4. **(15 min)** Score: severity, likelihood. Identify top 5.
5. **(10 min)** Decide owners and dates for top 5. Everything else: backlog or accept.

90 minutes is the wall. Longer sessions decay. Better to run a second session next week than push past 90.

## Output — what to capture

Don't write prose. Capture a structured artifact:

```markdown
# Threat Model: Mentor verification feature

**Date:** 2026-05-31
**Authors:** Adedamola A., Jane Doe (security)
**Status:** Active — review by 2026-08-31

## DFD

(embedded image or Mermaid)

## Trust boundaries

| Boundary | Notes |
|---|---|
| User → CloudFront | Standard external |
| CloudFront → API | Auth required beyond /healthz |
| API → KYC vendor | New — outbound HTTPS w/ API key |

## Threats

| ID | Component | Threat | STRIDE | Severity | Likelihood | Disposition |
|---|---|---|---|---|---|---|
| 01 | KYC API call | API key leak in client-side bundle | I | C | L | Mitigated: key on server only |
| 02 | KYC API call | Tampered response (no signature check) | T | H | M | Action: Implement webhook sig |
| ... | ... | ... | ... | ... | ... | ... |

## Mitigations (top 5)

1. **02 — Webhook signature** — Eng: Alice — Due: 2026-06-15
2. ... 

## Accepted risks

- **05 — KYC vendor outage causes feature unavailability** — accepted; acceptable degradation; monitoring exists.

## Re-evaluate when

- New KYC vendor added
- Authentication changes
- 90-day stale
```

The file lives in the repo (`docs/security/threat-models/<feature>.md`). It's reviewed in PR. It changes when the design changes.

## Integration into the SDLC

### At RFC / design-doc time

Most engineering orgs have some form of design review for new services. Add a "Security considerations" section to the template. The author writes the initial threat model there before the design is "approved." Security partners review.

```markdown
# RFC: Mentor verification

## ... (design sections) ...

## Security considerations

### Trust boundaries

The KYC vendor introduces a new outbound trust boundary. Their API key, response handling, and webhook signing are described below.

### Threats

(table — see template)

### Open questions

- Should KYC responses be encrypted at rest beyond DB-level encryption?
```

### In PR review

For PRs that touch the threat-modeled component:

- The CI bot links to the threat model.
- A `security-relevant` label triggers an extra reviewer (security partner or a designated reviewer).
- Significant changes prompt updating the threat model in the same PR.

### In sprint planning

Mitigation tickets get the threat-model ID in their description. The team's sprint board has a column for security work that doesn't get backlogged into oblivion.

### At incident postmortems

A standard postmortem question: "Did the threat model anticipate this? If yes, why didn't the mitigation work? If no, what should we add?"

This is the *did we do a good job* answer. Threat models that survive incidents without updates are dead documents.

## What good output looks like

Concrete signals that a threat-modeling practice is working:

- **Threat models referenced in PR descriptions** — "this addresses TM-02 from the verification model."
- **Mitigation tickets have IDs back to threat models** — visible traceability.
- **Postmortems mention threat models** — usually self-critically.
- **Onboarding includes reading 2-3 existing models** — they become institutional memory.
- **Security partners are facilitators, not gatekeepers** — engineers do most of the talking.

And what bad looks like:

- **PDFs in SharePoint with last-modified dates years old.**
- **Threat models only the security team ever reads.**
- **All threats marked "high severity, fix later" — the prioritization muscle has atrophied.**
- **No mention in PR / incident venues.**
- **Threat-modeling treated as compliance checkbox** — "we did it once for ISO."

## Defense in depth — the program shape

Threat modeling is one layer. A mature AppSec program also runs:

| Layer | What it produces |
|---|---|
| Secure coding training | Engineers don't introduce common bugs |
| Threat modeling at design | Bugs caught before code |
| Lint / SAST in CI | Bugs caught at PR time |
| Dependency / SCA in CI | Known-CVE'd components fail builds |
| DAST in staging | Runtime bugs caught before prod |
| Pen test / bug bounty | Bugs found by humans you couldn't catch automated |
| Detection rules (Week 15) | Bugs that slipped through are seen |
| Incident response | Confirmed incidents handled |
| Postmortem & feedback | Findings update the earlier layers |

No single layer is sufficient. The point of threat modeling specifically is that it produces information **upstream** — when fixes are cheapest and the design is fluid.

## Maturity model — where to start

If your org has nothing today, don't try to threat-model the whole stack. Start with:

1. **One critical service.** The auth service, the payment service, or the customer data service.
2. **One template.** Use the one above; iterate over real sessions.
3. **One security partner.** Embed them with the team for the first 2-3 sessions.
4. **Quarterly cadence.** Track stale.

After 6 months: extend to 3-5 services. After 12 months: every new service hits the template at design time.

## Building your own competence after Week 16

You've completed an introductory AppSec curriculum. What's next:

### Reading

- **Threat Modeling: Designing for Security** — Adam Shostack (the book)
- **The Tangled Web** — Michał Zalewski (deep web security)
- **The Web Application Hacker's Handbook** (2nd ed) — Stuttard & Pinto (classic offensive)
- **Building Secure & Reliable Systems** — Google SRE on security (free PDF)
- **Real-World Cryptography** — David Wong (modern crypto in production)

### Practice

- **PortSwigger Web Security Academy** — the rest of the catalog, especially advanced labs
- **HackTheBox / TryHackMe** — for hands-on
- **CTFs** — picoCTF (beginner), DEF CON CTF qualifiers (advanced)
- **Bug bounty** — HackerOne, Bugcrowd, Intigriti
- **OSCP / PNPT** — if you want the offensive-security cert track

### Community

- OWASP local chapter
- DEF CON AppSec Village
- The Cloud Security Alliance
- /r/netsec, /r/AskNetsec
- BSides (your nearest one)

### Specialization tracks

| Direction | What to add |
|---|---|
| Cloud Security | AWS / GCP / Azure security certifications, CSPM tooling |
| Detection Engineering | Threat hunting, SIEM internals, Sigma rule contribution |
| Pen Test / Red Team | OSCP, AWS / Azure red team, Cobalt Strike, internal red team rotation |
| AppSec Engineer | Embed with a product team, write security tooling, contribute to OWASP |
| Compliance / GRC | SOC2 / ISO27001 / PCI / HIPAA implementation experience |
| Privacy Engineering | LINDDUN, GDPR / CCPA implementation, differential privacy basics |

Pick one. You won't be deep on all of them; depth on one is more valuable than breadth on six.

## A closing word

Sixteen weeks isn't enough to make anyone "an AppSec expert." It is enough to recognize the patterns, ask the right questions, and know where to look next. The discipline beats the talent: most production AppSec work is operational — patching, reviewing, threat-modeling, alert-tuning — not finding novel exploits.

If you finished this curriculum, you have the foundation. The job from here is the practice.

## Going further

- [Threat Modeling Manifesto](https://www.threatmodelingmanifesto.org/)
- [OWASP Threat Modeling Project](https://owasp.org/www-project-threat-model/)
- [Microsoft Threat Modeling Tool](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool)
- [Shostack — Threat Modeling: Designing for Security](https://shostack.org/books/threat-modeling-book)
- [Building Secure & Reliable Systems — Google SRE book](https://google.github.io/building-secure-and-reliable-systems/)
- [OWASP SAMM — Software Assurance Maturity Model](https://owaspsamm.org/)
- [BSIMM — Building Security In Maturity Model](https://www.bsimm.com/)
