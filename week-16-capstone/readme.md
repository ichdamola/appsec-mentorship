# Week 16: Threat Modeling Capstone

## 🎯 What you'll learn

The synthesis week. You've spent 15 weeks finding individual bugs. The capstone teaches you to **find bugs before they're written** — by reasoning about an architecture, before the first line of code, and identifying what could go wrong.

By the end of this week you'll be able to:

- Draw a **Data Flow Diagram (DFD)** of a system with trust boundaries
- Apply **STRIDE** (Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege) to each component
- Build **attack trees** for high-value flows (login, payment, data export)
- Prioritize threats with **DREAD-like risk scoring** — without it becoming theater
- Integrate threat modeling into your SDLC — at the right granularity, frequency, and ownership
- Run a threat-modeling session for a team that has never done one

This week's deliverable is a real threat model. Not a write-up of a hypothetical — a working artifact you can show.

## ⚠️ Scope reminder

Threat-modeling is a defensive practice; no offensive labs here. Apply it to **your own** systems or any open-source reference architecture (we'll use a reference for the worked example).

## 🧰 Lab setup

### The system you'll threat-model

We use a deliberately-realistic-but-small reference: **"Mentorbase"** — a fictional mentorship-matching SaaS like the one you'd build after this curriculum.

Architecture:

```
[Web SPA (React)]  ──┐
[iOS App]           ├──> [API Gateway (CloudFront)]
[Android App]        ┘             │
                                   ▼
                            [API Service (Django)]
                                   │
        ┌──────────┬───────────────┼───────────────┬──────────────┐
        ▼          ▼               ▼               ▼              ▼
   [Postgres] [Redis]      [S3 — user uploads] [Stripe API]  [SendGrid email]
                                                                 │
                                                                 ▼
                                                          [users' inboxes]
```

Features: signup/login (email + Google SSO), mentor profiles, mentorship requests, messaging, file attachments, payment, weekly email digest.

Choose ONE of:

1. **Apply the threat model to Mentorbase** as a learning exercise.
2. **Apply it to a real system you work on** — much higher value, but the architecture is on you.

### Templates

In this directory:

- `templates/dfd-template.md` — DFD scaffolding
- `templates/stride-worksheet.md` — fillable STRIDE per component
- `templates/attack-tree-template.md` — for high-value flows
- `templates/threat-model-report.md` — final deliverable structure

*(If those template files don't exist in your checkout, generate them from the examples in attack.md.)*

## ✅ Your job

1. **Draw the DFD** of your chosen system. Pen-and-paper, draw.io, or Mermaid (see [attack.md](attack.md) for syntax). Mark the trust boundaries — solid lines where data crosses a security perimeter.

2. **Apply STRIDE to each component.** For every box / line, ask: how could each of the six classes apply here? Don't skip components that "obviously aren't affected" — write "N/A — read-only with no input from outside trust boundary" or whatever the reason is. The discipline matters.

3. **Build an attack tree for at least one high-value flow.** Suggested: "attacker takes over a paid mentor's account." Root node = goal; child nodes = means; refine each until you bottom out at concrete attack techniques.

4. **Score and prioritize.** For each threat, decide: severity, likelihood, mitigation cost. Rank. Plan the top 5 mitigations.

5. **Write the report.** Use the template. Output is a 5-15 page document an engineering team can act on.

6. **Read [attack.md](attack.md)** for the worked Mentorbase example.

7. **Read [defense.md](defense.md)** for the SDLC integration patterns.

## 📚 Required reading

| Resource | Why | Time |
|---|---|---|
| [Adam Shostack — Threat Modeling: Designing for Security (Ch. 1-4)](https://shostack.org/books/threat-modeling-book) | The reference book; chapters 1-4 are essentials | 3 hours |
| [Microsoft — Threat Modeling tools and resources](https://learn.microsoft.com/en-us/security/engineering/threat-modeling) | The framework that gave us STRIDE | 30 min |
| [OWASP — Threat Modeling Process](https://owasp.org/www-community/Threat_Modeling_Process) | Vendor-neutral overview | 30 min |
| [Threat Modeling Manifesto](https://www.threatmodelingmanifesto.org/) | A short, opinionated framing | 10 min |
| ["Four Question Framework" — Shostack](https://www.threatmodelingmanifesto.org/) | What are we working on / what can go wrong / what are we going to do about it / did we do a good job | 5 min |

## 💡 What you should already know

- Weeks 1-15 (you'll apply each bug class as a STRIDE consideration)
- How to draw boxes and arrows on paper
- A real (or realistic) system to model — Mentorbase is a fallback
