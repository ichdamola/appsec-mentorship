# Attack tree - `<goal>`

> STRIDE gives breadth across the DFD. Attack trees give depth on a single high-value goal.
> Build one tree per goal that, if achieved, would be a Bad Day.

## When to draw a tree

- Compromise a privileged account (admin, paid mentor, support agent)
- Exfiltrate a high-value data set (payments, PII, IP)
- Disrupt a core flow (login, checkout, file upload)
- Tamper with a critical action (price change, role grant)

If a goal would not show up in a postmortem, it does not need a tree.

## Format

- Root node = the attacker's goal (one sentence).
- Each child = a way to achieve the parent. AND-children mean both required; OR-children mean any suffices.
- Leaves = concrete techniques you can name with a CVE class or curriculum week.
- For each leaf: note your defense, and whether it's `Mitigated`, `Action`, or `Accepted`.

## Example (Mentorbase - fill yours in below)

```
GOAL: Attacker controls a paid mentor's account
├── PATH 1: Credential theft
│   ├── Phishing
│   │   └── Mitigation: 2FA-by-default, lookalike-domain monitoring
│   ├── Credential stuffing (Week 04)
│   │   └── Mitigation: HIBP check at signup; per-account + per-IP rate limit; CAPTCHA after 5
│   ├── Brute force (Week 04)
│   │   └── Mitigation: rate limit + account-lock back-off
│   └── Password reset hijack (Week 10)
│       └── Mitigation: CSPRNG tokens, short expiry, re-auth before sensitive change
│
├── PATH 2: Session theft
│   ├── XSS steals cookie (Week 06)
│   │   └── Mitigation: strict CSP + HttpOnly + SameSite=Strict
│   ├── Network MITM (Week 10)
│   │   └── Mitigation: HSTS preload, secure cookies
│   └── Session fixation (Week 02)
│       └── Mitigation: rotate session on login
│
├── PATH 3: Account takeover via API
│   ├── BOLA on password change (Week 13)
│   │   └── Mitigation: ownership check + re-auth-on-sensitive
│   ├── Mass assignment sets new email (Week 13)
│   │   └── Mitigation: explicit DTOs; confirm new email to old address
│   └── BOLA on /api/users/<id>/email_change (Week 13)
│       └── Mitigation: filter queryset by request.user
│
├── PATH 4: Identity provider compromise
│   ├── id_token aud not validated (Week 02)
│   │   └── Mitigation: verify aud/iss/sig/exp on every callback
│   ├── OAuth refresh token stored in JS-readable storage
│   │   └── Mitigation: httpOnly cookie OR short-lived access only
│   └── Account-merge logic accepts unverified email
│       └── Mitigation: explicit confirm flow on merge
│
└── PATH 5: Insider / admin tool misuse
    ├── Support "impersonate user" without audit log (Week 15)
    │   └── Mitigation: every impersonation logged + daily review
    └── Direct DB write
        └── Mitigation: prod DB writes only through audited gateway
```

## Your tree(s) go here

### Goal: `<your goal>`

```
GOAL: <restate>
├── PATH 1: <category>
│   ├── <technique>
│   │   └── Mitigation: <existing> / Action: <new> / Accept: <reasoning>
│   ├── <technique>
│   └── <technique>
│
├── PATH 2: <category>
│   ├── <technique>
│   └── <technique>
│
└── PATH N: <category>
    └── <technique>
```

### Goal: `<next goal, if any>`

```
GOAL: <restate>
...
```

## Reading the tree

You're done with the tree when **every path bottoms out at either a mitigation in place, a concrete action with an owner, or a written-down accepted risk.** Paths that bottom out at "we'd notice it eventually" are not done.

## Cross-reference

- Threats you find here that aren't in the [STRIDE worksheet](stride-worksheet.md) - add them.
- Mitigations you list here that aren't tracked anywhere - write them into the [threat-model-report.md](threat-model-report.md) under top-N mitigations.
