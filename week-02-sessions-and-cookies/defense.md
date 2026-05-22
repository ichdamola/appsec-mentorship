# Week 02: Defense — Sessions, Cookies, and JWTs

You've exploited the failure modes in [attack.md](attack.md). Now: the patterns that make those attacks fail.

---

## The single rule

> **Sessions identify users; protect them like a password.** Every cookie flag, rotation policy, and crypto choice flows from that one principle.

## Cookie hardening — the four flags

Every session-bearing cookie should have **all four**:

```
Set-Cookie: session=...; HttpOnly; Secure; SameSite=Lax; Path=/
```

| Flag | What it does | When to skip |
|---|---|---|
| `HttpOnly` | JS can't read the cookie via `document.cookie` | Never |
| `Secure` | Cookie only sent over HTTPS | Never (in production) |
| `SameSite=Lax` | Cookie not sent on cross-site `POST` requests | Use `Strict` if you can live with the UX; never `None` for session cookies |
| `Path=/` | Cookie sent for all paths on this host | Keep wide; narrow paths give a false sense of security |

Optional but recommended:

- **Don't set `Domain`** unless you have a specific cross-subdomain use case. Default ("host-only") is safer.
- **Short lifetime + sliding refresh.** Session cookies expire after N hours of inactivity, not at a fixed wall-clock time.

## Server-side session rotation

A session ID must change at every meaningful privilege transition:

| Event | Rotate? |
|---|---|
| Login | **Yes** — kills session fixation |
| MFA success | **Yes** |
| Logout | **Yes** — invalidate server-side |
| Password change | **Yes** — also invalidate all other sessions for this user |
| Role/permission change | **Yes** |
| Session refresh (no auth event) | Optional; some frameworks rotate periodically |

The bug to watch for in frameworks: anonymous → authenticated *upgrade* of the same session ID. Anonymous IDs are guessable in fixation attacks; reusing them post-login is the bug.

## Use a battle-tested session library

Don't roll your own. Every modern framework ships one:

| Framework | Use this |
|---|---|
| Django | `django.contrib.sessions` (default; rotate via `request.session.cycle_key()`) |
| Rails | `ActionDispatch::Session::CookieStore` with signed encrypted cookies |
| Express | `express-session` + a real store (Redis/DB), not the default `MemoryStore` |
| Spring | `Spring Session` with `HttpSessionEventPublisher` for rotation |
| Go | `gorilla/sessions` or `securecookie`; rotate via session destruction + recreation |

If your team is building a session layer from scratch, stop. There's no upside.

## JWT — when to use it and how

JWTs are useful for **stateless cross-service identity propagation**: a microservice receives a request and validates the JWT locally without a DB hit. They are **misused** for session management of a single web app, where opaque session cookies + a DB are simpler and easier to revoke.

If you do use JWTs, the non-negotiable rules:

### 1. Use asymmetric signatures (RS256 / EdDSA)

```js
// Issuance (auth service)
const token = jwt.sign(claims, privateKey, { algorithm: 'RS256' });

// Verification (each service)
const decoded = jwt.verify(token, publicKey, {
  algorithms: ['RS256']   // ← explicitly allow-list, never read from the JWT header
});
```

**Always pass an explicit `algorithms` allow-list to `verify()`.** This is the single line that prevents algorithm confusion (RS256 ↔ HS256) and `alg: none`.

### 2. Validate every standard claim

```js
jwt.verify(token, publicKey, {
  algorithms: ['RS256'],
  issuer:    'https://auth.example.com',
  audience:  'api.example.com',
  clockTolerance: 5,   // seconds
});
```

Check:

- `iss` (issuer) — who minted this token?
- `aud` (audience) — was it minted for me?
- `exp` (expiry) — is it still valid?
- `nbf` (not-before) — is it active yet?

Most JWT-bypass bugs are missing claim validation, not crypto.

### 3. Short expiry + refresh tokens

| Token | TTL | Storage |
|---|---|---|
| Access token (JWT) | 5-15 minutes | Memory / Authorization header |
| Refresh token (opaque, server-side) | Days | HttpOnly cookie + server DB |

When the access token expires, the client uses the refresh token to get a new one. The server can revoke the refresh token to terminate the session. This is the only way to revoke a JWT-based session in practice — short expiry + a server-side gatekeeper.

### 4. No secrets in the payload

JWT claims are **plaintext**. Anyone with the token can decode them. Don't put:

- Passwords (obviously)
- API keys
- PII you don't intend to ship to every service that sees the JWT
- Internal IDs you don't want exposed

If you need secret data, encrypt the JWT (JWE) — but at that point you've reinvented sessions; consider just using sessions.

### 5. Validate the `kid` carefully

The `kid` field tells the verifier which key to use. Treat it as untrusted input:

- Allow-list known `kid` values; reject everything else.
- Never use `kid` as a file path or DB key without validation.
- Map `kid → key material` via a fixed dictionary, not via lookup.

## Defense in depth

Even with all the above, plan for failure:

| Layer | What it catches |
|---|---|
| `HttpOnly` cookie | Prevents JS exfiltration via XSS |
| `SameSite=Lax` | Stops CSRF on session cookies |
| Server-side session table | Lets you revoke instantly |
| Anomaly detection (below) | Catches stolen sessions in use |
| Re-auth for sensitive actions | Limits damage of stolen session |
| MFA for privileged users | Raises the bar above session theft |

---

## Detection — what does this look like in logs?

Stolen sessions are the hardest XSS/network-snooping outcome to detect, because the attacker uses the legitimate token. Three signals worth building.

### Signal 1: Impossible travel / session-IP shift

```
session_id=X used from IP 198.51.100.10 (NYC) at 09:00
session_id=X used from IP 203.0.113.50 (Lagos) at 09:05
```

5 minutes; 9,000 km. Either the user is on a VPN that just changed exit nodes, or the session is stolen. Flag, prompt re-auth, optionally invalidate.

Pseudo-rule:

```
| stats earliest(time) as first, latest(time) as last,
       values(geoip(client_ip).city) as cities
  by session_id
| where mvcount(cities) > 1
  and (last - first) < 600
```

Calibrate against your false-positive rate. Real travelers exist; just prompt re-auth before destroying their session.

### Signal 2: User-Agent shift mid-session

A stable session should have a stable User-Agent (and ideally Sec-CH-UA headers). A sudden change from "Chrome 123 on macOS" to "curl/7.x" is suspicious:

```
| stats values(http_user_agent) as agents by session_id
| where mvcount(agents) > 2  -- some legit shifts; many is rare
```

### Signal 3: JWT verification failures spiking

If your verifier rejects tokens, log the rejection reason. A spike in:

- `alg=none rejected`
- `signature mismatch`
- `unknown kid`
- `expired token` from a single IP

...is almost always an attacker probing JWT acceptance behavior.

```
| search action="jwt_reject"
| stats count by reason, client_ip
| where count > 10
```

### Signal 4: Concurrent sessions

For roles where it shouldn't happen (admin, finance), alert on more than 1 active session per user. For everyone else, alert at much higher thresholds (3+ concurrent in different geographies, say).

---

## Remediation playbook

When session-related vulnerabilities are found:

| Finding | Immediate action | Longer fix |
|---|---|---|
| Cookies missing `HttpOnly` / `Secure` / `SameSite` | Add flags; ship | None — flags are free |
| `alg: none` accepted | Block at WAF; ship verifier fix same day | Add `algorithms` allow-list everywhere |
| JWT stolen / leaked | Revoke refresh token; rotate signing key | Reduce access-token TTL; tighten refresh-token usage |
| Predictable session IDs | Force-logout all sessions; rotate to crypto-random | Replace generator; audit other secret-randomness uses |
| Session fixation working | Rotate on login server-side | Audit framework defaults across the codebase |

## Automated tests

```python
def test_session_cookie_is_hardened(client):
    response = client.post("/login", data={"u": "alice", "p": "secret"})
    cookies = response.cookies
    session = cookies["session"]
    assert session.has_nonstandard_attr("HttpOnly")
    assert session.secure is True
    assert session["samesite"] in ("Lax", "Strict")

def test_session_rotated_on_login(client):
    pre = client.get("/").cookies["session"]
    client.post("/login", data={"u":"alice","p":"secret"})
    post = client.cookies["session"]
    assert pre != post   # session ID changed

def test_jwt_alg_none_rejected(client):
    token = forge_jwt_with_alg_none({"sub": "alice", "role": "admin"})
    response = client.get("/admin", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code in (401, 403)
```

## Tools

| Tool | Role |
|---|---|
| **Burp Suite (Sequencer)** | Statistical randomness analysis on captured session tokens |
| **JWT Editor (Burp extension)** | Manipulate JWTs inline |
| **jwt_tool** | CLI for testing JWT verifier behavior |
| **hashcat -m 16500** | Crack weak HMAC secrets |
| **Semgrep** | SAST patterns for `alg='none'`, missing `algorithms=`, weak random |

## Common mistakes when defending

- **`HttpOnly` only on the session cookie, not on the CSRF token.** Both should be `HttpOnly` if the CSRF token is server-issued via cookie.
- **Server-side session table not synced with logout.** Logout should both clear the client cookie *and* delete the server-side session row.
- **JWT verifier left with defaults.** Many libraries default to `algorithms: ['HS256','RS256',...]` — that's the algorithm-confusion vulnerability. Always specify.
- **"Refresh token" that's just a long-lived JWT.** That defeats the point of separating access from refresh. Refresh must be opaque + server-checkable.
- **Detection rules built on `User-Agent` alone.** Modern clients spoof it easily; combine with other signals.

## Going further

- [PortSwigger — JWT attacks](https://portswigger.net/web-security/jwt)
- [OWASP — JSON Web Token Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [Auth0 — JWT best practices RFC 8725](https://datatracker.ietf.org/doc/html/rfc8725) — the actual standards-track guidance
- [Trail of Bits — JWT pitfalls](https://blog.trailofbits.com/2024/02/01/jwt-cracking-the-misconceptions/)
