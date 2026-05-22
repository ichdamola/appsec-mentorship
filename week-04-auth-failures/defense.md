# Week 04: Defense — Stopping Authentication Failures

You've broken authentication ten different ways in [attack.md](attack.md). Defending requires layered controls; no single fix covers all of them.

---

## The single rule

> **Authentication has to fail closed, fail quietly, and fail consistently.**

- **Fail closed:** errors deny access, not allow it.
- **Fail quietly:** don't leak whether the user, the password, or the recovery channel is the thing that's wrong.
- **Fail consistently:** identical response shape and timing across "wrong user" and "wrong password."

## Password handling

### Storage (we go deep in Week 10; here's the minimum)

```python
# Hashing on signup / password change
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))

# Verifying on login
if bcrypt.checkpw(submitted.encode(), stored_hash):
    ...
```

| Use | Don't use |
|---|---|
| **argon2id** (preferred), **bcrypt** (acceptable), **scrypt** | MD5, SHA-1, SHA-256 (without a slow KDF) |
| 12+ cost factor on bcrypt | 4-8 cost factor |
| Per-user random salt (default in modern libs) | Global salt |
| | Plaintext (obviously) |
| | "Encrypted" passwords (encryption is reversible by anyone with the key) |

### Password policy (NIST 800-63B, not what you think)

The 2017 NIST guidance flipped what "strong passwords" means:

| Do | Don't |
|---|---|
| Allow long passwords (min 8, up to 64+) | Require frequent rotation (only on suspected compromise) |
| Check against breach databases (Have I Been Pwned API) | Require special-character composition rules (`Aa1!` proves nothing) |
| Allow Unicode | Disallow paste (defeats password managers) |
| Encourage password managers | Send password by email |

The "must include uppercase, lowercase, number, special character" rule is *defunct*. NIST removed it. Replace it with breach-corpus checks.

## Rate limiting that actually works

### Per-user is necessary but not sufficient

Per-user lockout stops brute force but invites:

- Account lockout DoS (attacker locks every user out)
- Account-existence enumeration (lockout response leaks valid users)

### Per-IP defeats some, hurts mobile networks

Per-IP rate limits help against credential stuffing from one source — but a single carrier-NAT IP can host thousands of legitimate users.

### Layered approach

The right answer is multiple counters:

```python
def check_rate_limits(username, client_ip):
    # Per-user: stops brute force
    if attempts_for_user(username, window='5m') > 5:
        raise RateLimited("user_lockout", retry_after=300)

    # Per-IP: stops stuffing from one source
    if attempts_for_ip(client_ip, window='5m') > 50:
        raise RateLimited("ip_throttle", retry_after=300)

    # Global: catches distributed attacks
    if global_failure_rate(window='1m') > baseline * 3:
        require_captcha_for_all_logins(window='5m')
```

### Throttle, don't lock

A "lockout" is a hard binary. **Throttling** (delay) achieves the same risk reduction without the DoS surface:

| Attempt # | Delay introduced |
|---|---|
| 1-3 | None |
| 4 | 1 second |
| 5 | 5 seconds |
| 6 | 30 seconds |
| 7+ | Several minutes; backoff increases |

Throttling is invisible to the legitimate user (who knows their password) but devastating to a brute-forcer.

### Trust the right IP source

```python
# Wrong: anyone can spoof
client_ip = request.headers["X-Forwarded-For"]

# Right: trust the right hop in X-Forwarded-For (the one your LB sets)
trusted_proxies = ["10.0.0.1"]
xff = request.headers["X-Forwarded-For"].split(",")
# Walk right-to-left, skipping trusted proxy hops, until you find the real client
client_ip = first_untrusted_ip(xff, trusted_proxies)
```

## Defeating account enumeration

### Uniform responses

Every login failure returns:

```
HTTP/1.1 401 Unauthorized
Content-Length: 47

{"error": "invalid_credentials"}
```

Same message, same length, same status code, whether the user exists or not.

### Uniform timing

```python
# Wrong: only hash if user exists
user = User.objects.filter(email=email).first()
if user and bcrypt.checkpw(password, user.hashed):
    return ok()
return unauthorized()    # fast path for "no user" — leaks via timing

# Right: always do the bcrypt work
user = User.objects.filter(email=email).first()
dummy_hash = b"$2b$12$dummyDUMMYdummyDUMMYdummyDUMMYdummyDUMMYdummyDUMMYduUUUe"
hash_to_check = user.hashed if user else dummy_hash
ok_password = bcrypt.checkpw(password, hash_to_check)
if user and ok_password:
    return ok()
return unauthorized()
```

### Uniform password-reset behavior

```
POST /password-reset {"email": "alice@example.com"}
POST /password-reset {"email": "nobody@example.com"}
```

Both should return:

```
HTTP/1.1 200 OK
{"message": "If an account exists, a reset link has been sent."}
```

After a uniform delay (queue the email send async; reply immediately).

## MFA — done right

### Use phishing-resistant factors

Ranked by strength:

1. **WebAuthn / Passkeys** (FIDO2) — cryptographic, origin-bound, can't be phished
2. **TOTP** (authenticator app) — phishable but solid
3. **Push notification** (mobile app approve) — phishable via fatigue; needs number-matching
4. **Email-link MFA** — only as strong as the user's email account
5. **SMS** — vulnerable to SIM-swap; *avoid where possible*
6. **Security questions** — not MFA; treat as a username supplement

NIST 800-63B explicitly **deprecates SMS** as a second factor. Many regulated industries now prohibit it for high-value access.

### Rate-limit MFA verification

```python
def verify_mfa(session, code):
    attempts = mfa_attempts(session)
    if attempts >= 5:
        invalidate_session(session)   # force re-auth from scratch
        raise TooManyAttempts
    if not verify_totp(session.user, code):
        increment_mfa_attempts(session)
        raise InvalidCode
    ...
```

Bruteforcing 6-digit codes is only viable when verification is unlimited.

### Number-matching for push notifications

Modern push MFA (Microsoft Authenticator, Duo) shows a number on the login page. The user must enter that number on their phone. Defeats fatigue attacks — you can't just tap "approve."

### Recovery codes done right

- Generated at MFA setup, displayed *once*, hashed before storage.
- One-time use.
- 8+ alphanumeric characters.
- Stored in the password manager, not in plaintext.

### MFA fallback rules

- Never let SMS or email be a fallback for higher-grade MFA on privileged accounts. The fallback **becomes** the MFA.
- For admins, no fallback. They use a backup hardware key.

## Password reset hardening

```python
def request_password_reset(email):
    user = User.objects.filter(email=email).first()
    if user:
        token = secrets.token_urlsafe(32)         # 256 bits of entropy
        PasswordResetToken.objects.create(
            user=user,
            token_hash=sha256(token).hexdigest(),  # store hash, not token
            expires_at=now() + timedelta(minutes=15),
            used=False,
        )
        send_email_async(
            user.email,
            f"Click to reset: https://{settings.CANONICAL_HOST}/reset?token={token}"
            # ← always use canonical host, never request.host (host-header injection)
        )
    # Same delay regardless of whether user exists
    sleep_until(consistent_response_time)
    return ok("If an account exists, an email has been sent.")
```

Key points:

- **Token is high-entropy random**, not derived from user data
- **Stored hashed**, not plaintext — DB leak doesn't compromise pending resets
- **Short expiry** (15 min, not days)
- **Single use** — set `used=True` after consumption
- **Canonical host** in the URL — defeats host-header injection
- **No-op for nonexistent users**, with same timing

## "Remember me" hardening

If you must have it (most apps shouldn't):

- Separate from session token — a long-lived "device token."
- Stored hashed in DB, mapped to (user, device fingerprint).
- Re-prompts for MFA on sensitive actions, no matter how "remembered" the device is.
- Revocable from a "Devices" UI in account settings.
- Expires after N days of inactivity (not just N days from issue).

---

## Detection

### Signal 1: Failed-login spikes per user

```
| where event = "login_failure"
| stats count by username, source = "username"
| where count > 10
```

Buckets:

- 10-20 in 5 min from few IPs → brute force
- 1-3 each across 1000+ usernames from many IPs → credential stuffing
- Same password tried across 1000+ usernames → password spray

### Signal 2: Diverse usernames from one source

```
| where event = "login_failure"
| stats dc(username) as users_tried, count as attempts by client_ip
| where users_tried > 20 and attempts > 30
```

Almost always stuffing.

### Signal 3: Successful login after many failures

A user account that just failed 8 times and then succeeded. Could be a memory lapse; could be the attacker who finally got it right.

```
| transaction username startswith=login_failure endswith=login_success maxspan=5m
| stats count by username, client_ip
| where count > 5
```

Pair with: was the source IP one the user had used before? Geolocation match?

### Signal 4: MFA failures

A user with MFA enabled is in the middle of MFA-validation. Bursts of MFA failures from one session:

```
| where event = "mfa_failure"
| stats count by session_id
| where count > 3
```

This is the "2FA brute force" signal. If you see it, kill the session.

### Signal 5: Reset-token failures

```
| where event = "password_reset_failure"
| stats count by client_ip
| where count > 10
```

Someone is guessing reset tokens. Either there's a leak somewhere or your tokens are too short.

### Signal 6: Concurrent sessions from different geos

Covered in Week 02. Worth repeating: if it happens within an MFA-still-valid window, the account is compromised.

---

## Remediation playbook

| Finding | Immediate action | Longer fix |
|---|---|---|
| Enumeration via different responses | Patch responses to be uniform | Add response-shape tests |
| Enumeration via timing | Add dummy bcrypt for invalid users | Audit all auth-adjacent endpoints for timing |
| Brute force succeeded | Force password reset for victim; review breach-corpus | Tighten per-user and per-IP limits |
| Stuffing succeeded | Force password reset; require new password not in breach corpus | Add behavioral signals (device fingerprint, geo) |
| Push fatigue compromise | Switch to number-matching push | Adopt phishing-resistant factor (WebAuthn) for the user's role |
| Reset poisoning via Host header | Pin canonical host in reset email | Add WAF rule for unusual Host values |

## Automated tests

```python
def test_enumeration_response_uniform(client):
    valid_user = client.post("/login", json={"email": "alice@example.com", "password": "wrong"})
    invalid_user = client.post("/login", json={"email": "nobody@example.com", "password": "wrong"})

    assert valid_user.status_code == invalid_user.status_code
    assert valid_user.text == invalid_user.text

def test_enumeration_timing_uniform(client):
    import time
    t1 = []; t2 = []
    for _ in range(50):
        s = time.perf_counter()
        client.post("/login", json={"email": "alice@example.com", "password": "wrong"})
        t1.append(time.perf_counter() - s)

        s = time.perf_counter()
        client.post("/login", json={"email": "nobody@example.com", "password": "wrong"})
        t2.append(time.perf_counter() - s)

    # Means within 10% of each other
    assert abs(sum(t1)/len(t1) - sum(t2)/len(t2)) / max(t1+t2) < 0.10

def test_login_rate_limit(client):
    for _ in range(20):
        client.post("/login", json={"email": "alice@example.com", "password": "guess"})
    response = client.post("/login", json={"email": "alice@example.com", "password": "guess"})
    assert response.status_code == 429
    assert "Retry-After" in response.headers

def test_password_reset_no_op_for_nonexistent_user(client):
    response = client.post("/password-reset", json={"email": "nobody@example.com"})
    assert response.status_code == 200
    assert "if an account exists" in response.text.lower()
```

## Tools

| Tool | Role |
|---|---|
| **Burp Suite (Intruder)** | Manual brute force / fuzz testing |
| **Hydra / Medusa** | Network-protocol brute force; useful for non-HTTP auth |
| **Have I Been Pwned API** | Check passwords against breach corpus at signup/reset |
| **Pwned Passwords k-Anonymity API** | Same check without sending the password (send the first 5 chars of the SHA-1) |
| **Auth0 / Cloudflare bot management** | Detect credential-stuffing patterns |
| **WebAuthn libraries** (SimpleWebAuthn, etc.) | Implement phishing-resistant MFA |

## Common mistakes when defending

- **CAPTCHA as a primary control.** It's a speed bump. Real attackers solve via paid services.
- **Account lockout (binary).** Throttling is strictly better.
- **Same response code but different message.** "Authentication failed" vs. "Invalid credentials" still enumerates.
- **Forgetting to rate-limit the MFA verification step.** Most apps rate-limit login but not the OTP entry.
- **Email as a fallback for MFA.** That's just "password + email password," which is one factor.
- **Allowing the user to disable MFA via email link.** Bypasses MFA by definition.

## Going further

- [NIST SP 800-63B — Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [OWASP — Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [PortSwigger — Authentication vulnerabilities](https://portswigger.net/web-security/authentication)
- [Krebs on Security — MFA Fatigue & Uber](https://krebsonsecurity.com/2022/09/uber-says-lapsus-hackers-attacker-may-have-used-mfa-fatigue/) — real-world push fatigue post-mortem
