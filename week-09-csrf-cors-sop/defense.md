# Week 09: Defense — CSRF, SameSite, SOP, CORS

You've exploited the gaps in [attack.md](attack.md). Now the layered defenses.

---

## The single rule

> **Defense in depth: SameSite cookies + CSRF tokens + Origin/Referer validation. Pick at least two.**

No single mechanism catches everything. Modern apps stack SameSite (browser-enforced default), CSRF tokens (application-enforced precision), and Origin/Sec-Fetch checks (additional context).

## CSRF defenses

### Defense 1: SameSite cookies (you mostly get this for free)

```
Set-Cookie: session=abc; HttpOnly; Secure; SameSite=Lax; Path=/
```

`Lax` is the modern browser default — even if you forget to set it, Chrome assumes Lax for cookies older than 2 minutes. It blocks:

- Cross-site form POSTs
- Cross-site `fetch()` (`credentials: 'include'`)
- Cross-site subresource requests

It does *not* block top-level GET navigation. So:

**Rule:** **Never** change state via GET. Combined with `SameSite=Lax`, no normal CSRF works.

Use `SameSite=Strict` for cookies that authenticate truly high-value actions (banking transactions). Trade: a user clicking your link from email isn't logged in yet — has to log in. Acceptable for some products.

### Defense 2: Synchronizer token pattern (the canonical CSRF defense)

The server issues a per-session random token. Every state-changing form includes the token. The server verifies the token matches the session.

```python
# At login
session['csrf_token'] = secrets.token_urlsafe(32)

# On every state-changing endpoint
@require_csrf_token
def transfer():
    submitted = request.form.get('csrf_token')
    if not hmac.compare_digest(submitted or '', session.get('csrf_token', '')):
        raise CSRFError
    ...
```

In the template:

```html
<form method="POST" action="/transfer">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
  ...
</form>
```

Key properties:

- **Tied to the session.** Stealing a token from your account doesn't help against the victim's session.
- **Per-session rotation, optionally per-request.** Per-request is overkill for most apps; per-session is the standard.
- **`hmac.compare_digest`** for constant-time comparison (defeats timing-based token guessing).
- **All state-changing methods enforced.** POST, PUT, PATCH, DELETE. GET should not change state.

Almost every framework ships this:

| Framework | How |
|---|---|
| Django | `{% csrf_token %}` + `CsrfViewMiddleware` |
| Flask | `flask-wtf` + `Form` validation |
| Rails | `protect_from_forgery` (default) |
| Express | `csurf` middleware |
| Spring | `CsrfTokenRepository` |

### Defense 3: Double-submit cookie pattern

For stateless / API-only apps that don't have server sessions:

1. Server sets a `csrf_cookie` cookie with a random value at first request.
2. Client reads the cookie via JS (NOT HttpOnly) and sends it in a custom header on every state-changing request.
3. Server verifies the cookie value equals the header value.

```javascript
// Client
const token = document.cookie.split('csrf_cookie=')[1].split(';')[0];
fetch('/transfer', {
  method: 'POST',
  credentials: 'include',
  headers: {'X-CSRF-Token': token, 'Content-Type': 'application/json'},
  body: JSON.stringify(...)
});
```

```python
# Server
if request.cookies.get('csrf_cookie') != request.headers.get('X-CSRF-Token'):
    raise CSRFError
```

The CSRF attacker can attach the victim's cookie (cookies attach automatically), but can't read it (Same-Origin Policy) and so can't set the header. Match check fails.

**Caveat:** if any subdomain has XSS, an attacker can write a same-site cookie and bypass. Use signed cookies (HMAC the value with a server secret) to harden.

### Defense 4: Origin / Sec-Fetch-Site validation

Modern browsers send headers describing the request's origin:

```
Origin: https://app.example
Sec-Fetch-Site: same-origin
```

Server validates:

```python
def csrf_check(request):
    origin = request.headers.get('Origin') or request.headers.get('Referer', '').split('/')[2]
    if origin not in ALLOWED_ORIGINS:
        raise CSRFError

    # Modern browsers: also check Sec-Fetch-Site
    if request.headers.get('Sec-Fetch-Site') not in ('same-origin', 'same-site'):
        raise CSRFError
```

The Origin header is set by the browser, not user code, and can't be spoofed cross-origin from a normal page. Sec-Fetch-Site is even harder to forge — only browser code sets it.

This works as a primary defense for state-changing endpoints, especially in API contexts where token-based CSRF is awkward.

### What about JSON-only APIs?

If the API:

- Only accepts `Content-Type: application/json`
- Rejects requests without that exact Content-Type
- Validates `Origin` header

…then classic CSRF is structurally impossible — a form can't send `Content-Type: application/json` without preflight, and preflight requires CORS allow.

But: **don't rely on this alone.** Add SameSite cookies and Origin checks. Defense in depth.

## CORS — done right

### The minimal correct CORS

For an API that needs to serve cross-origin requests from your own first-party origins:

```python
ALLOWED_ORIGINS = {
    'https://app.example',
    'https://admin.example',
}

@app.after_request
def add_cors_headers(response):
    origin = request.headers.get('Origin')
    if origin in ALLOWED_ORIGINS:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Vary'] = 'Origin'  # critical for caching
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE'
        response.headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type'
    return response
```

Key properties:

- **Exact-match allow-list.** Never substring. Never reflect.
- **`Vary: Origin` header.** Tells caches the response depends on the request origin. Otherwise a cached response for `app.example` gets served to `evil.example`.
- **No `null` in the allow-list. Ever.**
- **HTTPS only.** No `http://` origins.

### CORS for public APIs (no credentials)

```python
response.headers['Access-Control-Allow-Origin'] = '*'
# No Access-Control-Allow-Credentials
```

`*` with no credentials is the spec-compliant way to expose a public API. Browsers won't attach cookies/auth automatically. Fine for read-only public APIs.

### Preflight (OPTIONS) caching

If your API does many cross-origin requests, cache the preflight:

```
Access-Control-Max-Age: 86400
```

Reduces preflight overhead. The cache key includes the requesting origin and the method/headers being preflighted.

### Common CORS misconfig fixes

| Misconfig | Fix |
|---|---|
| `Access-Control-Allow-Origin: *` + credentials | Switch to exact allow-list |
| Origin reflection | Use exact allow-list, never echo |
| Substring match in allow-list | Use exact match |
| `null` in allow-list | Remove it; no use case justifies it for credentialed requests |
| HTTP origins in allow-list | HTTPS-only |
| Missing `Vary: Origin` | Add it (cache poisoning protection) |

## Defense in depth — the modern stack

For an authenticated app endpoint that changes state, the layers in 2026 are:

1. **`SameSite=Lax` (or `Strict`) session cookie.** Browser-enforced, free.
2. **CSRF token** (synchronizer or double-submit). Application-enforced, precise.
3. **`Sec-Fetch-Site` validation.** Catches edge cases SameSite misses.
4. **Strict CORS** (exact allow-list, no `null`).
5. **No state-changing GETs.** Architectural.

If any one of these has a bug, the others still catch the attack.

---

## Detection

### Signal 1: Cross-origin requests with credentials, no Origin allow

Watch for requests where:

- `Origin` header is present and not in your allow-list
- `Sec-Fetch-Site: cross-site`
- Session cookie still attached (didn't get blocked by SameSite)

```
| where sec_fetch_site = "cross-site" or origin not in allowed_origins
| where session_cookie_present = true
| stats count by origin, endpoint
```

Almost all hits are either misconfigured client apps you own (fix the client) or CSRF attempts (block + investigate).

### Signal 2: CSRF token mismatches

The CSRF middleware should log every rejection:

```
| where event = "csrf_rejected"
| stats count by user, client_ip, endpoint
| where count > 5
```

Real users very rarely hit this (token gets out of sync on tab restoration, browser back button); high counts from one source = attack.

### Signal 3: Same-origin claims with mismatched Referer

```
| where sec_fetch_site = "same-origin"
   and referer not matches "^https://(app|admin)\.example/"
```

Mismatched signals — either a misconfigured CDN/proxy or an attacker setting `Origin` manually (older browsers).

### Signal 4: 'null' Origin in production

```
| where origin = "null"
| stats count by endpoint, status
```

The only legitimate sources of `null` Origin are sandboxed iframes and file:// URLs — vanishingly rare in production traffic. Spike = attack.

---

## Remediation playbook

| Finding | Immediate action | Longer fix |
|---|---|---|
| State-changing GET | Add 403 in that handler if method != POST | Migrate to POST/PUT/DELETE; deploy CSRF middleware |
| CSRF without tokens | Add tokens to the form; enforce | Adopt framework's CSRF middleware fleet-wide |
| Origin reflection in CORS | Replace with exact allow-list; ship today | CORS middleware with allow-list config |
| `null` in CORS allow-list | Remove; ship today | Audit other CORS configs |
| Missing SameSite on session cookies | Add `SameSite=Lax`; ship today | Audit all cookies; Strict for sensitive ones |
| Wildcard CORS + credentials | Either remove `Allow-Credentials` (public API) or replace with allow-list (private API) | Decide which model the API is |

## Automated tests

```python
def test_state_change_requires_csrf_token(client, alice_token):
    # Without token — must fail
    response = client.post("/api/profile",
                           json={"email": "new@example.com"},
                           headers={"Authorization": f"Bearer {alice_token}"})
    assert response.status_code == 403

    # With token — must succeed
    token = client.get("/api/csrf-token").json()["token"]
    response = client.post("/api/profile",
                           json={"email": "new@example.com"},
                           headers={"Authorization": f"Bearer {alice_token}",
                                    "X-CSRF-Token": token})
    assert response.status_code == 200

def test_cors_allow_origin_is_specific(client):
    response = client.options("/api/transfer",
                              headers={"Origin": "https://evil.example"})
    assert response.headers.get("Access-Control-Allow-Origin") != "https://evil.example"
    assert response.headers.get("Access-Control-Allow-Origin") != "*"

def test_cors_does_not_reflect_null_origin(client):
    response = client.options("/api/transfer", headers={"Origin": "null"})
    assert response.headers.get("Access-Control-Allow-Origin") != "null"

def test_state_change_via_get_returns_405(client, alice_token):
    response = client.get("/api/transfer?to=attacker&amount=100",
                          headers={"Authorization": f"Bearer {alice_token}"})
    assert response.status_code in (404, 405)

def test_samesite_lax_on_session_cookie(client):
    response = client.post("/login", json={"username": "alice", "password": "secret"})
    cookie_header = response.headers.get("Set-Cookie", "")
    assert "SameSite=Lax" in cookie_header or "SameSite=Strict" in cookie_header
```

## Tools

| Tool | Role |
|---|---|
| **Burp Suite (CSRF PoC generator)** | Auto-generates HTML CSRF exploit from a captured request |
| **CORS scanner** | Tests an endpoint against the misconfig matrix |
| **Mozilla Observatory** | Web-based scan of headers; flags missing CORS / SameSite / cookie flags |
| **csp-evaluator / cors-checker** | Browser extensions |
| **Semgrep** | Rules for `cors(origin="*")`, weak CSRF token comparison, GET state changes |

## Common mistakes when defending

- **Treating SameSite as the only defense.** Method-override bypass demolishes it.
- **CSRF tokens not tied to the session.** Attacker grabs a token from their account, paste into CSRF page.
- **Origin reflection in CORS.** Tempting because "it works"; instantly exploitable.
- **No `Vary: Origin` header.** Cache poisoning — CDNs serve cached responses meant for one origin to another.
- **Trusting `Referer` as the primary defense.** Easy to omit, easy to confuse, deprecated as a security signal.

## Going further

- [PortSwigger — CSRF](https://portswigger.net/web-security/csrf)
- [PortSwigger — CORS](https://portswigger.net/web-security/cors)
- [OWASP — CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Web.dev — SameSite cookies](https://web.dev/samesite-cookies-explained/)
- [Web.dev — Fetch metadata](https://web.dev/fetch-metadata/)
- [Google — Cross-Origin Isolation](https://web.dev/coop-coep/)
