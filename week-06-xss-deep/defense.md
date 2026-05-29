# Week 06: Defense — Stored & DOM XSS, CSP Bypass

You've exploited stored XSS, DOM XSS, and walked around real CSPs. Now the layered defenses that make those attacks fail.

---

## The two single rules

> 1. **Encode for the output context, always — same as Week 01.**
> 2. **Add a strict CSP as defense in depth — because encoding sometimes gets missed.**

The fixes for stored XSS are the same as for reflected XSS at the rendering level. The fixes for DOM XSS are different — the data flow is client-side, so the defense is too.

## Stored XSS — same defense as reflected, with one addition

Stored XSS arises from the same root cause as reflected XSS: user input lands in a place where the browser parses it as code. The defense is the same context-aware encoding from [Week 01 defense.md](../week-01-http-and-burp/defense.md):

| Context | Right pattern |
|---|---|
| HTML body | `{{ user_input }}` in an auto-escaping template |
| HTML attribute | `<a title="{{ user_input | attr_escape }}">` |
| JavaScript | `var x = {{ user_input | json }}` |
| URL | Validate scheme + URL-escape |

What stored XSS adds:

### Sanitize before storage *for rich content only*

If the field is rich text (a blog post body, a comment with formatting), sanitize the HTML before storing it:

```python
from bleach import clean

def save_comment(raw_html, user):
    safe_html = clean(raw_html,
                      tags=['p', 'em', 'strong', 'a', 'code', 'blockquote'],
                      attributes={'a': ['href', 'title']},
                      protocols=['http', 'https', 'mailto'])
    Comment.objects.create(body=safe_html, author=user)
```

| Library | Language |
|---|---|
| `DOMPurify` | JavaScript (client and Node) |
| `bleach` | Python |
| `sanitize-html` | Node |
| `JSoup` | Java |
| `HtmlSanitizer` | .NET |
| `Loofah` / `Rails::Html::Sanitizer` | Ruby |

**For plain-text fields, do nothing at storage — escape at render.** Sanitizing plain text creates "what did the sanitizer do to my input?" bugs (e.g., the user's name shows up as different on each page).

### Render in a sandboxed iframe for fully untrusted content

For very rich user content (custom HTML, embedded scripts, user-rendered Markdown), put it in an iframe at a separate origin:

```html
<!-- main app at example.com -->
<iframe sandbox="allow-scripts" src="https://usercontent.example.com/render/post/123"></iframe>
```

The iframe's origin (`usercontent.example.com`) is isolated from your main app's origin. Even if the user's content has XSS, the JS runs in a sandbox that can't reach your app's cookies, DOM, or APIs.

This is how Google Docs, GitHub Gists, CodeSandbox, and most CMSes that allow custom HTML do it.

## DOM XSS — different defense

The classic encoding rules apply to server-rendered HTML. DOM XSS is *client-side*, so the defense lives in JavaScript:

### Avoid the sinks

In order of preference:

| Goal | Use | Avoid |
|---|---|---|
| Insert text | `element.textContent = x` | `element.innerHTML = x` |
| Insert structured content | Framework templates (React `{x}`, Vue `{{x}}`, etc.) | `document.write(x)`, `innerHTML` concatenation |
| Set an attribute | `element.setAttribute('attr', x)` | `element.outerHTML = '<tag attr="' + x + '">'` |
| Set an href | `element.href = x` (validate scheme!) | `element.outerHTML = '<a href="' + x + '">'` |
| Execute dynamic code | Restructure to avoid; you almost never need this | `eval(x)`, `new Function(x)`, `setTimeout(string, ...)` |

### Validate URL schemes

The `href` and `src` attributes accept `javascript:` URLs. Filter:

```javascript
function safeHref(input) {
  try {
    const url = new URL(input, location.origin);
    if (!['http:', 'https:', 'mailto:'].includes(url.protocol)) {
      return '#';
    }
    return url.toString();
  } catch {
    return '#';
  }
}
```

### Use a sanitizer for unavoidable `innerHTML`

```javascript
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userContent);
```

DOMPurify handles mXSS, weird HTML, and SVG-context tricks. The other sanitizers don't.

### Trusted Types (the modern browser API)

Trusted Types is a browser API that makes DOM XSS *structurally impossible* by requiring every DOM-sink write to go through a registered policy.

```http
Content-Security-Policy: require-trusted-types-for 'script'; trusted-types myPolicy
```

In JS:

```javascript
const policy = trustedTypes.createPolicy('myPolicy', {
  createHTML: (input) => DOMPurify.sanitize(input)
});

// Now this:
element.innerHTML = policy.createHTML(userContent);   // works
element.innerHTML = userContent;                       // throws TypeError
```

Every DOM sink (innerHTML, document.write, etc.) refuses raw strings. The compiler/linter enforces that you went through your sanitization policy. **Trusted Types is the closest thing to "DOM XSS solved" we have in 2026.**

Browser support is Chrome/Edge; Firefox and Safari still lack it. Use as defense in depth where you can.

### postMessage handlers — always check origin

```javascript
addEventListener('message', e => {
  // ALWAYS check origin against an allow-list FIRST
  if (e.origin !== 'https://expected.example.com') return;

  // Then validate shape
  if (typeof e.data !== 'object' || typeof e.data.action !== 'string') return;

  // Then dispatch
  handleAction(e.data.action);
});
```

The single most common postMessage bug is missing the origin check.

## Content Security Policy — done right

CSP is defense in depth. A correct CSP catches XSS payloads even if your encoding has a gap.

### The strict-dynamic + nonce pattern

This is the modern recommendation from Google's strict-CSP guide:

```
Content-Security-Policy:
  script-src 'nonce-{random_per_request}' 'strict-dynamic';
  object-src 'none';
  base-uri 'none';
  require-trusted-types-for 'script';
  trusted-types default;
  upgrade-insecure-requests;
  report-uri /csp-report
```

What each line does:

- **`script-src 'nonce-X' 'strict-dynamic'`** — only `<script>` tags with the per-request nonce attribute run. `'strict-dynamic'` says "if you trust this script, also trust any scripts it loads." That means you don't have to manually allow-list every CDN — your bundled bootstrap.js loads everything else and the trust propagates.
- **`object-src 'none'`** — blocks `<object>`/`<embed>` plugin content.
- **`base-uri 'none'`** — prevents `<base>` tag injection.
- **`require-trusted-types-for 'script'`** — DOM sinks must go through a Trusted Types policy.
- **`upgrade-insecure-requests`** — auto-upgrade http: subresources to https.
- **`report-uri`** — collects violation reports for monitoring.

### Per-request nonces

The nonce must be:

- **Cryptographically random** per request (`secrets.token_urlsafe(16)`)
- **Embedded in the CSP header** AND in every legitimate `<script>` tag
- **Never reused across requests**

A static nonce defeats the entire scheme.

### What CSP can't fix

- **JSONP endpoints** on allowed CDNs — `'strict-dynamic'` helps but the deeper fix is to remove JSONP
- **Dangling-markup attacks** that exfiltrate via images — add `connect-src` + `img-src` restrictions
- **CSS-based attacks** — `style-src` similarly to scripts
- **Open redirects** that bounce off your domain — separate defense

### CSP in report-only first

Deploy CSP `report-only` before enforcing. Collect violations for a few weeks:

```
Content-Security-Policy-Report-Only: ...the strict policy...
```

Real violations from real users tell you what your app actually uses. Fix or allow them before flipping to enforcing.

## Defense in depth

| Layer | What it catches |
|---|---|
| Auto-escaping framework | Most reflected/stored XSS |
| Sanitizer (DOMPurify) | Rich-text fields, mXSS |
| Sandboxed iframe origin | Fully untrusted user content |
| Strict CSP (nonce + strict-dynamic) | XSS that landed despite encoding |
| Trusted Types | DOM-side write attempts on raw strings |
| `HttpOnly` session cookies | Stops XSS from immediately taking sessions |
| `SameSite` cookies | Stops XSS-from-other-origin from acting as you |
| Subresource integrity (SRI) | Compromised CDN can't ship malicious JS |

---

## Detection

### Signal 1: CSP violation reports

The signal-richness of CSP reporting is the underrated win. Reports come as JSON to your endpoint:

```json
{
  "csp-report": {
    "document-uri": "https://app.example/profile",
    "violated-directive": "script-src",
    "blocked-uri": "https://attacker.example/payload.js",
    "source-file": "https://app.example/profile",
    "line-number": 42,
    "column-number": 7
  }
}
```

Cluster reports by `blocked-uri` and `document-uri`. Spikes from a previously-unseen `blocked-uri` are either:

- Your dev team pushed something legitimate the CSP doesn't allow (fix the CSP)
- An attacker is probing for XSS opportunities (investigate)

### Signal 2: Request log patterns (similar to Week 01)

For reflected/stored XSS attempts in HTTP traffic:

```
| where uri_query matches "(?i)(<script|<svg|<img.*onerror|javascript:|on\w+=)"
   or post_body matches "(?i)(<script|<svg|<img.*onerror)"
| stats count by client_ip, user_id, endpoint
| where count > 5
```

False positives are real; tune by parameter (some fields legitimately accept HTML).

### Signal 3: Stored XSS — detect at write time

For stored XSS specifically: a payload that survives storage indicates the validation/sanitization is broken. Hook the storage layer:

```python
def save_comment(body):
    if SANITIZER_CHANGED_OUTPUT(body):
        log.warning("comment_required_sanitization",
                    user=current_user.id, body_hash=hash(body))
    Comment.objects.create(body=sanitizer.sanitize(body))
```

Hit-rate on this signal is interesting — most legit users never trigger it. The ones who do are either rich-text editors that escape-then-encode (predictable, dismissible) or attackers (you want to know).

### Signal 4: Cookie / token theft callbacks

If your app's cookies *could* be exfiltrated, monitor outbound requests from your origin to unknown destinations. The Burp Collaborator pattern works in production too — set up a beacon endpoint on a domain you control, look for unexpected callbacks containing session-shaped data.

---

## Remediation playbook

| Finding | Immediate action | Longer fix |
|---|---|---|
| Stored XSS in comment body | Sanitize at render; ship today | Migrate field to a sanitizer at write; add tests |
| DOM XSS via `innerHTML` write | Replace with `textContent` if text-only; DOMPurify if HTML | Adopt Trusted Types; add Trusted Types CI lint |
| `dangerouslySetInnerHTML` in React | Audit every callsite | Codebase-wide ban via lint rule; allow only with explicit `// allowlisted-by-security` comment |
| CSP missing or permissive | Deploy strict CSP report-only; flip to enforcing after 2-week observation | Adopt the strict-dynamic + nonce pattern |
| postMessage handler without origin check | Add origin allow-list | Lint rule that flags `addEventListener('message', ...)` without origin check |
| `unsafe-inline` in CSP | Migrate inline scripts to nonced/hashed scripts | Plan to remove unsafe-inline within a release |

## Automated tests

```python
def test_comment_renders_html_escaped(client, alice_token):
    client.post("/comments", json={"body": "<script>alert(1)</script>"},
                headers={"Authorization": f"Bearer {alice_token}"})
    response = client.get("/comments")
    assert "<script>" not in response.text
    assert "&lt;script&gt;" in response.text

def test_dom_sink_not_used_with_raw_input(page):
    # Headless browser test with Playwright
    page.goto("http://localhost:3000/profile/me")
    page.fill('#display_name', '<img src=x onerror=window.__xss=true>')
    page.click('#save')
    page.reload()
    assert page.evaluate("window.__xss") is None

def test_csp_header_present_and_strict(client):
    response = client.get("/")
    csp = response.headers["Content-Security-Policy"]
    assert "'unsafe-inline'" not in csp.split("script-src", 1)[1].split(";", 1)[0]
    assert "'nonce-" in csp
    assert "base-uri" in csp
    assert "object-src" in csp

def test_postmessage_handler_validates_origin(page):
    page.goto("http://localhost:3000/")
    # Send a postMessage from a fake origin
    page.evaluate("""
        window.postMessage({attack: 'payload'}, '*')
    """)
    page.wait_for_timeout(100)
    assert page.evaluate("window.__exploited") is None
```

## Tools

| Tool | Role |
|---|---|
| **Burp Suite (DOM Invader)** | Identifies source-to-sink data flows in client-side JS |
| **DOMPurify** | HTML sanitizer; safe defaults |
| **CSP Evaluator** | https://csp-evaluator.withgoogle.com/ — paste a CSP, get bypass analysis |
| **Trusted Types** | Browser API + polyfill |
| **Semgrep** | Static rules for `dangerouslySetInnerHTML`, `v-html`, `innerHTML =`, `eval`, `new Function` |
| **CodeQL** | Data-flow analysis catches source-to-sink paths in big codebases |

## Common mistakes when defending

- **Sanitizing input but trusting the rendering context.** A sanitizer that produces safe HTML doesn't protect you when the same content is rendered into a JS string context.
- **Building a custom sanitizer.** Every custom sanitizer has mXSS bugs. Use DOMPurify.
- **`unsafe-inline` in CSP.** Removes the central XSS protection.
- **`object-src 'self'`.** Blocks `<object>` only from external; an upload-as-object attack from your own origin still works. Use `'none'`.
- **Skipping `base-uri` in CSP.** It defaults to `*`. Always set to `'self'` or `'none'`.
- **Deploying CSP enforcing on day one.** Report-only first; tune; then enforce.

## Going further

- [Google — Strict CSP](https://csp.withgoogle.com/docs/strict-csp.html)
- [Trusted Types](https://web.dev/trusted-types/)
- [PortSwigger — Content Security Policy](https://portswigger.net/web-security/cross-site-scripting/content-security-policy)
- [DOMPurify documentation](https://github.com/cure53/DOMPurify)
- [PortSwigger — DOM-based vulnerabilities](https://portswigger.net/web-security/dom-based)
