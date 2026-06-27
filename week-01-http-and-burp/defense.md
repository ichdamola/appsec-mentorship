# Week 01: Defense - Stopping Reflected XSS

You've exploited it in [attack.md](attack.md). Now the harder, more useful half: how do you stop it, detect it when it gets through, and prove it stays fixed?

---

## The single rule

> **Encode for the context you're outputting into. Never trust input filtering alone.**

XSS happens when user-controlled input lands in a place where the browser parses it as code. The defense is to make sure the browser parses it as *data* - by encoding it correctly for the context (HTML body, HTML attribute, JavaScript string, URL, CSS).

## Context-specific encoding

| Context | Wrong | Right |
|---|---|---|
| HTML text content | `<div>${userInput}</div>` | `<div>${htmlEscape(userInput)}</div>` |
| HTML attribute | `<a title=${userInput}>` | `<a title="${attrEscape(userInput)}">` (and quote the attribute) |
| JavaScript string | `<script>var x = "${userInput}"</script>` | `<script>var x = ${JSON.stringify(userInput)}</script>` |
| URL | `<a href="${userInput}">` | Validate URL + use the appropriate URL escaper; reject `javascript:` schemes |
| CSS value | `style="background:${userInput}"` | Don't. Allow-list a set of safe values instead |

The wrong code looks reasonable. That's why this bug class won't die - it requires the developer to think about *output context*, not just "is this input clean?"

## Use a templating engine that auto-escapes

Modern frameworks default to safe output. Recognize when you're opting *out* of that protection - that's where bugs live:

| Framework | Safe by default | "Trust me" escape hatch (DANGER) |
|---|---|---|
| React | `{userInput}` is escaped | `dangerouslySetInnerHTML={{__html: userInput}}` |
| Vue | `{{ userInput }}` is escaped | `v-html="userInput"` |
| Django templates | `{{ user.name }}` is escaped | `{{ user.name\|safe }}` or `{% autoescape off %}` |
| Jinja2 | Escapes by default | `{{ user.name\|safe }}` or `{% autoescape false %}` |
| Handlebars | `{{name}}` is escaped | `{{{name}}}` (triple-brace = raw) |

> 💡 **Bug-hunter shortcut:** when reviewing code, grep for the "trust me" patterns above. Every one is a candidate XSS.

## When you actually need to render user HTML

Sometimes (rich-text comments, markdown previews) you *do* need to output user-supplied HTML. Two options:

### Option 1: Render to a sandboxed iframe

The user content lives at a different origin (`usercontent.example.com`), in an iframe with `sandbox` attributes. JS in there can't reach your main app. Google Docs, GitHub Gists, and Medium all do versions of this.

### Option 2: HTML sanitizer

A library that parses the HTML and *removes* dangerous elements/attributes. **DOMPurify** is the gold standard:

```js
import DOMPurify from 'dompurify';
const clean = DOMPurify.sanitize(userHtml);
element.innerHTML = clean;
```

Sanitizers are easier to get wrong than you think. The mutation-XSS (mXSS) family of bugs is specifically about confusing sanitizers vs. browser HTML parsers. Don't roll your own.

## Content Security Policy (CSP)

CSP is a defense-in-depth layer: even if XSS lands, CSP can prevent the malicious script from executing.

Minimum useful CSP for a modern app:

```
Content-Security-Policy:
  default-src 'self';
  script-src 'self' 'nonce-{random-per-request}';
  object-src 'none';
  base-uri 'self';
  frame-ancestors 'none';
```

Key principles:

- **`script-src 'self' 'nonce-X'`** - only scripts from your origin OR scripts tagged with the per-request nonce can run. Inline `<script>alert(1)</script>` is blocked.
- **`object-src 'none'`** - blocks `<object>` / `<embed>` plugins.
- **`base-uri 'self'`** - prevents `<base href>` injection from rewriting relative URLs.

`unsafe-inline` defeats most of CSP's value for XSS prevention. Avoid it.

## Cookie hardening (limits XSS damage)

XSS lets an attacker run JS in your origin. That JS can read non-`HttpOnly` cookies. Limit the blast radius:

```
Set-Cookie: session=abc; HttpOnly; Secure; SameSite=Lax; Path=/
```

| Flag | What it does |
|---|---|
| `HttpOnly` | JS can't read this cookie via `document.cookie` |
| `Secure` | Cookie only sent over HTTPS |
| `SameSite=Lax` or `Strict` | Cookie not sent on cross-site requests (defense vs. CSRF, separate topic) |

This doesn't prevent XSS, but it stops XSS from immediately becoming session theft.

---

## Detection - what does this look like in logs?

XSS exploit attempts leave fingerprints. Build detections at three layers.

### Layer 1: HTTP request logs

Look for unencoded `<`, `>`, `"`, `'` in query parameters or form bodies. The simplest signal:

```
GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E
GET /search?q=<svg/onload=alert(1)>
POST /comment    body: { "text": "<img src=x onerror=fetch(...)" }
```

Detection patterns (Splunk-style):

```
index=web sourcetype=access_log
  | regex uri_query="<(script|svg|img|iframe|style|link|object|embed)"
  | stats count by client_ip, uri_path
  | where count > 5
```

False-positive rate is real - legitimate users sometimes paste HTML into searches. Tune by adding context (is this user already suspicious? is this a parameter that should never contain HTML?).

### Layer 2: CSP violation reports

CSP can be configured to *report* violations without blocking them, or both:

```
Content-Security-Policy-Report-Only:
  default-src 'self';
  report-uri /csp-violations
```

Every blocked script execution becomes a JSON report sent to `/csp-violations`. If you're seeing violations in production from real user IPs, you're either:

- (a) blocking a legitimate script because your CSP is too tight, or
- (b) blocking an actual XSS payload that landed.

Both are useful signals.

### Layer 3: WAF rules

A WAF (Web Application Firewall - CloudFlare, AWS WAF, ModSecurity) ships with XSS rule packs. Useful as defense-in-depth; **never your only defense.** Every WAF rule has bypasses. Modsecurity's OWASP CRS rule 941 family is the open-source baseline.

---

## Remediation when XSS is found in your code

When a scanner or pentest finds reflected XSS in your codebase, the fix order:

1. **Confirm the context.** Where in the response is the payload landing? HTML body? Attribute? JavaScript? Each context has a different fix.
2. **Use the framework's auto-escape.** Don't write your own escaper.
3. **If you must concatenate HTML, sanitize with DOMPurify** (client) or your language's equivalent (server).
4. **Add a CSP header.** Even if you miss a spot, CSP gives you a safety net.
5. **Write a regression test.** See below.

## Automated tests that catch this class

A test for an XSS fix should attempt the exploit and assert it doesn't fire:

```python
def test_search_does_not_reflect_html_unencoded(client):
    response = client.get("/search?q=<script>alert(1)</script>")
    assert "<script>" not in response.text
    assert "&lt;script&gt;" in response.text
```

For client-side / DOM XSS, the same idea using a headless browser:

```python
def test_dom_xss_in_search_not_executed(page):
    page.goto("http://localhost:3000/#/search?q=<img src=x onerror=window.__xss_fired=true>")
    page.wait_for_load_state("networkidle")
    assert page.evaluate("window.__xss_fired") is None
```

Wire these into CI. Once a class of XSS is fixed, the test prevents regression.

## Tools that find this class automatically

| Tool | Role |
|---|---|
| **Burp Suite (Active Scan)** | Sends probes during a crawl; flags reflected payloads |
| **OWASP ZAP** | Free alternative to Burp; similar coverage |
| **Semgrep** | Static analysis - finds the *insecure patterns* in source code (e.g. `dangerouslySetInnerHTML`, unescaped template substitution) |
| **CodeQL** | Deeper static analysis with data-flow tracking |

Run a SAST tool (Semgrep) in CI and a DAST tool (ZAP) on a staging deploy. Both find different bugs; you need both.

---

## Common mistakes when defending

- **Allow-listing tags but not attributes.** `<a>` is "safe" until you allow `href="javascript:..."` or `onclick=...`.
- **Filtering `<script>` and assuming you're done.** Twenty other tags trigger JS (`<img onerror>`, `<svg onload>`, `<iframe srcdoc>`, etc.).
- **Encoding once, but the value passes through encoding-aware contexts.** Double-encoding bugs are common - sanitizer escapes once, framework escapes again on output → display breaks → developer "fixes" by skipping the framework's escape.
- **Trusting client-side validation.** All client-side checks can be bypassed (just don't run your JS). Server side is authoritative.
- **Relying on CSP alone.** CSP catches some payloads, misses others (data-URI iframes, unsafe-inline allowances, JSONP endpoints). It's a layer, not a fix.

## Going further

- [PortSwigger - XSS prevention](https://portswigger.net/web-security/cross-site-scripting/preventing)
- [OWASP - XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [Google Web Fundamentals - CSP](https://web.dev/csp/)
- [Trusted Types](https://web.dev/trusted-types/) - browser API that makes XSS harder by requiring all DOM-sink writes to be explicitly trusted
