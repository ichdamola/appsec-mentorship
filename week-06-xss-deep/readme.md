# Week 06: Stored & DOM XSS, CSP Bypass

## 🎯 What you'll learn

- Exploit **stored XSS** (persistent, hits every viewer) - the high-impact cousin of reflected XSS
- Identify and exploit **DOM-based XSS** where the server never sees the payload
- Understand **mutation XSS (mXSS)** - sanitizer bypasses via browser HTML re-parsing
- Bypass real-world **Content Security Policy** configurations
- Design a CSP that's actually effective and harder to bypass

By the end of this week you'll be able to:

- Walk a complex web app and identify every sink that writes attacker-controlled data to the DOM
- Read a CSP header and predict which payloads it allows / blocks
- Tell whether a sanitizer call is safe or whether it has a known bypass
- Write a CSP that survives real-world XSS attempts without breaking the app

## Prerequisite

[Week 01: HTTP, Burp, and Reflected XSS](../week-01-http-and-burp/) is required - we're building on its definition of XSS, its tooling setup, and the basic payload patterns.

## ⚠️ Scope reminder

**Labs only.** See [root readme](../readme.md#️-ethics--scope).

## 🧰 Lab setup

### Lab 1: PortSwigger Academy - stored, DOM, and CSP labs

The Academy has [extensive XSS labs](https://portswigger.net/web-security/cross-site-scripting). Recommended:

**Stored XSS:**
- ["Stored XSS into HTML context with nothing encoded"](https://portswigger.net/web-security/cross-site-scripting/stored/lab-html-context-nothing-encoded)
- ["Stored XSS into anchor href attribute with double quotes HTML-encoded"](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-href-attribute-double-quotes-html-encoded)

**DOM-based XSS:**
- ["DOM XSS in `document.write` sink using source `location.search`"](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink)
- ["DOM XSS via client-side prototype pollution"](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-client-side-prototype-pollution)

**CSP bypasses:**
- ["Reflected XSS with AngularJS sandbox escape and CSP"](https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection/lab-angularjs-csp)
- ["Reflected XSS protected by very strict CSP, with dangling markup attack"](https://portswigger.net/web-security/cross-site-scripting/content-security-policy/lab-very-strict-csp-with-dangling-markup-attack)

### Lab 2: Juice Shop

Continue with the XSS challenges. Juice Shop has stored XSS in the user profile and DOM XSS in the search.

## ✅ Your job

1. **Solve the stored XSS lab cold.** Then exploit it for cookie theft *with* a payload that runs `fetch()` - go past `alert(1)`.
2. **Solve the DOM XSS lab.** This requires reading client-side JS, which is half of modern AppSec.
3. **Solve one of the CSP-bypass labs.** Bring a real understanding of why each rule blocks what.
4. **Read [attack.md](attack.md).**
5. **Read [defense.md](defense.md).**

## 📚 Required reading

| Resource | Why | Time |
|---|---|---|
| [PortSwigger - DOM-based vulnerabilities](https://portswigger.net/web-security/dom-based) | The taxonomy of DOM sinks | 45 min |
| [Google - Strict CSP guide](https://csp.withgoogle.com/docs/strict-csp.html) | The modern CSP recipe | 30 min |
| [OWASP - XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) | Context-by-context rules | 30 min |
| [Trusted Types](https://web.dev/trusted-types/) | The modern browser API that makes DOM XSS structurally harder | 20 min |
| [DOMPurify documentation](https://github.com/cure53/DOMPurify) | The de-facto HTML sanitizer | 20 min |

## 💡 What you should already know

- Reflected XSS basics ([Week 01](../week-01-http-and-burp/))
- HTML, CSS, JavaScript - at the level of reading minified production code
- The browser's same-origin policy at a conceptual level
- How to use browser DevTools (Sources tab, console, breakpoints)
