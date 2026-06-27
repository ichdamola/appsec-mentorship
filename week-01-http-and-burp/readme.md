# Week 01: HTTP, Burp, and Reflected XSS

## 🎯 What you'll learn

- Set up an intercepting proxy (Burp Suite Community) and route browser traffic through it
- Read and modify HTTP requests/responses by hand
- Identify and exploit a **reflected XSS** vulnerability in a lab app
- Recognize the same pattern in production code

This week is your gentle introduction to the workflow. Every subsequent week assumes you can intercept, modify, and replay HTTP traffic without thinking about it.

## ⚠️ Scope reminder

**Run all labs locally or against the platforms listed.** Don't point Burp at sites you don't own. See the root [readme.md](../readme.md#️-ethics--scope) for the full ethics statement.

## 🧰 Lab setup

You'll use two labs this week:

### Lab 1: OWASP Juice Shop (Docker)

```bash
docker run -d -p 3000:3000 --name juice-shop bcoles/juice-shop
```

Visit `http://localhost:3000` - you should see a beverage-themed e-commerce site. Every part of it is deliberately broken.

### Lab 2: PortSwigger Web Security Academy

Free account at https://portswigger.net/web-security. We'll use the **["Reflected XSS into HTML context with nothing encoded"](https://portswigger.net/web-security/cross-site-scripting/reflected/lab-html-context-nothing-encoded)** lab.

### Burp Suite setup

1. Install [Burp Suite Community Edition](https://portswigger.net/burp/communitydownload).
2. Open Burp → "Temporary project" → "Use Burp defaults" → "Start Burp".
3. Configure your browser to use Burp's proxy:
   - Manual: HTTP proxy `127.0.0.1:8080` for both HTTP and HTTPS.
   - Easier: install Burp's "FoxyProxy"-style switcher, or use Burp's built-in embedded browser (Proxy → Intercept → Open Browser).
4. Visit Burp's CA cert at `http://burp` → "CA Certificate" → install it in your browser's trust store. (Required to intercept HTTPS.)

## ✅ Your job

1. **Set up Burp.** Confirm you can intercept a request to `http://localhost:3000` in the Proxy tab and see it appear in HTTP History.
2. **Try Lab 2 (PortSwigger Reflected XSS) yourself first.** Spend 20-30 minutes. The goal is *not* to succeed; the goal is to develop intuition.
3. **Then open [attack.md](attack.md)** to compare your approach.
4. **Read [defense.md](defense.md)** to understand how this vulnerability gets fixed in real code.

## 📚 Required reading

| Resource | Why it matters | Time |
|---|---|---|
| [PortSwigger - What is Burp Suite?](https://portswigger.net/burp/documentation/desktop/getting-started) | The official tour | 20 min |
| [MDN - HTTP overview](https://developer.mozilla.org/en-US/docs/Web/HTTP/Overview) | Foundation - requests, responses, methods, status codes | 20 min |
| [OWASP - Cross-Site Scripting (XSS)](https://owasp.org/www-community/attacks/xss/) | The canonical classification | 15 min |
| [PortSwigger Academy - Reflected XSS](https://portswigger.net/web-security/cross-site-scripting/reflected) | Lab + theory in one | 30 min |

## 💡 What you should already know

- Basic HTML and JavaScript - enough to read a `<script>` tag and understand `alert()`
- What a URL is, what query parameters look like
- How to use a browser's DevTools (Network tab, Console)
- Be comfortable in a terminal (Docker, curl)
