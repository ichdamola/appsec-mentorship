# Week 09: CSRF, SameSite, SOP, and CORS

## 🎯 What you'll learn

- Read the **Same-Origin Policy** rules and predict what crosses origins and what doesn't
- Exploit **CSRF** via form POST, GET-CSRF, and JSON CSRF
- Understand the three **`SameSite`** modes (`Strict`, `Lax`, `None`) and when each breaks
- Bypass **CORS misconfigurations** - wildcard with credentials, origin reflection, null origin
- Recognize the modern **Cross-Origin headers** (CORP, COOP, COEP) and when you need them
- Design CSRF protection that works alongside SameSite, not against it

By the end of this week you'll be able to:

- Read a CORS configuration and predict which origins can call which endpoints with credentials
- Build a CSRF proof-of-concept HTML page that exploits a vulnerable form
- Pick the right CSRF defense pattern for your stack (synchronizer token, double-submit, SameSite)
- Explain why SameSite alone isn't enough for high-value state changes

## ⚠️ Scope reminder

**Lab only.** See [root readme](../readme.md#️-ethics--scope).

## 🧰 Lab setup

### Lab 1: PortSwigger Academy - CSRF labs

[11 CSRF labs](https://portswigger.net/web-security/csrf). Recommended:

1. ["CSRF vulnerability with no defenses"](https://portswigger.net/web-security/csrf/lab-no-defenses) - the gentle start
2. ["CSRF where token validation depends on request method"](https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-validation-depends-on-request-method)
3. ["CSRF where token is not tied to user session"](https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-not-tied-to-user-session)
4. ["CSRF where Referer validation depends on header being present"](https://portswigger.net/web-security/csrf/bypassing-referer-based-defenses/lab-referer-validation-depends-on-header-being-present)
5. ["SameSite Lax bypass via method override"](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions/lab-samesite-lax-bypass-method-override)

### Lab 2: PortSwigger Academy - CORS labs

[3 CORS labs](https://portswigger.net/web-security/cors). All worth doing:

1. ["CORS vulnerability with basic origin reflection"](https://portswigger.net/web-security/cors/lab-basic-origin-reflection-attack)
2. ["CORS vulnerability with trusted null origin"](https://portswigger.net/web-security/cors/lab-null-origin-whitelisted-attack)
3. ["CORS vulnerability with trusted insecure protocols"](https://portswigger.net/web-security/cors/lab-breaking-https-attack)

### Lab 3: Juice Shop

Continue with the "Forged Coupon" and "CSRF" challenges.

## ✅ Your job

1. **Solve "CSRF with no defenses" cold.** This is the canonical attack pattern.
2. **Solve "CORS basic origin reflection" cold.** Two pages: an attacker site that exfiltrates data from the target.
3. **Try "SameSite Lax bypass via method override"** - modern, gets at why SameSite isn't a complete fix.
4. **Read [attack.md](attack.md).**
5. **Read [defense.md](defense.md).**

## 📚 Required reading

| Resource | Why | Time |
|---|---|---|
| [PortSwigger - CSRF](https://portswigger.net/web-security/csrf) | Best CSRF overview | 30 min |
| [PortSwigger - CORS](https://portswigger.net/web-security/cors) | Best CORS overview | 30 min |
| [MDN - Same-origin policy](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy) | The browser rules | 20 min |
| [MDN - SameSite cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite) | The three modes | 15 min |
| [Web.dev - Cross-Origin-Embedder-Policy](https://web.dev/coop-coep/) | The modern header soup | 20 min |

## 💡 What you should already know

- HTTP requests and headers ([Week 01](../week-01-http-and-burp/))
- Cookies and how browsers attach them ([Week 02](../week-02-sessions-and-cookies/))
- What an "origin" is: scheme + host + port
- HTML forms and how they submit (default `Content-Type`, method behavior)
- The fact that the browser is enforcing all of this - it's a client-side trust boundary
