# Week 04: Authentication Failures

## 🎯 What you'll learn

- The difference between brute force, credential stuffing, and password spraying — they need different defenses
- How rate limits get bypassed by header tricks and credential format manipulation
- MFA bypass patterns: recovery flow, push fatigue, fallback channel abuse
- Why timing differences between "wrong password" and "no such user" are an attack surface
- Account enumeration via password reset, error messages, and response sizes

By the end of this week you'll be able to:

- Identify which authentication-attack category a real-world incident falls into
- Spot subtle account-enumeration vectors in a login or password-reset flow
- Recognize an MFA implementation that's lying about its own strength
- Suggest the right defense for each class — they're not the same

## ⚠️ Scope reminder

**All labs run locally or on PortSwigger Academy.** Never run authentication attacks against real services. See [root readme](../readme.md#️-ethics--scope).

## 🧰 Lab setup

### Lab 1: PortSwigger Academy — authentication labs

The Academy has [16 authentication labs](https://portswigger.net/web-security/authentication). Recommended starters:

- ["Username enumeration via response messages"](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-different-responses)
- ["Username enumeration via subtly different responses"](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-subtly-different-responses)
- ["Brute-forcing a stay-logged-in cookie"](https://portswigger.net/web-security/authentication/other-mechanisms/lab-brute-forcing-a-stay-logged-in-cookie)
- ["2FA bypass using a brute-force attack"](https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-bypass-using-a-brute-force-attack)
- ["Password reset poisoning via middleware"](https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-poisoning-via-middleware)

### Lab 2: Juice Shop

```bash
docker run -d -p 3000:3000 --name juice-shop bcoles/juice-shop
```

Target challenges: "Login Admin", "Reset Bjoern's password", "Login MC SafeSearch".

## ✅ Your job

1. **Pick "Username enumeration via response messages."** Solve cold.
2. **Then "2FA bypass via brute force."** This one is satisfying.
3. **Read [attack.md](attack.md).**
4. **Read [defense.md](defense.md)** — pay attention to **why** different attacks need different defenses.

## 📚 Required reading

| Resource | Why | Time |
|---|---|---|
| [PortSwigger — Authentication vulnerabilities](https://portswigger.net/web-security/authentication) | Best taxonomy of attacks | 60 min |
| [OWASP — Top 10 A07:2021 Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) | Framing | 15 min |
| [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html) | The actual standard for digital identity. Sections 5.1.1.2, 5.1.2 | 45 min |
| [Auth0 — Anatomy of credential stuffing](https://auth0.com/blog/anatomy-of-credential-stuffing/) | Real-world attacker economics | 15 min |

## 💡 What you should already know

- HTTP requests and Burp Suite ([Week 01](../week-01-http-and-burp/))
- Sessions and cookies ([Week 02](../week-02-sessions-and-cookies/))
- Access control concepts ([Week 03](../week-03-broken-access-control/))
- That passwords are stored hashed, not encrypted, in any sane system (we'll go deep on password hashing in Week 10)
