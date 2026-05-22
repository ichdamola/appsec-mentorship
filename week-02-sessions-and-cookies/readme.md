# Week 02: Sessions, Cookies, and JWTs

## 🎯 What you'll learn

- Read and understand the contents of a cookie or a JWT by hand
- Exploit session fixation, session hijacking, and predictable session IDs
- Strip a JWT signature (`alg: none`) and confuse RS256 with HS256
- Recognize the cookie flags and session-rotation patterns that prevent all of the above

By the end of this week you'll be able to:

- Identify whether a site uses opaque session tokens or JWTs
- Decode a JWT in your head (header / payload / signature) and verify a signature manually
- Spot `Set-Cookie` headers missing `HttpOnly`, `Secure`, or `SameSite`
- Explain when and why a session must be rotated

## ⚠️ Scope reminder

**All labs run locally or on PortSwigger Academy.** Don't try any of this against sites you don't own. See the root [readme.md](../readme.md#️-ethics--scope).

## 🧰 Lab setup

You'll use three labs this week:

### Lab 1: Juice Shop (Docker)

Same one as Week 01. Multiple session/cookie challenges:

```bash
docker run -d -p 3000:3000 --name juice-shop bcoles/juice-shop
```

We'll target the "Login Admin" and "Forged Coupon" challenges, both of which rely on session weirdness.

### Lab 2: PortSwigger Academy — JWT labs

The Academy has [11 JWT-specific labs](https://portswigger.net/web-security/jwt). The most instructive starters:

- ["JWT authentication bypass via unverified signature"](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-unverified-signature)
- ["JWT authentication bypass via flawed signature verification"](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-flawed-signature-verification)
- ["JWT authentication bypass via algorithm confusion"](https://portswigger.net/web-security/jwt/algorithm-confusion/lab-jwt-authentication-bypass-via-algorithm-confusion)

### Lab 3: PortSwigger Academy — session labs

- ["Session fixation"](https://portswigger.net/web-security/authentication/other-mechanisms/lab-session-fixation)

## ✅ Your job

1. **Decode a JWT by hand.** Grab any JWT (mint one at [jwt.io](https://jwt.io) if you don't have a handy app). Split it on `.` — base64-decode each part. Read the JSON.
2. **Try the PortSwigger "unverified signature" lab yourself first.** 20-30 minutes minimum.
3. **Open [attack.md](attack.md).** Compare your approach.
4. **Read [defense.md](defense.md).** Pay specific attention to the asymmetric-key recommendation and the session-rotation triggers.

## 📚 Required reading

| Resource | Why it matters | Time |
|---|---|---|
| [PortSwigger — JWT attacks](https://portswigger.net/web-security/jwt) | Best single resource on JWT exploitation | 45 min |
| [OWASP — Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) | The defense bible | 30 min |
| [RFC 6265 — HTTP State Management Mechanism](https://datatracker.ietf.org/doc/html/rfc6265) | The cookie spec; skim sections 4-5 | 20 min |
| [RFC 7519 — JSON Web Token](https://datatracker.ietf.org/doc/html/rfc7519) | The JWT spec; skim §4 (claims) and §10 (security considerations) | 20 min |

## 💡 What you should already know

- HTTP request/response basics, including how cookies are sent ([Week 01](../week-01-http-and-burp/))
- Base64 encoding (what it is, that it's not encryption)
- That JWTs are signed but **not** encrypted by default — the payload is readable by anyone
- HMAC vs. asymmetric signatures at a conceptual level
