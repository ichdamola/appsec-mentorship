# Week 10: Cryptographic Failures

## 🎯 What you'll learn

- Recognize weak password hashing (`SHA-256(password)` is the canonical wrong answer)
- Spot weak randomness - when `Math.random()` is used for security tokens
- Find hardcoded secrets and bad secret-management patterns
- Understand timing attacks against string comparisons
- Identify a padding oracle and what it enables
- Pick the right modern primitive for each task

By the end of this week you'll be able to:

- Read auth code and tell whether passwords are hashed correctly
- Audit a codebase for weak randomness (`Math.random`, `rand()`, etc. used in token generation)
- Configure a TLS server with modern cipher suites and HSTS
- Use a secret manager properly (AWS Secrets Manager, GCP Secret Manager, Vault)

## Why this matters

OWASP A02:2021 is "Cryptographic Failures" (renamed from "Sensitive Data Exposure"). The bugs in this category are mostly *avoidable engineering choices* - using the wrong primitive for the job, not crypto-math errors. The defenses are simple if you commit to them.

## ⚠️ Scope reminder

**Lab only.** See [root readme](../readme.md#️-ethics--scope).

## 🧰 Lab setup

### Lab 1: PortSwigger Academy

- ["Authentication bypass via flawed signing"](https://portswigger.net/web-security/jwt/algorithm-confusion/lab-jwt-authentication-bypass-via-algorithm-confusion) (revisits Week 02 with crypto lens)
- ["Web cache poisoning with multiple headers"](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-with-multiple-headers) (touches secret-handling)

### Lab 2: Hashcat + sample hashes

```bash
# Install hashcat (most package managers have it)
brew install hashcat   # macOS
apt install hashcat    # Debian/Ubuntu

# Download rockyou.txt (the classic password list)
# It ships with Kali; otherwise find it at common AppSec resources
```

We'll crack sample hashes - SHA-256-of-password vs bcrypt. The point is to feel the difference.

### Lab 3: A vulnerable-by-design Flask app

A minimal app with weak password hashing, hardcoded secret keys, and `Math.random()` reset tokens. We'd ship this in `lab/`; for now, PortSwigger and code examples in [attack.md](attack.md) work.

### Lab 4: ssllabs.com

For TLS inspection - run any of your test/lab origins through https://www.ssllabs.com/ssltest/ to see what's misconfigured.

## ✅ Your job

1. **Hash three passwords** with SHA-256, MD5, and bcrypt. Crack each with hashcat. Time it. The 10⁶× gap between them is the point.
2. **Audit a real codebase** (your own personal project, or an open-source Flask/Express app) for any of: `Math.random`, `random.random`, hardcoded secrets, `SHA-256(password)`.
3. **Run ssllabs.com against any of your sites.** Read the report.
4. **Read [attack.md](attack.md).**
5. **Read [defense.md](defense.md).**

## 📚 Required reading

| Resource | Why | Time |
|---|---|---|
| [OWASP - A02:2021 Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | The framing | 15 min |
| [OWASP - Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) | Argon2id / bcrypt specifics | 20 min |
| [Cryptographic Right Answers (Latacora)](https://www.latacora.com/blog/2018/04/03/cryptographic-right-answers/) | The single best "what do I use?" reference | 30 min |
| [HSTS preload](https://hstspreload.org/) | The preload list and why you might want on it | 15 min |
| [NIST SP 800-131A - Transitions](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final) | The retired-algorithm reference | 20 min |

## 💡 What you should already know

- What a hash function is (one-way; same input → same output)
- The difference between *encryption* (reversible with key) and *hashing* (one-way)
- Symmetric (AES) vs asymmetric (RSA, EdDSA) crypto at a conceptual level
- That TLS uses asymmetric crypto for key exchange + symmetric for bulk data
