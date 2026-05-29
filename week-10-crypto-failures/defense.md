# Week 10: Defense — Cryptographic Failures

You've seen the failure modes in [attack.md](attack.md). The good news: each defense is well-known, well-supported by libraries, and free.

---

## The single rule

> **Don't design your own crypto. Use the libraries' high-level APIs. Pick one library and trust it.**

The bugs in OWASP A02 almost never come from broken primitives. They come from someone reaching past the safe defaults and reinventing something.

## Password storage

### Use argon2id (preferred) or bcrypt

```python
from argon2 import PasswordHasher

ph = PasswordHasher()

# At signup / password change
hashed = ph.hash(password)

# At login
try:
    ph.verify(stored_hash, submitted_password)
    # OK
except VerifyMismatchError:
    # wrong password
```

Defaults (memory cost ~64 MB, time cost ~3 iterations, parallelism 4) are the OWASP recommendation. Library handles salt generation and embedding.

If you can't use argon2id (older runtime, regulatory constraint), bcrypt is the second-best:

```python
import bcrypt

# At signup
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))

# At login
if bcrypt.checkpw(submitted.encode(), stored_hash):
    ...
```

**Never use:** plain SHA-256/SHA-1/MD5, your own salt scheme, "encryption" of passwords (passwords should be hashed, never encrypted — encryption is reversible).

### Periodic upgrade

If you have an old codebase using bcrypt cost-10 and want to move to argon2id, do it at next login:

```python
def login(username, submitted_password):
    user = get_user(username)
    if not verify(user.stored_hash, submitted_password):
        raise BadCredentials

    # Successful login — opportunistically rehash with newer algorithm
    if needs_rehash(user.stored_hash):
        user.stored_hash = ph.hash(submitted_password)
        user.save()

    return user
```

Within a few months, most active users are on the new hash. The straggler accounts that never log in stay on the old hash — which is fine because they're not active attack targets.

## Randomness

### Use a CSPRNG, always

| Use | Don't use |
|---|---|
| `secrets.token_urlsafe(32)` (Python) | `random.choices(...)` |
| `crypto.randomBytes(32)` (Node) | `Math.random()` |
| `SecureRandom().nextBytes(...)` (Java) | `Math.random()` / `new Random()` |
| `crypto/rand` (Go) | `math/rand` |
| `SecureRandom.hex(32)` (Ruby) | `rand` |

If you can't tell whether the source is cryptographic, **assume it isn't.** The exception is when the language docs explicitly say "this is a CSPRNG" — `Python.secrets`, `Node.crypto`, `Java.SecureRandom`, etc.

### Token entropy

| Purpose | Bytes | Hex chars | URL-safe chars |
|---|---|---|---|
| Session ID | 16-32 | 32-64 | 22-43 |
| Reset token | 32 | 64 | 43 |
| API key | 32 | 64 | 43 |
| Long-term identifier | 16 (UUID) | 32 | 22 |

32 bytes (256 bits) is the modern default for everything. It's cheap; randomness has no per-byte cost relative to anything else.

## Constant-time comparison

For any secret comparison (tokens, HMACs, password verification *after* hashing) use the constant-time helper:

```python
import hmac

hmac.compare_digest(submitted_token, expected_token)
```

The library's purpose-built for this: no short-circuit, no length-dependent path, no JIT escape hatch.

In templates or string-building code, the comparison happens *after* the secret has been compared by a library — don't roll your own.

## Secret management

### Never hardcode secrets

Patterns to use:

1. **Environment variables** for development and small deployments
2. **Cloud secret managers** (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault) for production
3. **HashiCorp Vault** for self-hosted, multi-cloud, or rotated secrets

The minimum bar:

- No secret in source control
- No secret in build artifacts (Docker images, frontend bundles)
- No secret in logs (mask in logging middleware)
- Rotation has a process — manual is OK; automated is better

### Pre-commit secrets scanning

Wire **detect-secrets** or **GitLeaks** into pre-commit hooks:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.5.0
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']
```

Catches the bug before it's pushed. CI scans as a secondary catch.

### When a secret leaks — rotation playbook

1. **Confirm.** Is it actually live?
2. **Revoke.** Don't wait to "investigate first" — the secret is in attacker hands.
3. **Rotate.** Generate the new one; deploy.
4. **Audit access.** What did the attacker do with the old one?
5. **Backstop.** Was this avoidable with secrets scanning? Add the hook.

For high-impact secrets (signing keys, prod database creds), have the rotation procedure written down ahead of time.

## TLS configuration

### Use Mozilla's SSL Configuration Generator

https://ssl-config.mozilla.org/ — gives nginx, Apache, HAProxy, AWS ALB configurations for three profiles:

| Profile | Use for |
|---|---|
| **Modern** | New deployments; only modern clients |
| **Intermediate** | Most production sites; broad client support |
| **Old** | Legacy compatibility (Windows XP IE6 era; almost never needed in 2026) |

In 2026, "Intermediate" is the default. "Modern" is fine for sites that don't need to support old browsers.

### HSTS

Add the header on every HTTPS response from your app:

```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```

After running with this for a few months, submit to the [HSTS preload list](https://hstspreload.org/) for first-connection protection.

Be careful about `includeSubDomains` — every subdomain must support HTTPS. If you have `http://internal.example`, this header breaks it.

### Certificate management

Use **Let's Encrypt** + an ACME client (cert-manager in Kubernetes, certbot on VMs) for automated renewal. Manual cert rotation causes more outages than any other class.

For high-assurance contexts (banks, government), use an organization-managed CA with regular rotation.

## Encryption

### When you encrypt, use AEAD

For symmetric encryption:

- **AES-GCM** (with a randomly-generated 96-bit nonce per message)
- **ChaCha20-Poly1305** (especially when CPU has no AES hardware)

Both are AEAD — Authenticated Encryption with Associated Data. The output is ciphertext *plus a MAC*. Tampering is detected. No padding oracle is possible.

```python
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import os

key = ChaCha20Poly1305.generate_key()  # 256 bits
nonce = os.urandom(12)
cipher = ChaCha20Poly1305(key)
ciphertext = cipher.encrypt(nonce, plaintext, associated_data=None)

# To decrypt
plaintext = cipher.decrypt(nonce, ciphertext, associated_data=None)
# Raises if MAC fails
```

**Never use** AES-ECB, AES-CBC alone, RC4, DES, 3DES, MD5, SHA-1 for new code.

### Key management

For high-assurance applications:

- **Use a KMS** (AWS KMS, GCP KMS, Azure Key Vault) — your code never sees the raw key
- **Envelope encryption** — KMS encrypts a per-record DEK; you store the encrypted DEK with the data
- **Rotate keys regularly** — yearly minimum

For everything else, derive keys from a master secret via HKDF, store the master secret in your secret manager.

## Use vetted libraries

### Recommended

| Language | Library |
|---|---|
| Cross-language high-level API | **libsodium** / NaCl |
| Cross-language modern API | **Tink** (Google) |
| Python | `cryptography`, `pynacl` |
| Node | built-in `crypto`, `tweetnacl` |
| Java | Tink, Bouncy Castle |
| Go | `crypto/...` (standard library), `golang.org/x/crypto/nacl/...` |
| Ruby | `RbNaCl` |

### Avoid

- Custom JCE providers (Java)
- "Roll your own AES" code
- Crypto code from Stack Overflow not vetted by the project
- Any library where the docs say "do not use in production"

## Defense in depth

Even with all of the above correct:

| Layer | What it catches |
|---|---|
| Argon2id password hashing | Cracking from a database leak |
| Salt + per-user randomization | Rainbow tables |
| CSPRNG for tokens | Token prediction |
| Constant-time comparison | Timing-side-channel leaks |
| Secret manager + scanning | Hardcoded secrets |
| HSTS | SSL strip MITM |
| AEAD encryption | Padding oracles, tampering |
| Periodic rehash on login | Catches old-algorithm accounts |
| HIBP password check at signup | Blocks known-breached credentials |

---

## Detection

### Signal 1: Password verification time anomalies

Brute-forcing bcrypt is slow. If you suddenly see thousands of password-verification calls per minute:

```
| where event = "password_verify"
| stats count by client_ip, source
| where count > 100
```

This is rate-limit territory; pair with Week 04 detection.

### Signal 2: Failed decryptions

For app-level encrypted data: a spike in decryption failures = either a bug or someone probing for a padding oracle / tampering:

```
| where event = "decrypt_failed"
| stats count by client_ip
| where count > 10
```

### Signal 3: TLS handshake failures from internal services

If an internal service can't reach the cert authority or has clock skew, TLS handshakes fail. Indicates a cert expiry incident — page before users notice.

### Signal 4: Secrets in logs

A logger that captures full request bodies in error paths sometimes captures API keys, tokens, passwords. Periodic scans of log indices for secret-shaped strings find the bug:

```bash
# search for patterns in last day of logs
grep -E 'sk_(live|test)_[A-Za-z0-9]{24}|AKIA[0-9A-Z]{16}' /var/log/app/*.log
```

Real production systems leak via this pattern more often than any other.

---

## Remediation playbook

| Finding | Immediate action | Longer fix |
|---|---|---|
| Passwords in SHA-256 | Add new column for bcrypt/argon2id; rehash at next login | Drop old column once all active users migrated |
| `Math.random()` for tokens | Replace immediately; deploy | Lint rule banning the pattern |
| Hardcoded secret in code | Revoke + rotate + remove + add scanner | Pre-commit hook for secrets |
| `==` comparing tokens | Switch to constant-time helper | Lint rule for `== token` patterns |
| TLS 1.0 / 1.1 enabled | Disable; expect a tail of old-client failures | Modern profile config |
| No HSTS | Add header at 30-day max-age first; increase over time | Eventually preload |

## Automated tests

```python
def test_password_hash_uses_slow_kdf(client):
    response = client.post("/signup", json={"email": "a@b.com", "password": "test123"})
    user = User.objects.get(email="a@b.com")
    # bcrypt hashes start with $2 or $2a/b/y
    # argon2id hashes start with $argon2id$
    assert user.password.startswith(("$2", "$argon2id$"))

def test_tokens_use_csprng(client):
    # Issue many tokens; check entropy is consistent with crypto-random
    import statistics
    response = client.post("/api/keys")
    tokens = [response.json()["token"] for _ in range(100)]
    # Shannon entropy across the token chars
    # Real test: import statistics + count char distribution
    # Simplified: any two tokens are guaranteed different
    assert len(set(tokens)) == len(tokens)

def test_constant_time_token_compare(client, alice_id):
    # Replay attack with corrupted token; should respond same as wrong-format
    response_wrong = client.get(f"/api/users/{alice_id}",
                                headers={"X-API-Key": "wrong"})
    response_almost = client.get(f"/api/users/{alice_id}",
                                 headers={"X-API-Key": "almost_right_..."})
    # Time difference must be negligible
    # (a real timing test runs many samples; this is a basic shape test)

def test_hsts_present(client):
    response = client.get("/")
    hsts = response.headers.get("Strict-Transport-Security")
    assert hsts is not None
    assert "max-age" in hsts.lower()
```

## Tools

| Tool | Role |
|---|---|
| **hashcat / John the Ripper** | Password cracking (lab) |
| **HIBP API / Pwned Passwords k-anonymity API** | Check passwords against breach corpus at signup |
| **ssllabs.com** | TLS configuration scanning |
| **testssl.sh** | Local equivalent of ssllabs |
| **GitLeaks / TruffleHog** | Secrets in source / git history |
| **detect-secrets** | Pre-commit hook |
| **Trivy / Snyk / Dependabot** | Dependencies with crypto-related CVEs |
| **Semgrep** | Static rules for `Math.random()`, `hashlib.sha256` near `password`, `==` near `token` |

## Common mistakes when defending

- **Treating SHA-256 as a password hash.** It's not.
- **Adding pepper without slow KDF.** Pepper helps, but the slowness is what stops cracking.
- **Custom AEAD constructions.** Use library-provided AEAD.
- **Keeping TLS 1.0/1.1 "just in case."** Real cost of removal is zero; risk of keeping is non-zero.
- **Rotating passwords periodically.** NIST 800-63B says don't (unless suspected compromise). The user friction creates worse passwords.
- **Storing encryption keys next to encrypted data.** Same blob with the key inside it: that's not encryption, that's encoding.

## Going further

- [Latacora — Cryptographic Right Answers](https://www.latacora.com/blog/2018/04/03/cryptographic-right-answers/)
- [OWASP — Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [OWASP — Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- [Cryptopals Challenges](https://cryptopals.com/) — practice cryptanalysis hands-on (educational only)
- [NIST SP 800-131A](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final) — retired-algorithm reference
