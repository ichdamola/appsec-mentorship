# Week 10: Attack walkthrough - Cryptographic Failures

> ⚠️ **Lab only.**

---

## Part 1: Weak password storage

### The pattern

A developer stores passwords as:

```python
hashed = hashlib.sha256(password.encode()).hexdigest()
```

Or:

```python
hashed = md5(password)
```

Both look like hashing. Both are broken - not because the hash algorithm itself is "broken" (SHA-256 is fine for general hashing), but because **password hashing has different requirements**.

### Why SHA-256 is wrong for passwords

A password hash function should be:

1. **Slow** - many milliseconds per hash, so brute force is expensive
2. **Memory-hard** - resists GPU/ASIC parallelization
3. **Salted** - same password by different users hashes differently
4. **Tunable** - can increase cost as hardware gets faster

SHA-256 is none of these. A GPU computes ~10 billion SHA-256 hashes per second. bcrypt at cost factor 12 does ~100 hashes per second.

### Crack it

Get a hash:

```bash
$ python -c "import hashlib; print(hashlib.sha256(b'password').hexdigest())"
5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
```

Crack with hashcat:

```bash
$ echo "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8" > hash.txt
$ hashcat -a 0 -m 1400 hash.txt rockyou.txt
...
5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8:password
```

For comparison - a bcrypt hash of `password` at cost 12 takes hashcat several days on the same hardware to brute-force from a list, and **effectively forever** to brute-force without a list.

The compute-time gap between SHA-256-of-password and bcrypt is the entire reason this matters.

### Salted SHA-256 - still wrong

```python
hashed = hashlib.sha256((salt + password).encode()).hexdigest()
```

The salt defeats rainbow tables (precomputed hash → password databases), but doesn't make the hash slow. A GPU still does 10 billion SHA-256 per second. Per-user brute-force is still trivial.

The salt is necessary but not sufficient. Slow is what makes the difference.

### Step 1: Identify weak password hashing in a codebase

Grep for:

- `hashlib.sha256`, `hashlib.sha1`, `hashlib.md5` near "password"
- `crypto.createHash("sha256")` near "password" (Node)
- `MessageDigest.getInstance("SHA-256")` near "password" (Java)
- Custom hash functions in auth flows

### Step 2: Identify if you can extract hashes

In a real engagement, password hashes are accessed via:

- SQLi or other RCE that yields the user table
- Application logs that accidentally include hashes
- Memory dumps
- Backup files
- The "remember me" cookie that contains hashed values

In lab: pull from the database directly.

### Step 3: Crack at scale

Hashcat modes for common hashes:

| Hash | Hashcat mode | Crack rate (single GPU) |
|---|---|---|
| MD5 | -m 0 | 50B/sec |
| SHA-1 | -m 100 | 25B/sec |
| SHA-256 | -m 1400 | 10B/sec |
| bcrypt | -m 3200 | ~50/sec |
| Argon2id | -m 27000 | ~10/sec |

The bcrypt → Argon2id row is why "use a slow KDF" is the universal advice.

## Part 2: Weak randomness

### The pattern

```python
# generating a password reset token
import random
token = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
```

`random` is the Python standard pseudorandom generator. It uses Mersenne Twister, which is **not cryptographically secure**. Given a few of its outputs, an attacker can predict the rest.

### Exploit: predict reset tokens

A specific attack pattern:

1. Attacker requests a password reset for their own account. Gets token T1.
2. Attacker requests a few more (different accounts they own, or via signup spam). Gets T2, T3, T4.
3. With those four 32-character tokens (and the algorithm), the attacker can predict T5 - the next token issued.
4. Attacker requests reset for victim's account just after. The token they predicted *is* the victim's reset token. Take over.

This is real. Tools like `randcrack` (Python) automate it for Mersenne Twister.

### Common bad-random patterns

| Language | Don't use | Use |
|---|---|---|
| Python | `random`, `random.random()`, `random.choice()` | `secrets`, `os.urandom()` |
| Node | `Math.random()` | `crypto.randomBytes()` |
| Java | `Math.random()`, `new Random()` | `SecureRandom` |
| Go | `math/rand` | `crypto/rand` |
| Ruby | `rand`, `Random.new()` | `SecureRandom` |
| Shell | `$RANDOM` | `/dev/urandom` |

The first column is fine for game dice, A/B test bucketing, simulation. **Never for tokens, IDs, passwords, keys, IVs, salts, or anything attacker-relevant.**

## Part 3: Hardcoded secrets

### The pattern

In code:

```python
SECRET_KEY = "my-super-secret-key-123"
DB_PASSWORD = "Pr0d_p4ssw0rd!"
STRIPE_API_KEY = "sk_live_EXAMPLE_KEY_REDACTED"
```

The secrets are checked into source. They live forever in Git history even if removed from the current code.

### Step 1: Find them

Tools:

- **GitLeaks:** `gitleaks detect --source=.`
- **TruffleHog:** `trufflehog filesystem .`
- **detect-secrets** (pre-commit hook)
- Grep:

```bash
grep -rE 'sk_live_|AKIA[0-9A-Z]{16}|secret.*=.*"' --include="*.py" --include="*.js"
```

### Step 2: Verify and abuse

A live API key is testable:

```bash
# Stripe key
curl -u sk_live_xxx: https://api.stripe.com/v1/customers
# returns customer list, payment methods, etc.

# AWS key
AWS_ACCESS_KEY_ID=AKIA... aws s3 ls
# enumerate accessible buckets

# GitHub token
curl -H "Authorization: token ghp_xxx" https://api.github.com/user/repos
# enumerate accessible repos
```

In a real engagement: confirm in-scope, document, do not use beyond proof. In bug bounty: report immediately and don't act on the access.

### Step 3: Check Git history

Even if the secret has been removed from current code:

```bash
git log -p --all -S "SECRET_KEY"
```

Finds every commit where that string appeared. The secret is still in history; rotate it.

### Step 4: Common leak locations beyond code

- `.env` committed
- Comments in templates (`<!-- TODO: rotate this -->`)
- Logs and error messages
- Debug pages (Django's debug-traceback page shows env vars)
- Storybook / docs sites
- Browser localStorage / sessionStorage (Burp's "Storage" inspector)
- Mobile app bundles (decompile APK, find baked-in API keys)
- S3 buckets exposed publicly

## Part 4: Timing attacks on comparison

### The pattern

```python
def verify_token(submitted, expected):
    return submitted == expected
```

Python's `==` for strings short-circuits at the first mismatch. The comparison time depends on how many leading characters match:

| `submitted` | `expected` | Time |
|---|---|---|
| `axxxxxxxxx` | `correctstr` | ~ns (first char differs) |
| `cxxxxxxxxx` | `correctstr` | ~ns + tiny (first char matches, second differs) |
| `coxxxxxxxx` | `correctstr` | ~ns + tinier |

If the attacker can make many measurements with low noise, they can derive the expected string one character at a time - a **timing attack**.

This is rarely exploitable over the internet (network jitter swamps the signal). It's much more exploitable:

- Local processes (a low-privilege process attacking a high-privilege one)
- Inside the same VM / container
- Against side channels in shared CPU caches

### Exploit (lab - local)

In Python (lab):

```python
import time

def vulnerable_compare(submitted, expected):
    return submitted == expected

expected = "very-secret-token-here"

# Time many submissions
for guess in candidates:
    start = time.perf_counter_ns()
    for _ in range(1000000):
        vulnerable_compare(guess, expected)
    end = time.perf_counter_ns()
    print(guess, end - start)
```

Across many runs, the guess with the longest matching prefix takes slightly longer. With enough samples and clean conditions, you derive the secret one character at a time.

> ⚠️ **This is a teaching demo, not a viable exploit in pure Python.** Running the loop above against `vulnerable_compare` *in CPython* usually shows no timing signal - interpreter noise (GC pauses, attribute-lookup overhead, branch prediction) swamps the per-byte short-circuit difference.
>
> The real-world primitives are in compiled code: a constant-time bug in a C extension, a CPU side-channel like RIDL/MDS, or a shared L1 cache between attacker and victim VMs. Across the network, timing attacks against `==` are rarely viable; in shared-tenant cloud environments, sometimes they are.
>
> The defense (`hmac.compare_digest`) is correct regardless of whether you can reproduce the attack - the cost of using it is zero and the bug surface it closes is non-zero.

### Defense

Use constant-time comparison:

```python
import hmac
hmac.compare_digest(submitted, expected)
```

This compares all bytes regardless of where they differ. The library is written specifically to avoid timing leaks (no short-circuit, no array indexing patterns the compiler can optimize).

Every modern crypto library has this:

- Python: `hmac.compare_digest`
- Node: `crypto.timingSafeEqual`
- Java: `MessageDigest.isEqual`
- Go: `subtle.ConstantTimeCompare`

## Part 5: Padding oracle

### The pattern (older AES-CBC apps)

CBC encryption requires padding to a block size. Decryption checks the padding; if it's invalid, the app returns an error. That error is observable. If the attacker can submit modified ciphertext and learn "valid padding" vs "invalid padding," they can decrypt arbitrary ciphertext **without the key**.

Two famous instances:

- **POODLE (2014):** SSL 3.0 padding oracle, killed SSLv3 in browsers
- **Multiple application-level instances** in app frameworks (Microsoft ASP.NET's ViewState, BREACH attacks)

### Why this still matters in 2026

Most modern code uses authenticated encryption (AES-GCM, ChaCha20-Poly1305), which doesn't have a padding-oracle equivalent. But legacy code, custom protocols, and rolled-your-own crypto sometimes still use unauthenticated CBC. When you see:

- `AES/CBC/PKCS5Padding` or `aes-256-cbc` in code
- No MAC / authentication tag in the ciphertext format
- An API that decrypts and reports "decryption failed" vs "data invalid"

…you have a padding oracle candidate. The fix is always: use AEAD (AES-GCM, ChaCha20-Poly1305) instead of unauthenticated modes.

## Part 6: TLS / certificate misconfigurations

### Common issues

| Issue | Severity |
|---|---|
| Self-signed cert in production | Critical - disables cert validation |
| TLS 1.0 / 1.1 still supported | High - multiple known weaknesses |
| Weak cipher suites (RC4, 3DES, NULL, EXPORT) | High |
| Missing HSTS header | Medium - vulnerable to SSL strip |
| Mixed content (HTTPS page loads HTTP resource) | Medium |
| Expired or near-expiry certificate | Medium - outage risk |
| Certificate validation disabled in client code | Critical - silent MITM |

The Mozilla SSL Configuration Generator gives you correct configs for nginx/Apache/HAProxy at three security levels (modern / intermediate / old).

### Step: Scan with ssllabs

```
https://www.ssllabs.com/ssltest/analyze.html?d=your-target.example
```

The report grades the configuration A-F and explains every issue. In lab, run it against any of your sites you can configure; understand what each finding means.

### Step: HSTS

`Strict-Transport-Security` header tells browsers "always use HTTPS for this hostname, even if the user types `http://`." Without it, SSL-strip MITM downgrades the user to HTTP.

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

`preload` opts you into the hard-coded list shipped with browsers. Once on, you can't easily get off - irreversible-ish commitment. But: catches first-visit (no prior HSTS header seen yet) protection.

## Common mistakes when learning

- **Treating "hashed = secure."** SHA-256 is hashing; it's still not appropriate for passwords.
- **Using `random` for tokens.** Always `secrets` / `crypto.randomBytes`.
- **Skipping the constant-time comparison.** Timing attacks are obscure but real.
- **Trusting "I removed the secret from the file."** Git history keeps it. Rotate.
- **Configuring custom crypto.** Use libraries (NaCl/libsodium, Tink) over hand-rolled.

Now read [defense.md](defense.md).
