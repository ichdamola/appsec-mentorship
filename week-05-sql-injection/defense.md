# Week 05: Defense — Stopping SQL Injection

You've exploited SQLi nine different ways. Defending it is mostly one thing — and that one thing is non-negotiable.

---

## The single rule

> **Parameterize every query. There is no acceptable substitute.**

Every other "defense" — filtering, escaping, WAFs, ORMs — is defense in depth. The actual fix is using the database driver's parameter binding so that user input never becomes part of the query string.

## Parameterized queries — the only real fix

The database driver sends the query and the parameters separately. The parameters are *data*, not parsed as SQL.

### Python (psycopg2 / Postgres)

```python
# WRONG
query = f"SELECT * FROM users WHERE email = '{email}'"
cursor.execute(query)

# RIGHT
cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
```

The `%s` is a placeholder *for the driver*, not Python string formatting. The driver sends the query template and the parameter to Postgres separately.

### Python (sqlite3)

```python
# WRONG
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# RIGHT
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```

### Node.js (pg / Postgres)

```javascript
// WRONG
const result = await client.query(`SELECT * FROM users WHERE email = '${email}'`);

// RIGHT
const result = await client.query('SELECT * FROM users WHERE email = $1', [email]);
```

### Java (JDBC)

```java
// WRONG
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);

// RIGHT
PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
stmt.setInt(1, userId);
ResultSet rs = stmt.executeQuery();
```

### Go (database/sql)

```go
// RIGHT (no wrong version — Go's API makes parameterization the obvious path)
row := db.QueryRow("SELECT * FROM users WHERE email = $1", email)
```

The pattern is the same across every modern language: **separate the query text from the parameters at the driver boundary.**

## ORMs help — but only when used correctly

ORMs default to parameterized queries. The trap is when developers drop back to raw SQL.

### Django ORM

```python
# SAFE - the ORM parameterizes everything
User.objects.filter(email=email)
User.objects.filter(email__contains=search_term)

# DANGEROUS - .extra() lets you inject raw SQL
User.objects.extra(where=[f"email = '{email}'"])

# DANGEROUS - .raw() with f-string
User.objects.raw(f"SELECT * FROM users WHERE email = '{email}'")

# OK - .raw() with parameters
User.objects.raw("SELECT * FROM users WHERE email = %s", [email])
```

### SQLAlchemy

```python
# SAFE - text clause with bind params
session.execute(text("SELECT * FROM users WHERE email = :email"), {"email": email})

# SAFE - ORM query
session.query(User).filter(User.email == email).all()

# DANGEROUS - f-string into text
session.execute(text(f"SELECT * FROM users WHERE email = '{email}'"))
```

### Sequelize (Node.js)

```javascript
// SAFE
User.findAll({ where: { email: email } });

// SAFE - $bind
sequelize.query('SELECT * FROM users WHERE email = $email', {
  bind: { email: email }
});

// DANGEROUS - template literal
sequelize.query(`SELECT * FROM users WHERE email = '${email}'`);
```

**The pattern to grep for in any codebase:** template literals, f-strings, `+` string concatenation immediately before any `.query()`, `.execute()`, or `.raw()` call. Almost always vulnerable.

## What about identifiers (table / column names)?

Parameter placeholders only work for *values*, not table/column names. If you need a dynamic table or column:

```python
# WRONG - SQLi
cursor.execute(f"SELECT * FROM {table_name} WHERE id = %s", (user_id,))

# RIGHT - allow-list lookup
ALLOWED_TABLES = {"users", "products", "orders"}
if table_name not in ALLOWED_TABLES:
    raise ValueError("invalid table")
cursor.execute(f"SELECT * FROM {table_name} WHERE id = %s", (user_id,))
```

There's no escaping for identifiers across all DBs that's both safe and correct. Always allow-list.

For ORDER BY direction:

```python
DIRECTION_MAP = {"asc": "ASC", "desc": "DESC"}
direction = DIRECTION_MAP.get(user_input, "ASC")   # default safely
cursor.execute(f"SELECT * FROM users ORDER BY name {direction}")
```

For ORDER BY *column* — same pattern, but the allow-list is longer and you must hard-reject unknowns (silently defaulting on unknown columns confuses users and can hide bugs):

```python
ALLOWED_SORT_COLUMNS = {"name", "created_at", "email", "last_login"}
DIRECTION_MAP = {"asc": "ASC", "desc": "DESC"}

def list_users(sort_col: str, direction: str):
    if sort_col not in ALLOWED_SORT_COLUMNS:
        raise BadRequest(f"invalid sort column: {sort_col!r}")
    direction = DIRECTION_MAP.get(direction.lower(), "ASC")
    return db.execute(f"SELECT * FROM users ORDER BY {sort_col} {direction}")
```

The lesson: identifier injection has no "escape the value" shortcut. The allow-list IS the defense — and for column names specifically, fail loudly on unknown input rather than falling through to a default.

## Stored procedures — only sometimes a defense

A stored procedure is parameterized **if and only if** it doesn't dynamically construct SQL internally:

```sql
-- SAFE - bind parameters, fixed query
CREATE PROCEDURE GetUser(IN p_id INT)
BEGIN
    SELECT * FROM users WHERE id = p_id;
END;

-- VULNERABLE - dynamic SQL inside the proc
CREATE PROCEDURE GetUserByEmail(IN p_email VARCHAR(255))
BEGIN
    SET @q = CONCAT('SELECT * FROM users WHERE email = ''', p_email, '''');
    PREPARE stmt FROM @q;
    EXECUTE stmt;
END;
```

Many legacy enterprise systems are full of the second pattern. Stored procedures are not automatic protection.

## Defense in depth

Even with parameterization everywhere:

### Least-privilege database accounts

The web app's DB user should have **only** the permissions it needs:

| Permission | Default | Justification needed? |
|---|---|---|
| `SELECT` on app tables | Yes | — |
| `INSERT / UPDATE / DELETE` on app tables | Per-table | What does this app actually write? |
| `CREATE / DROP / ALTER` | **No** | Schema changes happen via migration tooling with a separate, higher-privilege account |
| `LOAD_FILE` / `INTO OUTFILE` | **No** | Removes the OAST exfiltration path |
| Access to system tables | **No** | Blocks `information_schema` enumeration |
| Access to other DBs on the same server | **No** | Blocks lateral movement |

If a SQLi *does* land, the blast radius is bounded by what this user can do.

### Database firewall / activity monitor

Enterprise tools (Imperva, IBM Guardium, open-source: `db_guard`) sit between app and DB. They alert on or block queries matching anomalous patterns:

- `UNION SELECT` from an application that has never used UNION before
- Queries against `information_schema` from app-tier connections
- High-volume row exfiltration

### WAF — useful as a fast-fail layer

A WAF with a SQLi ruleset (ModSecurity OWASP CRS rule family 942) catches the obvious payloads at the edge. **Don't rely on it as the only control.** Every WAF rule has a bypass — encode the payload, smuggle it via a header the WAF doesn't inspect, hide it in a JSON field a request body rule doesn't decode.

The WAF buys you time. It doesn't replace parameterization.

### Input validation as data-shape check (not as security)

Validating that an input *looks like* what you expected is good engineering:

```python
if not user_id.isdigit():
    raise BadRequest
```

This won't stop a determined SQLi (the attacker will use values that pass the check), but it does:

- Reject obviously malformed input early (fewer hits on backend)
- Bound the input alphabet, narrowing the attack surface
- Make injected payloads more conspicuous in logs

**Treat input validation as data hygiene, not as the SQL injection defense.**

---

## Detection — what does this look like in logs?

SQLi exploit attempts leave loud signatures in HTTP and DB logs. Build detections at both layers.

### HTTP-layer signals

Look for known SQL syntax keywords in parameter values:

```
| where uri_query matches "(?i)(union|select|insert|update|delete|drop|;|--|/\*|xp_)"
   or post_body matches "(?i)(union|select|sleep\(|benchmark\()"
| stats count by client_ip, user_id, endpoint
| where count > 5
```

False positives are real — legitimate search queries sometimes contain `SELECT`. Tune by:

- Excluding parameters that legitimately contain free-text (search boxes)
- Adding context (authenticated user? known role?)
- Pairing with status-code patterns (5xx in response = error-based probing)

### Specific high-fidelity signals

| Signal | Meaning |
|---|---|
| `information_schema` in any parameter value | Schema enumeration attempt |
| `SLEEP(`, `BENCHMARK(`, `WAITFOR DELAY` | Time-based blind SQLi probe |
| `xp_cmdshell`, `LOAD_FILE`, `INTO OUTFILE` | Post-exploit attempts |
| Very long single-parameter values (> 500 chars) | UNION enumeration or sqlmap |
| Parameter pollution (same key twice) | Often WAF bypass |
| Any inbound traffic with `--`, `/*`, `;` followed by SQL keywords | Common pattern |

### Database-layer signals

If your DB driver / proxy logs queries:

```
| where query matches "UNION.*SELECT.*FROM" or query matches "OR.*1=1"
```

The strongest signal is **queries from app-tier connections that don't match the app's known query templates**. Apps have a finite query repertoire; new templates appearing in production are either a deploy or an attack.

### Out-of-band canaries

Set up a DNS / HTTP listener (Burp Collaborator in lab, an internal Collaborator-like service in prod) and seed it as a "honey value":

```
INSERT INTO config (key, value)
VALUES ('canary_callback', 'http://canary.internal.example/$ID')
```

Any DNS or HTTP request to that hostname from your DB servers indicates an attacker has triggered an out-of-band exfiltration payload. Almost zero false positives.

---

## Remediation playbook

When SQLi is found:

| Finding | Immediate action | Longer fix |
|---|---|---|
| SQLi in one endpoint | Patch *that endpoint*; ship same-day | Audit codebase for the *pattern* (concatenation pre-execute) — every match is also vulnerable |
| SQLi via ORM `.extra()` / `.raw()` | Patch the specific use; ban with linter | Replace with parameterized equivalent or pure ORM |
| DB user has too much privilege | Restrict immediately (in a maintenance window) | Per-service DB credentials with minimal grants |
| SQLi enabled enumeration of other tables | Force credential rotation for any leaked secrets | Investigate downstream — what did they access? |

## Automated tests

```python
def test_search_does_not_concatenate_user_input(client):
    # This payload would trigger SQLi if vulnerable; safe parameterized query
    # treats it as the literal string "'; DROP TABLE products;--"
    response = client.get("/products?search=';DROP TABLE products;--")
    assert response.status_code == 200
    # ensure no products were deleted
    response2 = client.get("/products")
    assert len(response2.json()["products"]) > 0

def test_blind_sql_injection_no_time_difference(client):
    import time
    delays = []
    for payload in ["normal", "' OR SLEEP(5)--", "1 AND 1=1"]:
        start = time.perf_counter()
        client.get(f"/products?id={payload}")
        delays.append(time.perf_counter() - start)
    # No payload should cause a measurable delay
    assert max(delays) - min(delays) < 0.5
```

Wire into CI. Also: keep a corpus of historical exploit payloads (from sqlmap's tamper scripts, OWASP CRS rules, etc.) and run them against every endpoint as a CI test.

## Tools

| Tool | Role |
|---|---|
| **Burp Suite (Scanner)** | Active SQLi scanning during crawl |
| **sqlmap** | Lab-only exploitation/enumeration |
| **CodeQL** | Static analysis — finds the *patterns* (string concat before query call) |
| **Semgrep** | Lighter SAST, also catches the patterns |
| **OWASP CRS (ModSecurity)** | WAF rule pack — fast-fail layer |
| **GitLeaks / TruffleHog** | Find DB credentials accidentally committed (related but separate) |

## Common mistakes when defending

- **"We use an ORM, so we're safe."** Not if the codebase has `.raw()`, `.extra()`, or template-literal queries.
- **Escaping single quotes manually.** Misses every other context, breaks on dialect differences. Use the driver's parameter binding.
- **Trusting input validation as the SQLi defense.** Validation is engineering hygiene; parameterization is the fix.
- **Blocking specific keywords at a WAF.** Bypasses are trivial. Useful as defense in depth, not as the fix.
- **Using PreparedStatement but concatenating into the query string.** Yes, this happens — `PreparedStatement` doesn't parameterize unless you actually call `setX()` for each placeholder.

## Going further

- [OWASP — SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [PortSwigger — SQL injection](https://portswigger.net/web-security/sql-injection)
- [SQLMap documentation](https://github.com/sqlmapproject/sqlmap/wiki/Usage)
- [HackTricks — SQL injection](https://book.hacktricks.xyz/pentesting-web/sql-injection) — exhaustive technique reference, lab/CTF context only
