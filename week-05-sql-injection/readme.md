# Week 05: SQL Injection

## 🎯 What you'll learn

- Identify SQLi candidates in any input field by reading the response
- Exploit UNION-based, error-based, blind boolean, and time-based SQLi
- Use sqlmap effectively in a lab - and know when *not* to use it
- Bypass simple WAF and input filters
- Recognize second-order SQLi (stored payload, executed later in a different query)
- Understand why parameterized queries are the *only* real defense - and why ORMs don't always save you

By the end of this week you'll be able to:

- Take a black-box web app and find SQLi within an hour if it exists
- Read a backend stack trace and pivot it into data extraction
- Read SQL-handling code (Python, Node, Java) and predict whether it's vulnerable
- Write a CI test that proves a specific endpoint is parameterized correctly

## ⚠️ Scope reminder

**All labs run locally or on PortSwigger Academy.** Never run SQLi (especially sqlmap) against systems you don't own - it leaves database-level fingerprints and can corrupt data. See [root readme](../readme.md#️-ethics--scope).

## 🧰 Lab setup

### Lab 1: PortSwigger Academy - SQL injection labs

The Academy has [18 SQLi labs](https://portswigger.net/web-security/sql-injection). Recommended path:

1. ["SQL injection vulnerability in WHERE clause allowing retrieval of hidden data"](https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data) - gentle start
2. ["SQL injection UNION attack, retrieving data from other tables"](https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-data-from-other-tables)
3. ["Blind SQL injection with conditional responses"](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses)
4. ["Blind SQL injection with time delays and information retrieval"](https://portswigger.net/web-security/sql-injection/blind/lab-time-delays-info-retrieval)
5. ["SQL injection with filter bypass via XML encoding"](https://portswigger.net/web-security/sql-injection/lab-sql-injection-with-filter-bypass-via-xml-encoding) - bypass practice

### Lab 2: DVWA (Docker)

```bash
docker run -d -p 80:80 vulnerables/web-dvwa
```

Visit `http://localhost`. Login `admin/password`. Set DIFFICULTY to "low", then progress to "medium" and "high" - each level introduces a real-world filter you have to bypass.

### Lab 3: sqlmap (in lab only)

```bash
# Most distros have it; otherwise:
pip install sqlmap
sqlmap --version
```

We'll use it to *confirm* findings from manual exploitation - not as a primary tool. Manual first; sqlmap to verify and to enumerate at scale.

## ✅ Your job

1. **Solve "Retrieve hidden data" cold.** It takes 5 minutes once you know the pattern; if it takes you 30, that's healthy struggling.
2. **Solve the UNION attack lab.** This is the canonical "extract real data" SQLi pattern.
3. **Solve one of the blind labs** (boolean or time-based). Blind SQLi is what you'll see in real engagements.
4. **Read [attack.md](attack.md).**
5. **Read [defense.md](defense.md).**

## 📚 Required reading

| Resource | Why | Time |
|---|---|---|
| [PortSwigger - SQL injection](https://portswigger.net/web-security/sql-injection) | Best overview of all variants | 60 min |
| [OWASP - SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) | The defense reference | 30 min |
| [Bobby Tables](https://bobby-tables.com/) | Quick examples of parameterized queries in 20+ languages | 20 min |

## 💡 What you should already know

- HTTP basics ([Week 01](../week-01-http-and-burp/))
- Burp Suite (Proxy, Repeater, Intruder)
- SQL fundamentals: `SELECT`, `WHERE`, `UNION`, `ORDER BY`, basic JOINs
- The shape of a typical web-app query: `SELECT * FROM users WHERE id = ?`
- That MySQL, Postgres, SQL Server, and Oracle have different syntaxes for system functions (we'll lean on this)
