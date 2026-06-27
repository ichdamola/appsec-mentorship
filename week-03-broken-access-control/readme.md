# Week 03: Broken Access Control & IDOR

## 🎯 What you'll learn

- Find IDOR (Insecure Direct Object Reference) bugs in a real API
- Distinguish horizontal from vertical privilege escalation
- Exploit forced browsing - hidden admin URLs that aren't actually hidden
- Recognize HTTP method override tricks
- Understand why authorization must live in the backend, not the UI

By the end of this week you'll be able to:

- Walk through every authenticated request in Burp and ask "what stops me changing this ID?"
- Identify front-end-only authorization (a JS check, a hidden menu) vs. real backend checks
- Spot deny-list vs. allow-list authorization patterns
- Write a server-side authorization check that's hard to forget

## Why this week matters

**Broken Access Control is the #1 entry in the OWASP Top 10 (2021).** It's the most common, highest-impact bug class in modern web apps - partly because frameworks make it easy to add features without remembering to add the authorization check. Every endpoint is a potential IDOR.

## ⚠️ Scope reminder

**All labs run locally or against PortSwigger Academy.** Never against systems you don't own. See [root readme](../readme.md#️-ethics--scope).

## 🧰 Lab setup

### Lab 1: PortSwigger Academy - access control labs

The Academy has [13 access control labs](https://portswigger.net/web-security/access-control). Recommended starters:

- ["Unprotected admin functionality"](https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality)
- ["User ID controlled by request parameter"](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter)
- ["Insecure direct object references"](https://portswigger.net/web-security/access-control/lab-insecure-direct-object-references)
- ["URL-based access control can be circumvented"](https://portswigger.net/web-security/access-control/lab-url-based-access-control-can-be-circumvented)

### Lab 2: DVWA (Docker)

```bash
docker run -d -p 80:80 vulnerables/web-dvwa
```

Visit `http://localhost`, login `admin/password`, set DIFFICULTY to "low" to start.

## ✅ Your job

1. **Pick the PortSwigger "User ID controlled by request parameter" lab.** Don't read solutions; try it cold.
2. **Then do the "Unprotected admin functionality" lab.** Notice how trivial it is.
3. **Open [attack.md](attack.md).**
4. **Read [defense.md](defense.md).**

While doing the labs, every time you observe an ID in a URL or request body, **stop and ask the same three questions**:

1. What happens if I change it to someone else's ID?
2. What happens if I change it to a deleted / nonexistent ID?
3. What happens if I change it to a *different type* of ID (e.g., admin user ID)?

## 📚 Required reading

| Resource | Why | Time |
|---|---|---|
| [PortSwigger - Access control vulnerabilities](https://portswigger.net/web-security/access-control) | Best overview + lab links | 45 min |
| [OWASP - Top 10 A01:2021 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) | The framing | 15 min |
| [HackerOne - Top 10 access control reports](https://hackerone.com/hacktivity?querystring=idor) | Real-world disclosures | 30 min |

## 💡 What you should already know

- HTTP methods (GET, POST, PUT, DELETE, PATCH) and what each typically means
- Sessions and authentication ([Week 02](../week-02-sessions-and-cookies/))
- The difference between *authentication* (who are you?) and *authorization* (what can you do?)
