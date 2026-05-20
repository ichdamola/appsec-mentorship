# Week 03: Broken Access Control & IDOR

## 🎯 What you'll learn

The #1 vulnerability in the OWASP Top 10. Authorization checks that exist on the UI but not the backend, and how to hunt for them.

By the end of this week you'll be able to:
- Insecure Direct Object Reference (IDOR)
- Horizontal vs. vertical privilege escalation
- Forced browsing and exposed admin routes
- Allow-list vs. deny-list authorization

## ⚠️ Scope reminder

**Run all labs locally or against the platforms listed.** Don't point any of these techniques at systems you don't own. See the root [readme.md](../readme.md#️-ethics--scope).

## 🧰 Lab setup

_Pending — Docker compose for a local vulnerable app, or PortSwigger Academy lab links, will go here._

## ✅ Your job

1. **Spin up the lab.**
2. **Try to exploit it yourself first** (30+ minutes minimum — the struggle is the learning).
3. **Then open [attack.md](attack.md)** for the canonical walkthrough.
4. **Read [defense.md](defense.md)** for detection, remediation, and secure-coding patterns.

## 📚 Required reading

_Pending — curated reading list will go here._

## 💡 What you should already know

- Comfort with HTTP and Burp Suite (see [Week 01](../week-01-http-and-burp/))
- Whatever language/framework the lab uses (we keep this minimal)

---

> 🚧 **This week is scaffolded.** Full content (lab setup, attack walkthrough, defense)
> coming as the curriculum is written. See [Week 01](../week-01-http-and-burp/) for the
> format your answer file will follow.
