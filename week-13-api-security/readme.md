# Week 13: API Security (REST + GraphQL)

## 🎯 What you'll learn

The bug classes that hit APIs the hardest - and that traditional web scanners often miss. APIs have no HTML to reflect XSS into; they have JSON, IDs, and verbose error messages. The OWASP API Security Top 10 is *not* a subset of the regular Top 10 - it's its own list, and the dominant bug class (BOLA) shows up almost nowhere else.

By the end of this week you'll be able to:

- Exploit **BOLA / IDOR at scale** - enumerate every record an API exposes
- Find **BOPLA (Broken Object-Property-Level Authorization)** - the field-level cousin of BOLA
- Exploit **mass assignment** via JSON body manipulation (the `is_admin: true` trick)
- Find missing rate limits and reason about their security impact
- Attack **GraphQL** specifically: introspection, depth/aliasing DoS, query batching
- Recognize the "two endpoints, one auth check" pattern that produces most API breaches

## ⚠️ Scope reminder

**Lab only.** API attacks are particularly easy to run at scale (loops over user IDs are very fast). That makes them powerful in a lab and *very illegal* against production systems you don't own. See [root readme](../readme.md#️-ethics--scope).

## 🧰 Lab setup

### Lab 1: crAPI (Completely Ridiculous API) - OWASP

The OWASP-blessed vulnerable API playground. Maps directly to the OWASP API Top 10.

```bash
mkdir crapi && cd crapi
curl -o docker-compose.yml https://raw.githubusercontent.com/OWASP/crAPI/main/deploy/docker/docker-compose.yml
docker-compose -f docker-compose.yml --compatibility up -d
```

Visit http://localhost:8888. Register two accounts (you'll need both - one "attacker," one "victim").

### Lab 2: VAmPI - Vulnerable API

```bash
docker run -d -p 5000:5000 erev0s/vampi
```

Smaller than crAPI, easier to read the source if you want to understand each bug.

### Lab 3: DVGA (Damn Vulnerable GraphQL Application)

```bash
docker run -d -p 5013:5013 -e WEB_HOST=0.0.0.0 dolevf/dvga
```

The GraphQL-specific lab. Worth doing after crAPI's REST work.

### Lab 4: PortSwigger Academy - GraphQL

[GraphQL labs](https://portswigger.net/web-security/graphql). Recommended:
- "Accessing private GraphQL posts"
- "Accidental exposure of private GraphQL fields"
- "Bypassing GraphQL brute force protections"

## ✅ Your job

1. **Register two accounts in crAPI.** Note both user IDs.
2. **Find one BOLA via Burp.** Access User A's data while authenticated as User B. The fix is "check ownership server-side" - find a place that doesn't.
3. **Exploit mass assignment.** crAPI has at least one endpoint that accepts a field it shouldn't accept from clients. Find it.
4. **Open DVGA, enable introspection if it's off, and dump the schema.**
5. **Solve "Accessing private GraphQL posts" on PortSwigger.**
6. **Read [attack.md](attack.md).** The walkthrough names the patterns you found.
7. **Read [defense.md](defense.md).** Object-level auth filters and schema-first design.

## 📚 Required reading

| Resource | Why | Time |
|---|---|---|
| [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x11-t10/) | The canonical list | 40 min |
| [PortSwigger - GraphQL API vulnerabilities](https://portswigger.net/web-security/graphql) | The best GraphQL-specific walkthrough | 30 min |
| [API Security Project - crAPI walkthrough](https://github.com/OWASP/crAPI/blob/main/docs/scenarios.md) | Each bug mapped to a scenario | 25 min |
| [Inon Shkedy - BOLA: The most impactful API vulnerability](https://inonst.medium.com/a-deep-dive-on-the-most-critical-api-vulnerability-bola-1342224ec3f2) | Why BOLA dominates | 15 min |

## 💡 What you should already know

- HTTP, JSON, REST verbs (`GET`/`POST`/`PUT`/`PATCH`/`DELETE`)
- How JWTs work (see [Week 02](../week-02-sessions-and-cookies/))
- Object-level authorization concepts from [Week 03](../week-03-broken-access-control/) - Week 13 is "Week 03 at API scale"
- Burp Intruder basics - you'll iterate over IDs and field names
