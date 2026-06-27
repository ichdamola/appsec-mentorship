# Week 08: Server-Side Request Forgery (SSRF)

## 🎯 What you'll learn

- Find SSRF in any feature that fetches a URL from user input
- Pivot SSRF into cloud metadata access (AWS IMDSv1, GCP metadata) - the catastrophic case
- Bypass naive URL filters (decimal/octal IPs, IPv6, redirects, DNS rebinding)
- Detect blind SSRF using Burp Collaborator / OAST
- Design a defense that survives the bypass arms race

By the end of this week you'll be able to:

- Identify every "fetches a URL" feature in an app (avatar import, webhooks, link previews, PDF generators)
- Walk SSRF to internal service access in a lab cloud environment
- Read URL-parsing code and predict which bypasses defeat it
- Write a URL validator that actually works

## Why this matters

SSRF is consistently in the OWASP Top 10 (currently A10) because it's the easiest pivot from "I have a foothold" to "I'm inside your network." The 2019 Capital One breach (100M+ records) was SSRF → cloud metadata → S3.

## ⚠️ Scope reminder

**Lab only.** SSRF probes against real systems often hit internal infrastructure that crosses authorization boundaries. See [root readme](../readme.md#️-ethics--scope).

## 🧰 Lab setup

### Lab 1: PortSwigger Academy - SSRF labs

[7 SSRF labs](https://portswigger.net/web-security/ssrf). Recommended:

1. ["Basic SSRF against the local server"](https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-localhost)
2. ["Basic SSRF against another back-end system"](https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-backend-system)
3. ["SSRF with blacklist-based input filter"](https://portswigger.net/web-security/ssrf/lab-ssrf-with-blacklist-filter)
4. ["SSRF with filter bypass via open redirection vulnerability"](https://portswigger.net/web-security/ssrf/lab-ssrf-filter-bypass-via-open-redirection)
5. ["Blind SSRF with out-of-band detection"](https://portswigger.net/web-security/ssrf/blind/lab-out-of-band-detection)

### Lab 2: Local lab (optional Docker)

A vulnerable Flask app with a "fetch URL" feature plus a fake metadata endpoint on localhost. Many CTF challenge frameworks ship one; in lab, you can stand up:

```bash
# Fake AWS metadata service on localhost (for safe lab work)
docker run -d -p 169.254.169.254:80:80 --name fake-metadata \
  --add-host metadata-fake:169.254.169.254 \
  ... lab image ...
```

(In real cloud environments, the metadata service is at `169.254.169.254`. **Never probe this address against production AWS - that's testing internal infrastructure.**)

## ✅ Your job

1. **Solve "Basic SSRF against the local server" cold.** The point is to feel the moment when the server makes a request *for you* to a place you can't reach directly.
2. **Solve the blacklist-bypass lab.** This teaches the bypass family.
3. **Solve the blind SSRF lab.** Burp Collaborator is the key here.
4. **Read [attack.md](attack.md).**
5. **Read [defense.md](defense.md).**

## 📚 Required reading

| Resource | Why | Time |
|---|---|---|
| [PortSwigger - SSRF](https://portswigger.net/web-security/ssrf) | Best overview | 45 min |
| [Capital One breach post-mortem](https://krebsonsecurity.com/2019/08/capital-one-data-theft-impacts-106m-people/) | Real-world SSRF → metadata → S3 chain | 20 min |
| [OWASP - SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) | Defense reference | 20 min |
| [AWS - Instance Metadata Service v2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html) | Why IMDSv2 fixes most SSRF-to-metadata attacks | 15 min |

## 💡 What you should already know

- DNS basics (A, AAAA, CNAME) and the IP→hostname relationship
- IP address representations (192.168.1.1, IPv6, decimal `3232235777`, octal)
- RFC1918 private address ranges
- That `169.254.169.254` is the cloud metadata IP across AWS/GCP/Azure
- HTTP redirects and how clients follow them
