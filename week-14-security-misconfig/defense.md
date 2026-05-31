# Week 14: Defense — Security Misconfiguration & Vulnerable Components

You exploited default-creds, debug pages, Log4Shell, and a handful of file-disclosure misconfigs in [attack.md](attack.md). The defenses here are unusually operational rather than code-level — and that's the point. **This class lives in build pipelines, deploy configs, and patching cadence, not in the application source.**

---

## The single rule

> **Treat your dependency graph and your deploy config as code. Version them. Review them. Test them.**

If your `Dockerfile` pins `FROM ubuntu:20.04` and never gets rebuilt, you ship 2020-era CVEs forever. If `production.yml` lives only on a single VM, no one notices when DEBUG=True ends up there. Every config and every dependency needs the same review, lint, and CI treatment you give application code.

## Defense 1: Sane defaults — pick "secure" over "convenient"

### Frameworks

```python
# Django settings.py — production
DEBUG = False
ALLOWED_HOSTS = ["example.com"]      # NOT "*"
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
```

```yaml
# Spring Boot — application-prod.yml
management:
  endpoints:
    web:
      exposure:
        include: health, info      # NEVER *, env, heapdump
  endpoint:
    env:
      enabled: false
    heapdump:
      enabled: false
spring:
  jpa:
    show-sql: false
server:
  error:
    include-stacktrace: never
    include-message: never
```

```javascript
// Express — production
app.use(helmet());            // sets a dozen security headers in one line
app.use(helmet.contentSecurityPolicy({...}));
app.disable('x-powered-by');  // don't tell attackers "Express"
```

These should not be left as defaults *to remember to change*. They should be the default values in your generated project template / cookiecutter / scaffold.

### Containers

```dockerfile
FROM ubuntu:22.04   # NOT :latest — pin
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip && \
    rm -rf /var/lib/apt/lists/*

# DON'T run as root
RUN useradd -m -u 10001 app
USER app

# DON'T bake secrets — pass at runtime
# ENV DATABASE_PASSWORD=...   <-- never

# Drop capabilities
# (in compose:) cap_drop: [ALL]
# (in k8s:) securityContext: { capabilities: { drop: [ALL] } }
```

### Cloud

- S3 — enable Block Public Access at the account level. Specific publicness is opt-in per bucket.
- IAM roles — least privilege per service; no `*:*` or `Resource: *` unless audited.
- Default VPC — disable public IPs for new instances by default.
- KMS — encrypt-at-rest by default for new volumes/buckets.

## Defense 2: Patch process

### Automated update PRs

| Ecosystem | Tool |
|---|---|
| Multi-language, GitHub-native | Dependabot |
| Multi-language, configurable | Renovate |
| Python | pip-tools + pip-audit |
| Node | npm-audit / pnpm audit + Renovate |
| Java | OWASP Dependency-Check + Renovate |
| Ruby | bundler-audit |
| Go | govulncheck |
| Containers | Watchtower (auto pull) + image scan |

Configure these to open PRs *automatically*. The PR queue is your patching backlog. Treat unmerged dependency PRs as security debt.

Critical: have your CI run the test suite on Dependabot PRs. Without that, "this PR opened" → no signal on whether the upgrade is safe → ignored.

### Patching SLAs

A reasonable framework:

| Severity | SLA |
|---|---|
| Critical, exploited in the wild | <24 hours to patched build, <72 hours to full rollout |
| Critical, no known exploit | 7 days |
| High | 30 days |
| Medium | 90 days |
| Low | Next maintenance cycle |

The 24-hour target requires that you've practiced the deploy path on a Tuesday afternoon — not just in theory.

## Defense 3: SBOM + SCA in CI

```yaml
# .github/workflows/security.yml — example
name: Security scan
on: [push, pull_request]
jobs:
  trivy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build
        run: docker build -t app:${{ github.sha }} .
      - name: Trivy filesystem
        uses: aquasecurity/trivy-action@0.24.0   # pin — same lesson as ":latest" above
        with:
          scan-type: image
          image-ref: app:${{ github.sha }}
          severity: HIGH,CRITICAL
          exit-code: 1     # FAIL the build
      - name: Generate SBOM
        run: syft app:${{ github.sha }} -o cyclonedx-json > sbom.json
      - uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: sbom.json
```

The shift here: vulnerable-version detection moves from "annual pen test" → "on every commit." When the next critical CVE drops in a popular library, you find out in minutes via the existing pipeline.

## Defense 4: Hardening baselines (CIS / DISA STIG)

For every platform you run (Linux distros, Kubernetes, Docker, RDS, Nginx, Apache, IIS, Postgres, Mongo) there's a CIS Benchmark — a checklist of configuration items with severity. Mostly: disable defaults, restrict permissions, enable auditing.

You don't read these top-to-bottom; you run them as a tool:

```bash
# CIS-style auditing tool
docker run --rm --net host --pid host --userns host --cap-add audit_control \
  -v /etc:/etc:ro -v /var/lib:/var/lib:ro \
  aquasec/kube-bench:latest run --targets node
```

Kube-bench, lynis, scout-suite (cloud), prowler (AWS), and dozens of others map directly to CIS items.

Integrate into CI so a hardening regression fails the build.

## Defense 5: Secrets never in code

Already covered in [Week 10 defense.md](../week-10-crypto-failures/defense.md). Recap in the context of misconfig:

- Secrets in env vars (not source) — fine if env is provisioned by IaC + secret manager.
- Secrets in a secret manager (Vault, AWS SM, GCP Secret Manager) — better, auditable.
- Secrets in the Spring Boot Actuator `env` endpoint — disaster.
- Secrets in heap dumps — disaster.
- Secrets in error pages — disaster.

The deploy config matters more than the storage:

```yaml
# bad
env:
  DATABASE_PASSWORD: my-prod-password    # in plain k8s manifest in git

# good
env:
  DATABASE_PASSWORD:
    valueFrom:
      secretKeyRef:
        name: db-creds
        key: password
```

## Defense 6: Honest "production" checklist before deploy

Stop deploys that fail any of:

- [ ] `DEBUG = False` / `ENV=production`
- [ ] No default credentials in any seed migration
- [ ] No `*` in `ALLOWED_HOSTS` / `CORS` / IAM resource
- [ ] HTTPS-only with HSTS header on all responses
- [ ] Logging configured but never logging passwords/tokens/CC
- [ ] `/.git/`, `/.env`, `/backup/` not served by webserver
- [ ] Latest critical-severity CVE scan = 0 findings (or documented exception with mitigations)
- [ ] No `latest` tags in production manifests
- [ ] Pre-commit hook for secret detection enabled

Some teams literally have this in a `deploy-checklist.md` and require sign-off. More mature teams encode it as automated checks that block the deploy pipeline.

## Detection

### Signal 1: 5xx + stack trace patterns

```
| where status >= 500 and response_body matches "Traceback\|Exception\|at .+\(.+:\d+\)"
| stats count by endpoint, 5min
```

Stack traces in responses should be zero in production. Any nonzero rate is an alert.

### Signal 2: Verbose error endpoint hits

```
| where path matches "^/(actuator|admin|debug|phpinfo|env|\.git|\.env|backup)"
| stats count by client_ip, 1h
```

These are paths attackers always check. A spike means scanning.

### Signal 3: Default credential attempts in auth logs

```
| where username in ("admin","root","tomcat","grafana") and auth_result = "success"
| stats values(client_ip), values(user_agent)
```

A successful login as "admin" from an unfamiliar IP, especially during scan times.

### Signal 4: JNDI-pattern strings in logs

```
| where request_body matches "\$\{(jndi|sys|env|lower|upper):"
   or any_header_value matches "\$\{(jndi|sys|env|lower|upper):"
| stats count by client_ip, 1min
```

Log4Shell + variants. Vanishingly rare in legitimate traffic.

### Signal 5: New process spawned by web server

```
| where parent_process in ("java","python","node","nginx","apache2")
   and child_process in ("sh","bash","curl","wget","nc","ncat","python","perl")
```

A web process forking a shell is almost always an RCE chain (Log4Shell, command injection, deserialization).

### Signal 6: Outdated component fleet drift

A regular sweep:

```bash
# In each service repo:
trivy fs --severity HIGH,CRITICAL --format json --output report.json .
```

Aggregate report.json across repos into a dashboard. Watch components that are vulnerable >7 days.

## Remediation playbook

| Finding | Immediate | Longer fix |
|---|---|---|
| Default credential found on prod service | Rotate immediately; review recent access logs | Provisioning script never sets default password; auto-fail on default-cred CIS check |
| Debug enabled in production | Disable; redeploy | CI check that compiles config and fails if `DEBUG=True` / `actuator: *` |
| `/.git/` exposed via webserver | nginx/Apache rule to deny `/.git/*`; redeploy | Reverse-proxy default-deny; explicit allow for public paths |
| Critical CVE in production component | Hotfix patch; SLA-driven rollout | Auto-PRs via Dependabot/Renovate; track time-to-patch |
| Hardcoded secret in container env | Rotate; replace with secret-manager ref | Pre-commit secret detection; scan history for residual |
| Anonymous-readable S3 bucket | Set bucket policy to private; remove file index from search engines if indexed | Account-wide Block Public Access; quarterly bucket audit |
| Heap dump endpoint exposed (Spring Boot Actuator) | Disable endpoint or IP-restrict; rotate any secrets in current heap | Default-deny actuator endpoints |

## Automated tests

```python
def test_no_debug_pages_in_production_settings():
    from myapp import settings_prod
    assert settings_prod.DEBUG is False
    assert "*" not in settings_prod.ALLOWED_HOSTS

def test_no_default_credentials_in_seed_data():
    import json
    seed = json.load(open("fixtures/initial_data.json"))
    for user in seed.get("users", []):
        assert user["password"] != "admin"
        assert user["password"] != "password"

def test_dotgit_not_served():
    # Run against a deployed staging environment
    response = requests.get("https://staging.example.com/.git/config")
    assert response.status_code == 404

def test_actuator_env_disabled():
    response = requests.get("https://prod.example.com/actuator/env")
    assert response.status_code in (404, 403)

def test_no_known_critical_cves():
    # Integration with Trivy / Grype results
    import json
    findings = json.load(open("trivy-report.json"))["Results"]
    critical = [v for r in findings for v in r.get("Vulnerabilities", [])
                if v["Severity"] == "CRITICAL"]
    assert not critical, f"Critical CVEs found: {[v['VulnerabilityID'] for v in critical]}"
```

## Tools

| Tool | Role |
|---|---|
| **Trivy / Grype** | Container + filesystem CVE scanning |
| **Syft** | SBOM generation |
| **Dependabot / Renovate** | Auto-PRs for dep updates |
| **Snyk / Mend / Black Duck** | Enterprise SCA, license + CVE |
| **kube-bench / lynis / cis-cat** | CIS hardening audits |
| **Prowler / Scout Suite / ScubaGoggles** | Cloud (AWS/Azure/GCP/M365) config audit |
| **TruffleHog / GitLeaks / detect-secrets** | Secret leaks in history |
| **OWASP ZAP** | Catches forgotten endpoints in DAST scans |
| **Nuclei** | Templated checks for known misconfig patterns (debug pages, default creds, etc.) |
| **httpx + nuclei** | Bulk asset scanning for managed-fleet misconfig |

## Common mistakes when defending

- **"We patched Log4j in November 2021."** Cool. What about everything since? Patching is continuous.
- **Trusting "we use a managed service."** Managed services patch the runtime; you still configure access. Default IAM is often permissive.
- **Treating Dependabot PRs as noise.** They're your patch queue.
- **Believing "internal-only" is a security boundary.** Misconfig + internal lateral movement is how breaches deepen.
- **Skipping the rebuild step.** Patching the source dep doesn't help until the container is rebuilt and rolled out.
- **No exception process.** Sometimes a CVE genuinely doesn't apply or can't be patched. Document the exception; revisit on a calendar; don't suppress the finding forever.

## Going further

- [OWASP — Security Misconfiguration (A05:2021)](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- [OWASP — Vulnerable and Outdated Components (A06:2021)](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)
- [CIS Benchmarks index](https://www.cisecurity.org/cis-benchmarks/)
- [Aqua Trivy docs](https://aquasecurity.github.io/trivy/)
- [Renovate config reference](https://docs.renovatebot.com/configuration-options/)
- [Spring Boot — Actuator security](https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html#actuator.endpoints.security)
- [Django — Deployment checklist](https://docs.djangoproject.com/en/stable/howto/deployment/checklist/)
- [LunaSec — Log4Shell technical writeup](https://www.lunasec.io/docs/blog/log4j-zero-day/)
- [LiveOverflow — Log4Shell walkthrough video](https://www.youtube.com/watch?v=7qoPDq41xhQ)
