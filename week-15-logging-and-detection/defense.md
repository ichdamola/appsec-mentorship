# Week 15: Defense — Logging, Monitoring, and Detection

In [attack.md](attack.md) you saw how attackers exploit log gaps. This week's defense is a *system*, not a code patch — structured logging, the right detection rules, and a sustainable alerting practice.

---

## The single rule

> **Treat your detection pipeline (logs → SIEM → rule → alert → response) as a product. It has SLAs, owners, and tests, or it doesn't work.**

A logging library, a SIEM license, and a "we have alerts" page are necessary but absolutely not sufficient. Detection is operational practice.

## Defense 1: Structured logging everywhere

### Why structured

Free-text logs (`"User abc logged in"`) require regex extraction at query time. They break when the format changes. They make schema-evolution painful. Structured logs (`{event: "login.success", user: "abc"}`) are queryable directly.

### What to emit

```python
# structlog with stdlib processors
import structlog

log = structlog.get_logger()

# Login attempt
log.info("auth.login.attempt",
    user_id=user.id,
    username=username,
    client_ip=request.remote_addr,
    user_agent=request.user_agent,
    request_id=request_id)

# Successful auth
log.info("auth.login.success",
    user_id=user.id,
    session_id=session.id,
    mfa_used=mfa_was_used,
    request_id=request_id)

# Failed auth
log.warning("auth.login.failure",
    username=username,
    reason="wrong_password",   # or "no_such_user" or "account_locked"
    client_ip=request.remote_addr,
    request_id=request_id)

# Authorization deny
log.warning("authz.deny",
    user_id=request.user.id,
    target_resource_type="order",
    target_resource_id=order_id,
    target_owner_id=order.user_id,    # tells you the cross-tenant attempt
    endpoint=request.endpoint,
    request_id=request_id)
```

Key conventions:

- **Event names are dotted, namespaced, low-cardinality.** `auth.login.success` not `"Login succeeded for user xyz"`.
- **One event = one log line.** Don't split state across multiple lines.
- **Always include a request_id** that ties the line to the HTTP request.
- **Always include client_ip and user_id** when available.
- **No raw PII or secrets** in any field.

### What NOT to log

| Never log | Why |
|---|---|
| Plaintext password (even on failure) | Logs leak; users reuse passwords |
| Full session token / JWT | Anyone with log access becomes the user |
| Full credit card number | PCI scope; logs become regulated systems |
| Full SSN, government IDs | Personal-data scope |
| API keys (yours or partners') | Use a token reference, not the token |
| Request bodies of payment / health endpoints | PII/PHI in logs is logs-as-database |
| Full email addresses in low-signal events | Privacy; truncate for non-essential records |

Tokenize:

```python
# instead of logging the password (don't)
log.warning("auth.login.failure", username=username)

# instead of logging the JWT
log.info("session.start", session_id=session.id)  # opaque ID, not the JWT itself

# instead of logging the full key
log.info("api.request", key_prefix=api_key[:8] + "...")
```

## Defense 2: Centralize and ship off-host immediately

Local logs:
- Are mutable (an attacker who reaches the host wipes them)
- Are limited by disk
- Are not searchable

Ship them to a remote system (your SIEM, an S3 bucket with immutability, a managed logging service) immediately. Filebeat / Fluent Bit / Vector are common shippers. Modern hosted Splunk, Datadog Logs, Sumo Logic, Elasticsearch, ClickHouse all support direct ingestion APIs.

**Immutability matters.** Use S3 Object Lock, or a write-only role to a tenancy the application can't read or delete. The forensic value of logs is precisely that they can't be edited after the fact.

## Defense 3: Detection rules — the consolidated library

Here is the canonical first-pass library for the bug classes in weeks 1-14. Each rule names: signal, query (Sigma-ish pseudocode), expected false-positive rate, severity.

> **Format note.** Most rules below use Sigma-ish pseudocode for readability — they describe the *logic*, not a copy-paste-into-Splunk SPL or production Sigma YAML. Field names, escape rules, and operators differ between SIEMs; treat these as the source for porting, not the artifact itself. One real Sigma YAML appears further down (the JNDI rule) so you have a concrete example of the actual on-disk format.

### Reflected/Stored XSS attempts (Weeks 01, 06)

```
title: Possible XSS payload in request
detection:
  condition: any_param_value matches "(?i)(<script|onerror=|onload=|javascript:|onmouseover=)"
fp_rate: low (some legit fields can contain `<script` — code-sharing apps especially)
severity: medium
```

### SQL injection attempts (Week 05)

```
title: SQL injection payloads in request
detection:
  condition: any_param_value matches "(?i)(union\\s+select|sleep\\(|benchmark\\(|or\\s+1=1|';\\s*drop)"
fp_rate: low
severity: high — investigate every IP that gets >5/day
```

### IDOR / BOLA enumeration (Weeks 03, 13)

```
title: User accessing many distinct IDs of a sensitive resource
detection:
  query: stats dcount(resource_id) by user_id in 1h
  condition: dcount > 50
fp_rate: medium — power users / admins legitimately access many resources
severity: high — confirm against role
```

### Auth brute force, burst variant (Week 04)

```
title: Many failed logins from one IP
detection:
  query: stats count by client_ip in 5min where event = "auth.login.failure"
  condition: count > 20
fp_rate: medium — corporate NAT, password-manager misconfigs
severity: medium
```

### Auth brute force, slow-and-low variant (Week 04)

```
title: One IP attempting many distinct usernames
detection:
  query: stats dcount(username) by client_ip in 24h where event = "auth.login.failure"
  condition: dcount > 30
fp_rate: low
severity: high
```

### Successful login after many failures

```
title: Successful login after burst of failures (credential stuffing hit)
detection:
  sequence:
    - event = "auth.login.failure" by client_ip count > 5 in 10min
    - then event = "auth.login.success" by same client_ip within 10min
fp_rate: low
severity: high
```

### SSRF / outbound to internal address (Week 08)

```
title: App made outbound connection to RFC1918 / metadata IP
detection:
  query: where dst_ip matches "(^127\\.|^10\\.|^192\\.168\\.|^172\\.(1[6-9]|2[0-9]|3[01])\\.|^169\\.254\\.)"
         and process_name in (web_application_processes)
fp_rate: low — most apps don't make outbound calls to RFC1918
severity: critical
```

### Outbound to metadata service specifically

```
title: Cloud metadata service access from web app
detection:
  query: where dst_ip in ("169.254.169.254", "fd00:ec2::254", "metadata.google.internal")
         and process_name in (web_application_processes)
fp_rate: low if not normal for the app
severity: critical
```

### Log4Shell-pattern strings (Week 14)

In Sigma-ish pseudocode:

```
title: JNDI-substitution-pattern in any logged field
detection:
  query: where any_logged_field matches "\\$\\{(jndi|lower|upper|sys|env|date|::-):"
fp_rate: vanishingly low
severity: critical
```

As real Sigma YAML (the on-disk artifact you'd commit to a detection-as-code repo) — this is what the rest of the rules in this section would look like once ported into your SIEM:

```yaml
title: Log4j JNDI substitution pattern in HTTP request
id: 9c8d1f3a-c2d4-4f5e-b6a7-8e9f0a1b2c3d
status: experimental
description: |
  Detects Log4Shell (CVE-2021-44228) and follow-on variants by matching the
  ${jndi:…} / ${lower:…} / ${upper:…} / ${env:…} substitution patterns in
  any HTTP request field (URI, headers, body). Vanishingly rare in legitimate
  traffic.
references:
  - https://www.lunasec.io/docs/blog/log4j-zero-day/
  - https://nvd.nist.gov/vuln/detail/CVE-2021-44228
author: appsec-mentorship
date: 2026/05/31
logsource:
  category: webserver
detection:
  selection:
    request_uri|contains:
      - '${jndi:'
      - '${lower:'
      - '${upper:'
      - '${env:'
      - '${sys:'
      - '${date:'
      - '${::-'
  condition: selection
fields:
  - client_ip
  - request_uri
  - user_agent
falsepositives:
  - Vulnerability scanners running in scope
  - Researchers documenting payloads
level: critical
tags:
  - attack.initial_access
  - attack.t1190
  - cve.2021-44228
```

(`sigma-cli convert` turns this into Splunk SPL, Elastic EQL, Sentinel KQL, Chronicle YARA-L, etc. The point of writing it once in Sigma is that you don't re-port for each SIEM.)

### Deserialization payload signatures (Week 11)

```
title: Known serialized payload header in HTTP body
detection:
  query: where body_starts_with in
    ("aced0005",          # Java ObjectStream
     "\\x80\\x02",         # Python pickle proto 2 (Python 2.3+ / py3 minimum)
     "\\x80\\x03",         # Python pickle proto 3 (Python 3.0-3.3 default)
     "\\x80\\x04",         # Python pickle proto 4 (Python 3.4-3.7 default)
     "\\x80\\x05",         # Python pickle proto 5 (Python 3.8+ default)
     "rO0AB",             # Java serialized, base64-encoded
     "AAEAAAD",           # .NET BinaryFormatter, base64-encoded
     "O:\\d+:\"")          # PHP serialize() — "O:6:\"Object\":..."
fp_rate: low — internal services may legitimately exchange Java-serialized data; allow-list
severity: high
```

### Privilege escalation (DB-level)

```
title: Privilege change recorded in user table
detection:
  query: where event = "user.role.changed" and (new_role = "admin" or new_role = "staff")
fp_rate: low — these should be very rare; alert on every one
severity: critical
```

### Sensitive S3 / blob access from new identity

```
title: S3 object access from new principal
detection:
  query: where event in ("GetObject","ListObjects") and bucket in (sensitive_buckets)
         and principal not in (allowed_principals_baseline)
fp_rate: low
severity: high
```

### Cross-tenant access attempt

```
title: User accessed object owned by different user
detection:
  query: where event = "data.access" and resource_owner_id != actor_user_id
         and actor.role not in ("admin","support")
fp_rate: low for B2B / multi-tenant apps
severity: high
```

### Large data export

```
title: Large CSV / API bulk export
detection:
  query: where event = "data.export" and record_count > 10000
fp_rate: medium — depends on the product
severity: medium — require review
```

### Detection-control failure

```
title: Logs not arriving from a host
detection:
  query: where host in (production_hosts) and not seen in (logs) in 15min
fp_rate: medium — hosts cycle, but should re-appear quickly
severity: critical if it persists
```

## Defense 4: Alerting design — don't make people hate the SOC

### The triage triangle

For every detection rule, define:

1. **Severity** — page-now / review-in-business-hours / aggregate-into-dashboard
2. **Action** — what does the on-call do *immediately*?
3. **Decision criteria** — when escalate?

Without (2) and (3), high-severity alerts cause alert fatigue. The classic SRE alerting wisdom (Google's "Alerting on SLOs") applies: **only alert on conditions that require human action**.

### Tier alerts by what they need

| Tier | Example | Channel |
|---|---|---|
| Page (PagerDuty wake-up) | Log4Shell payload + RCE-signal | 24x7 |
| Ticket | BOLA enumeration detected | Business hours |
| Dashboard | 4xx rate ticked up | Quarterly review |
| Audit-only | Privilege change | Compliance log |

### Alert fidelity > alert count

It's better to have 10 rules that fire 100 times/year at 80% true-positive than 100 rules at 5%. The latter trains the team to ignore.

### Quarterly rule review

Each rule should be re-examined every 90 days:

- Did it fire? If not in 6+ months, is it still relevant?
- What was the true-positive rate?
- Were the alerts actioned?

Rules that don't fire don't catch anything; rules that fire but get dismissed are noise. Both should be tuned or retired.

## Defense 5: Incident response handoff

When a detection becomes a *suspected incident*, the handoff to IR matters more than the detection itself.

### Required at handoff

- **Timeline** — when did each signal fire? Auto-build from the SIEM data.
- **Affected scope** — which users, which records, which systems?
- **Containment options** — can we revoke a session? Kill an API key? Pause an account?
- **Evidence preserved** — relevant log slices saved off-pipeline before retention rotates them out.

Practice this with tabletop exercises. The first time you discover that your "rotate the leaked API key" runbook is missing a step is during an incident; it's better to discover it during a tabletop in March.

### Roles

Common minimal-team roles for the first 24 hours of a confirmed incident:

| Role | Job |
|---|---|
| Incident Commander | Decisions, status, timing |
| Investigator (Forensics) | Build the timeline; preserve evidence |
| Operator (Containment) | Rotate, revoke, isolate, patch |
| Comms | Status page, customer comms, legal/comms loop-in |
| Scribe | Document the running narrative — critical for the postmortem |

Even in small orgs, one person can wear multiple hats — but they need to consciously switch contexts. Mixed signals about who's deciding are the most-common source of slow incidents.

## Defense in depth

| Layer | What it catches |
|---|---|
| Structured logs with rich event vocabulary | Forensic basis for everything |
| Ship logs off-host immediately, immutable | Resistance to log tampering |
| SIEM with detection-rule library | Real-time recognition |
| Tiered alerts (page vs. ticket vs. dashboard) | Sustainable practice |
| Quarterly rule review | Drift correction |
| Threat-intel feed integration | New IoCs across deploys |
| Tabletop exercises | IR readiness |
| MITRE ATT&CK coverage map | Gap visibility — which TTPs are uncovered? |

## Remediation playbook (when *logging* is the gap)

| Finding | Immediate | Longer fix |
|---|---|---|
| Critical event not logged | Add the log line; deploy hotfix | Audit: what other events are missing? |
| Log destination went down | Failover to backup; investigate | Multi-shipper redundancy |
| Sensitive data in logs | Redact in retention; rotate credentials if applicable | Logging-library middleware that strips by type |
| Alert fires but no one looks | Re-tier or kill | Quarterly review process |
| Detection rule with >50% false positive | Tune or remove | Define the FP/TP target up front |
| Logs retained too briefly for legal | Extend; archive to cold | Retention policy aligned with regs |

## Automated tests

```python
def test_login_failure_is_logged(client, capture_logs):
    client.post("/login", json={"username": "alice", "password": "wrong"})
    events = [e for e in capture_logs if e["event"] == "auth.login.failure"]
    assert events
    assert events[0]["username"] == "alice"
    assert "password" not in str(events[0])    # never log the password

def test_password_never_in_logs(capture_logs, client):
    client.post("/signup", json={"username": "alice", "password": "supersecret"})
    for event in capture_logs:
        assert "supersecret" not in str(event)

def test_admin_role_change_emits_audit_log(client, capture_logs):
    promote_to_admin(target_user_id=42, by_admin=admin_user)
    events = [e for e in capture_logs if e["event"] == "user.role.changed"]
    assert events
    assert events[0]["new_role"] == "admin"
    assert events[0]["actor_user_id"] == admin_user.id

def test_request_id_propagates_across_events(client, capture_logs):
    client.get("/api/orders/1", headers={"X-Request-ID": "abc-123"})
    ids = {e.get("request_id") for e in capture_logs}
    assert "abc-123" in ids
```

## Tools

| Tool | Role |
|---|---|
| **Elasticsearch / OpenSearch / Splunk / Datadog Logs** | SIEM core |
| **Fluent Bit / Vector / Filebeat** | Log shippers |
| **structlog / pino / Logback JSON / serilog** | Structured logging libs |
| **Sigma + sigma-cli** | Portable detection-rule format |
| **MITRE ATT&CK Navigator** | Map coverage |
| **Atomic Red Team** | Synthetic-attack replay to test detections |
| **PagerDuty / Opsgenie / Squadcast** | Alert routing |
| **Grafana / Kibana / Splunk dashboards** | Visualization for the dashboards-tier alerts |

## Common mistakes when defending

- **"We have Splunk"** — buying the SIEM is 5% of the work.
- **"Log everything"** — verbose logs hide signal, cost money, and tempt people to log PII.
- **Alerting on the symptom, not the threat** — "the API returned 500" isn't an attack; alert on the cause.
- **No on-call practice** — quarterly tabletop is the actual training.
- **Logs as cost center** — treat them as forensic evidence; retention budget is non-negotiable for regulated environments.
- **Building rules without false-positive estimates** — rules with no estimated FP rate are how teams get alert fatigue.
- **Pretending one team can do everything** — if the same person writes the rule, triages the alert, and patches the bug, none of the three get attention.

## Going further

- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [Sigma rules repository](https://github.com/SigmaHQ/sigma) — read real rules
- [MITRE ATT&CK](https://attack.mitre.org/) and [MITRE D3FEND](https://d3fend.mitre.org/)
- [Google SRE — Alerting on SLOs](https://sre.google/workbook/alerting-on-slos/)
- [Florian Roth — Detection engineering blog](https://nextron-systems.com/blog/)
- [Red Canary — Threat detection report](https://redcanary.com/threat-detection-report/)
- [Mandiant M-Trends](https://www.mandiant.com/m-trends) — annual breach data
