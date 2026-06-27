# Week 15: Attack walkthrough - Where the logs aren't

> ⚠️ **Lab only.**

---

## The framing

Every prior week ended with detection signals. This week flips it: **what does the attacker do to make sure you don't see them?** A09 ("Security Logging and Monitoring Failures") is in the Top 10 specifically because absent logs make every other bug class harder to detect, harder to investigate, and harder to recover from. We walk the gaps real attackers exploit.

Mandiant M-Trends 2024/2025 puts the global median **dwell time** (attacker in the network → detection) at ~10-11 days - down dramatically from 30+ days a decade ago, largely because ransomware shortens the kill chain. The figure varies sharply by region and by how the breach is discovered: externally-notified breaches still trend much higher, and the median masks a long tail. Dwell time traces directly back to detection-control quality.

## Part 1: Things commonly NOT logged (the attacker's best friend)

### Authentication

| Event | Often logged? | Should be |
|---|---|---|
| Successful login | Often | Yes |
| Failed login | Sometimes | Yes |
| Login from new device/IP | Rarely | Yes |
| MFA challenge sent | Rarely | Yes |
| MFA bypass / fallback used | Rarely | Yes (high-signal) |
| Password reset requested | Sometimes | Yes |
| Session created | Sometimes | Yes |
| Session terminated (logout vs. expiry vs. revoke) | Rarely all 3 distinct | Yes |
| Privilege change (`is_admin` flipped) | Rarely | **Always**, with the before/after |

A surprising amount of breach forensics fails because "we don't have records of when this account was promoted to admin." A privilege change event must be permanent, immutable, and shipped off-box immediately.

### Authorization

| Event | Should log |
|---|---|
| 403 (access denied) | Yes - high-fidelity attack signal |
| 404 (not found) | Yes - but careful with volume |
| 200 OK after a permission check passed | No (volume) |
| Cross-tenant access attempt | **Always** |

### Data access

| Event | Should log |
|---|---|
| User reads their own data | No (volume) |
| User reads someone else's data via an admin path | Yes - must include who/whose/why |
| Export of N records (CSV, GraphQL bulk) | Yes - include count |
| Data downloaded to a new IP | Yes |
| Searches against PII | Yes (compliance) |

### Configuration & secrets

| Event | Should log |
|---|---|
| Settings changed | Yes - diff of before/after |
| API key minted | Yes - never the key itself |
| API key revoked | Yes |
| Secret read from secret manager | Yes - most secret managers log this for you |
| Database schema change | Yes |

## Part 2: Attacker techniques against logging

### Technique 1: Trigger before logging

If logging happens *after* the action, an action that crashes the process never gets logged.

```python
# bad
def transfer(from_acct, to_acct, amount):
    do_the_transfer(from_acct, to_acct, amount)
    audit_log("transfer", from_acct, to_acct, amount)   # never runs if exception above
```

An attacker who crashes `do_the_transfer` (resource exhaustion, exception, malformed input) executes the transfer but leaves no audit record. Fix: log *intent* first, then act.

### Technique 2: Log injection

Inject log-format characters to confuse downstream tooling:

```http
GET /search?q=foo%0a2026-01-01%2012:00:00%20INFO%20user%20admin%20logged%20in HTTP/1.1
```

If your app does `log.info(f"search query: {q}")` without escaping, the resulting log line looks like an additional admin-login event to a SIEM that parses on newlines.

Same in JSON loggers if user input ends up unescaped in a structured field - though most JSON loggers escape this correctly. The classic CVE class here is "log4j 2.0-2.14 lookups" - the unrestricted substitution in Log4Shell wasn't *only* RCE; it was also log injection into anything indexing Log4j output.

### Technique 3: Log volume DoS

Generate enough innocuous-looking traffic that the real attack hides in the noise. SIEMs typically retain hot data for 7-30 days; flooding the index pushes legitimate evidence off the retention window.

```bash
# Background traffic generator
for i in {1..1000000}; do
  curl -s "http://target/?q=$RANDOM" &
done
```

Specifically affects:
- Smaller orgs with metered SIEM ingestion (Splunk's per-GB licensing)
- Cloud-managed services with index-rotation policies based on size

### Technique 4: Log file tampering

If the attacker reaches the host (a step deeper than the bug we're exploiting), they may try to clean logs:

```bash
# wiping evidence - what real APTs do post-compromise
sed -i '/<attacker-ip>/d' /var/log/auth.log
> /var/log/auth.log                       # truncate
echo "" > /var/log/nginx/access.log
journalctl --rotate && journalctl --vacuum-time=1s
```

This is why **logs must ship off-host immediately** - local logs are not evidence. They're a convenience for ops.

### Technique 5: Slow-and-low to stay under detection thresholds

Most detection rules fire on bursts:

```
| where event = "auth.fail"
| stats count by user_id, 5min
| where count > 10
```

The 10-failures-in-5min rule misses an attacker who tries one password per hour across thousands of accounts. Modern credential stuffing tools default to slow-and-low pacing.

Defense: detection rules also need a low-rate variant (`> 50 distinct usernames touched / 24h from one IP`), and you should pair with anomaly detection that flags "this IP attempted login on N% more accounts than baseline".

### Technique 6: Living off the land

Don't bring new binaries - use what's already there. `curl`, `wget`, `bash`, `python`, `powershell` exist on most hosts. Their use is normal in many places. Detections that key on `*.exe filename in /tmp/` miss everything that runs through the existing interpreter.

### Technique 7: Cloud control plane vs. data plane

Many orgs log application logs richly but log very little of AWS/GCP/Azure API activity. An attacker with stolen credentials:

```bash
aws iam create-access-key --user-name billing
aws secretsmanager get-secret-value --secret-id prod-db-creds
aws s3 sync s3://customer-backups ./loot/
```

Looks normal *to the application* - the app never sees it. CloudTrail / Cloud Audit Logs / Azure Activity Log are the answer; many teams have them on but don't actually alert on the high-signal events.

## Part 3: Concrete log-gap walkthrough (the lab)

### Step 1: Run a baseline attack with rich logging

Replay Week 04's brute-force-login traffic against the lab app. Verify Kibana shows the failures.

### Step 2: Subvert the detection - slow-and-low

```python
import requests, time, random
USERNAMES = open("usernames.txt").read().splitlines()
PASSWORDS = ["Password123!", "Welcome2025!", "Spring2026!"]
for user in USERNAMES:
    for pw in PASSWORDS:
        requests.post("http://localhost:5000/login",
                      json={"username": user, "password": pw})
        time.sleep(60 + random.uniform(0, 30))   # one attempt every ~60-90 seconds
```

Against the burst-detection rule (>10 fails per 5 min per user), this fires nothing - distributed across many users, paced. The "count distinct users attempted per IP per day" rule catches it.

### Step 3: Subvert the detection - log injection

```python
malicious_username = "test\\nadmin login successful for victim@example.com"
requests.post("http://localhost:5000/login",
              json={"username": malicious_username, "password": "x"})
```

If the lab app's log line is `f"login attempt: user={user}"`, the injected newline produces what looks like a separate "admin login successful" entry. Compare logs with and without escaping.

### Step 4: Subvert the detection - volume DoS

```python
for _ in range(100_000):
    requests.get("http://localhost:5000/?q=test")
```

Watch your local SIEM. Does the disk fill? Does retention drop your legitimate Week 04 attack data?

### Step 5: Find what's missing

Pick three of the previous weeks. For each, ask: **what would I log to be certain a successful attack was visible?** Compare to what the lab app actually logs. Most of the time, the answer is "not enough."

## Part 4: Real-world gaps (with citation lessons)

### Target (2013)

Famously, the breach was *detected by FireEye* and ignored. Logs existed. Detection rules existed. Alerts fired. No one looked. **Logging without operational practice is not detection.**

### Equifax (2017)

The Struts CVE was published months before the breach. The patch deploy was incomplete. The exploitation was loud - but expired SSL certs on the egress-monitoring system meant the egress wasn't being decrypted, so the data exfiltration looked like normal TLS to monitoring. **One broken control invalidated the rest.**

### Capital One (2019)

SSRF (Week 08) to fetch EC2 instance credentials → S3 enumeration → bulk data download. CloudTrail logs *existed* showing the unusual API access pattern. They were ingested into the SIEM. No one alerted on "user role X is reading objects from bucket Y, which it has never accessed before."

### MGM Resorts (2023)

Social engineering of the help desk → MFA reset. **The help-desk interaction was not logged** in a way that surfaced to the SOC. The MFA reset event was, but not paired with the human context.

## Common mistakes when learning

- **Confusing logs with detection.** Logs are evidence; detection is queries on logs; alerting is action on detections. All three are needed.
- **"We have Splunk."** A SIEM with no rules is an expensive disk.
- **Logging everything.** Verbose logs hide signal; expensive to retain; tempt people to log PII/secrets.
- **Local-only logging.** First thing an attacker does is clear `/var/log/`. Ship logs off-host before you index them.
- **No tabletop exercises.** Detection rules go stale. Quarterly "did this rule fire? would it fire on today's traffic?" reviews are required.

Now read [defense.md](defense.md).
