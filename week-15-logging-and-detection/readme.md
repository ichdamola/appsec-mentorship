# Week 15: Logging, Monitoring, and Detection

## 🎯 What you'll learn

OWASP A09 - Security Logging and Monitoring Failures. You can't respond to what you can't see. This week takes the attack patterns from weeks 1-14 and asks: **what would have caught it in your logs?** The product is a set of detection rules and a sustainable alerting practice - not "more logs."

By the end of this week you'll be able to:

- Design a structured logging schema for an HTTP-facing application
- Know **what to log and what NOT to log** (passwords, full tokens, PII)
- Write detection rules for the attack classes in weeks 1-14 - XSS, SQLi, IDOR, brute-force auth, BOLA enumeration, deserialization, Log4Shell-shaped payloads
- Reason about **alerting fatigue** - why "more alerts" reduces security, and how to tune
- Stand up a tiny SIEM stack locally and write queries against it
- Articulate the **handoff to incident response** - when does a finding become a ticket vs. a page

## ⚠️ Scope reminder

**Lab only** for any attack traffic you generate. Logging your own apps is fine; attaching detection rules to systems you don't own is not. See [root readme](../readme.md#️-ethics--scope).

## 🧰 Lab setup

### Lab 1: A tiny ELK stack

```bash
mkdir elk-lab && cd elk-lab
curl -O https://raw.githubusercontent.com/deviantony/docker-elk/main/docker-compose.yml
docker compose up -d
```

Kibana → http://localhost:5601. Elasticsearch → http://localhost:9200.

Then point a small Python web app at it via Filebeat or direct logging:

```python
# tiny FastAPI app emitting structured logs
import structlog, time, uuid

log = structlog.get_logger()

@app.middleware("http")
async def log_request(request, call_next):
    request_id = str(uuid.uuid4())
    log.info("request.start", request_id=request_id, method=request.method,
             path=request.url.path, client=request.client.host)
    start = time.perf_counter()
    response = await call_next(request)
    log.info("request.end", request_id=request_id, status=response.status_code,
             duration_ms=int((time.perf_counter()-start)*1000))
    return response
```

### Lab 2: Generate attack traffic + observe

Replay the attacks from previous weeks against the lab app:

- SQLi attempts (Week 05)
- XSS payloads (Weeks 01, 06)
- BOLA enumeration (Week 13)
- Failed-login bursts (Week 04)
- Path-traversal probes (Week 12)
- Log4Shell-pattern strings (Week 14)

Write Kibana queries that surface each.

### Lab 3: Splunk Free or OpenSearch (alternative)

If ELK is heavy: Splunk Free supports up to 500MB/day on a laptop. OpenSearch is a fork of Elasticsearch that's permissively licensed.

### Lab 4: OWASP Mutillidae logs (for realistic noise)

```bash
docker run -d -p 80:80 -p 3306:3306 citizenstig/nowasp
```

Attack Mutillidae through Burp; ship its access logs to your SIEM; build detections.

## ✅ Your job

1. **Stand up the ELK stack.** Confirm Kibana loads.
2. **Wire one app's structured logs in.** Use the FastAPI example or your existing project.
3. **Replay 3 attack patterns from prior weeks against it.** Confirm the logs land in Elasticsearch.
4. **Write 5 detection queries.** Each detection rule should:
   - Name the attack class
   - Have a query that fires on the attack
   - Have a noise estimate (how many false positives per week in your lab traffic)
   - Have a severity ("page now" vs. "review tomorrow")
5. **Read [attack.md](attack.md).** This week's "attack" is the attacker's *evasion of logging* - log gaps, log tampering, blind spots.
6. **Read [defense.md](defense.md).** The detection rule library + alerting design.

## 📚 Required reading

| Resource | Why | Time |
|---|---|---|
| [OWASP - Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) | What to log, what not | 25 min |
| [OWASP - Security Logging and Monitoring Failures (A09:2021)](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/) | The category overview | 15 min |
| [Sigma - generic SIEM detection rules](https://github.com/SigmaHQ/sigma) | Format for shareable detections | 20 min skim |
| [Google SRE - Alerting Philosophy](https://sre.google/workbook/alerting-on-slos/) | Why most alerting is broken | 30 min |
| [MITRE D3FEND](https://d3fend.mitre.org/) | Defensive techniques mapped against MITRE ATT&CK | 30 min skim |
| [Florian Roth - Sigma rule writing guide](https://github.com/SigmaHQ/sigma/wiki/Rule-Creation-Guide) | The how | 25 min |

## 💡 What you should already know

- A working knowledge of the previous 14 weeks (this is the synthesis week from the detection side)
- HTTP request/response anatomy
- Some regex (for log queries)
- Docker-compose basics for the lab stack
