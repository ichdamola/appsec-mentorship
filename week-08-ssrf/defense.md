# Week 08: Defense — Stopping SSRF

You've turned SSRF into cloud-credential theft and internal-network access in [attack.md](attack.md). Defense requires multiple layers — a single URL validator will lose the bypass arms race.

---

## The single rule

> **Don't validate the URL string. Validate the *destination IP* after resolution, and connect to that specific IP only.**

Filtering URL strings is whack-a-mole. The right approach is to resolve DNS yourself, check the resulting IP against a denylist (or allow-list), then connect to that IP specifically — defeating DNS rebinding and most parser-confusion bypasses in one move.

## Layer 1: Allow-list, not deny-list

For SSRF defense, the question to ask is: **what hosts does this feature *need* to reach?**

| Feature | Likely allow-list |
|---|---|
| Avatar import | Specific image-hosting domains (Gravatar, AWS S3 public bucket) |
| Webhook callbacks | Customer-configured hosts (validate at config time, not call time) |
| Link unfurling | All of the public internet (the hardest case) |
| OAuth redirects | Pre-registered callback URLs (mandatory anyway) |
| PDF/screenshot from URL | Specific allowed domains |

If the feature is "fetch arbitrary URLs," defense is hard. If it's "fetch from these specific places," defense is trivial. **Push the product toward the latter wherever possible.**

## Layer 2: Resolve then validate, then connect by IP

The pattern that defeats parser confusion, DNS rebinding, and redirects in one move:

```python
import socket
import ipaddress
import requests
from urllib.parse import urlparse

PRIVATE_NETWORKS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),   # link-local + metadata
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),         # IPv6 unique local
    ipaddress.ip_network('fe80::/10'),        # IPv6 link-local
]

def is_private_ip(ip_str):
    ip = ipaddress.ip_address(ip_str)
    return any(ip in net for net in PRIVATE_NETWORKS)

def safe_fetch(url, allow_schemes={'http', 'https'}):
    parsed = urlparse(url)

    # 1. Validate scheme
    if parsed.scheme not in allow_schemes:
        raise ValueError(f"scheme not allowed: {parsed.scheme}")

    # 2. Resolve hostname to a specific IP
    try:
        infos = socket.getaddrinfo(parsed.hostname, None)
    except socket.gaierror:
        raise ValueError("DNS lookup failed")

    # 3. Check every resolved address; reject if any is private
    for info in infos:
        family, _, _, _, sockaddr = info
        ip = sockaddr[0]
        if is_private_ip(ip):
            raise ValueError(f"resolves to private address: {ip}")

    # 4. Connect to the specific IP, sending the original hostname as Host header.
    target_ip = infos[0][4][0]
    safe_url = url.replace(parsed.hostname, target_ip, 1)

    session = requests.Session()
    session.mount(
        f"{parsed.scheme}://{target_ip}",
        PinnedHostAdapter(original_host=parsed.hostname),
    )
    return session.get(
        safe_url,
        timeout=5,
        allow_redirects=False,   # ← critical
        headers={'Host': parsed.hostname},
        # For HTTPS: SNI/cert verification needs the original hostname.
        # PinnedHostAdapter handles SNI; cert verification uses Host.
    )


class PinnedHostAdapter(requests.adapters.HTTPAdapter):
    """Connect to the IP in the URL but set SNI + cert validation hostname
    to the original hostname. Defeats DNS rebinding because no further DNS
    lookup is needed at connect time."""
    def __init__(self, original_host, *args, **kwargs):
        self.original_host = original_host
        super().__init__(*args, **kwargs)

    def send(self, request, **kwargs):
        # urllib3 honors a server_hostname kwarg via connection pools.
        # See urllib3's HTTPSConnectionPool docs for the production pattern.
        kwargs['verify'] = True
        return super().send(request, **kwargs)
```

> ⚠️ **This is the shape, not a drop-in.** The HTTPS SNI / cert-validation handoff between the IP-pinned connection and the original hostname is subtle and varies across `urllib3` versions. In production, use a vetted helper (`ssrf-requests`, the SOCKS-style approach via a dedicated egress proxy, or `httpx`'s custom transport API) rather than rolling your own. The point of this snippet is to show *what defeats DNS rebinding* — single resolution + connect by IP — not to ship as-is.

Key properties:

- **Single DNS resolution.** Defeats DNS rebinding because the connect-time URL contains the IP, not the hostname — there is no second lookup.
- **Connect by IP.** What the URL parser saw is what gets contacted, byte for byte.
- **No redirect following.** A 30x response is returned to the caller, who must explicitly opt in to following — and that next URL goes through the same validator.

### Implementation note: SSRF-aware HTTP clients

In practice, you want a library that handles this for you:

- **Python:** `requests` with a custom `HTTPAdapter` that pins the IP. Or use a vetted helper: `ssrf-guard`-style packages.
- **Node:** `safe-fetch` style libraries, or implement custom `lookup` for `http.request`.
- **Go:** Custom `http.Transport.DialContext` that resolves once and checks the IP.
- **Java:** `URLConnection` with a custom `SocketImpl`, or use a library.

**Don't roll your own HTTP client.** Use a tested library.

## Layer 3: Block egress at the network layer

Even with perfect application-level validation, network-layer egress filtering is defense in depth.

### Cloud egress rules

Limit what your application servers can reach:

| Egress destination | Should the app reach it? |
|---|---|
| External API providers (Stripe, Twilio) | Yes — allow specific FQDNs |
| Your own internal services | Yes — via known internal IPs/DNS |
| Public internet | Probably not |
| `169.254.169.254` (metadata) | Only via IMDSv2 token; block direct |
| RFC1918 private ranges | Only specific known internal services |

VPC security groups, AWS network firewalls, GCP firewall rules — all can express this.

### Proxy all egress

A common architectural pattern: application servers can't make outbound HTTP. Instead, they call an internal **egress proxy** that does the allow-list check at the network boundary:

```
App → Squid proxy (with allow-list) → Internet
```

This centralizes the SSRF defense and gives you one place to update the allow-list.

## Layer 4: Cloud metadata hardening

### Enforce IMDSv2 (AWS)

IMDSv2 requires a PUT to get a token, then GET with the token in a header. Typical HTTP fetchers can't do this — they only do GET. Forcing IMDSv2 makes SSRF-to-metadata structurally hard.

```
# Make IMDSv2 required (not optional) on every EC2 instance
aws ec2 modify-instance-metadata-options \
  --instance-id i-xxx \
  --http-tokens required \
  --http-put-response-hop-limit 1
```

`--http-put-response-hop-limit 1` is the killer — the metadata service refuses to respond to requests that have been forwarded (hop count > 1). SSRF from a container fetching through the host can't reach the host's metadata.

Set as an Organizational SCP. New instances default to IMDSv2-required.

### GCP and Azure equivalents

- GCP: require `Metadata-Flavor: Google` header (default). The vast majority of SSRF fetchers don't set arbitrary headers.
- Azure: require `Metadata: true` header. Same property.

## Layer 5: Don't run unnecessary services on the metadata IP

Your app might allow `169.254.0.0/16` for legitimate reasons (Docker, link-local services). If so, make sure `169.254.169.254` specifically is blocked or running an authenticated proxy.

## Defense in depth summary

| Layer | What it catches |
|---|---|
| Allow-list of destinations | The "fetch arbitrary URL" case |
| Resolve-then-validate-then-connect-by-IP | DNS rebinding, parser confusion |
| No redirect following (or re-validating redirects) | Open-redirect → internal chains |
| Egress proxy with allow-list | What slips past application-level checks |
| Network-layer egress filtering | Catches direct internal-IP fetches |
| IMDSv2 enforced | The cloud-metadata catastrophe path |
| Outbound DNS monitoring | Detection of attempts that get through |

---

## Detection

### Signal 1: Outbound requests to private IPs

```
| where event = "outbound_http_request"
| where destination_ip in (private_ranges)
| stats count by application, source_user, destination_ip
```

For most applications, this should be zero or constrained to known internal targets. Anything else investigates.

### Signal 2: Outbound requests to `169.254.169.254`

If IMDSv2 is enforced, the only legitimate request to this IP is from the instance's own AWS SDK code (which knows the v2 dance). Any other source process calling it is suspicious:

```
| where destination_ip = "169.254.169.254"
   and not initiating_process_path matches "(aws-sdk|aws-cli)"
```

### Signal 3: Spike in HTTP requests to unfamiliar hosts

A workload that normally hits 5 destinations suddenly hits 500 — could be a scraper feature working as intended, or could be SSRF being abused for port-scanning.

```
| stats dc(destination_host) as unique_destinations by application
| baseline 7d
| where unique_destinations > baseline * 3
```

### Signal 4: Burp Collaborator-style requests

If you set up a unique-DNS canary endpoint and seed it as a "honeypot URL" in an internal database, any DNS lookup for that domain from your network is an attacker probing for SSRF.

### Signal 5: Failed connection attempts to internal ports

App-layer logs of failed outbound connections, especially to non-standard ports:

```
| where event = "connect_failed"
   and dest_port in (6379, 11211, 27017, 9200, 2375, 5984, 8500)
```

These are typical internal-service ports (Redis, memcached, Mongo, ES, Docker, CouchDB, Consul). An app probing for them is being abused.

---

## Remediation playbook

| Finding | Immediate action | Longer fix |
|---|---|---|
| SSRF in user-controlled URL field | Add IP allow/denylist; ship today | Migrate to resolve-then-connect-by-IP pattern |
| IMDSv1 still enabled | Enforce IMDSv2 across the fleet | SCP requiring v2 for new instances |
| SSRF found in PDF/screenshot generator | Disable iframe / external-resource loading | Sandbox the generator (no network, container with egress proxy) |
| DNS rebinding bypass | Move to single-resolution pattern | Use vetted SSRF-safe HTTP library |
| Open redirect chained to SSRF | Disable redirect following in fetcher | Validate redirect targets if you must follow |

## Automated tests

```python
def test_fetch_url_rejects_private_ip(client, admin_token):
    response = client.post("/import/avatar",
                           json={"url": "http://10.0.0.5/image.png"},
                           headers={"Authorization": f"Bearer {admin_token}"})
    assert response.status_code == 400

def test_fetch_url_rejects_metadata_ip(client, admin_token):
    response = client.post("/import/avatar",
                           json={"url": "http://169.254.169.254/latest/meta-data/"},
                           headers={"Authorization": f"Bearer {admin_token}"})
    assert response.status_code == 400

def test_fetch_url_rejects_decimal_ip(client, admin_token):
    # 2130706433 == 127.0.0.1
    response = client.post("/import/avatar",
                           json={"url": "http://2130706433/admin"},
                           headers={"Authorization": f"Bearer {admin_token}"})
    assert response.status_code == 400

def test_fetch_url_rejects_dns_pointing_to_private(client, admin_token):
    # A test DNS name that you control that resolves to 192.168.1.1
    response = client.post("/import/avatar",
                           json={"url": "http://private-resolver.test.example/data"},
                           headers={"Authorization": f"Bearer {admin_token}"})
    assert response.status_code == 400

def test_fetch_url_does_not_follow_redirects_to_private(client, admin_token):
    # A public URL that 302s to an internal one
    response = client.post("/import/avatar",
                           json={"url": "https://public-redirector.test.example/to-internal"},
                           headers={"Authorization": f"Bearer {admin_token}"})
    # Either rejects, or fetches the redirect response (302) but doesn't follow
    assert response.status_code in (400, 502)
```

## Tools

| Tool | Role |
|---|---|
| **Burp Suite (Collaborator)** | Detects blind SSRF via OAST callbacks |
| **Semgrep / CodeQL** | Static rules for `requests.get(user_input)`, `urllib.request.urlopen(user_input)` |
| **AWS IAM Access Analyzer** | Detects roles with excessive permissions reachable via SSRF |
| **Steampipe / Prowler / ScoutSuite** | Cloud audits for IMDSv1 still enabled |
| **HTTPie / curl** | Quick CLI testing for URL filters |

## Common mistakes when defending

- **Filtering `127.0.0.1` and stopping.** Decimal, octal, hex, IPv6, DNS → defeats string filters.
- **Validate URL, then fetch.** DNS rebinding turns this into the validation pass + the fetch into two different connections.
- **Following redirects.** Defeats most validators. Disable, or re-validate each hop.
- **Trusting the URL parser to normalize.** Parsers differ; what passes validation may resolve differently in the HTTP client.
- **Allow-listing entire CDNs.** Sounds safe, but those CDNs host customer-controlled content. `cdn.example.com/customer-bucket/redirect.html` can chain.

## Going further

- [PortSwigger — SSRF](https://portswigger.net/web-security/ssrf)
- [OWASP — SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Capital One breach post-mortem](https://krebsonsecurity.com/2019/08/capital-one-data-theft-impacts-106m-people/)
- [Orange Tsai — A new era of SSRF](https://blog.orange.tw/2017/07/how-i-chained-4-vulnerabilities-on.html) — the canonical SSRF research talk
- [AWS — IMDSv2 documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
