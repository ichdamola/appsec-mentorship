# Week 13: Defense — API Security

You exploited BOLA, BOPLA, mass assignment, missing rate limits, and a handful of GraphQL-specific bugs in [attack.md](attack.md). The defenses cluster around two principles: **never trust an ID from the client as authorization**, and **declare your schema explicitly**.

---

## The single rule

> **Every request that names a resource must compare the resource's owner to `request.user`, server-side, on every endpoint.**

If your framework lets you forget this — Flask routes, Express handlers — it's your responsibility to add it. If your framework forces it — Django REST Framework permission classes, Rails Pundit/CanCanCan policies — use it consistently.

## Defense 1: Centralize object-level authorization

The wrong pattern is per-endpoint:

```python
# wrong — easy to forget on any one endpoint
@app.route("/api/orders/<id>")
def get_order(id):
    order = Order.query.get(id)
    if order.user_id != current_user.id:   # easy to forget
        abort(403)
    return jsonify(order)
```

The right pattern is centralized:

```python
# Django REST Framework
class OrderViewSet(viewsets.ModelViewSet):
    serializer_class = OrderSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # The user can only ever see their own orders.
        # No endpoint in this ViewSet can leak others.
        return Order.objects.filter(user=self.request.user)
```

Now BOLA is impossible by construction in `OrderViewSet`: the query layer filters before the URL parameter is ever used. Any `pk` not in `request.user`'s orders returns 404.

Equivalent patterns:
- **Rails:** Pundit policies — `Order.policy_scope(user)` returns the filtered queryset.
- **Spring:** `@PreAuthorize("@orderService.isOwner(authentication, #id)")`.
- **Node/Express:** middleware that wraps every `/:id` route with an ownership check that uses route-defined `resource` metadata.

## Defense 2: Define your read schema explicitly (stop BOPLA)

The wrong pattern is "serialize the model":

```python
# wrong
return jsonify(user.to_dict())   # whatever fields the model has
```

The right pattern is explicit:

```python
# DRF serializer — only these fields go out
class UserPublicSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "name", "email_truncated"]
```

```python
# Pydantic response model
class UserResponse(BaseModel):
    id: int
    name: str
    email_truncated: str

@app.get("/users/{id}", response_model=UserResponse)
def get_user(id: int): ...
```

The schema is in code, version-controlled, and reviewable. Adding a sensitive field to `User` doesn't accidentally expose it in `/api/users/<id>` — it has to be added to the response schema too.

## Defense 3: Define your write schema explicitly (stop mass assignment)

Same pattern, write-side:

```python
# Rails — strong_parameters
def user_params
  params.require(:user).permit(:name, :email)   # is_admin not allowed
end

# Django — explicit fields in form/serializer
class UpdateUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["name", "email"]   # NOT "__all__"

# Spring — explicit DTO, never bind directly to entity
public class UpdateUserDTO {
    private String name;
    private String email;
    // no is_admin field — can't be mass-assigned
}

# Express + Zod
const UpdateUserBody = z.object({
  name: z.string(),
  email: z.string().email(),
}).strict();   // .strict() rejects unknown fields
```

The pattern is the same: a DTO/schema for the request that includes ONLY user-controllable fields. Sensitive fields (`is_admin`, `password_hash`, `created_at`) are written by server-side logic, never by deserialization from the request body.

## Defense 4: Multi-dimensional rate limits

Rate limiting has at least four dimensions. Apply all that fit each endpoint:

| Dimension | Library/Pattern |
|---|---|
| Per-IP | nginx `limit_req`, Cloudflare rules, Envoy local rate limit |
| Per-account | Application-layer (`flask-limiter` with `key_func=lambda: g.user.id`) |
| Per-endpoint | Tighter limits on `/login`, `/password-reset`, `/api/coupon` |
| Per-API-key | For partner integrations — kill switch + analytics |
| Per-resource | "User X can only fetch their own data 100x/min" |

For the OTP / password-reset / login class specifically:

```python
@app.route("/login", methods=["POST"])
@limiter.limit("5/minute", key_func=lambda: request.json.get("email"))
@limiter.limit("20/minute", key_func=get_remote_address)
@limiter.limit("100/minute", key_func=lambda: "global")  # absolute cap
def login(): ...
```

Three independent limiters. Bypassing one doesn't bypass the others.

### CAPTCHA when limits aren't enough

For high-value endpoints (signup, password reset, login from a new device), require CAPTCHA after N failed attempts. The legit user sees a CAPTCHA once; the attacker can't iterate efficiently. hCaptcha and Turnstile are the modern privacy-respecting options.

## Defense 5: GraphQL hardening

### Disable introspection in production

```javascript
// Apollo Server
const server = new ApolloServer({
  schema,
  introspection: process.env.NODE_ENV !== 'production'
});
```

### Disable field suggestions

```javascript
// graphql-js — set didYouMean: false in custom error formatter
formatError: (err) => {
  if (err.message.includes('Did you mean')) {
    return new GraphQLError('Cannot query field');  // strip the hint
  }
  return err;
}
```

### Depth limit

```javascript
import depthLimit from 'graphql-depth-limit';
const server = new ApolloServer({ validationRules: [depthLimit(5)] });
```

### Cost analysis

Better than depth limit alone — assign costs to fields, reject queries above a threshold:

```javascript
import costAnalysis from 'graphql-cost-analysis';

const server = new ApolloServer({
  validationRules: [costAnalysis({ maximumCost: 1000, defaultCost: 1 })]
});
```

Apollo also ships `graphql-armor` which bundles depth+cost+aliases+directives limits.

### Disable batching unless you need it

```javascript
const server = new ApolloServer({ allowBatchedHttpRequests: false });
```

### Per-resolver auth

```javascript
// Wrap every resolver with the auth check it needs.
const resolvers = {
  Query: {
    user: requireAuth(async (_, { id }, ctx) => {
      if (ctx.user.id !== id && !ctx.user.isAdmin) throw new ForbiddenError();
      return User.findById(id);
    })
  }
}
```

Or use a framework like Nexus / type-graphql that puts the auth annotation next to the field.

## Defense 6: ID strategy

| ID type | BOLA-friendly? | Notes |
|---|---|---|
| Sequential integers (1, 2, 3) | Worst — enumeration trivial | Switch unless internal-only |
| `uuid1` | Bad — leaks MAC + time | Don't use |
| `uuid4` | OK — but doesn't replace auth | The CSPRNG variant |
| ULID / KSUID | Good — sortable, opaque, secure | Better DX than uuid4 |
| Hashids (encoded ints) | False sense of security | Reversible — still need authz |
| Stripe-style prefixed IDs (`cus_abc...`) | Same as uuid4 + readability | Recommended |

**ID randomness reduces enumeration but does not replace authorization.** A BOLA with UUIDs is still a BOLA — it just takes one leak (a referrer header, a public profile URL) to bridge.

## Defense in depth

| Layer | What it catches |
|---|---|
| Centralized object-level auth | BOLA (the dominant bug) |
| Explicit request/response schemas | BOPLA + mass assignment |
| Schema-validated input (Pydantic / Zod / Bean Validation) | Type confusion + extra fields |
| Multi-dimensional rate limits | OTP brute force, credential stuffing, enumeration |
| GraphQL: introspection off, depth + cost limits, batching off | GraphQL DoS + reconnaissance |
| API gateway with auth at the edge | Forgotten endpoints |
| Per-key analytics (which client is making what call) | Anomaly detection |
| Outbound monitoring (Week 08) | If BOLA's used for data exfil, you see volume |

## Detection

### Signal 1: One user accessing many IDs

```
| where user_id = "victim_attacker_id"
| stats dcount(target_resource_id) as ids_touched by 5min
| where ids_touched > 50
```

A legitimate user accesses ~10-20 distinct resources in a session. 5000 distinct IDs is exfil.

### Signal 2: Sequential ID walk

```
| where endpoint matches "/api/.*/<id>"
| stats values(id) as ids by user_id
| eval is_sequential = ids_are_arithmetic_progression(ids)
| where is_sequential = true
```

Legitimate users almost never hit IDs in numeric order.

### Signal 3: 403/404 spikes per user

```
| where status in (403, 404)
| stats count by user_id, 5min
| where count > 100
```

Attacker probing for accessible IDs gets many denies before finding one that works. Legitimate users get ~0 403/404s per hour.

### Signal 4: GraphQL high-depth queries

```
| where endpoint = "/graphql"
| eval depth = graphql_depth(query)
| where depth > 10
```

### Signal 5: GraphQL aliased login attempts

```
| where endpoint = "/graphql"
   and query matches "login.*login.*login"   # naive but effective
| stats count by client_ip
```

### Signal 6: Mass-assignment attempts

Log when a request includes a field your schema doesn't accept (Pydantic with `extra="forbid"` raises on this, and you can log the rejection):

```
| where event = "schema_validation_failed"
   and rejected_fields contains "is_admin" or contains "is_staff" or contains "role"
| stats count by user_id
```

A single such attempt is suspicious. They almost certainly come from an attacker probing.

## Remediation playbook

| Finding | Immediate | Longer fix |
|---|---|---|
| Endpoint returns objects without ownership check | Add the check; deploy as hotfix | Move auth to queryset/repository layer for the whole module |
| Endpoint accepts arbitrary JSON, blind-binds to model | Add explicit DTO/serializer | Lint rule banning `params.permit!` / `Meta.fields = "__all__"` / unsafe binding |
| GraphQL introspection on in production | Toggle off | Bake into deploy config; add CI check |
| No rate limit on `/login`, `/password-reset`, OTP | Add limiter via gateway | Multi-dimensional limits on every auth-adjacent endpoint |
| Sequential integer IDs on user-facing resources | Add per-IP rate limit; alert on high-velocity enumeration | Migrate to opaque IDs in new endpoints |
| Mobile API returns more fields than web | Audit responses; lock to explicit schema | Single response-schema definition shared across clients |

## Automated tests

```python
def test_user_cannot_access_other_users_order(client, user_a, user_b):
    order = create_order(owner=user_b)
    response = client.get(f"/api/orders/{order.id}",
                          headers={"Authorization": f"Bearer {user_a.token}"})
    assert response.status_code in (403, 404)

def test_cannot_set_is_admin_via_profile_update(client, user_a):
    response = client.put(f"/api/users/{user_a.id}",
                          headers={"Authorization": f"Bearer {user_a.token}"},
                          json={"name": "ok", "is_admin": True})
    assert response.status_code in (200, 400)
    user_a.refresh()
    assert user_a.is_admin is False

def test_login_rate_limited(client):
    # 10 attempts fast — at least one should be rate-limited
    statuses = []
    for _ in range(10):
        r = client.post("/login", json={"email": "x@x.com", "password": "wrong"})
        statuses.append(r.status_code)
    assert 429 in statuses

def test_graphql_depth_limit(client, user_token):
    deep_query = "{" + "user { friends {" * 15 + "id" + "}}" * 15 + "}"
    r = client.post("/graphql", json={"query": deep_query},
                    headers={"Authorization": f"Bearer {user_token}"})
    assert r.status_code == 400
    assert "depth" in r.text.lower()
```

## Tools

| Tool | Role |
|---|---|
| **Burp Suite Pro / OSS** | Repeater + Intruder for ID enumeration |
| **Autorize (Burp extension)** | Auto-detects BOLA: replays every request as a different user |
| **API Security Empire** | DAST for OWASP API Top 10 |
| **Akto, Postman Security, 42Crunch** | Schema-aware API DAST |
| **GraphQL Voyager / inql** | Map a GraphQL schema visually |
| **graphql-armor** | Drop-in GraphQL hardening for Apollo |
| **Pydantic / Zod / Joi / Jakarta Bean Validation** | Schema validation libraries |
| **Semgrep rules** | `permit!`, `fields = "__all__"`, missing `permission_classes` |

## Common mistakes when defending

- **"Auth at the gateway is enough."** It authenticates. Per-endpoint code still has to authorize.
- **Trusting that mobile or partner clients won't send unexpected fields.** Anyone can replay HTTP requests.
- **Using opaque IDs as your *only* defense.** UUIDs slow enumeration; they don't replace auth.
- **Per-IP rate limit only.** Distributed source IPs are cheap.
- **GraphQL introspection on "for the docs."** Generate static docs from a schema file; don't expose live introspection.
- **Different schemas for mobile and web.** Two surfaces, double the BOPLA risk. Unify.

## Going further

- [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)
- [Inon Shkedy — A deep dive on BOLA](https://inonst.medium.com/a-deep-dive-on-the-most-critical-api-vulnerability-bola-1342224ec3f2)
- [Akto — APIsec University](https://www.akto.io/academy)
- [Apollo — Securing your GraphQL API](https://www.apollographql.com/docs/router/configuration/authn-jwt/)
- [graphql-armor](https://github.com/Escape-Technologies/graphql-armor)
- [PortSwigger — GraphQL API vulnerabilities](https://portswigger.net/web-security/graphql)
- [crAPI scenarios](https://github.com/OWASP/crAPI/blob/main/docs/scenarios.md)
