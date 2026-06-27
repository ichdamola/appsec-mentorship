# Week 03: Defense - Stopping Broken Access Control

You've now exploited the IDOR / forced-browsing / mass-assignment family. Now: the defenses that make them impossible.

---

## The single rule

> **Deny by default. Every request, every object, every field - explicitly authorize.**

Access control bugs win when developers default to "allow" and then list the things that aren't allowed (a denylist). The denylist always has gaps. Flip it: default deny; explicitly authorize each access.

## Authorize at the object level, not the endpoint level

**Wrong pattern (endpoint-level only):**

```python
@route('/api/users/<id>')
@login_required
def get_user(id):
    return User.objects.get(id=id)   # any logged-in user reads any user
```

`@login_required` says "is *some* user logged in?" but never asks "does *this* user have permission to read *that* object?" That's the IDOR.

**Right pattern (object-level):**

```python
@route('/api/users/<id>')
@login_required
def get_user(id):
    user = User.objects.get(id=id)
    require_can_read(request.user, user)   # raises 403 if not authorized
    return user
```

Better: use a query that already filters by ownership:

```python
@route('/api/users/<id>')
@login_required
def get_user(id):
    # Returns 404 if id doesn't belong to the requester
    return User.objects.get(id=id, owner=request.user)
```

Returning 404 instead of 403 is a small win - it doesn't leak object existence.

## Centralize authorization logic

If every endpoint has its own check, you'll forget some. Centralize:

| Approach | How |
|---|---|
| **Policy classes** (Rails Pundit, Laravel Policies, Django Guardian) | One class per resource. Endpoints call `authorize(action, object)`. |
| **OPA (Open Policy Agent)** | Authorization rules as code, evaluated centrally. Used for cross-service auth. |
| **Casbin** | Library implementing common patterns (RBAC, ABAC, ACL). |
| **Framework middleware** | Some frameworks (Spring Security, FastAPI dependencies) make declarative auth idiomatic. |

The win: one policy file per resource, not one check per endpoint. Reviewers can see "what's allowed on `User`?" in one place.

## RBAC vs. ABAC - pick consciously

| Model | Best for | Example |
|---|---|---|
| **RBAC** (Role-Based) | Coarse-grained roles, small role count | "admin can do X, member can do Y" |
| **ABAC** (Attribute-Based) | Fine-grained, dynamic conditions | "engineer can read PRs they're a reviewer on" |
| **ReBAC** (Relationship-Based, Zanzibar-style) | Sharing models with arbitrary relationships | Google Docs, GitHub repos |

Most apps start RBAC, end up ABAC. The mistake is **mixing them ad-hoc** - half the codebase checks `user.role == 'admin'`, the other half checks `user.has_permission('delete_user')`. Pick one model and apply it consistently.

## Allow-list inputs (defeats mass assignment)

Never trust the request body wholesale. Allow-list the fields a user can modify:

**Wrong:**

```python
@route('/api/users/me', methods=['PATCH'])
def update_me():
    user = request.user
    for key, value in request.json.items():
        setattr(user, key, value)   # role=admin? sure.
    user.save()
```

**Right (Django-style serializer):**

```python
class UserSelfUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['name', 'email', 'avatar']   # explicit allow-list

@route('/api/users/me', methods=['PATCH'])
def update_me():
    serializer = UserSelfUpdateSerializer(request.user, data=request.json, partial=True)
    serializer.is_valid(raise_exception=True)
    serializer.save()
```

The `role` field isn't in the serializer's allow-list, so attempts to set it are silently dropped. (Some frameworks log it as a warning - useful detection signal.)

## Method-level access control on every endpoint

For every endpoint, document **every method** it accepts and what protects it:

```python
@route('/api/users/<id>', methods=['GET', 'PATCH', 'DELETE'])
@authorize('users', lambda r, id: User.objects.get(id=id))
def user_view(id):
    ...
```

A linter that asserts every route has an `@authorize` decorator (or an explicit `@public` marker) catches the forgotten-DELETE bug at code review.

## Defense in depth

Even with object-level authz:

| Layer | What it catches |
|---|---|
| Application authorization | Primary defense |
| Database row-level security (PG RLS, Spanner DLP) | Catches direct DB access bugs |
| Audit logging | Catches what you missed in real time |
| Honeypot endpoints (`/admin-prod`) | Detection signal: only attackers visit |
| Rate limiting per endpoint | Slows enumeration |
| Random / UUID object IDs | Doesn't prevent IDOR, but makes enumeration harder |

> 💡 **Note on UUIDs:** Replacing numeric IDs with UUIDs is *not* a fix for IDOR. UUIDs make enumeration harder, but if the bug exists, an attacker still wins via any leak that exposes the UUID (logs, sharing links, error messages). UUIDs are obscurity, not access control. Add proper authorization too.

---

## Detection - what does this look like in logs?

Access control violations are subtle in logs because successful exploitation looks like a normal request. You need *behavioral* signals.

### Signal 1: Enumeration on ID-bearing endpoints

A single client requesting many different object IDs in a short window:

```
| stats values(object_id) as ids, count by client_ip, endpoint
| where mvcount(ids) > 50 and count > 100
```

Legitimate users typically access a small set of objects. Attackers iterating through IDs stand out.

### Signal 2: 403 / 404 spikes

Sudden burst of 403/404 from one user is often forced browsing:

```
| where status in (403, 404)
| stats count by user_id, client_ip
| where count > 50
```

Tune; some apps have legitimately high 404 rates (referrer-based, etc.).

### Signal 3: Cross-tenant access in multi-tenant SaaS

If your data model has organizations and a request from a user crosses an org boundary, log and alert:

```python
def authorize(user, obj):
    if obj.org_id != user.org_id:
        log.warning("cross_org_access_attempted",
                    user_id=user.id, user_org=user.org_id,
                    object_id=obj.id, object_org=obj.org_id)
        raise PermissionDenied
```

This is one of the highest-fidelity signals in B2B SaaS - almost no legitimate traffic.

### Signal 4: Admin endpoint access by non-admin

```
| search endpoint=/admin/*
| join user_id [
    | search role!="admin"
  ]
| stats count by user_id, client_ip, endpoint
```

If you see hits, somebody is finding admin URLs they shouldn't even know about.

---

## Remediation playbook

| Finding | Immediate action | Longer fix |
|---|---|---|
| IDOR found | Add object-level check + return 404 instead of 403 | Audit *every* endpoint with ID parameters; add linter for missing `@authorize` |
| Forced browsing into `/admin` | Add auth check in route; ship today | Centralize all admin endpoints under one auth middleware |
| Mass assignment | Replace `update(**body)` with allow-list serializer | Adopt serializer-per-endpoint pattern everywhere |
| Method-specific gap (e.g. only `DELETE` unprotected) | Add method-level test | Required: every endpoint declares its allowed methods explicitly |
| GraphQL field-level miss | Add resolver-level check; mark field admin-only | Generate field permissions from a schema annotation |

## Automated tests

Two pair: one that proves you *can't* access something, one that proves you *can*.

```python
def test_user_cannot_read_other_users_profile(client, alice_token, bob_id):
    response = client.get(f"/api/users/{bob_id}/profile",
                          headers={"Authorization": f"Bearer {alice_token}"})
    assert response.status_code == 404   # we prefer 404 to 403

def test_user_can_read_own_profile(client, alice_token, alice_id):
    response = client.get(f"/api/users/{alice_id}/profile",
                          headers={"Authorization": f"Bearer {alice_token}"})
    assert response.status_code == 200

def test_non_admin_cannot_delete_user(client, member_token, target_id):
    response = client.delete(f"/api/users/{target_id}",
                             headers={"Authorization": f"Bearer {member_token}"})
    assert response.status_code in (403, 404)

def test_mass_assignment_role_field_ignored(client, alice_token):
    response = client.patch("/api/users/me",
                            json={"name": "alice", "role": "admin"},
                            headers={"Authorization": f"Bearer {alice_token}"})
    assert response.status_code == 200
    me = response.json()
    assert me["role"] != "admin"   # role change silently dropped
```

Wire these into CI. A regression here is a CVE.

## Tools

| Tool | Role |
|---|---|
| **Burp Suite (Authz extension, Autorize)** | Replays every request as a second user and flags responses that differ |
| **ffuf / dirsearch / gobuster** | Forced browsing fuzzing |
| **Semgrep (`generic.secrets.security-audit.express-route-missing-auth`)** | Static rules for missing auth decorators |
| **Open Policy Agent (OPA)** | Centralized policy evaluation across services |
| **PostgreSQL Row-Level Security (RLS)** | Database-level enforcement; defense in depth |

## Common mistakes when defending

- **`@login_required` and calling it done.** That's authentication, not authorization.
- **Authorization in the controller only.** A new service that reuses the model bypasses the controller; auth needs to be near the data.
- **403 leaking object existence.** Use 404 for "this isn't yours" - denies enumeration.
- **Trusting the gateway's `X-Forwarded-User` header.** Anyone can send that header; only trust it after the gateway has stripped any client-supplied version.
- **GraphQL with introspection enabled in production.** Lets attackers discover every field, including the ones with missing checks.

## Going further

- [OWASP - Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- [Google's Zanzibar paper](https://research.google/pubs/pub48190/) - the canonical text on relationship-based access control at scale
- [PortSwigger - Access Control](https://portswigger.net/web-security/access-control)
- [HackerOne's IDOR hacktivity](https://hackerone.com/hacktivity?querystring=idor) - read the public disclosures
