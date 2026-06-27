# Week 11: Defense - Insecure Deserialization

You've seen the chains in [attack.md](attack.md). The defenses are unusually clean: this is a class where the right answer is mostly "don't do the thing."

---

## The single rule

> **Never deserialize untrusted bytes with formats that carry behavior.**

If you're sending data over the wire, use a *data format* - JSON, Protobuf, MsgPack - not a *behavior-carrying serializer* - Java `ObjectInputStream`, Python pickle, PHP `unserialize`, .NET `BinaryFormatter`.

If you must deserialize behavior-carrying formats (legacy compatibility, perf), make sure the bytes are *from your own code*, not from an untrusted source - and validate integrity with a signature.

## Defense 1: Use safe formats

| Untrusted input | Use |
|---|---|
| Browser → API | JSON (schema-validated) |
| Service → service (internal) | Protobuf, JSON, MsgPack |
| Object persistence (DB) | JSON column, or a vetted ORM serializer |
| Message queues (Celery, Sidekiq) | JSON (Celery >=4 defaults to JSON; ensure you didn't switch back to pickle) |
| Cache (Redis) | JSON, MsgPack |
| Session cookies | Signed JSON (Django's `signed_cookies` style), or opaque server-side |

JSON is the easy answer for ~90% of cases. The remaining 10% (binary data, large structured data) goes to Protobuf or similar - also behavior-free.

## Defense 2: Validate with a schema

Just choosing JSON isn't enough - the receiver should validate the shape:

```python
from pydantic import BaseModel

class TransferRequest(BaseModel):
    to_account: str
    amount_cents: int
    memo: str | None = None

# safe
transfer = TransferRequest.model_validate_json(request.body)
```

Pydantic raises on shape mismatch. Equivalent in other languages:

| Language | Library |
|---|---|
| Python | Pydantic, marshmallow |
| Node | Zod, AJV |
| Java | Jackson with Bean validation, Protobuf |
| Go | Standard library `json.Unmarshal` into typed struct + validation |
| Ruby | dry-schema, dry-validation |

Schema-first design prevents:

- Class injection (the schema doesn't permit `$type`)
- Extra fields (mass assignment - Week 03)
- Type confusion ("amount" arrives as a list)

## Defense 3: Sign the bytes if you can't change the format

When you're stuck with PHP serialization in cookies (legacy), or Java-RMI between trusted services, add an HMAC:

```python
import hmac, hashlib

def safe_dumps(obj, key):
    payload = serialize(obj)
    sig = hmac.new(key, payload, hashlib.sha256).digest()
    return sig + payload

def safe_loads(data, key):
    sig, payload = data[:32], data[32:]
    expected = hmac.new(key, payload, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected):
        raise TamperedError
    return deserialize(payload)
```

Two important caveats:

- **Validate signature BEFORE deserialization.** The vulnerable code does `unserialize($_COOKIE['x'])` then "validates" - the deserialization already ran.
- **HMAC key must be a real secret.** Hardcoded keys in code that's accessible are useless.

## Defense 4: Allow-list classes when format is fixed

If you genuinely need to deserialize Java/etc. behavior-carrying formats - *with* signatures *and* trusted source - restrict which classes can be reconstructed:

### Java - JEP 290 + ObjectInputFilter

```java
ObjectInputStream ois = new ObjectInputStream(stream);
ois.setObjectInputFilter(filter -> {
    if (filter.serialClass() == null) return Status.ALLOWED;
    String name = filter.serialClass().getName();
    if (List.of("com.myapp.SafeClass1", "com.myapp.SafeClass2").contains(name)) {
        return Status.ALLOWED;
    }
    return Status.REJECTED;
});
```

Or set a global filter via `jdk.serialFilter` system property.

### Python pickle - don't. Switch to JSON.

> ⚠️ **This section is for completeness; do not ship a `find_class` allow-list as your defense.** Pickle's `REDUCE` opcode lets an attacker craft payloads whose `__reduce__` returns `(allowed_callable, (attacker_iter,))` - the iterator can itself be a class call into anything else in the allow-list, and chains across allow-listed classes have been demonstrated. The right answer is: **change the data format to JSON** (or msgpack with no extension types, or protobuf). The format is the defense.

If you absolutely cannot change the format, here is the minimal shape:

```python
import pickle

ALLOWED = frozenset({
    # Only immutable primitives. Adding any class with side effects on
    # construction (or with a __reduce__ that takes a callable) is a foothold.
    ("builtins", "int"), ("builtins", "float"), ("builtins", "str"),
    ("builtins", "tuple"), ("builtins", "frozenset"),
})

class SafeUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if (module, name) not in ALLOWED:
            raise pickle.UnpicklingError(f"forbidden: {module}.{name}")
        return getattr(__import__(module), name)

SafeUnpickler(stream).load()
```

Even this is research-territory: bypass papers exist for restrictive allow-lists when combined with pickle's stack-machine semantics. The robust answer is still: **don't use pickle for data from outside the trust boundary.**

### .NET - drop BinaryFormatter

There's no good way to safely use `BinaryFormatter` with untrusted input. Microsoft's official guidance is: replace it. Use `System.Text.Json` or Protobuf.

## Defense 5: Network and process isolation

If the deserializer must run untrusted bytes (some legacy patterns are stuck), run it in a sacrificial process or container with:

- No network egress
- No filesystem write access
- Severe CPU/memory limits
- `seccomp` profile blocking `execve`

An RCE in that sandbox can't reach anything useful.

## Defense 6: Dependency hygiene

Java's deserialization vulnerabilities are mostly in libraries (Apache Commons Collections, Spring AOP, etc.). Keep dependencies current:

- **Dependabot / Renovate** - auto-PR new versions
- **SCA tools** - Snyk, Trivy, GitHub Advanced Security
- **Known-vulnerable version flagging** - fail the build if a CVE-bearing version is included

For Java specifically, [JEP 290](https://openjdk.org/jeps/290) (Filter Incoming Serialization Data) ships with JDK 9+. Enable a global filter.

## Defense in depth

| Layer | What it catches |
|---|---|
| Safe data format (JSON + schema) | The whole bug class |
| HMAC signature on serialized payloads | Tampering |
| Class allow-list | Untrusted class injection |
| Updated dependencies | Library-gadget chains |
| Process isolation | Limits damage of RCE |
| WAF rules for known payload shapes | Catches some opportunistic exploitation |
| Outbound monitoring (Week 08-style) | Detection after the fact |

---

## Detection

### Signal 1: Known payload prefixes in HTTP traffic

```
| where post_body matches "(?i)(rO0AB|\\xac\\xed\\x00\\x05|\\x80\\x04\\x95)"
   or cookies matches "(?i)O:\d+:\""
   or post_body matches "\"\\$type\":"
| stats count by client_ip, endpoint
```

Vanishingly rare in legitimate traffic. Almost always either:

- Legitimate internal service-to-service traffic (allow-list source)
- Exploit attempt (alert)

### Signal 2: Server processes spawning shells after deserialization

```
| where process_name in (java_processes)
   and child_process in (sh, bash, cmd.exe, powershell.exe)
```

A web application server forking a shell is almost always a deserialization RCE. (Or a [Week 07](../week-07-ssti-and-command-injection/) command injection.)

### Signal 3: Outbound connections from deserializer-using processes

Gadget chains often callback to the attacker. Pair with Week 08's outbound-monitoring signals.

### Signal 4: Failed deserialization spikes

If your deserialization has logging on failures, a spike of failures indicates probing:

```
| where event = "deserialize_failed"
| stats count by client_ip
| where count > 5
```

The attacker is trying different payloads; some failures are normal as they probe shapes.

---

## Remediation playbook

| Finding | Immediate action | Longer fix |
|---|---|---|
| Java `ObjectInputStream.readObject()` on untrusted input | Set ObjectInputFilter immediately; rotate any leaked secrets | Migrate to JSON+schema |
| `pickle.loads()` on untrusted input | Replace with `json.loads()`; ship | Lint rule banning pickle on untrusted sources |
| `unserialize()` in PHP on untrusted cookies | Replace with `json_decode()`; sign cookies | Audit entire cookie handling |
| `BinaryFormatter.Deserialize` in .NET | Replace with `System.Text.Json` | Remove BinaryFormatter from project |
| Jackson with `enableDefaultTyping` | Switch to explicit `@JsonTypeInfo` per class | Audit deserializers fleet-wide |
| Vulnerable Apache Commons Collections version | Upgrade in patch release | Fail builds on known-vulnerable versions |

## Automated tests

```python
def test_endpoint_rejects_pickle_payload(client):
    import pickle
    class Evil:
        def __reduce__(self):
            return (str, ('not executed',))
    payload = pickle.dumps(Evil())
    response = client.post("/api/import", data=payload,
                           content_type="application/octet-stream")
    # The endpoint must not even attempt to deserialize via pickle
    assert response.status_code in (400, 415)

def test_json_schema_rejects_extra_fields(client):
    response = client.post("/api/profile",
                           json={"name": "alice", "is_admin": True})  # extra field
    assert response.status_code == 400  # schema rejects

def test_no_pickle_imports(monkeypatch):
    # CI-time check that no production module imports pickle
    import importlib, pkgutil
    for module_info in pkgutil.iter_modules(myapp.__path__):
        mod = importlib.import_module(f"myapp.{module_info.name}")
        assert "pickle" not in dir(mod), f"{module_info.name} imports pickle"
```

## Tools

| Tool | Role |
|---|---|
| **ysoserial / ysoserial.net** | Generate gadget payloads (lab) |
| **GadgetProbe** | Identifies deserialization gadget candidates in Java targets |
| **Burp Suite extension: Java Deserialization Scanner** | Active scan for the bug |
| **Semgrep** | Rules for `pickle.loads`, `ObjectInputStream`, `unserialize`, `BinaryFormatter` |
| **CodeQL** | Data-flow analysis for untrusted-input → deserialize sinks |
| **Trivy / Snyk / OWASP Dependency Check** | Find known-vulnerable library versions |

## Common mistakes when defending

- **Allow-listing classes when you should just use JSON.** The allow-list is fragile and easy to break with future code changes.
- **HMAC verification *after* deserialization.** The deserialize is the bug; verifying after is too late.
- **Trusting "we only deserialize internal traffic."** Internal services have been the breach point in many incidents.
- **`enableDefaultTyping` "with whitelist" in Jackson.** Most "fixes" of this still have known bypasses; rip it out.
- **Keeping Apache Commons Collections "for one library that needs it."** Eventually you have a chain.

## Going further

- [PortSwigger - Insecure deserialization](https://portswigger.net/web-security/deserialization)
- [OWASP - Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [Frohoff & Lawrence - Java Deserialization Vulnerabilities (AppSec USA 2015)](https://frohoff.github.io/appseccali-marshalling-pickles/) - the talk that made everyone realize this was bad
- [Foxglove Security - What do WebLogic, WebSphere, JBoss, Jenkins, OpenNMS, and your application have in common?](https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/) - the seminal real-world chain writeup
- [JEP 290 - Filter Incoming Serialization Data](https://openjdk.org/jeps/290)
