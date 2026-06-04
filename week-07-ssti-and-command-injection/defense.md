# Week 07: Defense — Stopping SSTI & Command Injection

You've turned both bug classes into RCE in [attack.md](attack.md). The defenses share a single principle.

---

## The single rule

> **User input is *data*. Never let it become *code* — neither template code nor shell code.**

For templates: pass user input as template variables (data), not as part of the template source (code).

For commands: pass user input as arguments to a process executed without a shell, not as part of a string the shell parses.

## SSTI — defenses

### Rule 1: Never call `render_string` / `from_string` with user input

The single most common SSTI pattern in real codebases:

```python
# WRONG — user input becomes part of the template source
template = f"Hello {name}!"
return env.from_string(template).render()

# RIGHT — name is a variable, the template is static
return env.from_string("Hello {{ name }}!").render(name=name)

# BEST — the template is on disk, not constructed at runtime
return render_template("greeting.html", name=name)
```

Grep your codebase for these patterns:

| Pattern | Language |
|---|---|
| `from_string(` with non-literal first arg | Jinja2 (Python) |
| `new Template(` with non-literal first arg | Velocity, Freemarker (Java) |
| `Template.new(` | ERB (Ruby) |
| `eval(template_string)` | Various |
| `_.template(` | Lodash/Underscore (JS) |
| `compile(...)` then `tmpl(data)` | Handlebars (JS) |

Almost every match is either a bug or a place that needs careful review.

### Rule 2: Use a real sandbox if you must accept user templates

If your product genuinely needs user-supplied templates (email templates, dashboard widgets), use a sandboxed engine:

| Engine | Sandboxed alternative |
|---|---|
| Jinja2 | `jinja2.sandbox.SandboxedEnvironment` (still has bypasses; assume RCE possible) |
| Twig | `Twig\Sandbox\SecurityPolicy` |
| Freemarker | Configure `MemberAccessPolicy` to deny dangerous classes |
| Untrusted user expressions | Better: a custom mini-language (JSON Logic, CEL) without RCE primitives |

Even sandboxed engines have bypass histories. **Treat any template engine accepting untrusted input as eventually RCE.** Run it in an isolated container/process with no real privileges.

### Rule 3: Auto-escape doesn't help

Auto-escaping prevents *XSS* in the output — it escapes the *result* of evaluation. SSTI happens *during* evaluation, before any escaping. Auto-escape is orthogonal to SSTI defense.

### Rule 4: Filter incoming HTML before storing it in templated contexts

If user input ends up in a template variable that's later rendered, the variable substitution is safe. The risk is when *the template itself* incorporates user data. Keep templates and data separate at every layer.

## Command injection — defenses

### Rule 1: Never use `shell=True` with concatenated user input

```python
# WRONG
subprocess.run(f"ping -c 1 {host}", shell=True)

# RIGHT
subprocess.run(["ping", "-c", "1", host])
```

The list form passes args directly to `execve`; no shell parses them. Metacharacters in `host` are treated as literal characters of the argument, not parsed.

### Rule 2: Validate input shape

Even with list-form subprocess, user input shouldn't be a free-form string for most use cases:

```python
def ping(host):
    if not re.match(r'^[a-zA-Z0-9.-]+$', host):
        raise BadRequest("invalid host")
    if len(host) > 253:
        raise BadRequest("hostname too long")
    return subprocess.check_output(["ping", "-c", "1", "--", host])
```

The validation:

- Restricts the alphabet (no spaces, no shell metas, no `-` to prevent argument injection)
- Bounds the length
- Uses `--` to terminate options (where supported by the tool) — anything after `--` is a positional argument, never a flag

### Rule 3: Prefer the language API over the CLI

For most tools, there's a library:

| Don't call | Do call |
|---|---|
| `convert input.jpg output.png` (ImageMagick CLI) | Pillow (Python) / Sharp (Node) |
| `curl URL` | `requests.get(url)` / `fetch(url)` |
| `tar -xf archive.tar` | Python `tarfile` module |
| `unzip archive.zip` | Python `zipfile` module |
| `git clone URL` | Library bindings (libgit2, JGit) |

The library API doesn't pass through a shell or get tricked by `--flag-name` arguments.

### Rule 4: When you must call the CLI, allow-list the binary

```python
ALLOWED_BINARIES = {"ping", "traceroute", "dig"}

def run_diagnostic(tool, target):
    if tool not in ALLOWED_BINARIES:
        raise BadRequest("unknown tool")
    if not re.match(r'^[a-zA-Z0-9.-]+$', target):
        raise BadRequest("invalid target")
    return subprocess.check_output([tool, target], timeout=5)
```

### Rule 5: Drop privileges

If the subprocess truly needs to run, give it the smallest possible privileges:

```python
subprocess.run(
    ["nice", "-n", "19", "convert", input_path, output_path],
    user="nobody",      # Python 3.9+ only
    group="nogroup",    # Python 3.9+ only
    cwd="/var/run/sandbox",
    env={"PATH": "/usr/bin"},
    timeout=30,
    capture_output=True
)
```

> ℹ️ `user=` and `group=` are Python 3.9+. On older runtimes, the production-grade pattern is to invoke a wrapper shell script via `sudo -u nobody` (with a tight sudoers rule) — `preexec_fn=os.setuid` works but has signal-handling caveats and is hard to get right.

Better: containerize. Run the conversion in a single-purpose container with no network and a read-only filesystem outside the working directory.

## Defense in depth

| Layer | What it catches |
|---|---|
| Input validation (allow-list alphabet) | Most opportunistic payloads |
| `subprocess` list-form (no shell) | The metacharacter family |
| `--` terminator + leading-dash check | Argument injection |
| Library API instead of CLI | Tool-specific RCE primitives |
| Reduced-privilege execution (Linux capabilities) | Limits damage if RCE lands |
| Containerized execution | Isolation if RCE lands |
| Outbound network egress filtering | Stops command-injection callbacks |
| `seccomp` / `AppArmor` profiles | Blocks unexpected syscalls (block `execve` of `/bin/sh`?) |

---

## Detection

### Signal 1: Shell metacharacters in parameters

```
| where uri_query matches "[;|&`$]"
   or post_body matches "[;|&`$]"
| stats count by client_ip, user_id, endpoint
| where count > 3
```

Tune by parameter; some legitimate inputs contain these characters.

### Signal 2: SSTI math-test patterns

```
| where uri_query matches "\{\{[^}]*\d+[*+\-/]\d+[^}]*\}\}"
   or post_body matches "\$\{[^}]*\d+[*+\-/]\d+[^}]*\}"
```

Almost no legitimate traffic has `{{7*7}}`-style patterns in query strings. Spike = scanner or attacker probing.

### Signal 3: Outbound connections from app servers

Application servers shouldn't initiate outbound connections to random destinations. Build a baseline:

- Known good: package mirrors, API partners, DNS resolvers
- Anything else: investigate

If a workload that normally only talks to `api.stripe.com` and `db.internal` suddenly does a DNS lookup for `victim.attacker.example`, that's command injection or SSTI calling home.

### Signal 4: New child processes from web-server processes

Process-execution telemetry (Linux auditd, Sysmon on Windows, EDR products):

```
| where parent_image in (web_server_paths)
   and child_image in (suspect_paths)
```

`nginx` forks `/bin/sh -c curl http://...` = problem. `gunicorn` forks `/usr/bin/python` to do its job = normal. Tune by baseline.

### Signal 5: SSTI-derived environment access

In Python apps, SSTI often results in reading `os.environ`. If your secret store is in env vars, watch for spikes in secret-shaped reads from app processes that shouldn't be touching them.

---

## Remediation playbook

| Finding | Immediate action | Longer fix |
|---|---|---|
| SSTI in a template-string call | Replace `from_string(user_input)` with parameterized template | Lint rule banning the pattern |
| `shell=True` with user input | Refactor to list-form; ship today | Repo-wide ban on `shell=True` (linter) |
| Argument injection via CLI tool | Add `--` terminator + alphabet allow-list | Migrate to library API |
| ImageMagick/Ghostscript exposure | Disable risky policy entries (`coders`); update to patched version | Move to Pillow / Sharp |
| Subprocess sudo / root | Drop to least-privilege user | Containerize the workload |

## Automated tests

```python
def test_ssti_math_not_evaluated(client):
    response = client.post("/preview", json={"template": "{{7*7}}"})
    assert "49" not in response.text
    assert "{{7*7}}" in response.text   # echoed literally, not evaluated

def test_command_injection_in_host_param(client):
    response = client.get("/ping?host=8.8.8.8;id")
    # Even if the response is the ping output, it must NOT contain `uid=` (id output)
    assert "uid=" not in response.text

def test_subprocess_called_without_shell(monkeypatch):
    calls = []
    def fake_run(*args, **kwargs):
        calls.append((args, kwargs))
        return Mock(returncode=0, stdout=b"", stderr=b"")
    monkeypatch.setattr("subprocess.run", fake_run)
    do_ping("example.com")
    args, kwargs = calls[0]
    assert isinstance(args[0], list), "subprocess.run was called with a string; use list form"
    assert kwargs.get("shell", False) is False
```

## Tools

| Tool | Role |
|---|---|
| **Burp Suite (Active Scan)** | Finds SSTI and command injection during crawl |
| **tplmap** | SSTI exploitation framework (sqlmap for templates) — lab only |
| **Semgrep** | Static rules for `shell=True`, `from_string(`, `eval(` with non-literal arg |
| **CodeQL** | Data-flow analysis catches source-to-sink paths for both classes |
| **Bandit** (Python) | Detects `subprocess` with `shell=True` and similar patterns |
| **gosec** (Go) | Equivalent for Go |

## Common mistakes when defending

- **Filtering specific shell characters.** Bypasses are routine. Switch to list-form subprocess.
- **Sandboxed Jinja2 as a hard guarantee.** It's defense in depth; assume RCE is possible.
- **Auto-escape "fixes SSTI."** It doesn't — escape happens after evaluation.
- **`--` saves you from all argument injection.** Tool-dependent. Some tools (Java's `Runtime.exec`) don't honor it. Allow-list inputs too.
- **Trusting subprocess list form when one arg can include flags.** Always check arg [0] doesn't start with `-` if it's user-controlled.

## Going further

- [PortSwigger — SSTI](https://portswigger.net/web-security/server-side-template-injection)
- [PortSwigger — OS command injection](https://portswigger.net/web-security/os-command-injection)
- [OWASP — Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
- [PayloadsAllTheThings — SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)
- [GTFOBins](https://gtfobins.github.io/) — for every common Unix binary, the documented ways it can be abused (read in lab/CTF context)
