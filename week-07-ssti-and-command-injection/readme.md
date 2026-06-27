# Week 07: Server-Side Template Injection (SSTI) & Command Injection

## 🎯 What you'll learn

- Identify SSTI in any template engine by the math-test pattern (`{{7*7}}` returns `49`)
- Walk a Jinja2 / Twig / Velocity / Freemarker SSTI to remote code execution
- Recognize command injection in subprocess calls - and the subtle "argument injection" cousin
- Understand why `shell=True` is the foot-gun and what to use instead
- Distinguish "blind" command injection (no output) from "in-band"

By the end of this week you'll be able to:

- Probe any user input that ends up in a server-rendered template or shell command for injection
- Walk a Jinja2 chain to read files or get a reverse shell *in a lab*
- Identify dangerous subprocess patterns in code review (Python, Node, Java, Go)
- Write secure subprocess code that's still ergonomic

## ⚠️ Scope reminder

**Lab only.** Especially this week - RCE techniques are the most directly damaging in this curriculum. Never run any of this against systems you don't own. See [root readme](../readme.md#️-ethics--scope).

## 🧰 Lab setup

### Lab 1: PortSwigger Academy - SSTI

[7 SSTI labs](https://portswigger.net/web-security/server-side-template-injection). Recommended:

1. ["Basic server-side template injection"](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-basic)
2. ["Server-side template injection with information disclosure via user-supplied objects"](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-with-information-disclosure-via-user-supplied-objects)
3. ["Server-side template injection in a sandboxed environment"](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-in-a-sandboxed-environment)

### Lab 2: PortSwigger Academy - OS command injection

[5 command injection labs](https://portswigger.net/web-security/os-command-injection). Start with:

1. ["OS command injection, simple case"](https://portswigger.net/web-security/os-command-injection/lab-simple)
2. ["Blind OS command injection with time delays"](https://portswigger.net/web-security/os-command-injection/lab-blind-time-delays)

### Lab 3: Local vulnerable app

A minimal Flask app with both vulnerabilities, in `lab/` (we'd ship this with the repo for a fully-offline option). Until then, the PortSwigger labs are sufficient.

## ✅ Your job

1. **Solve the basic SSTI lab cold.** Then read about the Jinja2 `__class__` chain - that pattern shows up in CTFs constantly.
2. **Solve the basic command injection lab.** Then the blind one.
3. **Read [attack.md](attack.md).**
4. **Read [defense.md](defense.md).**

## 📚 Required reading

| Resource | Why | Time |
|---|---|---|
| [PortSwigger - Server-side template injection](https://portswigger.net/web-security/server-side-template-injection) | Best taxonomy | 45 min |
| [PortSwigger - OS command injection](https://portswigger.net/web-security/os-command-injection) | The other half | 30 min |
| [PayloadsAllTheThings - SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection) | Engine-specific payload reference (lab only) | 30 min |
| [OWASP - Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html) | Defense reference | 20 min |

## 💡 What you should already know

- Reading template syntax (Jinja2, Twig, ERB, etc.)
- Python's `subprocess` module and Node's `child_process`
- Shell metacharacters (`|`, `&`, `;`, `$()`, backticks)
- How standard input, stdout, stderr work in subprocesses
