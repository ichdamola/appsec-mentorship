# Week 12: XXE, File Upload, and Path Traversal

## 🎯 What you'll learn

- Exploit **XML External Entity (XXE)** for file disclosure, SSRF, and blind data exfiltration
- Bypass file-upload validation (extension, MIME type, magic-byte checks)
- Recognize **path traversal** in URLs, filenames, and archive extraction (zip slip)
- Walk an ImageMagick exploit (the "Image Tragick" class)
- Design upload pipelines that are safe under adversarial input

By the end of this week you'll be able to:

- Read XML-handling code and identify whether the parser fetches external entities
- Build an upload that survives every common naive filter and reaches the storage layer
- Detect path-traversal patterns even after various encodings
- Architect an upload pipeline with content scanning + sandboxed processing

## ⚠️ Scope reminder

**Lab only.** XXE can reach internal services (same risks as Week 08 SSRF). File-upload exploits can place real malware. See [root readme](../readme.md#️-ethics--scope).

## 🧰 Lab setup

### Lab 1: PortSwigger Academy — XXE

[9 XXE labs](https://portswigger.net/web-security/xxe). Recommended:

1. ["Exploiting XXE using external entities to retrieve files"](https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-retrieve-files)
2. ["Exploiting XXE to perform SSRF"](https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-perform-ssrf-attacks)
3. ["Blind XXE with out-of-band interaction"](https://portswigger.net/web-security/xxe/blind/lab-blind-xxe-with-out-of-band-interaction)

### Lab 2: PortSwigger Academy — File upload + path traversal

- ["Remote code execution via web shell upload"](https://portswigger.net/web-security/file-upload/lab-file-upload-remote-code-execution-via-web-shell-upload)
- ["Web shell upload via Content-Type restriction bypass"](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-content-type-restriction-bypass)
- ["File path traversal, simple case"](https://portswigger.net/web-security/file-path-traversal/lab-simple)

### Lab 3: DVWA

```bash
docker run -d -p 80:80 vulnerables/web-dvwa
```

The "File Inclusion" and "File Upload" modules at low/medium/high difficulties.

## ✅ Your job

1. **Solve the XXE file-retrieval lab cold.** This is the simplest XXE pattern.
2. **Solve the SSRF-via-XXE lab.** Same XXE primitive, different exfil destination.
3. **Solve "Web shell upload via Content-Type restriction bypass."** Several layers of validation, each defeatable.
4. **Solve "File path traversal, simple case."** Read the encoding tricks in [attack.md](attack.md).
5. **Read [attack.md](attack.md).**
6. **Read [defense.md](defense.md).**

## 📚 Required reading

| Resource | Why | Time |
|---|---|---|
| [PortSwigger — XXE](https://portswigger.net/web-security/xxe) | Best overview | 45 min |
| [PortSwigger — File upload vulnerabilities](https://portswigger.net/web-security/file-upload) | Best overview | 30 min |
| [PortSwigger — Path traversal](https://portswigger.net/web-security/file-path-traversal) | The encoding catalog | 20 min |
| [OWASP — XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html) | Defense by language | 20 min |
| [Snyk — Zip Slip](https://snyk.io/research/zip-slip-vulnerability) | The archive-extraction variant | 15 min |

## 💡 What you should already know

- XML basics (elements, attributes, what a DTD is)
- How HTTP file uploads work (multipart/form-data)
- What an absolute vs. relative path is in Unix and Windows
- That SSRF reachability matters here too (see [Week 08](../week-08-ssrf/))
