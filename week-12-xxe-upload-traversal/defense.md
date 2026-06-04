# Week 12: Defense — XXE, File Upload, Path Traversal

Three related bug classes, three related defenses.

---

## The single rules

> **XXE:** disable external entity processing in every XML parser. Default config of every modern XML library should already do this; verify.
> **Uploads:** validate by **content**, not by **name**. Process in a sandbox. Store with a randomized name in a non-executable location.
> **Path traversal:** never concatenate user input into filesystem paths. Resolve, then verify the result is inside the intended directory.

## XXE — disable external entities

### Python (lxml / xml.etree)

```python
# WRONG - lxml default
from lxml import etree
tree = etree.parse(filename)

# RIGHT - explicit safe parser
parser = etree.XMLParser(resolve_entities=False, no_network=True, dtd_validation=False)
tree = etree.parse(filename, parser)

# defusedxml - safest, drop-in
from defusedxml import ElementTree as ET
tree = ET.parse(filename)
```

**Always use `defusedxml` for untrusted XML.** It hardens against XXE, billion-laughs, and several other XML attacks. There's almost no reason to use the standard `xml.etree` directly.

### Java (DocumentBuilderFactory, SAX, JAXB)

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
```

The OWASP cheat sheet has identical lines for SAXParserFactory, XMLInputFactory, and other entry points. It's the same hardening, applied per parser.

### Node.js (fast-xml-parser, sax-js)

```javascript
// fast-xml-parser — secure by default
const parser = new XMLParser({
    ignoreAttributes: false,
    processEntities: false,  // don't process &custom;
    allowBooleanAttributes: false,
});
```

### .NET (XmlReader, XDocument)

```csharp
var settings = new XmlReaderSettings {
    DtdProcessing = DtdProcessing.Prohibit,
    XmlResolver = null
};
using var reader = XmlReader.Create(stream, settings);
```

### Verify by test

Always include a regression test:

```python
def test_xml_parser_rejects_external_entities():
    payload = '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>'''
    response = client.post("/api/import-xml", data=payload, content_type="application/xml")
    assert response.status_code in (200, 400)
    assert "root:" not in response.text     # /etc/passwd contents not in response
```

## Uploads — defense in layers

### Layer 1: Validate by content, not name

```python
import magic   # python-magic, libmagic bindings

def safe_upload(file):
    head = file.read(2048)
    file.seek(0)

    detected_type = magic.from_buffer(head, mime=True)
    if detected_type not in ALLOWED_MIME_TYPES:
        raise InvalidFileType(f"detected: {detected_type}")

    if detected_type.startswith("image/"):
        # re-encode through PIL to strip metadata + bad payloads
        from PIL import Image
        import io
        img = Image.open(io.BytesIO(head + file.read()))
        img.verify()  # raises on malformed images
        ...
```

The libmagic check looks at actual file content, not the client's claim. The PIL re-encode strips polyglot payloads — the output is a clean image regardless of what the input was.

### Layer 2: Randomize storage names

```python
import secrets, os

def store_upload(file, original_name):
    ext = os.path.splitext(original_name)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise InvalidExtension
    key = secrets.token_urlsafe(16) + ext
    storage.put(f"uploads/{key}", file.read())
    return key
```

Random names defeat path-traversal-via-filename, prevent guessing, and avoid filename-based execution surprises.

### Layer 3: Store outside the web root

Files served by your web server (Apache, nginx, IIS) sometimes execute by extension. Store uploads:

- In a different directory not configured to execute code
- On a different host (S3, GCS) entirely
- With explicit Content-Type when served, never relying on the server to "figure it out"

When serving:

```python
@route("/files/<key>")
def serve_file(key):
    # Authorization check
    if not user_can_read_file(current_user, key):
        abort(403)

    response = send_file(storage.get(f"uploads/{key}"))

    # RFC 6266 filename* encoding for the user-uploaded original name.
    # urllib.parse.quote with safe="" escapes everything non-ASCII and any
    # CR/LF — the latter is what blocks header injection if the stored
    # filename contains a literal \r\n.
    import urllib.parse
    safe_name = urllib.parse.quote(file_record.original_name, safe="")
    response.headers["Content-Disposition"] = (
        f"attachment; filename*=UTF-8''{safe_name}"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"                     # blocks MIME sniffing in browsers
    response.headers["Content-Type"] = "application/octet-stream"              # explicit + safe
    return response
```

### Layer 4: Process in a sandbox

If you process the file (resize, transcode, OCR), do it in a container or restricted process:

- No network
- Read-only filesystem outside `/tmp` or the input/output directory
- Strict CPU/memory limits
- Drop root, run as `nobody`
- Time limit (`timeout 30 ...`)

Image processing in particular has too many CVEs (ImageMagick, libpng, libwebp) to trust in your main process.

### Layer 5: Disable risky ImageMagick coders

If you use ImageMagick, harden `/etc/ImageMagick-6/policy.xml`:

```xml
<policymap>
  <policy domain="coder" rights="none" pattern="MVG" />
  <policy domain="coder" rights="none" pattern="MSL" />
  <policy domain="coder" rights="none" pattern="TEXT" />
  <policy domain="coder" rights="none" pattern="URL" />
  <policy domain="coder" rights="none" pattern="HTTPS" />
  <policy domain="coder" rights="none" pattern="HTTP" />
  <policy domain="coder" rights="none" pattern="EPHEMERAL" />
  <policy domain="path" rights="none" pattern="@*" />
</policymap>
```

Most distros ship this by default in 2026; verify.

### Layer 6: Scan for malware

For uploads that users will download (file-sharing features, marketplaces):

- ClamAV (open-source baseline)
- Commercial scanners (BinaryFox, VirusTotal API, MetaDefender)
- Async — scan after upload, mark "pending" until clean

## Path traversal — resolve and verify

### The pattern

```python
import os

UPLOAD_DIR = "/app/uploads"

def get_file(filename):
    requested = os.path.join(UPLOAD_DIR, filename)
    resolved = os.path.realpath(requested)
    if not resolved.startswith(UPLOAD_DIR + os.sep):
        raise PathTraversalDetected
    return open(resolved).read()
```

`realpath` resolves `..`, symlinks, and other tricks. The string-prefix check after resolution guarantees we're inside `UPLOAD_DIR` regardless of what the input claimed.

### Better: don't take user paths at all

```python
def get_file(file_id):  # file_id is an opaque ID, not a path
    file_record = File.objects.get(id=file_id, owner=current_user)
    return storage.get(file_record.storage_key)
```

The user references files by ID, never by path. The application maps ID → storage key. Path traversal becomes structurally impossible.

This is the right architecture for any new feature. Path-based access exists in legacy code; new features should avoid it.

### Zip slip — safe archive extraction

```python
import os
import stat
from zipfile import ZipFile

def safe_extract(zip_path, target_dir):
    """Extract one entry at a time, re-validating after each write, refusing
    symlink entries. The naive 'validate namelist then extractall' pattern is
    broken — it doesn't account for symlink entries (zip carries Unix mode
    bits and Python's zipfile extracts them as symlinks) or for TOCTOU between
    validation and extraction."""
    target_dir = os.path.realpath(target_dir)
    with ZipFile(zip_path) as z:
        for info in z.infolist():
            # Reject symlinks. A zip can contain a symlink entry pointing at
            # /etc/passwd followed by a file entry that writes "through" it.
            # The namelist check sees both paths under target_dir; the writer
            # follows the symlink and clobbers the host.
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise ValueError(f"symlink in archive: {info.filename}")

            destination = os.path.realpath(os.path.join(target_dir, info.filename))
            if destination != target_dir and not destination.startswith(target_dir + os.sep):
                raise ValueError(f"unsafe path in archive: {info.filename}")

            # Extract this single entry. Re-checking realpath() per-write
            # closes the TOCTOU window where an earlier-extracted directory
            # introduces a symlink that the validation didn't see.
            z.extract(info, target_dir)
```

Same idea: pre-validate every entry. Don't trust the archive's metadata.

> ⚠️ **Tarfiles**: Python 3.12+ ships `tarfile.extractall(..., filter='data')` which implements this hardening for you (CVE-2007-4559 hung around for 15 years before the stdlib fix). On 3.12+ use the filter; on older, use a vetted library. Don't reinvent.

Most archive libraries now have a `safe_extractall` variant — check yours.

## Defense in depth

| Layer | What it catches |
|---|---|
| XML parser with entities disabled | XXE |
| `defusedxml` (or equivalent) | XXE + adjacent XML attacks |
| Content-based MIME detection | Polyglot uploads, lying clients |
| Image re-encoding | Polyglot uploads, image library exploits |
| Randomized storage names | Path-based execution, predictable URLs |
| Storage outside web root | Webshell execution |
| Sandboxed processing | Damage limit if exploit lands |
| Realpath + prefix check | Path traversal |
| Opaque IDs for file references | Eliminates user-supplied paths |
| Malware scanning | User-facing redistribution |

---

## Detection

### Signal 1: XML payloads with DOCTYPE declarations

```
| where content_type matches "(xml|svg)"
   and request_body matches "(?i)<!DOCTYPE"
| stats count by client_ip, endpoint
```

Most legitimate XML clients don't include custom DOCTYPEs. Any spike is suspicious.

### Signal 2: Uploads with double extensions or unusual content vs. extension

Log the result of `magic`-based detection:

```python
log.info("upload_attempt",
         claimed_type=request.files["upload"].content_type,
         detected_type=detected_type,
         filename=filename)
```

Query:

```
| where claimed_type != detected_type
   or filename matches "\.(php|aspx|jsp|sh|exe)\."
```

Mismatches between client-claimed type and actual content are bypass attempts.

### Signal 3: Path traversal patterns in URLs

```
| where uri matches "(\.\./|\.\.%2F|%2e%2e/|%252e%252e/)"
| stats count by client_ip
| where count > 3
```

### Signal 4: Web shell access patterns

A new file appearing in an upload directory followed by HTTP access to it:

```
| join file_creation_event upload_dir [
    | event = "http_request"
    | uri matches upload_dir
  ]
| where uri_path = uploaded_file_path
```

A small number of webshell-shaped accesses (POST with `?cmd=`, `?c=`) is a high-fidelity signal.

### Signal 5: Outbound connections from upload-processing workers

ImageMagick / FFmpeg / archive workers should not make outbound HTTP. Any outbound connection is the exploitation signal:

```
| where process_name in (image_worker_processes)
   and event = "outbound_connection"
```

Pair with Week 08's outbound monitoring.

---

## Remediation playbook

| Finding | Immediate action | Longer fix |
|---|---|---|
| XXE-exploitable parser | Switch to defusedxml or harden the existing parser; ship | Audit all XML entry points |
| Upload accepts executable files | Block by content type at validator; ship | Add randomized names + non-executable storage |
| Path traversal in `?file=` | Add prefix-check after realpath | Migrate to opaque-ID-based file references |
| Zip slip in extraction | Add per-entry path validation | Switch to library with safe defaults |
| ImageMagick policy.xml missing or open | Apply OWASP-recommended policy; ship | Replace with Pillow/Sharp where possible |
| SSRF via XXE → metadata | Harden XML parser + apply Week 08 SSRF defenses | Both layers required |

## Automated tests

```python
def test_xml_endpoint_does_not_process_xxe(client):
    payload = '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>'''
    response = client.post("/api/import",
                           data=payload,
                           headers={"Content-Type": "application/xml"})
    assert "root:" not in response.text   # /etc/passwd contents

def test_upload_rejects_polyglot_image(client, alice_token):
    polyglot = b"\xff\xd8\xff<?php echo 'pwned'; ?>"
    response = client.post("/api/upload",
                           files={"file": ("evil.jpg", polyglot, "image/jpeg")},
                           headers={"Authorization": f"Bearer {alice_token}"})
    assert response.status_code == 400
    # Or: re-encoded version doesn't contain the PHP
    stored = storage.get(response.json()["key"])
    assert b"<?php" not in stored

def test_download_rejects_path_traversal(client, alice_token):
    response = client.get("/api/files/?key=../../../etc/passwd",
                          headers={"Authorization": f"Bearer {alice_token}"})
    assert response.status_code in (400, 403, 404)

def test_zip_extraction_rejects_traversal(client, alice_token):
    # craft a zip with a ../ entry
    import io, zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        z.writestr("../../evil", "evil")
    buf.seek(0)
    response = client.post("/api/import-archive",
                           files={"file": ("archive.zip", buf, "application/zip")},
                           headers={"Authorization": f"Bearer {alice_token}"})
    assert response.status_code == 400
```

## Tools

| Tool | Role |
|---|---|
| **defusedxml / safe-xml-parser** | Drop-in safer XML parsers |
| **python-magic / file-type** | Content-based MIME detection |
| **Pillow / Sharp** | Image re-encoding |
| **ClamAV** | Open-source malware scanning |
| **Semgrep** | Rules for `xml.etree.ElementTree`, `unsafe_extract`, `open(user_input)` |
| **Burp Suite** | XXE active scan; upload path testing |
| **OWASP DAST tools** | Path traversal automation |

## Common mistakes when defending

- **Extension allow-list as the only upload check.** Polyglots bypass it.
- **Validating MIME type from the request header.** Client controls it.
- **Storing uploads in `/var/www/html/`.** Web server may execute them.
- **Using `path.join` and assuming it's safe.** It doesn't validate; resolve and check after.
- **XML parser with "secure defaults" assumed.** Check explicitly; defaults change between versions.
- **Allowing SVG without sanitizing.** SVG is XML and can carry XXE + JS.

## Going further

- [PortSwigger — XXE](https://portswigger.net/web-security/xxe)
- [PortSwigger — File upload vulnerabilities](https://portswigger.net/web-security/file-upload)
- [PortSwigger — Path traversal](https://portswigger.net/web-security/file-path-traversal)
- [OWASP — File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [OWASP — XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [Snyk — Zip Slip vulnerability](https://snyk.io/research/zip-slip-vulnerability)
- [ImageMagick — Security Policy](https://imagemagick.org/script/security-policy.php)
