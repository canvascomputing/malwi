<p align="center">
  <img src="https://raw.githubusercontent.com/canvascomputing/malwi/main/logo.png" width="200" />
</p>

<h1 align="center">malwi</h1>

<p align="center">
  <strong>Let's end Supply-Chain Attacks.</strong>
</p>

<div align="center">Attackers exploit trust and undermine the sovereignty of open-source software. malwi aims to end the threat of supply-chain attacks. It spawns a fleet of security research agents evaluating the trustworthiness of software.</div>

## Demo

```
Coming soon
```

## Samples

```
Coming soon
```

## Types

malwi analyzes suspicious code and classifies each finding as malicious, exploitable, or benign.
Malicious findings identify harmful behavior, exploitable findings expose dangerous trust
boundaries, and benign findings rule out both. Each verdict is backed by a focused evidence trail.

| Verdict | Type | Evidence trail |
|---|---|---|
| Malicious | Obfuscation | Payload → transform → execution sink → trigger |
| Exploitable | Side-loading | Remote source → control → consent → installation trigger |
| Exploitable | Telemetry | Provider → destination → collected data → consent and cadence |
| Benign | None detected | No evidence of malicious or exploitable behavior |

Exploitable means a compromised third party could turn the package's existing code against its
users.

<details open>
<summary>🔴 <code>malicious / obfuscation</code></summary>

**Code**

```python
payload = base64.b64decode("aWYgLi4u").decode()
exec(payload)
```

**Extracted evidence**

```json
{
  "payload": "aWYgLi4u",
  "transform": "base64 at loader.py:8",
  "sink": "exec at loader.py:9",
  "trigger": {
    "phase": "runtime",
    "location": "loader.py:12",
    "execution_condition": "on import"
  }
}
```

</details>

<details>
<summary>🟠 <code>exploitable / side-loading</code></summary>

**Code**

```javascript
const script = "https://cdn.example/setup.sh";
execSync(`curl -fsSL ${script} | sh`);
```

**Extracted evidence**

```json
{
  "source": "https://cdn.example/setup.sh at install.js:18",
  "control": "static",
  "user_consent": false,
  "trigger": {
    "phase": "installation",
    "location": "package.json:4",
    "execution_condition": "on every install"
  }
}
```

</details>

<details>
<summary>🟠 <code>exploitable / telemetry</code></summary>

**Code**

```python
requests.post("https://api.segment.io/v1/track", json={
    "hostname": socket.gethostname(), "command": sys.argv,
})
```

**Extracted evidence**

```json
{
  "provider": "Segment",
  "destination": "https://api.segment.io/v1/track",
  "data": ["hostname", "command"],
  "user_consent": false,
  "trigger": {
    "phase": "startup",
    "location": "telemetry.py:18",
    "execution_condition": "once per process start"
  }
}
```

</details>

<details>
<summary>🟢 <code>benign</code></summary>

**Code**

```python
target = (destination / member.name).resolve()
if not target.is_relative_to(destination.resolve()):
    raise ValueError("archive member escapes destination")
```

**Extracted evidence**

```json
{
  "path": "src/archive.py",
  "line": 42,
  "description": "Archive members are confined to the destination before extraction."
}
```

</details>

## Commands

```sh
malwi analyze ./node_modules/left-pad
```

```sh
malwi osint
```

```sh
malwi download python requests
```

## Development

See [DEVELOPMENT.md](DEVELOPMENT.md).
