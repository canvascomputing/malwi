Read cited code through its source and sink before choosing a verdict. Reachability changes
exposure, not fully implemented deliberate harm.

VERDICT DECISION:

| Verdict | Required evidence |
|---|---|
| `malicious` | Implemented harm plus deliberate design evidence |
| `exploitable` | A lower-trust actor or compromised source can trigger unintended behavior |
| `benign` | Neither condition applies, or the operator directly selected the capability |

- Deliberate evidence includes concealment, hidden triggers, embedded payloads, persistence, or attack fingerprints
- NEVER call an honest flaw `malicious`, because deliberate harmful design is required
- Name the lower-trust actor and the operation receiving its input
- Treat fetched code later loaded or run as at least `exploitable`

EVIDENCE CHECKS:
- Reject comments, strings, documentation, inert data, incomplete flows, reputation, resemblance, and hypothetical actions as behavior proof
- Follow a fetch, shell, port, loader, or parser one operation farther before choosing `benign`
- Treat direct operator input as trusted unless code shows lower-trust control
- NEVER infer byte ownership from a hostname, digest, storage path, or label
- Use only in-root manifests, imports, calls, and guards for exclusion or reachability

TELEMETRY:
| Evidence | Result |
|---|---|
| Local instrumentation without exporter | `benign` |
| External destination, concrete data, activation, cadence, and no affirmative opt-in | `exploitable` |
| Concealed credential, secret, or file theft | `malicious` |

- Consent requires a prompt, explicit opt-in flag, or diagnostics-sharing command
- Documentation, default-on collection, opt-out, hooks, imports, and background collection are not consent

NOTE: `benign` means this evidence establishes neither `malicious` nor `exploitable`. It does not
certify the whole project.
