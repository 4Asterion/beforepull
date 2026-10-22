# Architecture and evidence contract

1. `internal/compose` reads canonical JSON or invokes Docker Compose to normalize YAML. There is no container lifecycle operation.
2. `internal/analysis` applies deterministic, explainable comparisons to parsed service maps. It never observes secret values: environment variables are reduced to their key sets.
3. `internal/output` renders terminal, versioned JSON, and auto-escaped standalone HTML reports.
4. `internal/registry` is an **optional** read-only OCI manifest query and is not part of `compare`.

## Report schema v1

```json
{
  "tool": "BeforePull",
  "schema_version": "1",
  "findings": [
    {"id": "privileged.enabled", "severity": "critical", "service": "web", "title": "Privileged mode enabled", "evidence": "privileged: false → true", "recommendation": "Avoid privileged mode or justify the new host-access requirement.", "confidence": "observed configuration change"}
  ],
  "summary": {"critical": 1},
  "limitations": ["Static configuration comparison cannot establish runtime compatibility or migration safety."]
}
```

Severity is a **review priority**, not an exploitability estimate. `confidence` represents evidence that a configuration changed, not evidence of actual runtime failure.

## Non-goals

- Deploying or pulling containers
- Scanning live container configuration or volumes
- Executing migrations, backing up data, or performing rollback
- Reliably evaluating semver or parsing release notes for arbitrary applications
- Credentialed registry authentication

A future registry enhancement should verify digests before basing a safety conclusion on them. Favor opt-in checks and fail-closed behavior where evidence is missing.
