# Release checklist

- [x] Dependency-free Go build completed locally
- [x] Tests, race detector and `go vet` completed locally
- [x] CLI example produced valid JSON and HTML reports
- [x] HTML output auto-escapes user-provided display strings
- [x] Environment variable values excluded from findings
- [x] README, licensing, security policy, templates and CI source prepared
- [x] YAML normalization confirmed on a host with Docker Compose v2 (CI job `compose-smoke`)
- [x] Anonymous OCI manifest lookup confirmed against a real registry (Docker Hub, 2026-10-23)
- [x] GitHub Actions completed on actual public repository (including the action self-test)
- [ ] Published release artifacts signed and checksummed

Do not mark unchecked gates complete before public release validation.
