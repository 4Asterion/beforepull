# Release checklist

- [x] Dependency-free Go build completed locally
- [x] Tests, race detector and `go vet` completed locally
- [x] CLI example produced valid JSON and HTML reports
- [x] HTML output auto-escapes user-provided display strings
- [x] Environment variable values excluded from findings
- [x] README, licensing, security policy, templates and CI source prepared
- [ ] YAML normalization confirmed on a host with Docker Compose v2
- [ ] Anonymous OCI manifest lookup confirmed against a real registry
- [ ] GitHub Actions completed on actual public repository
- [ ] Published release artifacts signed and checksummed

Do not mark unchecked gates complete before public release validation.
