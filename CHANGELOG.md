# Changelog

## 0.2.0 - 2026-10-23

- **Fix:** Compose YAML given as a relative path with a directory (`compose/app.yml`) failed: the path was resolved twice because `docker compose` ran in the file's directory with a relative `-f`. `docker compose config` errors now include its message instead of only `exit status 1`.
- **Fix:** single-number and suffixed tags (`postgres:16` → `17`, `nginx:1.27-alpine` → `2.0-alpine`) missed major upgrades, and registry ports (`10.0.0.1:5000/app`) were read as versions.
- **Fix:** `root:root` and `0:0` were not recognised as root; an IPv6 loopback port (`::1`) was reported as publicly exposed; new services were never checked for privileges, ports or mounts.
- **Fix:** `manifest --image docker.io/...` contacted `docker.io` instead of the Hub registry API.
- **New checks:** Docker/Podman/containerd socket mounts (critical), `cap_add: ALL`/`SYS_ADMIN` (critical), version downgrades, image repository switches, sensitive host bind mounts, host devices, host IPC/userns namespaces, disabled seccomp/AppArmor/SELinux, removed `no-new-privileges`, restored dropped capabilities, removed explicit non-root user, and loopback-to-public port widening.
- **New:** `--format markdown` for pull request comments and job summaries.
- **New:** composite GitHub Action (`uses: brkcn369-debug/beforepull@main`) that compares a PR's Compose file with its base branch.
- **New:** tag-triggered release workflow with cross-compiled binaries and `SHA256SUMS`; CI now exercises real `docker compose config` YAML normalisation and the action itself.
- **New:** `examples/target-sidecar.json` shows an update that adds a socket-mounting auto-updater.

## 0.1.0 - 2026-10-22

Initial release candidate: dependency-free Go CLI, canonical Compose comparison, prioritized security/operational findings, JSON/HTML/terminal reporting, optional anonymous OCI manifest inspection, examples, unit and CLI tests, GitHub Actions workflow, and release documentation.
