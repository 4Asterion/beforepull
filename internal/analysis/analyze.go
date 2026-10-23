// Package analysis identifies configuration changes with explicit evidence and uncertainty.
package analysis

import (
	"fmt"
	"path"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/4Asterion/beforepull/internal/compose"
)

type Severity string

const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
	Info     Severity = "info"
)

type Finding struct {
	ID             string   `json:"id"`
	Severity       Severity `json:"severity"`
	Service        string   `json:"service"`
	Title          string   `json:"title"`
	Evidence       string   `json:"evidence"`
	Recommendation string   `json:"recommendation"`
	Confidence     string   `json:"confidence"`
}
type Report struct {
	Tool          string         `json:"tool"`
	SchemaVersion string         `json:"schema_version"`
	Findings      []Finding      `json:"findings"`
	Summary       map[string]int `json:"summary"`
	Limitations   []string       `json:"limitations"`
}

// Container runtime sockets: write access to any of them is equivalent to root on the host.
var runtimeSockets = map[string]bool{
	"/var/run/docker.sock":                true,
	"/run/docker.sock":                    true,
	"/var/run/podman/podman.sock":         true,
	"/run/podman/podman.sock":             true,
	"/run/containerd/containerd.sock":     true,
	"/var/run/containerd/containerd.sock": true,
}

// Host paths whose bind mount exposes host configuration, credentials or kernel interfaces.
var sensitiveHostPaths = map[string]bool{
	"/": true, "/etc": true, "/root": true, "/home": true, "/proc": true, "/sys": true,
	"/dev": true, "/boot": true, "/run": true, "/var/run": true, "/var/lib/docker": true,
}

func Compare(oldM, newM *compose.Model) Report {
	out := Report{Tool: "BeforePull", SchemaVersion: "1", Findings: []Finding{}, Summary: map[string]int{}, Limitations: []string{
		"Static configuration comparison cannot establish runtime compatibility or migration safety.",
		"Image contents, changelogs, backups, and database state are not inspected by this command.",
		"Compose interpolation depends on the local environment; compare files with equivalent intended context.",
	}}
	add := func(sev Severity, svc, id, title, evidence, recommendation string) {
		out.Findings = append(out.Findings, Finding{ID: id, Severity: sev, Service: svc, Title: title, Evidence: evidence, Recommendation: recommendation, Confidence: "observed configuration change"})
	}
	services := map[string]bool{}
	for k := range oldM.Services {
		services[k] = true
	}
	for k := range newM.Services {
		services[k] = true
	}
	names := make([]string, 0, len(services))
	for k := range services {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, svc := range names {
		a, aok := oldM.Services[svc]
		b, bok := newM.Services[svc]
		if !bok {
			add(High, svc, "service.removed", "Service removed", "Service is absent from the proposed model.", "Confirm removal and persistence requirements.")
			continue
		}
		if !aok {
			add(Medium, svc, "service.added", "New service added", "Service was not present in the current model.", "Verify resource use, ingress and dependencies.")
			// A new service is checked against an empty definition, so its privileges and exposure are reported too.
			a = map[string]any{}
		}
		if a == nil {
			a = map[string]any{}
		}
		if b == nil {
			b = map[string]any{}
		}
		ai, bi := str(a["image"]), str(b["image"])
		if aok && ai != bi {
			sev := Medium
			if ai == "" || bi == "" {
				sev = High
			}
			add(sev, svc, "image.changed", "Image reference changed", safeImage(ai)+" → "+safeImage(bi), "Review official release notes, migration guidance and backup restore readiness.")
			imageVersionFindings(ai, bi, svc, add)
		}
		if bi != "" && (ai != bi || !aok) && mutableTag(bi) {
			add(Medium, svc, "image.mutable_tag", "Target image uses a mutable tag", safeImage(bi), "Consider pinning a specific version or digest for reproducible upgrades.")
		}
		if boolval(b["privileged"]) && !boolval(a["privileged"]) {
			add(Critical, svc, "privileged.enabled", "Privileged mode enabled", "privileged: false → true", "Avoid privileged mode or justify the new host-access requirement.")
		}
		if boolval(a["read_only"]) && !boolval(b["read_only"]) {
			add(High, svc, "rootfs.writable", "Read-only filesystem disabled", "read_only: true → false", "Check whether writable filesystem access is required.")
		}
		for _, ns := range []struct{ field, id, title string }{
			{"network_mode", "network.host", "Host networking enabled"},
			{"pid", "pid.host", "Host PID namespace enabled"},
			{"ipc", "ipc.host", "Host IPC namespace enabled"},
			{"userns_mode", "userns.host", "User namespace remapping disabled"},
		} {
			if str(a[ns.field]) != "host" && str(b[ns.field]) == "host" {
				add(High, svc, ns.id, ns.title, ns.field+" changed to host", "Review host isolation; host namespaces let the container observe or affect host processes and traffic.")
			}
		}
		oldUser, newUser := str(a["user"]), str(b["user"])
		if !isRoot(oldUser) && isRoot(newUser) {
			add(High, svc, "user.root", "Container user changed to root", "user changed to root or UID 0", "Keep least-privilege runtime identity where possible.")
		} else if aok && oldUser != "" && !isRoot(oldUser) && newUser == "" {
			add(Medium, svc, "user.removed", "Explicit non-root user removed", "user: "+oldUser+" → (image default)", "Many images default to root; keep an explicit unprivileged user.")
		}
		if a["healthcheck"] != nil && b["healthcheck"] == nil {
			add(Medium, svc, "healthcheck.removed", "Healthcheck removed", "Previously defined healthcheck is absent.", "Restore health signaling or document the replacement.")
		}
		if a["mem_limit"] != nil && b["mem_limit"] == nil {
			add(Medium, svc, "memory.unbounded", "Memory limit removed", "mem_limit removed", "Confirm capacity planning before deploy.")
		}
		if a["cpus"] != nil && b["cpus"] == nil {
			add(Low, svc, "cpu.unbounded", "CPU limit removed", "cpus removed", "Review host resource contention.")
		}
		changedSetKeys(a, b, "environment", svc, Medium, "env.removed", "Environment variable key removed", "Check whether the application still needs this setting.", add)
		changedSetKeys(a, b, "secrets", svc, High, "secret.removed", "Secret mount removed", "Confirm how credentials will be supplied.", add)
		changedSetKeys(a, b, "depends_on", svc, Medium, "dependency.removed", "Dependency relationship removed", "Validate startup and readiness behavior.", add)
		changedSetKeys(a, b, "cap_drop", svc, Medium, "capability.drop_removed", "Dropped capability restored", "Keep dropping capabilities the service does not need.", add)
		for _, capability := range difference(setKeys(b["cap_add"]), setKeys(a["cap_add"])) {
			sev := High
			if c := strings.ToUpper(strings.TrimPrefix(strings.ToUpper(capability), "CAP_")); c == "ALL" || c == "SYS_ADMIN" {
				sev = Critical
			}
			add(sev, svc, "capability.added", "Linux capability added", capability, "Prefer minimal required capabilities.")
		}
		for _, device := range difference(setKeys(b["devices"]), setKeys(a["devices"])) {
			add(High, svc, "device.added", "Host device mapped into container", device, "Confirm the device is required; device access bypasses much of the container boundary.")
		}
		oldOpts := normalizedSecurityOpts(a["security_opt"])
		for _, opt := range difference(normalizedSecurityOpts(b["security_opt"]), oldOpts) {
			if strings.HasSuffix(opt, ":unconfined") || opt == "label:disable" {
				add(High, svc, "security_opt.disabled", "Security profile disabled", opt, "Keep seccomp, AppArmor and SELinux confinement unless a documented requirement exists.")
			}
		}
		for _, opt := range difference(oldOpts, normalizedSecurityOpts(b["security_opt"])) {
			if opt == "no-new-privileges" || opt == "no-new-privileges:true" {
				add(Medium, svc, "security_opt.nnp_removed", "no-new-privileges removed", opt, "Restore no-new-privileges to block setuid privilege escalation.")
			}
		}
		portFindings(ports(a), ports(b), svc, add)
		for _, v := range diffList(mounts(a), mounts(b)) {
			if strings.HasPrefix(v, "-") {
				add(High, svc, "mount.removed", "Volume or bind mount removed", v[1:], "Verify persistent data path and backup before upgrading.")
			} else {
				add(Medium, svc, "mount.added", "Volume or bind mount added", v[1:], "Validate paths and file permissions.")
			}
		}
		for _, src := range difference(bindSources(b), bindSources(a)) {
			clean := path.Clean(src)
			switch {
			case runtimeSockets[clean]:
				add(Critical, svc, "runtime_socket.mounted", "Container runtime socket mounted", src, "Socket access equals root on the host; remove it or put a socket proxy with a narrow allowlist in between.")
			case sensitiveHostPaths[clean]:
				add(High, svc, "mount.sensitive_host_path", "Sensitive host path bind-mounted", src, "Mount only the specific files the service needs, read-only where possible.")
			}
		}
	}
	order := map[Severity]int{Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4}
	sort.SliceStable(out.Findings, func(i, j int) bool {
		a, b := out.Findings[i], out.Findings[j]
		if order[a.Severity] != order[b.Severity] {
			return order[a.Severity] < order[b.Severity]
		}
		if a.Service != b.Service {
			return a.Service < b.Service
		}
		return a.ID < b.ID
	})
	for _, f := range out.Findings {
		out.Summary[string(f.Severity)]++
	}
	return out
}
func str(x any) string   { v, _ := x.(string); return v }
func boolval(x any) bool { v, _ := x.(bool); return v }

// isRoot recognises root by name or UID, including user:group forms such as root:root and 0:0.
func isRoot(x string) bool {
	name, _, _ := strings.Cut(x, ":")
	return name == "root" || name == "0"
}
func safeImage(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
func mutableTag(image string) bool {
	if image == "" || strings.Contains(image, "@sha256:") {
		return false
	}
	last := image[strings.LastIndex(image, "/")+1:]
	return !strings.Contains(last, ":") || strings.HasSuffix(last, ":latest")
}

// imageRepo strips tag and digest and normalises Docker Hub spellings (docker.io/library/x == x).
func imageRepo(image string) string {
	if at := strings.Index(image, "@"); at >= 0 {
		image = image[:at]
	}
	if i := strings.LastIndex(image, ":"); i > strings.LastIndex(image, "/") {
		image = image[:i]
	}
	for _, prefix := range []string{"docker.io/", "index.docker.io/", "registry-1.docker.io/"} {
		image = strings.TrimPrefix(image, prefix)
	}
	return strings.TrimPrefix(image, "library/")
}

// imageTag returns only the tag, ignoring registry ports such as localhost:5000/app.
func imageTag(image string) string {
	if at := strings.Index(image, "@"); at >= 0 {
		image = image[:at]
	}
	last := image[strings.LastIndex(image, "/")+1:]
	if i := strings.LastIndex(last, ":"); i >= 0 {
		return last[i+1:]
	}
	return ""
}

// Numeric tag prefix: 16, 1.27-alpine, v2.0.1, 3.20.3-bookworm. A letter right after the
// digits (git SHAs like 3f2a9c1) or a date-sized number (20240101) is not treated as a version.
var leadingVersion = regexp.MustCompile(`^[vV]?(\d{1,5})(?:\.(\d+))?(?:\.(\d+))?(?:$|[-_+.])`)

func imageVersion(image string) ([]int, bool) {
	m := leadingVersion.FindStringSubmatch(imageTag(image))
	if m == nil {
		return nil, false
	}
	parts := []int{}
	for _, s := range m[1:] {
		if s == "" {
			break
		}
		n, err := strconv.Atoi(s)
		if err != nil {
			return nil, false
		}
		parts = append(parts, n)
	}
	return parts, true
}

// compareVersions compares the components both versions specify: 16 and 16.3 are equal.
func compareVersions(a, b []int) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func imageVersionFindings(oldImage, newImage, svc string, add func(Severity, string, string, string, string, string)) {
	if oldImage == "" || newImage == "" {
		return
	}
	if imageRepo(oldImage) != imageRepo(newImage) {
		add(High, svc, "image.repository_changed", "Image repository changed", imageRepo(oldImage)+" → "+imageRepo(newImage), "A different image source can change data layout, defaults and maintainers; treat it as a migration.")
		return
	}
	x, okA := imageVersion(oldImage)
	y, okB := imageVersion(newImage)
	if !okA || !okB {
		return
	}
	evidence := oldImage + " → " + newImage
	switch {
	case y[0] > x[0]:
		add(High, svc, "image.major_version", "Apparent major version upgrade", evidence, "Check the upstream upgrade path; image tag numbering may not follow semantic versions.")
	case compareVersions(x, y) > 0:
		add(High, svc, "image.downgrade", "Apparent version downgrade", evidence, "Downgrades are rarely supported after data has been migrated; confirm a tested rollback path and a restorable backup.")
	}
}

func setKeys(x any) []string {
	result := []string{}
	switch v := x.(type) {
	case map[string]any:
		for k := range v {
			result = append(result, k)
		}
	case []any:
		for _, item := range v {
			switch t := item.(type) {
			case string:
				key, _, _ := strings.Cut(t, "=")
				result = append(result, key)
			case map[string]any:
				if s := str(t["source"]); s != "" {
					result = append(result, s)
				}
				if s := str(t["target"]); s != "" && str(t["source"]) == "" {
					result = append(result, s)
				}
			}
		}
	}
	sort.Strings(result)
	return result
}

// normalizedSecurityOpts lower-cases options and accepts both seccomp=x and seccomp:x spellings.
func normalizedSecurityOpts(x any) []string {
	out := []string{}
	list, _ := x.([]any)
	for _, item := range list {
		if s, ok := item.(string); ok {
			out = append(out, strings.ToLower(strings.Replace(strings.TrimSpace(s), "=", ":", 1)))
		}
	}
	sort.Strings(out)
	return out
}
func difference(a, b []string) []string {
	present := map[string]bool{}
	for _, s := range b {
		present[s] = true
	}
	o := []string{}
	for _, s := range a {
		if !present[s] {
			o = append(o, s)
		}
	}
	return o
}
func changedSetKeys(a, b map[string]any, field, svc string, sev Severity, id, title, rec string, add func(Severity, string, string, string, string, string)) {
	for _, key := range difference(setKeys(a[field]), setKeys(b[field])) {
		add(sev, svc, id, title, key, rec)
	}
}
func canonical(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case map[string]any:
		if s := str(x["target"]); s != "" {
			return fmt.Sprintf("%s→%s (%s)", str(x["source"]), s, str(x["type"]))
		}
		if p, ok := x["target"]; ok {
			return fmt.Sprint(p)
		}
		return fmt.Sprint(x["published"]) + ":" + fmt.Sprint(x["target"]) + "/" + str(x["protocol"])
	default:
		return fmt.Sprint(v)
	}
}
func items(v any) []string {
	out := []string{}
	switch vv := v.(type) {
	case []any:
		for _, x := range vv {
			out = append(out, canonical(x))
		}
	}
	sort.Strings(out)
	return out
}

// bindSources lists host paths of bind mounts, from canonical objects or short "host:container" strings.
func bindSources(m map[string]any) []string {
	out := []string{}
	list, _ := m["volumes"].([]any)
	for _, v := range list {
		switch x := v.(type) {
		case string:
			if src, _, ok := strings.Cut(x, ":"); ok && strings.HasPrefix(src, "/") {
				out = append(out, src)
			}
		case map[string]any:
			if str(x["type"]) == "bind" && str(x["source"]) != "" {
				out = append(out, str(x["source"]))
			}
		}
	}
	sort.Strings(out)
	return out
}
func ports(m map[string]any) []string {
	out := []string{}
	if list, ok := m["ports"].([]any); ok {
		for _, v := range list {
			switch p := v.(type) {
			case string:
				out = append(out, p)
			case map[string]any:
				host := str(p["host_ip"])
				if host == "" {
					host = "0.0.0.0"
				} else if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
					host = "[" + host + "]" // IPv6, so that [::1] is recognised as loopback
				}
				out = append(out, host+":"+fmt.Sprint(p["published"])+"→"+fmt.Sprint(p["target"])+"/"+str(p["protocol"]))
			}
		}
	}
	sort.Strings(out)
	return out
}

// splitHost separates the host binding from the rest of a rendered port mapping.
func splitHost(p string) (string, string) {
	if strings.HasPrefix(p, "[") {
		if end := strings.Index(p, "]:"); end >= 0 {
			return p[:end+1], p[end+2:]
		}
	}
	host, rest, _ := strings.Cut(p, ":")
	return host, rest
}
func portFindings(oldPorts, newPorts []string, svc string, add func(Severity, string, string, string, string, string)) {
	diff := diffList(oldPorts, newPorts)
	removedLocal := map[string]string{}
	for _, p := range diff {
		if strings.HasPrefix(p, "-") && !externallyExposed(p[1:]) {
			_, rest := splitHost(p[1:])
			removedLocal[rest] = p[1:]
		}
	}
	for _, p := range diff {
		if !strings.HasPrefix(p, "+") {
			continue
		}
		mapping := p[1:]
		if !externallyExposed(mapping) {
			add(Medium, svc, "port.exposed", "Published port added", mapping, "Check ingress, firewall rules and public exposure.")
			continue
		}
		_, rest := splitHost(mapping)
		if previous, ok := removedLocal[rest]; ok {
			add(High, svc, "port.exposed", "Port exposure widened beyond loopback", previous+" → "+mapping, "The port was reachable only from the host; confirm it should now be reachable from the network.")
			continue
		}
		add(High, svc, "port.exposed", "Published port added", mapping, "Check ingress, firewall rules and public exposure.")
	}
}
func mounts(m map[string]any) []string { return items(m["volumes"]) }
func diffList(a, b []string) []string {
	if reflect.DeepEqual(a, b) {
		return nil
	}
	out := []string{}
	for _, x := range difference(a, b) {
		out = append(out, "-"+x)
	}
	for _, x := range difference(b, a) {
		out = append(out, "+"+x)
	}
	return out
}
func externallyExposed(p string) bool {
	return !strings.HasPrefix(p, "127.") && !strings.HasPrefix(p, "[::1]:") && !strings.HasPrefix(p, "localhost:")
}
func AtOrAbove(r Report, threshold Severity) bool {
	levels := map[Severity]int{Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0}
	n, ok := levels[threshold]
	if !ok {
		return false
	}
	for _, f := range r.Findings {
		if levels[f.Severity] >= n {
			return true
		}
	}
	return false
}
