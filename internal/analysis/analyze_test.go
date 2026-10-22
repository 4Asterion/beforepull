package analysis

import (
	"encoding/json"
	"github.com/brkcn369-debug/beforepull/internal/compose"
	"strings"
	"testing"
)

func model(src string) *compose.Model {
	var v compose.Model
	if err := json.Unmarshal([]byte(src), &v); err != nil {
		panic(err)
	}
	return &v
}
func exists(r Report, id string) bool {
	for _, f := range r.Findings {
		if f.ID == id {
			return true
		}
	}
	return false
}
func TestSecurityRiskEvidence(t *testing.T) {
	a := model(`{"services":{"web":{"image":"web:1.2.3","privileged":false,"user":"1000","read_only":true,"environment":{"PASSWORD":"SUPER_SECRET","REQUIRED":"foo"},"ports":[{"host_ip":"127.0.0.1","published":"8080","target":80,"protocol":"tcp"}],"volumes":[{"type":"volume","source":"data","target":"/data"}]}}}`)
	b := model(`{"services":{"web":{"image":"web:2.0.0","privileged":true,"user":"root","read_only":false,"environment":{"PASSWORD":"NEW_SUPER_SECRET"},"ports":[{"host_ip":"0.0.0.0","published":"8080","target":80,"protocol":"tcp"}],"volumes":[]}}}`)
	r := Compare(a, b)
	for _, id := range []string{"privileged.enabled", "rootfs.writable", "user.root", "env.removed", "port.exposed", "mount.removed", "image.changed", "image.major_version"} {
		if !exists(r, id) {
			t.Errorf("missing risk %s: %+v", id, r.Findings)
		}
	}
	raw, _ := json.Marshal(r)
	if strings.Contains(string(raw), "SUPER_SECRET") {
		t.Fatal("environment value leaked")
	}
	if !AtOrAbove(r, High) || !AtOrAbove(r, Critical) {
		t.Fatal("threshold failure")
	}
}
func TestNoFindingsForSameModel(t *testing.T) {
	a := model(`{"services":{"web":{"image":"web:1.0.0","environment":{"PASSWORD":"A"}}}}`)
	b := model(`{"services":{"web":{"image":"web:1.0.0","environment":{"PASSWORD":"B"}}}}`)
	r := Compare(a, b)
	if len(r.Findings) != 0 {
		t.Fatalf("expected no value-level findings: %+v", r.Findings)
	}
}
func TestServiceAddRemove(t *testing.T) {
	a := model(`{"services":{"a":{}}}`)
	b := model(`{"services":{"b":{}}}`)
	r := Compare(a, b)
	if !exists(r, "service.added") || !exists(r, "service.removed") {
		t.Fatal(r)
	}
}
func TestMutableTag(t *testing.T) {
	for _, s := range []string{"nginx", "nginx:latest", "ghcr.io/org/foo:latest"} {
		if !mutableTag(s) {
			t.Errorf("expected mutable: %s", s)
		}
	}
	for _, s := range []string{"nginx:1.2.3", "nginx@sha256:abc"} {
		if mutableTag(s) {
			t.Errorf("unexpected mutable: %s", s)
		}
	}
}
func TestSecretRemoval(t *testing.T) {
	a := model(`{"services":{"app":{"secrets":[{"source":"dbpass","target":"dbpass"}]}}}`)
	b := model(`{"services":{"app":{"secrets":[]}}}`)
	if !exists(Compare(a, b), "secret.removed") {
		t.Fatal("missing secret finding")
	}
}
func TestCapabilitiesNew(t *testing.T) {
	a := model(`{"services":{"app":{"cap_add":["NET_BIND_SERVICE"]}}}`)
	b := model(`{"services":{"app":{"cap_add":["NET_BIND_SERVICE","SYS_ADMIN"]}}}`)
	if !exists(Compare(a, b), "capability.added") {
		t.Fatal("missing added capability")
	}
}
func TestPortOnlyIPChange(t *testing.T) {
	a := model(`{"services":{"app":{"ports":[{"host_ip":"127.0.0.1","published":"443","target":443}]}}}`)
	b := model(`{"services":{"app":{"ports":[{"host_ip":"0.0.0.0","published":"443","target":443}]}}}`)
	if !exists(Compare(a, b), "port.exposed") {
		t.Fatal("host IP binding change missed")
	}
}
func TestMinimumRisk(t *testing.T) {
	r := Compare(model(`{"services":{"a":{}}}`), model(`{"services":{"a":{}}}`))
	if AtOrAbove(r, Low) {
		t.Fatal("unexpected risk")
	}
}
func find(r Report, id string) *Finding {
	for i := range r.Findings {
		if r.Findings[i].ID == id {
			return &r.Findings[i]
		}
	}
	return nil
}
func TestVersionHeuristics(t *testing.T) {
	cases := []struct {
		from, to string
		want     string // finding id, or "" for none
	}{
		{"postgres:16", "postgres:17", "image.major_version"},
		{"nginx:1.27-alpine", "nginx:2.0-alpine", "image.major_version"},
		{"localhost:5000/app:1.2.3", "localhost:5000/app:2.0.0", "image.major_version"},
		{"10.0.0.1:5000/app:1.2", "10.0.0.1:5000/app:1.3", ""},
		{"postgres:17.2", "postgres:16.4", "image.downgrade"},
		{"redis:7.4.1", "redis:7.2", "image.downgrade"},
		{"postgres:16", "postgres:16.4", ""},
		{"app:3f2a9c1", "app:9b1c0d2", ""},
		{"app:20240101", "app:20250101", ""},
		{"postgres:16", "docker.io/library/postgres:17", "image.major_version"},
		{"bitnami/postgresql:16", "postgres:16", "image.repository_changed"},
	}
	for _, c := range cases {
		a := model(`{"services":{"s":{"image":"` + c.from + `"}}}`)
		b := model(`{"services":{"s":{"image":"` + c.to + `"}}}`)
		r := Compare(a, b)
		for _, id := range []string{"image.major_version", "image.downgrade", "image.repository_changed"} {
			if got := exists(r, id); got != (id == c.want) {
				t.Errorf("%s → %s: finding %s present=%v, want %v", c.from, c.to, id, got, id == c.want)
			}
		}
	}
}
func TestRuntimeSocketAndSensitiveMounts(t *testing.T) {
	a := model(`{"services":{"agent":{"volumes":[{"type":"volume","source":"data","target":"/data"}]}}}`)
	b := model(`{"services":{"agent":{"volumes":[{"type":"volume","source":"data","target":"/data"},{"type":"bind","source":"/var/run/docker.sock","target":"/var/run/docker.sock"},"/etc:/host-etc:ro"]}}}`)
	r := Compare(a, b)
	if f := find(r, "runtime_socket.mounted"); f == nil || f.Severity != Critical {
		t.Fatalf("docker socket mount not critical: %+v", r.Findings)
	}
	if !exists(r, "mount.sensitive_host_path") {
		t.Fatalf("sensitive /etc bind missed: %+v", r.Findings)
	}
	if r.Findings[0].ID != "runtime_socket.mounted" {
		t.Fatalf("critical finding must sort first: %+v", r.Findings[0])
	}
}
func TestHardeningRegressions(t *testing.T) {
	a := model(`{"services":{"app":{"user":"1000","cap_drop":["ALL"],"security_opt":["no-new-privileges:true"]}}}`)
	b := model(`{"services":{"app":{"cap_add":["ALL"],"security_opt":["seccomp=unconfined"],"devices":["/dev/kvm:/dev/kvm"],"ipc":"host","userns_mode":"host"}}}`)
	r := Compare(a, b)
	for _, id := range []string{"user.removed", "capability.drop_removed", "security_opt.disabled", "security_opt.nnp_removed", "device.added", "ipc.host", "userns.host"} {
		if !exists(r, id) {
			t.Errorf("missing %s: %+v", id, r.Findings)
		}
	}
	if f := find(r, "capability.added"); f == nil || f.Severity != Critical {
		t.Errorf("cap_add ALL must be critical: %+v", f)
	}
}
func TestRootUserGroupForms(t *testing.T) {
	for _, user := range []string{"root", "root:root", "0", "0:0"} {
		r := Compare(model(`{"services":{"a":{"user":"1000:1000"}}}`), model(`{"services":{"a":{"user":"`+user+`"}}}`))
		if !exists(r, "user.root") {
			t.Errorf("user %q not recognised as root", user)
		}
	}
}
func TestNewServiceIsCheckedForPrivileges(t *testing.T) {
	r := Compare(model(`{"services":{}}`), model(`{"services":{"helper":{"image":"busybox","privileged":true,"ports":[{"published":"9000","target":9000,"protocol":"tcp"}]}}}`))
	for _, id := range []string{"service.added", "privileged.enabled", "port.exposed", "image.mutable_tag"} {
		if !exists(r, id) {
			t.Errorf("new service: missing %s: %+v", id, r.Findings)
		}
	}
	if exists(r, "image.changed") {
		t.Error("new service must not report an image change from (none)")
	}
}
func TestPortWideningEvidenceAndIPv6Loopback(t *testing.T) {
	a := model(`{"services":{"app":{"ports":[{"host_ip":"127.0.0.1","published":"8080","target":80,"protocol":"tcp"}]}}}`)
	b := model(`{"services":{"app":{"ports":[{"host_ip":"0.0.0.0","published":"8080","target":80,"protocol":"tcp"}]}}}`)
	f := find(Compare(a, b), "port.exposed")
	if f == nil || f.Title != "Port exposure widened beyond loopback" || !strings.Contains(f.Evidence, "127.0.0.1:8080") {
		t.Fatalf("unexpected widening finding: %+v", f)
	}
	v6 := model(`{"services":{"app":{"ports":[{"host_ip":"::1","published":"8080","target":80,"protocol":"tcp"}]}}}`)
	if g := find(Compare(model(`{"services":{"app":{}}}`), v6), "port.exposed"); g == nil || g.Severity != Medium {
		t.Fatalf("IPv6 loopback port should be medium, got %+v", g)
	}
}
