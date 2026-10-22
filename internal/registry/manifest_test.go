package registry

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseImage(t *testing.T) {
	h, p, r, e := ParseImage("alpine:3.20")
	if e != nil || h != "registry-1.docker.io" || p != "library/alpine" || r != "3.20" {
		t.Fatal(h, p, r, e)
	}
	h, p, r, e = ParseImage("ghcr.io/org/tool@sha256:123")
	if e != nil || h != "ghcr.io" || p != "org/tool" || r != "sha256:123" {
		t.Fatal(h, p, r, e)
	}
	for _, s := range []string{"docker.io/alpine:3.20", "index.docker.io/library/alpine:3.20"} {
		h, p, r, e = ParseImage(s)
		if e != nil || h != "registry-1.docker.io" || p != "library/alpine" || r != "3.20" {
			t.Fatal(s, h, p, r, e)
		}
	}
	h, p, _, e = ParseImage("docker.io/grafana/grafana:11.0.0")
	if e != nil || h != "registry-1.docker.io" || p != "grafana/grafana" {
		t.Fatal(h, p, e)
	}
}
func TestRejectMalformedRefs(t *testing.T) {
	for _, s := range []string{"", "https://evil/a", "repo:tag?hello", "../foo", "myorg//foo", "foo: "} {
		if _, _, _, e := ParseImage(s); e == nil {
			t.Errorf("accepted %s", s)
		}
	}
}
func TestInspectLocalRegistry(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept"), "application/vnd.oci.image.index.v1+json") {
			t.Error("missing Accept")
		}
		w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
		payload := []byte(`{"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"platform":{"os":"linux","architecture":"amd64"}}]}`)
		h := sha256.Sum256(payload)
		w.Header().Set("Docker-Content-Digest", fmt.Sprintf("sha256:%x", h))
		w.Write(payload)
	}))
	defer s.Close()
	image := strings.TrimPrefix(s.URL, "http://") + "/org/app:1.0"
	r, e := Inspect(context.Background(), image, s.Client(), true)
	if e != nil || len(r.Platforms) != 1 || !strings.HasPrefix(r.Digest, "sha256:") {
		t.Fatal(r, e)
	}
}
func TestInspectMissing(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) }))
	defer s.Close()
	_, e := Inspect(context.Background(), strings.TrimPrefix(s.URL, "http://")+"/app:1", s.Client(), true)
	if e == nil {
		t.Fatal("expected HTTP error")
	}
}

func TestAnonymousBearerFlow(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"token":"fixture_token"}`))
			return
		}
		if r.Header.Get("Authorization") != "Bearer fixture_token" {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s/token",service="registry",scope="repository:org/app:pull"`, server.URL))
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
		w.Write([]byte(`{"mediaType":"application/vnd.oci.image.manifest.v1+json"}`))
	}))
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "http://")
	result, err := Inspect(context.Background(), host+"/org/app:1.0", server.Client(), true)
	if err != nil || result.MediaType != "application/vnd.oci.image.manifest.v1+json" {
		t.Fatal(result, err)
	}
}
