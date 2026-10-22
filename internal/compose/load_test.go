package compose

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadValidJSON(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.json")
	os.WriteFile(p, []byte(`{"services":{"web":{"image":"nginx"}}}`), 0600)
	m, e := Load(context.Background(), p)
	if e != nil || m.Services["web"]["image"] != "nginx" {
		t.Fatal(m, e)
	}
}
func TestLoadRejectBadAndAbsentServices(t *testing.T) {
	for _, s := range []string{`{`, `{}`, `[]`, `{"services":{"web":{}}} xyz`} {
		p := filepath.Join(t.TempDir(), "test.json")
		os.WriteFile(p, []byte(s), 0600)
		if _, e := Load(context.Background(), p); e == nil {
			t.Errorf("accepted %q", s)
		}
	}
}
func TestUnsupportedExtension(t *testing.T) {
	_, e := Load(context.Background(), "test.toml")
	if e == nil || !strings.Contains(e.Error(), "unsupported") {
		t.Fatal(e)
	}
}
