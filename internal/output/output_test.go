package output

import (
	"github.com/4Asterion/beforepull/internal/analysis"
	"strings"
	"testing"
)

func TestRenderAndEscape(t *testing.T) {
	r := analysis.Report{Tool: "BeforePull", Findings: []analysis.Finding{{Title: "<script>alert(1)</script>", Service: "web"}}, Limitations: []string{"unknown"}}
	h, e := Render(r, "html")
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(h), "<script>") {
		t.Fatal("html injection")
	}
	j, e := Render(r, "json")
	if e != nil || !strings.Contains(string(j), "schema_version") {
		t.Fatal(string(j), e)
	}
	if _, e := Render(r, "yaml"); e == nil {
		t.Fatal("unsupported format accepted")
	}
}
