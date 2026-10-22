package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompareRealExamples(t *testing.T) {
	current := filepath.Join("..", "..", "examples", "current.json")
	target := filepath.Join("..", "..", "examples", "target.json")
	output := filepath.Join(t.TempDir(), "report.html")
	exit := run([]string{"compare", "--current", current, "--target", target, "--format", "html", "--output", output, "--fail-on", "high"})
	if exit != 3 {
		t.Fatalf("expected high risk exit=3, got %d", exit)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "Port exposure widened beyond loopback") || !strings.Contains(string(data), "Privileged mode enabled") {
		t.Fatal("report missing expected findings")
	}
}
func TestCompareMarkdownReport(t *testing.T) {
	current := filepath.Join("..", "..", "examples", "current.json")
	target := filepath.Join("..", "..", "examples", "target.json")
	output := filepath.Join(t.TempDir(), "report.md")
	if exit := run([]string{"compare", "--current", current, "--target", target, "--format", "markdown", "--output", output}); exit != 0 {
		t.Fatalf("default threshold must not fail, got %d", exit)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"## BeforePull preflight", "| Severity | Service | Change | Evidence |", "Privileged mode enabled"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("markdown report missing %q", want)
		}
	}
	if strings.Contains(string(data), "example-not-printed") {
		t.Fatal("environment value leaked into markdown")
	}
}
func TestMissingOutputDirectory(t *testing.T) {
	current := filepath.Join("..", "..", "examples", "current.json")
	output := filepath.Join(t.TempDir(), "missing", "report.json")
	if exit := run([]string{"compare", "--current", current, "--target", current, "--output", output}); exit != 2 {
		t.Fatalf("expected exit 2 for missing output directory, got %d", exit)
	}
}
func TestBadOptions(t *testing.T) {
	for _, args := range [][]string{{"unknown"}, {"compare"}, {"compare", "--current", "foo", "--target", "bar", "--fail-on", "invalid"}} {
		if run(args) != 2 {
			t.Errorf("expected invalid argument: %v", args)
		}
	}
}
