package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/4Asterion/beforepull/internal/analysis"
	"github.com/4Asterion/beforepull/internal/compose"
	"github.com/4Asterion/beforepull/internal/output"
	"github.com/4Asterion/beforepull/internal/registry"
)

// version is overridden at release build time with -ldflags "-X main.version=...".
var version = "0.2.1"

func main() { os.Exit(run(os.Args[1:])) }
func run(args []string) int {
	if len(args) == 0 {
		help()
		return 2
	}
	switch args[0] {
	case "-h", "--help", "help":
		help()
		return 0
	case "version", "--version":
		fmt.Println("beforepull", version)
		return 0
	case "compare":
		return compare(args[1:])
	case "manifest":
		return manifest(args[1:])
	default:
		fmt.Fprintln(os.Stderr, "unknown command:", args[0])
		help()
		return 2
	}
}
func help() {
	fmt.Println("BeforePull — evidence-first Compose upgrade preflight\n\nCommands:\n  compare   Inspect changes between current and proposed Compose models\n  manifest  Opt-in read-only OCI manifest metadata inspection\n  version   Print version\n\nExamples:\n  beforepull compare --current examples/current.json --target examples/target.json\n  beforepull compare --current docker-compose.yml --target next/docker-compose.yml --format html --output report.html\n  beforepull compare --current old.yml --target new.yml --format markdown --fail-on high >> \"$GITHUB_STEP_SUMMARY\"")
}
func compare(args []string) int {
	fs := flag.NewFlagSet("compare", flag.ContinueOnError)
	cur := fs.String("current", "", "Current Compose JSON/YAML")
	tar := fs.String("target", "", "Proposed Compose JSON/YAML")
	format := fs.String("format", "text", "text, json, html or markdown")
	dest := fs.String("output", "", "Write result to this file (default: stdout)")
	threshold := fs.String("fail-on", "none", "none, critical, high, medium or low")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *cur == "" || *tar == "" {
		fmt.Fprintln(os.Stderr, "--current and --target are required")
		return 2
	}
	valid := map[string]bool{"none": true, "critical": true, "high": true, "medium": true, "low": true}
	if !valid[*threshold] {
		fmt.Fprintln(os.Stderr, "invalid --fail-on level")
		return 2
	}
	ctx := context.Background()
	a, err := compose.Load(ctx, *cur)
	if err != nil {
		return reportErr(err)
	}
	b, err := compose.Load(ctx, *tar)
	if err != nil {
		return reportErr(err)
	}
	r := analysis.Compare(a, b)
	data, err := output.Render(r, *format)
	if err != nil {
		return reportErr(err)
	}
	data = append(data, '\n')
	if *dest == "" {
		_, err = os.Stdout.Write(data)
	} else {
		dir := filepath.Dir(*dest)
		if _, e := os.Stat(dir); e != nil {
			return reportErr(e)
		}
		err = os.WriteFile(*dest, data, 0600)
	}
	if err != nil {
		return reportErr(err)
	}
	if *threshold != "none" && analysis.AtOrAbove(r, analysis.Severity(*threshold)) {
		return 3
	}
	return 0
}
func manifest(args []string) int {
	fs := flag.NewFlagSet("manifest", flag.ContinueOnError)
	image := fs.String("image", "", "OCI image reference")
	httpAllowed := fs.Bool("allow-http-local", false, "Allow HTTP transport only for localhost testing")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *image == "" {
		fmt.Fprintln(os.Stderr, "--image is required")
		return 2
	}
	if *httpAllowed && !(strings.HasPrefix(*image, "localhost:") || strings.HasPrefix(*image, "127.0.0.1:")) {
		fmt.Fprintln(os.Stderr, "HTTP only allowed for localhost")
		return 2
	}
	r, err := registry.Inspect(context.Background(), *image, nil, *httpAllowed)
	if err != nil {
		return reportErr(err)
	}
	data, _ := json.MarshalIndent(r, "", "  ")
	fmt.Println(string(data))
	return 0
}
func reportErr(err error) int {
	if !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(os.Stderr, "error:", err)
	} else {
		fmt.Fprintln(os.Stderr, "file not found:", err)
	}
	return 2
}
