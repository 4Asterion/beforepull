// Package compose reads the normalized Compose application model without starting containers.
package compose

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type Model struct {
	Services map[string]map[string]any `json:"services"`
	Volumes  map[string]any            `json:"volumes,omitempty"`
	Networks map[string]any            `json:"networks,omitempty"`
}

// Load accepts canonical Compose JSON, or asks Docker Compose to normalize YAML.
// Values of environment variables and secret-like fields must never be rendered in reports.
func Load(ctx context.Context, path string) (*Model, error) {
	if path == "" {
		return nil, errors.New("configuration path is required")
	}
	var raw []byte
	var err error
	if strings.EqualFold(filepath.Ext(path), ".json") {
		raw, err = os.ReadFile(path)
	} else if ext := strings.ToLower(filepath.Ext(path)); ext == ".yaml" || ext == ".yml" {
		abs, absErr := filepath.Abs(path)
		if absErr != nil {
			return nil, fmt.Errorf("resolve %q: %w", path, absErr)
		}
		tctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		// An absolute -f path matters: the command runs from the file's directory so relative
		// env_file/build paths resolve as Compose expects, and a relative -f would resolve twice.
		cmd := exec.CommandContext(tctx, "docker", "compose", "-f", abs, "config", "--format", "json")
		cmd.Dir = filepath.Dir(abs)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		// Read-only: Compose config is invoked, never `up`, `pull`, or `exec`.
		raw, err = cmd.Output()
		if err != nil {
			detail := strings.TrimSpace(stderr.String())
			if len(detail) > 600 {
				detail = detail[:600] + "…"
			}
			if detail != "" {
				return nil, fmt.Errorf("normalize %s with `docker compose config`: %w: %s", path, err, detail)
			}
			return nil, fmt.Errorf("normalize %s: Docker Compose v2 is required for YAML (try `docker compose -f %s config --format json`): %w", path, path, err)
		}
	} else {
		return nil, fmt.Errorf("unsupported file %q: supply .json, .yaml, or .yml", path)
	}
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}
	if len(raw) > 8<<20 {
		return nil, errors.New("Compose file exceeds 8 MiB safety limit")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m Model
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("parse Compose %q: %w", path, err)
	}
	if m.Services == nil {
		return nil, fmt.Errorf("no services found in %q", path)
	}
	var trailing any
	if err := dec.Decode(&trailing); err == nil {
		return nil, errors.New("unexpected trailing JSON data")
	} else if !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("invalid trailing JSON data: %w", err)
	}
	return &m, nil
}
