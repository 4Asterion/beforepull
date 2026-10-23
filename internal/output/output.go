package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"strings"

	"github.com/4Asterion/beforepull/internal/analysis"
)

func Render(r analysis.Report, format string) ([]byte, error) {
	switch format {
	case "json":
		return json.MarshalIndent(r, "", "  ")
	case "text":
		var b strings.Builder
		fmt.Fprintf(&b, "BeforePull | %d findings\n", len(r.Findings))
		for _, f := range r.Findings {
			fmt.Fprintf(&b, "[%s] %s | %s: %s\n  Evidence: %s\n  Next: %s\n", strings.ToUpper(string(f.Severity)), f.Service, f.Title, f.ID, f.Evidence, f.Recommendation)
		}
		return []byte(b.String()), nil
	case "html":
		var b bytes.Buffer
		tmpl := template.Must(template.New("report").Parse(htmlTemplate))
		err := tmpl.Execute(&b, r)
		return b.Bytes(), err
	case "markdown", "md":
		return []byte(markdown(r)), nil
	default:
		return nil, fmt.Errorf("unknown format %q (use text, json, html or markdown)", format)
	}
}

var severityIcon = map[analysis.Severity]string{
	analysis.Critical: "🔴",
	analysis.High:     "🟠",
	analysis.Medium:   "🟡",
	analysis.Low:      "🔵",
	analysis.Info:     "⚪",
}

// mdText escapes untrusted text (service names, paths) for a Markdown table cell.
func mdText(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	return strings.NewReplacer(`\`, `\\`, "|", `\|`, "`", "\\`", "*", `\*`, "_", `\_`, "[", `\[`, "]", `\]`, "<", `\<`).Replace(s)
}

// mdCode renders evidence as inline code; inside table cells GitHub still needs pipes escaped.
func mdCode(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	return "`" + strings.NewReplacer("`", "'", "|", `\|`).Replace(s) + "`"
}

// markdown renders a compact report for pull request comments and $GITHUB_STEP_SUMMARY.
func markdown(r analysis.Report) string {
	var b strings.Builder
	b.WriteString("## BeforePull preflight\n\n")
	if len(r.Findings) == 0 {
		b.WriteString("✅ No security or operational changes detected between the two Compose models.\n")
	} else {
		counts := []string{}
		for _, sev := range []analysis.Severity{analysis.Critical, analysis.High, analysis.Medium, analysis.Low, analysis.Info} {
			if n := r.Summary[string(sev)]; n > 0 {
				counts = append(counts, fmt.Sprintf("%s **%d %s**", severityIcon[sev], n, sev))
			}
		}
		fmt.Fprintf(&b, "%d findings: %s\n\n", len(r.Findings), strings.Join(counts, " · "))
		b.WriteString("| Severity | Service | Change | Evidence |\n|---|---|---|---|\n")
		for _, f := range r.Findings {
			fmt.Fprintf(&b, "| %s %s | %s | %s | %s |\n", severityIcon[f.Severity], f.Severity, mdText(f.Service), mdText(f.Title), mdCode(f.Evidence))
		}
		b.WriteString("\n<details><summary>What to check</summary>\n\n")
		seen := map[string]bool{}
		for _, f := range r.Findings {
			if seen[f.ID] {
				continue
			}
			seen[f.ID] = true
			fmt.Fprintf(&b, "- **%s** — %s\n", mdText(f.Title), mdText(f.Recommendation))
		}
		b.WriteString("\n</details>\n")
	}
	b.WriteString("\n<sub>Static comparison of two Compose models by BeforePull. Environment variable values are never included. Findings show what changed, not whether the release is safe.</sub>\n")
	return b.String()
}

const htmlTemplate = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>BeforePull | Upgrade Readiness</title><style>:root{color-scheme:dark}body{font:15px system-ui;background:#0b1120;color:#e5e7eb;margin:0 auto;max-width:980px;padding:38px 20px}header{display:flex;justify-content:space-between;align-items:center}h1{margin:0;font-size:32px}p{color:#a8b5c8}article{background:#131e30;border:1px solid #2c3850;border-radius:12px;padding:19px;margin:12px 0}article h2{font-size:18px;margin:4px 0 9px}.severity{font-size:11px;letter-spacing:.08em;text-transform:uppercase;border-radius:5px;padding:4px 8px;background:#354059}.critical,.high{color:#fecaca}.medium{color:#fcd34d}.low{color:#93c5fd}code{white-space:pre-wrap;overflow-wrap:anywhere}strong{color:#dbeafe}footer{margin-top:30px;font-size:13px;color:#94a3b8}</style></head><body><header><div><h1>BeforePull</h1><p>Evidence-first upgrade readiness · static comparison</p></div><span>{{len .Findings}} findings</span></header><main>{{range .Findings}}<article><span class="severity {{.Severity}}">{{.Severity}}</span> <span>{{.Service}}</span><h2>{{.Title}}</h2><p><strong>Evidence:</strong> <code>{{.Evidence}}</code></p><p><strong>Recommendation:</strong> {{.Recommendation}}</p><small>{{.ID}} · {{.Confidence}}</small></article>{{else}}<article><h2>No configured changes detected</h2><p>This does not establish runtime compatibility.</p></article>{{end}}</main><footer><strong>Scope limits</strong><ul>{{range .Limitations}}<li>{{.}}</li>{{end}}</ul>Generated locally; no telemetry.</footer></body></html>`
