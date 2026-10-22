// Package registry implements opt-in, read-only OCI manifest discovery.
package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const accept = "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"

type Platform struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Variant      string `json:"variant,omitempty"`
}
type Result struct {
	Image     string     `json:"image"`
	Digest    string     `json:"digest,omitempty"`
	MediaType string     `json:"media_type,omitempty"`
	Platforms []Platform `json:"platforms"`
	Notice    string     `json:"notice"`
}
type manifest struct {
	MediaType string `json:"mediaType"`
	Manifests []struct {
		Platform Platform `json:"platform"`
	} `json:"manifests"`
}

// ParseImage accepts Docker Hub or explicit registry references; hostnames must be DNS-like.
func ParseImage(image string) (host, repo, reference string, err error) {
	if strings.TrimSpace(image) == "" || strings.ContainsAny(image, " \r\n?#") || strings.Contains(image, "://") {
		return "", "", "", errors.New("invalid image reference")
	}
	reference = "latest"
	name := image
	if at := strings.LastIndex(image, "@"); at >= 0 {
		reference = image[at+1:]
		name = image[:at]
	} else if i := strings.LastIndex(image, ":"); i > strings.LastIndex(image, "/") {
		reference = image[i+1:]
		name = image[:i]
	}
	if reference == "" || name == "" {
		return "", "", "", errors.New("empty name or tag")
	}
	parts := strings.Split(name, "/")
	if len(parts) > 1 && (strings.ContainsAny(parts[0], ".:") || parts[0] == "localhost") {
		host = parts[0]
		repo = strings.Join(parts[1:], "/")
		// docker.io is the Hub's name, not its API host; official images live under library/.
		if host == "docker.io" || host == "index.docker.io" {
			host = "registry-1.docker.io"
			if !strings.Contains(repo, "/") {
				repo = "library/" + repo
			}
		}
	} else {
		host = "registry-1.docker.io"
		repo = name
		if !strings.Contains(repo, "/") {
			repo = "library/" + repo
		}
	}
	if strings.ContainsAny(host, "@?#%") || strings.HasPrefix(host, ".") || strings.Contains(repo, "..") || strings.Contains(repo, "//") || strings.Contains(repo, "\\") || strings.ContainsAny(repo, "%?#@") || strings.HasPrefix(repo, "/") || strings.ContainsAny(reference, "/?#") {
		return "", "", "", errors.New("unsupported registry reference")
	}
	return host, repo, reference, nil
}

// Inspect sends only GET requests and performs anonymous bearer challenges.
// No registry credentials are read or transmitted.
func Inspect(ctx context.Context, image string, client *http.Client, allowHTTP bool) (Result, error) {
	host, repo, ref, err := ParseImage(image)
	if err != nil {
		return Result{}, err
	}
	if client == nil {
		client = &http.Client{Timeout: 12 * time.Second}
	}
	safeClient := *client
	safeClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client = &safeClient
	scheme := "https"
	if allowHTTP {
		scheme = "http"
	}
	base := scheme + "://" + host + "/v2/" + repo + "/manifests/" + url.PathEscape(ref)
	req, err := http.NewRequestWithContext(ctx, "GET", base, nil)
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Accept", accept)
	res, err := client.Do(req)
	if err != nil {
		return Result{}, err
	}
	if res.StatusCode == http.StatusUnauthorized {
		challenge := res.Header.Get("Www-Authenticate")
		res.Body.Close()
		tokenURL, ok := bearerURL(challenge, host)
		if !ok {
			return Result{}, errors.New("registry requires unsupported authentication")
		}
		tkreq, err := http.NewRequestWithContext(ctx, "GET", tokenURL, nil)
		if err != nil {
			return Result{}, err
		}
		tokenRes, err := client.Do(tkreq)
		if err != nil {
			return Result{}, err
		}
		defer tokenRes.Body.Close()
		if tokenRes.StatusCode != 200 {
			return Result{}, fmt.Errorf("anonymous token request returned HTTP %d", tokenRes.StatusCode)
		}
		var t struct {
			Token       string `json:"token"`
			AccessToken string `json:"access_token"`
		}
		if err := json.NewDecoder(io.LimitReader(tokenRes.Body, 1<<20)).Decode(&t); err != nil {
			return Result{}, err
		}
		token := t.Token
		if token == "" {
			token = t.AccessToken
		}
		if token == "" {
			return Result{}, errors.New("empty bearer token")
		}
		req, err = http.NewRequestWithContext(ctx, "GET", base, nil)
		if err != nil {
			return Result{}, err
		}
		req.Header.Set("Accept", accept)
		req.Header.Set("Authorization", "Bearer "+token)
		res, err = client.Do(req)
		if err != nil {
			return Result{}, err
		}
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return Result{}, fmt.Errorf("registry returned HTTP %d", res.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, 2<<20+1))
	if err != nil {
		return Result{}, err
	}
	if len(data) > 2<<20 {
		return Result{}, errors.New("manifest exceeds size limit")
	}
	var doc manifest
	if digest := res.Header.Get("Docker-Content-Digest"); strings.HasPrefix(digest, "sha256:") {
		expected, err := hex.DecodeString(strings.TrimPrefix(digest, "sha256:"))
		if err != nil || len(expected) != 32 {
			return Result{}, errors.New("invalid sha256 manifest digest header")
		}
		actual := sha256.Sum256(data)
		if !strings.EqualFold(hex.EncodeToString(actual[:]), hex.EncodeToString(expected)) {
			return Result{}, errors.New("registry manifest digest does not match payload")
		}
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return Result{}, err
	}
	out := Result{Image: image, Digest: res.Header.Get("Docker-Content-Digest"), MediaType: strings.Split(res.Header.Get("Content-Type"), ";")[0], Platforms: []Platform{}, Notice: "Manifest metadata only; migration and runtime compatibility remain unverified."}
	for _, d := range doc.Manifests {
		if d.Platform.OS != "" && d.Platform.Architecture != "" {
			out.Platforms = append(out.Platforms, d.Platform)
		}
	}
	return out, nil
}

// bearerURL supports only HTTPS token services, except explicitly local HTTP registries.
func bearerURL(header, host string) (string, bool) {
	if !strings.HasPrefix(strings.ToLower(header), "bearer ") {
		return "", false
	}
	h := strings.TrimSpace(header[7:])
	fields := map[string]string{}
	for _, chunk := range strings.Split(h, ",") {
		key, val, ok := strings.Cut(strings.TrimSpace(chunk), "=")
		if ok {
			fields[strings.ToLower(key)] = strings.Trim(val, "\"")
		}
	}
	raw := fields["realm"]
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return "", false
	}
	// Token URLs controlled by the registry are not contacted over insecure HTTP remotely.
	if u.Scheme != "https" && !(u.Scheme == "http" && strings.HasPrefix(host, "127.0.0.1:")) {
		return "", false
	}
	q := u.Query()
	for _, key := range []string{"service", "scope"} {
		if s := fields[key]; s != "" {
			q.Set(key, s)
		}
	}
	u.RawQuery = q.Encode()
	return u.String(), true
}
