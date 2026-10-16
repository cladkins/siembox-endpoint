package update

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// Repo is the only place the agent downloads updates from. It is hardcoded:
	// a server can name a version but never a location.
	Repo = "cladkins/siembox-endpoint"
	// DefaultBaseURL is the release download root; the full URL is
	// <base>/v<VERSION>/<asset>.
	DefaultBaseURL = "https://github.com/" + Repo + "/releases/download"

	// MaxDownloadBytes caps a single downloaded (or extracted) file.
	MaxDownloadBytes int64 = 300 << 20
	maxSumsBytes     int64 = 1 << 20
	sumsAsset              = "SHA256SUMS"
)

// NewHTTPClient returns the client used for release downloads: HTTPS only
// (including redirects), system CA store only, and HTTPS_PROXY honored. It
// deliberately ignores the SIEMBox ca_cert_path / insecure_skip_verify settings,
// which describe trust in the SIEMBox server, not in GitHub.
func NewHTTPClient() *http.Client {
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12}, // nil RootCAs: system pool
		TLSHandshakeTimeout:   30 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	return &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" {
				return fmt.Errorf("refusing non-HTTPS redirect to %s", req.URL.Redacted())
			}
			if len(via) >= 10 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
}

// Downloader fetches release files and verifies them against SHA256SUMS.
type Downloader struct {
	BaseURL string       // defaults to DefaultBaseURL
	Client  *http.Client // defaults to NewHTTPClient()
	MaxSize int64        // per-file cap, defaults to MaxDownloadBytes
}

func (d *Downloader) base() string {
	if d.BaseURL != "" {
		return strings.TrimRight(d.BaseURL, "/")
	}
	return DefaultBaseURL
}

func (d *Downloader) client() *http.Client {
	if d.Client != nil {
		return d.Client
	}
	return NewHTTPClient()
}

func (d *Downloader) max() int64 {
	if d.MaxSize > 0 {
		return d.MaxSize
	}
	return MaxDownloadBytes
}

// releaseURL builds <base>/v<version>/<name>. Both parts are validated; this is
// the only place a URL is constructed.
func (d *Downloader) releaseURL(version, name string) (string, error) {
	if !ValidVersion(version) {
		return "", errInvalidVersion
	}
	if name != sumsAsset && !assetNameRe.MatchString(name) {
		return "", fmt.Errorf("invalid asset name %q", name)
	}
	u := d.base() + "/v" + version + "/" + url.PathEscape(name)
	pu, err := url.Parse(u)
	if err != nil || pu.Scheme != "https" {
		return "", fmt.Errorf("download URL must be https")
	}
	return u, nil
}

// open issues the GET and returns the body, enforcing status, scheme and size.
func (d *Downloader) open(ctx context.Context, version, name string, limit int64) (io.ReadCloser, error) {
	u, err := d.releaseURL(version, name)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "siembox-agent-updater")
	resp, err := d.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", name, err)
	}
	if resp.Request != nil && resp.Request.URL.Scheme != "https" {
		resp.Body.Close()
		return nil, fmt.Errorf("download %s: final URL is not https", name)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("%s not found in release v%s (HTTP 404)", name, version)
		}
		return nil, fmt.Errorf("download %s: HTTP %d", name, resp.StatusCode)
	}
	if resp.ContentLength > limit {
		resp.Body.Close()
		return nil, fmt.Errorf("%s is %d bytes, over the %d byte limit", name, resp.ContentLength, limit)
	}
	return resp.Body, nil
}

// FetchSums downloads and parses the release's SHA256SUMS. A release without
// one cannot be used (fail closed).
func (d *Downloader) FetchSums(ctx context.Context, version string) (map[string]string, error) {
	body, err := d.open(ctx, version, sumsAsset, maxSumsBytes)
	if err != nil {
		if strings.Contains(err.Error(), "HTTP 404") {
			return nil, fmt.Errorf("release v%s has no SHA256SUMS; refusing unverified update", version)
		}
		return nil, err
	}
	defer body.Close()
	raw, err := io.ReadAll(io.LimitReader(body, maxSumsBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read SHA256SUMS: %w", err)
	}
	if int64(len(raw)) > maxSumsBytes {
		return nil, errors.New("SHA256SUMS too large")
	}
	return ParseSHA256SUMS(strings.NewReader(string(raw)))
}

// FetchAsset downloads name into dir, verifying size and the expected sha256
// (hex). The file only appears under its final name once verified. Returns the
// final path.
func (d *Downloader) FetchAsset(ctx context.Context, version, name, wantSum, dir string) (string, error) {
	limit := d.max()
	body, err := d.open(ctx, version, name, limit)
	if err != nil {
		return "", err
	}
	defer body.Close()

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	final := filepath.Join(dir, name)
	tmp, err := os.OpenFile(final+".part", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	cleanup := func() { tmp.Close(); os.Remove(final + ".part") }

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(body, limit+1))
	if err != nil {
		cleanup()
		return "", fmt.Errorf("download %s: %w", name, err)
	}
	if n > limit {
		cleanup()
		return "", fmt.Errorf("%s exceeds the %d byte limit", name, limit)
	}
	if got := hex.EncodeToString(h.Sum(nil)); !strings.EqualFold(got, wantSum) {
		cleanup()
		return "", fmt.Errorf("checksum mismatch for %s: got %s, SHA256SUMS says %s", name, got, wantSum)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(final + ".part")
		return "", err
	}
	if err := os.Rename(final+".part", final); err != nil {
		os.Remove(final + ".part")
		return "", err
	}
	return final, nil
}
