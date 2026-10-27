// Package transport implements the HTTPS client the agent uses to talk to the
// SIEMBox Endpoint API, plus an on-disk spool that lets events and vuln findings
// survive server outages and agent restarts.
package transport

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cladkins/siembox-endpoint/internal/models"
)

// Client is a thin REST client for the /api/edr/* endpoints.
type Client struct {
	baseURL     string
	agentID     string
	agentAPIKey string
	http        *http.Client
}

// Options configures a Client.
type Options struct {
	ServerURL          string
	AgentID            string
	AgentAPIKey        string
	CACertPath         string
	InsecureSkipVerify bool
	Timeout            time.Duration
}

// New constructs a Client, building a TLS config that optionally trusts a
// custom CA bundle (for homelab self-signed certificates).
func New(opts Options) (*Client, error) {
	tlsCfg, err := buildTLSConfig(opts.CACertPath, opts.InsecureSkipVerify)
	if err != nil {
		return nil, err
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return &Client{
		baseURL:     strings.TrimRight(opts.ServerURL, "/"),
		agentID:     opts.AgentID,
		agentAPIKey: opts.AgentAPIKey,
		http: &http.Client{
			Timeout:   timeout,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		},
	}, nil
}

// SetIdentity updates the agent credentials after enrollment so the same
// Client can be reused for authenticated calls.
func (c *Client) SetIdentity(agentID, agentAPIKey string) {
	c.agentID = agentID
	c.agentAPIKey = agentAPIKey
}

func buildTLSConfig(caPath string, insecure bool) (*tls.Config, error) {
	cfg := &tls.Config{InsecureSkipVerify: insecure, MinVersion: tls.VersionTLS12}
	if caPath != "" {
		pem, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("read CA cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no valid certificates in %s", caPath)
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

// Enroll exchanges an enrollment token for an agent identity and initial config.
func (c *Client) Enroll(ctx context.Context, req models.EnrollRequest) (models.EnrollResponse, error) {
	var resp models.EnrollResponse
	err := c.do(ctx, http.MethodPost, "/api/edr/agents/enroll", false, req, &resp)
	return resp, err
}

// Heartbeat reports liveness and returns the server's desired config version.
func (c *Client) Heartbeat(ctx context.Context, req models.HeartbeatRequest) (models.HeartbeatResponse, error) {
	var resp models.HeartbeatResponse
	path := fmt.Sprintf("/api/edr/agents/%s/heartbeat", c.agentID)
	err := c.do(ctx, http.MethodPost, path, true, req, &resp)
	return resp, err
}

// FetchConfig pulls the current agent config.
func (c *Client) FetchConfig(ctx context.Context) (models.AgentConfig, error) {
	var resp models.AgentConfig
	path := fmt.Sprintf("/api/edr/agents/%s/config", c.agentID)
	err := c.do(ctx, http.MethodGet, path, true, nil, &resp)
	return resp, err
}

// FetchYaraRules downloads the server's curated YARA signature bundle as raw
// rule text. The agent calls this only when the config's YaraRulesVersion
// exceeds its applied version. An empty body is valid (no server rules).
func (c *Client) FetchYaraRules(ctx context.Context) ([]byte, error) {
	path := fmt.Sprintf("/api/edr/agents/%s/yara", c.agentID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/plain")
	req.Header.Set("Authorization", "Bearer "+c.agentAPIKey)
	req.Header.Set("X-Agent-ID", c.agentID)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("GET %s: status %d: %s", path, resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	return io.ReadAll(resp.Body)
}

// SendInventory upserts the endpoint asset.
func (c *Client) SendInventory(ctx context.Context, req models.InventoryRequest) error {
	return c.do(ctx, http.MethodPost, "/api/edr/inventory", true, req, nil)
}

// SendEvents delivers a batch of detection/telemetry events.
func (c *Client) SendEvents(ctx context.Context, req models.EventBatch) error {
	return c.do(ctx, http.MethodPost, "/api/edr/events", true, req, nil)
}

// SendVulnerabilities delivers a vuln scan result batch.
func (c *Client) SendVulnerabilities(ctx context.Context, req models.VulnBatch) error {
	return c.do(ctx, http.MethodPost, "/api/edr/vulnerabilities", true, req, nil)
}

// ReportScan reports a scan's start or end for the scan history. A server
// that predates the route answers 404 (see StatusError).
func (c *Client) ReportScan(ctx context.Context, report models.ScanReport) (models.ScanReportResponse, error) {
	var resp models.ScanReportResponse
	err := c.do(ctx, http.MethodPost, "/api/edr/scans", true, report, &resp)
	return resp, err
}

// SendPackages delivers the host's installed-package snapshot (or, with no
// packages, asks whether the server has report.SnapshotHash). The body is
// gzip-compressed: a host's list is ~1 MB of JSON that compresses ~10x.
// A server that predates the route answers 404 (see StatusError).
func (c *Client) SendPackages(ctx context.Context, report models.PackageReport) (models.PackageReportResponse, error) {
	var resp models.PackageReportResponse
	raw, err := json.Marshal(report)
	if err != nil {
		return resp, fmt.Errorf("marshal request: %w", err)
	}
	var body bytes.Buffer
	zw := gzip.NewWriter(&body)
	if _, err := zw.Write(raw); err != nil {
		return resp, err
	}
	if err := zw.Close(); err != nil {
		return resp, err
	}
	const path = "/api/edr/packages"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, &body)
	if err != nil {
		return resp, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.agentAPIKey)
	req.Header.Set("X-Agent-ID", c.agentID)
	if err := c.send(req, http.MethodPost, path, &resp); err != nil {
		return resp, err
	}
	return resp, nil
}

// SendMetrics delivers performance samples and process snapshots. A server
// that predates the route answers 404 (see StatusError).
func (c *Client) SendMetrics(ctx context.Context, batch models.MetricsBatch) (models.MetricsResponse, error) {
	var resp models.MetricsResponse
	err := c.do(ctx, http.MethodPost, "/api/edr/metrics", true, batch, &resp)
	return resp, err
}

// StatusError is a non-2xx answer from the server.
type StatusError struct {
	Method string
	Path   string
	Status int
	Body   string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("%s %s: status %d: %s", e.Method, e.Path, e.Status, e.Body)
}

// PostRaw sends an already-serialized JSON body to an authenticated endpoint.
// Used by the spool to replay queued payloads without re-typing them.
func (c *Client) PostRaw(ctx context.Context, path string, raw []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.agentAPIKey)
	req.Header.Set("X-Agent-ID", c.agentID)

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("POST %s: status %d: %s", path, resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	return nil
}

// do performs a single JSON request/response. If out is nil the response body
// is discarded. Non-2xx responses become errors carrying the status and a
// snippet of the body.
func (c *Client) do(ctx context.Context, method, path string, auth bool, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		body = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if auth {
		req.Header.Set("Authorization", "Bearer "+c.agentAPIKey)
		req.Header.Set("X-Agent-ID", c.agentID)
	}
	return c.send(req, method, path, out)
}

// send performs req; a non-2xx answer becomes a *StatusError carrying a snippet
// of the body, and a 2xx JSON body is decoded into out unless out is nil.
func (c *Client) send(req *http.Request, method, path string, out any) error {
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return &StatusError{Method: method, Path: path, Status: resp.StatusCode, Body: strings.TrimSpace(string(snippet))}
	}

	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}
