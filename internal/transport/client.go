// Package transport implements the HTTPS client the agent uses to talk to the
// SIEMBox EDR API, plus an on-disk spool that lets events and vuln findings
// survive server outages and agent restarts.
package transport

import (
	"bytes"
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

	"github.com/cladkins/siembox-edr/internal/models"
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

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s %s: status %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(snippet)))
	}

	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}
