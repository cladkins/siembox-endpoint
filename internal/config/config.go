// Package config handles the agent's local, on-disk configuration and the
// persisted identity it receives after enrollment. Identity material (the
// agent API key) is written with 0600 permissions.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/cladkins/siembox-endpoint/internal/models"
)

// Settings is the operator-provided bootstrap configuration, typically written
// by the installer or an admin before first run.
type Settings struct {
	// ServerURL is the base URL of the SIEMBox API, e.g. http://siembox.local:8421.
	// The API on 8421 serves plain HTTP; use https only behind a TLS proxy.
	ServerURL string `json:"server_url"`
	// EnrollmentToken is consumed once to enroll, then cleared.
	EnrollmentToken string `json:"enrollment_token,omitempty"`
	// CACertPath optionally points to a PEM bundle to trust (homelab self-signed certs).
	CACertPath string `json:"ca_cert_path,omitempty"`
	// InsecureSkipVerify disables TLS verification. Strongly discouraged; for lab use only.
	InsecureSkipVerify bool `json:"insecure_skip_verify,omitempty"`
	// GrypeBinary is the grype executable to use (name on PATH or absolute path).
	// Empty defaults to "grype".
	GrypeBinary string `json:"grype_binary,omitempty"`
	// VulnScanTarget is the grype source to scan. Empty defaults to "dir:/"
	// (catalog the host's installed packages).
	VulnScanTarget string `json:"vuln_scan_target,omitempty"`
	// OsqueryBinary is the osqueryd executable to use (name on PATH or absolute
	// path). Empty defaults to "osqueryd".
	OsqueryBinary string `json:"osquery_binary,omitempty"`
}

// Identity is the persisted result of enrollment.
type Identity struct {
	AgentID     string             `json:"agent_id"`
	AgentAPIKey string             `json:"agent_api_key"`
	Config      models.AgentConfig `json:"config"`
	// AppliedYaraRulesVersion is the YARA bundle version currently written to
	// disk. Persisted so the agent doesn't re-download an unchanged bundle on
	// every restart.
	AppliedYaraRulesVersion int `json:"applied_yara_rules_version,omitempty"`

	// PendingUpdate is a self-update whose installer has been launched but whose
	// outcome is not yet known. The restarted agent resolves it on startup.
	PendingUpdate *PendingUpdate `json:"pending_update,omitempty"`
	// UpdateReport is the status of the most recent update attempt, reported on
	// heartbeats until the server's config stops carrying its request id.
	UpdateReport *models.UpdateReport `json:"update_report,omitempty"`
	// LastUpdateRequestID is the most recent update request id the agent acted
	// on. A request id is attempted at most once.
	LastUpdateRequestID string `json:"last_update_request_id,omitempty"`
}

// PendingUpdate records an in-flight self-update.
type PendingUpdate struct {
	RequestID string    `json:"request_id"`
	Version   string    `json:"version"`
	StartedAt time.Time `json:"started_at"`
}

// State bundles the loaded settings and identity along with the directory they
// live in.
type State struct {
	Dir      string
	Settings Settings
	Identity Identity

	mu sync.Mutex // serializes Mutate/View/SaveIdentity
}

const (
	settingsFile = "agent.json"
	identityFile = "identity.json"
)

// DefaultDir returns the platform-appropriate directory for agent state.
func DefaultDir() string {
	switch runtime.GOOS {
	case "windows":
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "SIEMBox", "agent")
	case "darwin":
		return "/Library/Application Support/SIEMBox/agent"
	default: // linux and others
		return "/etc/siembox-agent"
	}
}

// LoadSettingsOnly reads just the settings file, without requiring the
// server_url/enrollment fields. Used by one-shot commands (scan/check) that run
// locally and never contact the server. A missing file yields zero-value
// settings (callers fall back to PATH defaults).
func LoadSettingsOnly(dir string) (Settings, error) {
	var s Settings
	raw, err := os.ReadFile(filepath.Join(dir, settingsFile))
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return s, fmt.Errorf("parse settings: %w", err)
	}
	return s, nil
}

// Load reads settings and (if present) identity from dir. A missing identity
// file is not an error: it simply means the agent has not enrolled yet.
func Load(dir string) (*State, error) {
	s := &State{Dir: dir}

	raw, err := os.ReadFile(filepath.Join(dir, settingsFile))
	if err != nil {
		return nil, fmt.Errorf("read settings: %w", err)
	}
	if err := json.Unmarshal(raw, &s.Settings); err != nil {
		return nil, fmt.Errorf("parse settings: %w", err)
	}
	if s.Settings.ServerURL == "" {
		return nil, fmt.Errorf("server_url is required in %s", settingsFile)
	}

	if raw, err := os.ReadFile(filepath.Join(dir, identityFile)); err == nil {
		if err := json.Unmarshal(raw, &s.Identity); err != nil {
			return nil, fmt.Errorf("parse identity: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read identity: %w", err)
	}

	return s, nil
}

// Enrolled reports whether the agent already has an identity.
func (s *State) Enrolled() bool { return s.Identity.AgentID != "" && s.Identity.AgentAPIKey != "" }

// SaveIdentity persists the identity with restrictive permissions.
func (s *State) SaveIdentity() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveIdentityLocked()
}

// Mutate runs fn on the identity under the state lock and persists the result.
// Use it (and View) for fields touched by more than one goroutine.
func (s *State) Mutate(fn func(*Identity)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.Identity)
	return s.saveIdentityLocked()
}

// View runs fn on the identity under the state lock without persisting.
func (s *State) View(fn func(*Identity)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.Identity)
}

func (s *State) saveIdentityLocked() error {
	raw, err := json.MarshalIndent(s.Identity, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(s.Dir, identityFile)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return fmt.Errorf("write identity: %w", err)
	}
	return nil
}

// SaveSettings persists settings (used to clear the consumed enrollment token).
func (s *State) SaveSettings() error {
	raw, err := json.MarshalIndent(s.Settings, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.Dir, settingsFile), raw, 0o600)
}
