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

	"github.com/cladkins/siembox-edr/internal/models"
)

// Settings is the operator-provided bootstrap configuration, typically written
// by the installer or an admin before first run.
type Settings struct {
	// ServerURL is the base URL of the SIEMBox API, e.g. https://siembox.local:8421
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
}

// Identity is the persisted result of enrollment.
type Identity struct {
	AgentID     string             `json:"agent_id"`
	AgentAPIKey string             `json:"agent_api_key"`
	Config      models.AgentConfig `json:"config"`
}

// State bundles the loaded settings and identity along with the directory they
// live in.
type State struct {
	Dir      string
	Settings Settings
	Identity Identity
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
