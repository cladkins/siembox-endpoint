// Package models defines the wire types exchanged between the SIEMBox Endpoint
// agent and the SIEMBox server's /api/edr/* endpoints. These types are the
// Go-side mirror of the contract documented in docs/ENDPOINT_API.md and must stay
// in sync with the server implementation.
package models

import "time"

// Severity levels, aligned with SIEMBox's existing rule/alert severities.
const (
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// Event types carried in an EventBatch.
const (
	EventTypeDetection = "detection"
	EventTypeTelemetry = "telemetry"
)

// EnrollRequest is sent once on first run to exchange an enrollment token for
// a stable agent identity.
type EnrollRequest struct {
	EnrollmentToken string `json:"enrollment_token"`
	Hostname        string `json:"hostname"`
	OS              string `json:"os"`
	OSVersion       string `json:"os_version"`
	Arch            string `json:"arch"`
	AgentVersion    string `json:"agent_version"`
	IP              string `json:"ip"`
}

// EnrollResponse returns the agent's permanent identity and initial config.
type EnrollResponse struct {
	AgentID     string      `json:"agent_id"`
	AgentAPIKey string      `json:"agent_api_key"`
	Config      AgentConfig `json:"config"`
}

// AgentConfig is the server-controlled runtime configuration. It is returned
// on enroll and re-fetched whenever the heartbeat reports a newer
// ConfigVersion.
type AgentConfig struct {
	ConfigVersion         int      `json:"config_version"`
	HeartbeatIntervalSec  int      `json:"heartbeat_interval_seconds"`
	ConfigPollIntervalSec int      `json:"config_poll_interval_seconds"`
	InventoryIntervalSec  int      `json:"inventory_interval_seconds"`
	VulnScanIntervalSec   int      `json:"vuln_scan_interval_seconds"`
	EnabledModules        []string `json:"enabled_modules"`
	RuleSetVersion        int      `json:"rule_set_version"`
	Rules                 []string `json:"rules,omitempty"` // Sigma rule YAML documents
	// YaraRulesVersion increments whenever the server's YARA signature bundle
	// changes. When it exceeds the agent's applied version, the agent downloads
	// the bundle from GET /api/edr/agents/:id/yara and reloads detection.
	YaraRulesVersion int `json:"yara_rules_version"`
	// AgentUpdate is the server's pending request to update the agent binary, or
	// nil when none is requested. See AgentUpdateRequest.
	AgentUpdate *AgentUpdateRequest `json:"agent_update"`
}

// AgentUpdateRequest asks the agent to update itself to Version. The server only
// names a version (plain X.Y.Z, no "v"); the agent derives the download location
// itself and never accepts a URL from the server. RequestID is a server-generated
// UUID, new for every request; the agent attempts a given RequestID at most once.
type AgentUpdateRequest struct {
	Version   string `json:"version"`
	RequestID string `json:"request_id"`
}

// Agent self-update states reported in HeartbeatRequest.Update.
const (
	UpdateStateDownloading = "downloading"
	UpdateStateInstalling  = "installing"
	UpdateStateSucceeded   = "succeeded"
	UpdateStateFailed      = "failed"
)

// UpdateReport is the status of the agent's most recent update attempt. It is
// sent on every heartbeat until the server's config stops carrying RequestID.
type UpdateReport struct {
	RequestID string `json:"request_id"`
	Version   string `json:"version"`
	State     string `json:"state"`           // UpdateState*
	Error     string `json:"error,omitempty"` // short, <= 500 chars, only for failed
}

// HeartbeatRequest is sent periodically to signal liveness.
type HeartbeatRequest struct {
	Status       string `json:"status"`
	AgentVersion string `json:"agent_version"`
	// Update is the status of the most recent self-update attempt, omitted when
	// there is none to report.
	Update *UpdateReport `json:"update,omitempty"`
}

// HeartbeatResponse tells the agent the current desired config version so it
// knows whether to re-pull config.
type HeartbeatResponse struct {
	ConfigVersion int `json:"config_version"`
}

// Software is a single installed package/application discovered on the host.
type Software struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Source  string `json:"source"` // e.g. "dpkg", "homebrew", "msi"
}

// HostInventory is the set of host facts plus installed software, sent on
// enroll and on a schedule. The server upserts this as an asset of type
// "endpoint".
type HostInventory struct {
	Hostname     string     `json:"hostname"`
	OS           string     `json:"os"`
	OSVersion    string     `json:"os_version"`
	Arch         string     `json:"arch"`
	IP           string     `json:"ip"`
	MAC          string     `json:"mac"`
	AgentVersion string     `json:"agent_version"`
	Software     []Software `json:"software,omitempty"`
	CollectedAt  time.Time  `json:"collected_at"`
}

// InventoryRequest wraps a HostInventory with the reporting agent id.
type InventoryRequest struct {
	AgentID   string        `json:"agent_id"`
	Inventory HostInventory `json:"inventory"`
}

// Event is a single detection or telemetry record. Detections are normalized
// server-side into the existing alerts pipeline.
type Event struct {
	ID        string                 `json:"id"`
	Timestamp time.Time              `json:"timestamp"`
	Type      string                 `json:"type"`     // EventType*
	Severity  string                 `json:"severity"` // Severity*
	Title     string                 `json:"title"`
	RuleID    string                 `json:"rule_id,omitempty"`
	RuleName  string                 `json:"rule_name,omitempty"`
	Source    string                 `json:"source"` // e.g. "osquery:process_events"
	Fields    map[string]interface{} `json:"fields,omitempty"`
}

// EventBatch is a batch of events from one agent.
type EventBatch struct {
	AgentID string  `json:"agent_id"`
	Events  []Event `json:"events"`
}

// Vulnerability is a single CVE finding tied to an installed package. Mapped
// server-side into the existing vulnerabilities table against the endpoint
// asset.
type Vulnerability struct {
	CVE              string  `json:"cve"`
	Package          string  `json:"package"`
	InstalledVersion string  `json:"installed_version"`
	FixedVersion     string  `json:"fixed_version,omitempty"`
	Severity         string  `json:"severity"`
	CVSS             float64 `json:"cvss,omitempty"`
	Description      string  `json:"description,omitempty"`
	Source           string  `json:"source"` // e.g. "grype"
}

// VulnBatch is the result of one vulnerability scan from one agent.
type VulnBatch struct {
	AgentID         string          `json:"agent_id"`
	ScanStartedAt   time.Time       `json:"scan_started_at"`
	ScanCompletedAt time.Time       `json:"scan_completed_at"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// Package is one installed software package on the host, as the package
// inventory reports it. Type is the ecosystem: "deb", "rpm", "apk", "brew",
// "app" (a macOS app bundle), "pkg" (a macOS installer receipt), "msi"/"win"
// (a Windows uninstall entry).
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
}

// PackageReport is a full snapshot of the host's installed packages, sent to
// POST /api/edr/packages. It replaces the agent's previous snapshot on the
// server. SnapshotHash identifies the list; when the server already has it,
// nothing is written. Without Packages (nil), the request only asks whether the
// server has SnapshotHash.
type PackageReport struct {
	AgentID      string    `json:"agent_id"`
	SnapshotHash string    `json:"snapshot_hash"`
	CollectedAt  time.Time `json:"collected_at"`
	Force        bool      `json:"force,omitempty"`
	Packages     []Package `json:"packages,omitempty"`
}

// PackageReportResponse is the server's answer to a PackageReport.
type PackageReportResponse struct {
	// Accepted: the snapshot was stored, or the server already had it.
	Accepted bool `json:"accepted"`
	// Unchanged: the server already had this snapshot; nothing was written.
	Unchanged bool `json:"unchanged"`
	// SnapshotRequired: a hash-only report the server does not have.
	SnapshotRequired bool `json:"snapshot_required"`
	PackageCount     int  `json:"package_count"`
	Stored           int  `json:"stored"`
	Removed          int  `json:"removed"`
}
