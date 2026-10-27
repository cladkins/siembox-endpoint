package agent

import (
	"context"
	"testing"
	"time"

	"github.com/cladkins/siembox-endpoint/internal/models"
)

// Scan policies: when the server's config carries a managed scan_policy, the
// server schedules this agent's scans and issues them as heartbeat requests
// with trigger "policy"; the agent's own intervals and startup scans stop.

func managedPolicy(disabled ...string) *models.ScanPolicy {
	p := &models.ScanPolicy{Managed: true, Policy: "Servers", Scans: map[string]models.ScanPolicyEntry{}}
	for _, t := range []string{models.ScanTypeVuln, models.ScanTypeYara, models.ScanTypePackages, models.ScanTypeInventory} {
		p.Scans[t] = models.ScanPolicyEntry{Enabled: true}
	}
	for _, t := range disabled {
		p.Scans[t] = models.ScanPolicyEntry{Enabled: false}
	}
	return p
}

func TestScanPolicyHelpers(t *testing.T) {
	var none *models.ScanPolicy
	if none.IsManaged() || !none.Enabled(models.ScanTypeVuln) {
		t.Fatal("nil policy: not managed, everything enabled")
	}
	p := managedPolicy(models.ScanTypeYara)
	if !p.IsManaged() || p.Enabled(models.ScanTypeYara) || !p.Enabled(models.ScanTypeVuln) || !p.Enabled("future_type") {
		t.Fatalf("policy helpers: %+v", p)
	}
	if (&models.ScanPolicy{Managed: false}).IsManaged() {
		t.Fatal("managed=false is not managed")
	}

	a, _ := newScanTestAgent(t)
	if !a.ownSchedule() || a.scanPolicy() != nil {
		t.Fatal("no scan_policy in config: the agent runs its own intervals")
	}
	a.state.Identity.Config.ScanPolicy = p
	if a.ownSchedule() || a.scanPolicy() != p {
		t.Fatal("managed scan_policy: the server schedules scans")
	}
}

func TestPolicyRequestRunsAndReportsByID(t *testing.T) {
	a, fake := newScanTestAgent(t)
	a.state.Identity.Config.ScanPolicy = managedPolicy()
	fake.requests = []models.ScanRequest{{ScanID: "pol-1", ScanType: models.ScanTypeInventory, Trigger: models.ScanTriggerPolicy}}
	ctx := context.Background()
	a.heartbeat(ctx)
	a.scans.wg.Wait()
	a.heartbeat(ctx) // served again until the start report lands: runs once
	a.scans.wg.Wait()

	if len(fake.inventory) != 1 || fake.inventory[0].ScanID != "pol-1" {
		t.Fatalf("inventory sends: %+v", fake.inventory)
	}
	reps := fake.takeReports()
	if got := statuses(reps); got != "inventory:pol-1:running,inventory:pol-1:succeeded" {
		t.Fatalf("reports: %s", got)
	}
	for _, r := range reps {
		if r.Trigger != models.ScanTriggerPolicy {
			t.Errorf("report trigger %q, want policy", r.Trigger)
		}
	}
}

func TestPolicyPackageRunIsNotForced(t *testing.T) {
	a, fake := newScanTestAgent(t)
	a.runScan(context.Background(), models.ScanTypePackages, models.ScanTriggerPolicy, []string{"pol-2"})
	if len(fake.packages) != 1 || fake.packages[0].Force || fake.packages[0].ScanID != "pol-2" {
		t.Fatalf("policy package report: %+v", fake.packages)
	}
}

func TestPolicyRequestOnHostWithoutScannerFailsWithReason(t *testing.T) {
	a, fake := newScanTestAgent(t) // noop vulnerability scanner: grype missing
	a.runScan(context.Background(), models.ScanTypeVuln, models.ScanTriggerPolicy, []string{"pol-3"})
	reps := fake.takeReports()
	if got := statuses(reps); got != "vuln:pol-3:running,vuln:pol-3:failed" {
		t.Fatalf("reports: %s", got)
	}
	if reps[1].Error == "" || len(fake.vulns) != 0 {
		t.Fatalf("want a failure with the reason and no vulnerability report: %+v %+v", reps[1], fake.vulns)
	}
}

func TestStartupConfigFetchAppliesScanPolicyAtSameVersion(t *testing.T) {
	// A self-updated agent's cached config predates scan_policy at the same
	// config_version: the startup fetch applies it anyway; a regular poll would not.
	a, fake := newScanTestAgent(t)
	a.state.Identity.Config = models.AgentConfig{ConfigVersion: 7}
	fake.config = models.AgentConfig{ConfigVersion: 7, ScanPolicy: managedPolicy()}
	ctx := context.Background()
	a.fetchConfig(ctx, false)
	if !a.ownSchedule() {
		t.Fatal("a regular poll at the same version must not apply")
	}
	a.fetchConfig(ctx, true)
	if a.ownSchedule() {
		t.Fatal("the forced startup fetch applies scan_policy")
	}
}

func TestManagedYaraWatchesChangedFilesOnly(t *testing.T) {
	a, _ := newScanTestAgent(t)
	a.state.Identity.Config.ScanPolicy = managedPolicy()
	start := time.Now()
	a.yaraWatchFrom(start)
	if a.yaraNextFull(models.ScanTriggerSchedule) {
		t.Fatal("the per-minute pass of a managed agent reads only changed files")
	}
	if !a.yaraNextFull(models.ScanTriggerPolicy) {
		t.Fatal("a policy pass is full")
	}
	a.yaraWatchFrom(start.Add(time.Hour))
	a.yaraMu.Lock()
	since := a.yaraSince
	a.yaraMu.Unlock()
	if !since.Equal(start) {
		t.Fatalf("yaraWatchFrom keeps an existing cutoff: %v", since)
	}
}

// runFor runs the agent loop for d against the fake server, then stops it.
func runFor(t *testing.T, a *Agent, d time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	if err := a.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}
}

func TestRunUnmanagedRunsItsStartupScans(t *testing.T) {
	a, fake := newScanTestAgent(t)
	fake.config = models.AgentConfig{ConfigVersion: 1, HeartbeatIntervalSec: 3600}
	runFor(t, a, 500*time.Millisecond)
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.inventory) == 0 || len(fake.packages) == 0 {
		t.Fatalf("startup inventory and packages: inventory=%d packages=%d", len(fake.inventory), len(fake.packages))
	}
}

func TestRunManagedSkipsStartupScansAndRunsPolicyRequests(t *testing.T) {
	a, fake := newScanTestAgent(t)
	fake.config = models.AgentConfig{ConfigVersion: 1, HeartbeatIntervalSec: 1, ScanPolicy: managedPolicy()}
	fake.requests = []models.ScanRequest{{ScanID: "pol-9", ScanType: models.ScanTypeInventory, Trigger: models.ScanTriggerPolicy}}
	runFor(t, a, 1800*time.Millisecond)
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.packages) != 0 || len(fake.vulns) != 0 {
		t.Fatalf("a managed agent runs no startup scans: packages=%d vulns=%d", len(fake.packages), len(fake.vulns))
	}
	if len(fake.inventory) != 1 || fake.inventory[0].ScanID != "pol-9" {
		t.Fatalf("only the policy request's inventory: %+v", fake.inventory)
	}
	if len(fake.heartbeats) == 0 {
		t.Fatal("no heartbeat")
	}
}
