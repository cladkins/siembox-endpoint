package osquery

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/cladkins/siembox-edr/internal/telemetry"
	"github.com/cladkins/siembox-edr/internal/util"
)

// osqueryExtraDirs are non-PATH locations to look for osquery binaries, which
// matters under sudo/launchd/Windows-service where PATH is minimal. Covers the
// official install paths on each OS (macOS pkg + Homebrew, Windows MSI).
var osqueryExtraDirs = func() []string {
	if runtime.GOOS == "windows" {
		return []string{filepath.Join(os.Getenv("ProgramFiles"), "osquery")}
	}
	return []string{
		"/usr/local/bin",
		"/opt/homebrew/bin",
		"/opt/osquery/lib/osquery.app/Contents/MacOS",
	}
}()

// oneShotRunner executes a command and returns its stdout. Overridable in tests.
type oneShotRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

func defaultOneShotRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}

// RunOnce executes each query once via `osqueryi --json` and returns the rows
// as snapshot records. Unlike the daemon Source, this needs no scheduling and
// returns immediately — used by the one-shot "check" command for endpoint
// testing. Empty binary defaults to "osqueryi"; empty queries use the default
// pack.
func RunOnce(ctx context.Context, binary string, queries []Query) ([]telemetry.Record, error) {
	return runOnceWith(ctx, defaultOneShotRunner, binary, queries)
}

func runOnceWith(ctx context.Context, run oneShotRunner, binary string, queries []Query) ([]telemetry.Record, error) {
	if binary == "" {
		binary = "osqueryi"
	}
	binary, _ = util.FindBinary(binary, osqueryExtraDirs)
	if len(queries) == 0 {
		queries = DefaultQueries()
	}
	var records []telemetry.Record
	now := time.Now().UTC()
	for _, q := range queries {
		out, err := run(ctx, binary, "--json", q.SQL)
		if err != nil {
			if stderr := util.StderrText(err); stderr != "" {
				return nil, fmt.Errorf("osqueryi %s: %w: %s", q.Name, err, stderr)
			}
			return nil, fmt.Errorf("osqueryi %s: %w", q.Name, err)
		}
		rows, err := parseOsqueryiJSON(out)
		if err != nil {
			return nil, fmt.Errorf("parse %s output: %w", q.Name, err)
		}
		for _, row := range rows {
			records = append(records, telemetry.Record{
				Query:     q.Name,
				Action:    "snapshot",
				Columns:   row,
				Timestamp: now,
			})
		}
	}
	return records, nil
}

// RunYaraScan runs a one-shot on-demand YARA scan of paths against sigPath via
// osqueryi and returns each matching file as a record (query "yara_scan",
// action "added"). This is the same on-demand `yara` table used to verify
// matches by hand; running it from the agent avoids depending on osqueryd's
// internal scheduler. Empty binary defaults to "osqueryi". Returns nil if paths
// or sigPath are empty (YARA disabled).
func RunYaraScan(ctx context.Context, binary string, paths []string, sigPath string) ([]telemetry.Record, error) {
	return runYaraScanWith(ctx, defaultOneShotRunner, binary, paths, sigPath)
}

func runYaraScanWith(ctx context.Context, run oneShotRunner, binary string, paths []string, sigPath string) ([]telemetry.Record, error) {
	if len(paths) == 0 || sigPath == "" {
		return nil, nil
	}
	if binary == "" {
		binary = "osqueryi"
	}
	binary, _ = util.FindBinary(binary, osqueryExtraDirs)

	out, err := run(ctx, binary, "--json", buildYaraScanQuery(paths, sigPath))
	if err != nil {
		if stderr := util.StderrText(err); stderr != "" {
			return nil, fmt.Errorf("osqueryi yara: %w: %s", err, stderr)
		}
		return nil, fmt.Errorf("osqueryi yara: %w", err)
	}
	rows, err := parseOsqueryiJSON(out)
	if err != nil {
		return nil, fmt.Errorf("parse yara output: %w", err)
	}
	now := time.Now().UTC()
	records := make([]telemetry.Record, 0, len(rows))
	for _, row := range rows {
		records = append(records, telemetry.Record{
			Query:     "yara_scan",
			Action:    "added",
			Columns:   row,
			Timestamp: now,
		})
	}
	return records, nil
}

// parseOsqueryiJSON parses the JSON array osqueryi emits (one object per row,
// all values strings).
func parseOsqueryiJSON(raw []byte) ([]map[string]string, error) {
	var rows []map[string]string
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}
