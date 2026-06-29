// Package osquery implements a telemetry.Source backed by osquery. It runs the
// bundled osqueryd binary with a generated config of scheduled queries and
// tails its filesystem results log, converting each result row into a
// telemetry.Record. osqueryd is shipped alongside the agent by the installer.
package osquery

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/cladkins/siembox-endpoint/internal/telemetry"
	"github.com/cladkins/siembox-endpoint/internal/util"
)

// Query is a single scheduled osquery query.
type Query struct {
	Name     string
	SQL      string
	Interval int // seconds
}

// Daemon runs osqueryd and streams results as telemetry records.
type Daemon struct {
	binary  string
	workDir string
	queries []Query
}

// NewDaemon constructs a Daemon. Empty binary defaults to "osqueryd". workDir
// holds the generated config, results log, and osquery database.
func NewDaemon(binary, workDir string, queries []Query) *Daemon {
	if binary == "" {
		binary = "osqueryd"
	}
	if len(queries) == 0 {
		queries = DefaultQueries()
	}
	return &Daemon{binary: binary, workDir: workDir, queries: queries}
}

// Available reports whether osqueryd can be located (PATH or known dirs).
func (d *Daemon) Available() bool {
	_, ok := util.FindBinary(d.binary, osqueryExtraDirs)
	return ok
}

const resultsLogName = "osqueryd.results.log"

// Start launches osqueryd and tails its results until ctx is cancelled.
func (d *Daemon) Start(ctx context.Context, out chan<- telemetry.Record) error {
	if err := os.MkdirAll(d.workDir, 0o700); err != nil {
		return fmt.Errorf("create osquery workdir: %w", err)
	}
	cfgPath := filepath.Join(d.workDir, "osquery.conf")
	cfg, err := buildConfig(d.queries)
	if err != nil {
		return err
	}
	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
		return fmt.Errorf("write osquery config: %w", err)
	}

	// Start fresh each run so tailing from offset 0 only sees this run's rows.
	resultsPath := filepath.Join(d.workDir, resultsLogName)
	_ = os.Remove(resultsPath)

	bin, _ := util.FindBinary(d.binary, osqueryExtraDirs)
	cmd := exec.CommandContext(ctx, bin,
		"--config_path="+cfgPath,
		"--logger_plugin=filesystem",
		"--logger_path="+d.workDir,
		"--database_path="+filepath.Join(d.workDir, "osquery.db"),
		"--pidfile="+filepath.Join(d.workDir, "osqueryd.pid"),
		"--disable_events=false",
		"--force",
	)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start osqueryd: %w", err)
	}

	tailErr := make(chan error, 1)
	go func() { tailErr <- tailResults(ctx, resultsPath, out) }()

	select {
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return ctx.Err()
	case err := <-tailErr:
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return err
	}
}

// tailResults follows a growing results file line-by-line, emitting parsed
// records. It tolerates the file not existing yet (osqueryd creates it on the
// first scheduled run).
func tailResults(ctx context.Context, path string, out chan<- telemetry.Record) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	var f *os.File
	defer func() {
		if f != nil {
			f.Close()
		}
	}()
	reader := bufio.NewReader(nil)
	var pending []byte

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}

		if f == nil {
			opened, err := os.Open(path)
			if err != nil {
				continue // not created yet
			}
			f = opened
			reader = bufio.NewReader(f)
		}

		for {
			chunk, err := reader.ReadBytes('\n')
			pending = append(pending, chunk...)
			if err != nil {
				break // EOF or partial line; keep pending for next tick
			}
			line := bytes.TrimSpace(pending)
			pending = nil
			if len(line) == 0 {
				continue
			}
			records, perr := parseResultLine(line)
			if perr != nil {
				continue // skip malformed lines rather than aborting
			}
			for _, r := range records {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case out <- r:
				}
			}
		}
	}
}

// osqueryResult is the subset of an osquery filesystem result log line we need.
type osqueryResult struct {
	Name     string              `json:"name"`
	Action   string              `json:"action"`
	UnixTime int64               `json:"unixTime"`
	Columns  map[string]string   `json:"columns"`  // differential rows
	Snapshot []map[string]string `json:"snapshot"` // snapshot rows
}

// parseResultLine converts one results-log line into records. A snapshot line
// yields one record per row; a differential line yields a single record.
func parseResultLine(line []byte) ([]telemetry.Record, error) {
	var res osqueryResult
	if err := json.Unmarshal(line, &res); err != nil {
		return nil, err
	}
	ts := time.Unix(res.UnixTime, 0).UTC()
	if res.UnixTime == 0 {
		ts = time.Now().UTC()
	}
	name := normalizeQueryName(res.Name)

	if len(res.Snapshot) > 0 {
		out := make([]telemetry.Record, 0, len(res.Snapshot))
		for _, row := range res.Snapshot {
			out = append(out, telemetry.Record{Query: name, Action: "snapshot", Columns: row, Timestamp: ts})
		}
		return out, nil
	}
	if res.Columns != nil {
		return []telemetry.Record{{Query: name, Action: res.Action, Columns: res.Columns, Timestamp: ts}}, nil
	}
	return nil, nil
}

// normalizeQueryName strips osquery's "pack/<pack>/<name>" or "pack_<pack>_"
// prefixes so rules can reference plain logical names.
func normalizeQueryName(n string) string {
	if i := strings.LastIndex(n, "/"); i >= 0 {
		return n[i+1:]
	}
	return n
}

// YaraScanIntervalSec is how often (seconds) the agent re-runs its on-demand
// YARA scan. An agent-driven scan (RunYaraScan) is used instead of an osqueryd
// scheduled query so detection runs immediately at startup and on a predictable
// cadence the agent controls and logs, rather than waiting on osquery's internal
// scheduler.
const YaraScanIntervalSec = 60

// buildYaraScanQuery builds the on-demand yara-table query that scans the given
// paths against sigPath. osquery's yara table interprets "%" as a single path
// level and "%%" as recursive (the same globbing as file_paths), so the
// FIM-style globs translate directly into LIKE clauses. The signature file is
// referenced with sigfile (the form verified to match on the target host).
// count>0 keeps only matches.
//
// excludes are SQL LIKE patterns (where "%" matches any sequence) of paths to
// skip — used to keep the agent from scanning its own working files (notably
// grype's vulnerability database, which legitimately contains exploit/webshell
// signatures and would otherwise self-trigger the YARA rules).
func buildYaraScanQuery(paths []string, sigPath string, excludes []string) string {
	likes := make([]string, 0, len(paths))
	for _, p := range paths {
		likes = append(likes, fmt.Sprintf("path LIKE '%s'", p))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "SELECT path, matches, count FROM yara WHERE (%s)", strings.Join(likes, " OR "))
	for _, e := range excludes {
		if e != "" {
			fmt.Fprintf(&b, " AND path NOT LIKE '%s'", e)
		}
	}
	fmt.Fprintf(&b, " AND sigfile='%s' AND count > 0;", sigPath)
	return b.String()
}

// buildConfig renders an osquery config JSON from the scheduled queries
// (processes/ports/logins). YARA is handled separately by the agent's on-demand
// scan, not by osqueryd.
func buildConfig(queries []Query) ([]byte, error) {
	type sched struct {
		Query    string `json:"query"`
		Interval int    `json:"interval"`
		Snapshot bool   `json:"snapshot"`
	}
	schedule := map[string]sched{}
	for _, q := range queries {
		interval := q.Interval
		if interval <= 0 {
			interval = 60
		}
		schedule[q.Name] = sched{Query: q.SQL, Interval: interval, Snapshot: false}
	}
	cfg := map[string]any{
		"options":  map[string]any{"disable_events": false},
		"schedule": schedule,
	}
	return json.MarshalIndent(cfg, "", "  ")
}
