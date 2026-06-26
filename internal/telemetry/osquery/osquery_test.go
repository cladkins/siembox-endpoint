package osquery

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseDifferentialLine(t *testing.T) {
	line := `{"name":"pack/siembox/processes","action":"added","unixTime":1700000000,"columns":{"pid":"42","name":"sh","path":"/tmp/sh"}}`
	records, err := parseResultLine([]byte(line))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	r := records[0]
	if r.Query != "processes" { // prefix stripped
		t.Errorf("query = %q, want processes", r.Query)
	}
	if r.Action != "added" {
		t.Errorf("action = %q", r.Action)
	}
	if r.Columns["path"] != "/tmp/sh" {
		t.Errorf("columns = %v", r.Columns)
	}
	if r.Timestamp.IsZero() {
		t.Error("timestamp not set")
	}
}

func TestParseSnapshotLine(t *testing.T) {
	line := `{"name":"listening_ports","action":"snapshot","unixTime":1700000000,"snapshot":[{"port":"22"},{"port":"80"}]}`
	records, err := parseResultLine([]byte(line))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2", len(records))
	}
	if records[0].Action != "snapshot" || records[1].Columns["port"] != "80" {
		t.Errorf("unexpected snapshot records: %+v", records)
	}
}

func TestParseGarbageLine(t *testing.T) {
	if _, err := parseResultLine([]byte("not json")); err == nil {
		t.Error("expected error on garbage line")
	}
}

func TestBuildConfig(t *testing.T) {
	cfg, err := buildConfig(DefaultQueries())
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}
	var parsed struct {
		Options  map[string]any `json:"options"`
		Schedule map[string]struct {
			Query    string `json:"query"`
			Interval int    `json:"interval"`
			Snapshot bool   `json:"snapshot"`
		} `json:"schedule"`
	}
	if err := json.Unmarshal(cfg, &parsed); err != nil {
		t.Fatalf("config is not valid json: %v", err)
	}
	q, ok := parsed.Schedule["processes"]
	if !ok {
		t.Fatal("processes query missing from schedule")
	}
	if q.Interval != 60 || q.Snapshot {
		t.Errorf("processes schedule = %+v", q)
	}
	if q.Query == "" {
		t.Error("processes query SQL empty")
	}
	// Without YARA configured there must be no yara scan query or yara section.
	if _, ok := parsed.Schedule["yara_scan"]; ok {
		t.Error("yara_scan scheduled without YARA configured")
	}
}

func TestBuildConfigWithYara(t *testing.T) {
	sig := "/etc/siembox-agent/yara/siembox.yar"
	paths := []string{"/tmp/%%", "/usr/local/bin/%%"}
	cfg, err := buildConfigWithYara(DefaultQueries(), sig, paths)
	if err != nil {
		t.Fatalf("buildConfigWithYara: %v", err)
	}
	var parsed struct {
		Schedule map[string]struct {
			Query    string `json:"query"`
			Interval int    `json:"interval"`
		} `json:"schedule"`
	}
	if err := json.Unmarshal(cfg, &parsed); err != nil {
		t.Fatalf("config is not valid json: %v", err)
	}

	ys, ok := parsed.Schedule["yara_scan"]
	if !ok {
		t.Fatal("yara_scan query missing from schedule")
	}
	if ys.Interval != yaraScanIntervalSec {
		t.Errorf("yara_scan interval = %d, want %d", ys.Interval, yaraScanIntervalSec)
	}
	// Scans the on-demand yara table over each watched path, against the
	// signature file directly (sigfile), matches only.
	if !strings.Contains(ys.Query, "FROM yara ") {
		t.Errorf("yara_scan should use the on-demand yara table: %q", ys.Query)
	}
	if !strings.Contains(ys.Query, "sigfile='"+sig+"'") || !strings.Contains(ys.Query, "count > 0") {
		t.Errorf("yara_scan query unexpected: %q", ys.Query)
	}
	for _, p := range paths {
		if !strings.Contains(ys.Query, "path LIKE '"+p+"'") {
			t.Errorf("yara_scan query missing path %q: %s", p, ys.Query)
		}
	}
}

func TestBuildConfigWithYaraDisabledWhenNoPaths(t *testing.T) {
	// A signature path but no watch paths should leave YARA off.
	cfg, err := buildConfigWithYara(DefaultQueries(), "/some/sig.yar", nil)
	if err != nil {
		t.Fatalf("buildConfigWithYara: %v", err)
	}
	if strings.Contains(string(cfg), "yara_scan") {
		t.Error("yara should be disabled when no watch paths are given")
	}
}
