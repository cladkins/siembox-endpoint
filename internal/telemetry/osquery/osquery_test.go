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
	// Without YARA configured there must be no yara_events query or yara section.
	if _, ok := parsed.Schedule["yara_events"]; ok {
		t.Error("yara_events scheduled without YARA configured")
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
		FilePaths map[string][]string `json:"file_paths"`
		Yara      struct {
			Signatures map[string][]string `json:"signatures"`
			FilePaths  map[string][]string `json:"file_paths"`
		} `json:"yara"`
	}
	if err := json.Unmarshal(cfg, &parsed); err != nil {
		t.Fatalf("config is not valid json: %v", err)
	}

	ye, ok := parsed.Schedule["yara_events"]
	if !ok {
		t.Fatal("yara_events query missing from schedule")
	}
	if ye.Interval != yaraEventsInterval {
		t.Errorf("yara_events interval = %d, want %d", ye.Interval, yaraEventsInterval)
	}
	if !strings.Contains(ye.Query, "yara_events") || !strings.Contains(ye.Query, "count > 0") {
		t.Errorf("yara_events query unexpected: %q", ye.Query)
	}

	cat, ok := parsed.FilePaths["siembox_yara"]
	if !ok || len(cat) != len(paths) {
		t.Errorf("file_paths category = %v, want %v", cat, paths)
	}
	if got := parsed.Yara.Signatures["siembox"]; len(got) != 1 || got[0] != sig {
		t.Errorf("yara signatures = %v, want [%s]", got, sig)
	}
	if got := parsed.Yara.FilePaths["siembox_yara"]; len(got) != 1 || got[0] != "siembox" {
		t.Errorf("yara file_paths mapping = %v, want [siembox]", got)
	}
}

func TestBuildConfigWithYaraDisabledWhenNoPaths(t *testing.T) {
	// A signature path but no watch paths should leave YARA off.
	cfg, err := buildConfigWithYara(DefaultQueries(), "/some/sig.yar", nil)
	if err != nil {
		t.Fatalf("buildConfigWithYara: %v", err)
	}
	if strings.Contains(string(cfg), "yara_events") {
		t.Error("yara should be disabled when no watch paths are given")
	}
}
