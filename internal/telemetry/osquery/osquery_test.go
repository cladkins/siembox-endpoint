package osquery

import (
	"context"
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

func TestBuildYaraScanQuery(t *testing.T) {
	sig := "/Library/Application Support/SIEMBox/agent/yara/siembox.yar"
	paths := []string{"/tmp/%%", "/usr/local/bin/%%"}
	q := buildYaraScanQuery(paths, sig)

	if !strings.Contains(q, "FROM yara ") {
		t.Errorf("should use the on-demand yara table: %q", q)
	}
	if !strings.Contains(q, "sigfile='"+sig+"'") || !strings.Contains(q, "count > 0") {
		t.Errorf("query unexpected: %q", q)
	}
	for _, p := range paths {
		if !strings.Contains(q, "path LIKE '"+p+"'") {
			t.Errorf("query missing path %q: %s", p, q)
		}
	}
}

func TestRunYaraScanParsesRows(t *testing.T) {
	fake := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return []byte(`[{"path":"/tmp/x","matches":"SIEMBox_YARA_SelfTest","count":"1"}]`), nil
	}
	recs, err := runYaraScanWith(context.Background(), fake, "osqueryi",
		[]string{"/tmp/%%"}, "/sig/siembox.yar")
	if err != nil {
		t.Fatalf("runYaraScanWith: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	r := recs[0]
	if r.Query != "yara_scan" || r.Action != "added" {
		t.Errorf("record meta = %q/%q, want yara_scan/added", r.Query, r.Action)
	}
	if r.Columns["path"] != "/tmp/x" || r.Columns["matches"] != "SIEMBox_YARA_SelfTest" {
		t.Errorf("columns = %v", r.Columns)
	}
}

func TestRunYaraScanDisabled(t *testing.T) {
	called := false
	fake := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		called = true
		return []byte("[]"), nil
	}
	// No paths or no sigfile => disabled, runner not invoked.
	if recs, err := runYaraScanWith(context.Background(), fake, "osqueryi", nil, "/sig.yar"); err != nil || recs != nil {
		t.Errorf("expected nil,nil for no paths; got %v,%v", recs, err)
	}
	if recs, err := runYaraScanWith(context.Background(), fake, "osqueryi", []string{"/tmp/%%"}, ""); err != nil || recs != nil {
		t.Errorf("expected nil,nil for no sigfile; got %v,%v", recs, err)
	}
	if called {
		t.Error("runner should not be called when YARA is disabled")
	}
}
