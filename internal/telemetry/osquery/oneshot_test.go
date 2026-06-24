package osquery

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestRunOnceMapsRows(t *testing.T) {
	queries := []Query{{Name: "processes", SQL: "SELECT * FROM processes;"}}
	run := func(_ context.Context, _ string, args ...string) ([]byte, error) {
		// args should include --json and the SQL.
		if !contains(args, "--json") {
			t.Errorf("osqueryi not invoked with --json: %v", args)
		}
		return []byte(`[{"pid":"1","name":"systemd","path":"/sbin/init"},{"pid":"2","name":"sh","path":"/tmp/sh"}]`), nil
	}

	records, err := runOnceWith(context.Background(), run, "osqueryi", queries)
	if err != nil {
		t.Fatalf("runOnceWith: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2", len(records))
	}
	if records[0].Query != "processes" || records[0].Action != "snapshot" {
		t.Errorf("unexpected record meta: %+v", records[0])
	}
	if records[1].Columns["path"] != "/tmp/sh" {
		t.Errorf("columns = %v", records[1].Columns)
	}
}

func TestRunOnceDefaultsToAllQueries(t *testing.T) {
	var calls int
	run := func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		calls++
		return []byte(`[]`), nil
	}
	if _, err := runOnceWith(context.Background(), run, "", nil); err != nil {
		t.Fatalf("runOnceWith: %v", err)
	}
	if calls != len(DefaultQueries()) {
		t.Errorf("ran %d queries, want %d", calls, len(DefaultQueries()))
	}
}

func TestRunOncePropagatesError(t *testing.T) {
	run := func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return nil, errors.New("osqueryi missing")
	}
	_, err := runOnceWith(context.Background(), run, "osqueryi", DefaultQueries())
	if err == nil || !strings.Contains(err.Error(), "osqueryi") {
		t.Fatalf("expected osqueryi error, got %v", err)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
