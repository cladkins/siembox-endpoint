package config

import (
	"encoding/json"
	"testing"
	"time"
)

func TestPackageInventorySettings(t *testing.T) {
	var s Settings
	if !s.PackageInventoryEnabled() || s.PackageInventoryInterval() != 6*time.Hour {
		t.Errorf("defaults: enabled=%v interval=%v", s.PackageInventoryEnabled(), s.PackageInventoryInterval())
	}
	if err := json.Unmarshal([]byte(`{"server_url":"x","package_inventory":false,"package_inventory_interval_seconds":10}`), &s); err != nil {
		t.Fatal(err)
	}
	if s.PackageInventoryEnabled() {
		t.Error("package_inventory=false is ignored")
	}
	if s.PackageInventoryInterval() != 5*time.Minute {
		t.Errorf("interval %v, want the 5 minute floor", s.PackageInventoryInterval())
	}
}
