package update

import "testing"

func TestValidVersion(t *testing.T) {
	for v, want := range map[string]bool{
		"1.4.0": true, "0.0.1": true, "10.20.30": true,
		"": false, "dev": false, "v1.4.0": false, "1.4": false, "1.4.0-rc1": false,
		"1.4.0\n": false, "1.4.0/../x": false, "1.4.0 ": false, "1.4.a": false,
		"1234567890.0.0": false, "a8922f4-dirty": false, "１.2.3": false,
	} {
		if got := ValidVersion(v); got != want {
			t.Errorf("ValidVersion(%q)=%v want %v", v, got, want)
		}
	}
}

func TestValidRequestID(t *testing.T) {
	long := ""
	for i := 0; i < 65; i++ {
		long += "a"
	}
	for id, want := range map[string]bool{
		"b6f1c2d0-1111-4222-8333-444455556666": true, "abc": true, "ABCdef-01": true,
		"": false, "../x": false, "a b": false, "a\n": false, "xyz": false, long: false,
	} {
		if got := ValidRequestID(id); got != want {
			t.Errorf("ValidRequestID(%q)=%v want %v", id, got, want)
		}
	}
}

func TestCheckTarget(t *testing.T) {
	tests := []struct {
		name, cur, target string
		wantErr           bool
	}{
		{"upgrade", "1.3.2", "1.4.0", false},
		{"numeric not lexical", "1.9.0", "1.10.0", false},
		{"patch", "1.3.2", "1.3.10", false},
		{"same", "1.3.2", "1.3.2", true},
		{"downgrade", "1.4.0", "1.3.9", true},
		{"downgrade major", "2.0.0", "1.99.99", true},
		{"dev build allowed", "dev", "1.4.0", false},
		{"dirty build allowed", "a8922f4-dirty", "0.0.1", false},
		{"bad target", "1.0.0", "v1.4.0", true},
		{"bad target on dev", "dev", "latest", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := CheckTarget(tt.cur, tt.target); (err != nil) != tt.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

func TestIsDevBuild(t *testing.T) {
	if !IsDevBuild("dev") || !IsDevBuild("v1.2.3") || IsDevBuild("1.2.3") {
		t.Fatal("IsDevBuild wrong")
	}
}
