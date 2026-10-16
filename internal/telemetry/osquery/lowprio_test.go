package osquery

import (
	"context"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/cladkins/siembox-endpoint/internal/util"
)

func TestRunLowPriorityCapturesOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses sh")
	}
	out, err := runLowPriority(context.Background(), "sh", "-c", "echo hello")
	if err != nil {
		t.Fatalf("runLowPriority: %v", err)
	}
	if strings.TrimSpace(string(out)) != "hello" {
		t.Errorf("stdout = %q, want hello", out)
	}
}

func TestRunLowPrioritySurfacesStderr(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses sh")
	}
	_, err := runLowPriority(context.Background(), "sh", "-c", "echo boom >&2; exit 3")
	if err == nil {
		t.Fatal("expected an error for a non-zero exit")
	}
	if got := util.StderrText(err); got != "boom" {
		t.Errorf("StderrText = %q, want boom", got)
	}
}

func TestRunLowPriorityLowersChildPriority(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("nice is checked on unix only")
	}
	if _, err := exec.LookPath("ps"); err != nil {
		t.Skip("ps not available")
	}
	// The child reports its own nice value.
	out, err := runLowPriority(context.Background(), "sh", "-c", "ps -o nice= -p $$")
	if err != nil {
		t.Fatalf("runLowPriority: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != "19" {
		t.Errorf("child nice = %q, want 19", got)
	}
}
