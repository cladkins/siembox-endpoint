// Command siembox-agent is the SIEMBox EDR endpoint agent. It enrolls with a
// SIEMBox server, reports host inventory, scans for vulnerabilities, and
// evaluates detection rules against host telemetry, shipping results over
// HTTPS.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/cladkins/siembox-edr/internal/agent"
	"github.com/cladkins/siembox-edr/internal/config"
	"github.com/cladkins/siembox-edr/internal/transport"
	"github.com/cladkins/siembox-edr/internal/version"
	"github.com/cladkins/siembox-edr/internal/vuln"
)

func main() {
	var (
		dir     = flag.String("dir", config.DefaultDir(), "agent state directory")
		verbose = flag.Bool("v", false, "verbose (debug) logging")
	)
	flag.Parse()

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	cmd := flag.Arg(0)
	if cmd == "" {
		cmd = "run"
	}

	switch cmd {
	case "version":
		fmt.Println(version.Version)
	case "run":
		if err := run(*dir, log); err != nil {
			log.Error("agent exited with error", "err", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "usage: siembox-agent [-dir DIR] [-v] [run|version]\n")
		os.Exit(2)
	}
}

func run(dir string, log *slog.Logger) error {
	state, err := config.Load(dir)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	spool, err := transport.NewSpool(filepath.Join(dir, "spool"))
	if err != nil {
		return fmt.Errorf("init spool: %w", err)
	}

	a, err := agent.New(state, spool, log)
	if err != nil {
		return err
	}

	// Vulnerability scanning: use grype if its binary is available, otherwise
	// fall back to the noop scanner so the agent still runs.
	grype := vuln.NewGrypeScanner(state.Settings.GrypeBinary, state.Settings.VulnScanTarget)
	if grype.Available() {
		a.WithScanner(grype)
		log.Info("vulnerability scanning enabled", "scanner", "grype")
	} else {
		log.Warn("grype not found on PATH; vulnerability scanning disabled (install grype to enable)")
	}

	// Future phase swaps NoopEngine for osquery+Sigma via a.WithEngine(...).

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return a.Run(ctx)
}
