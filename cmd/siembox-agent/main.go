// Command siembox-agent is the SIEMBox EDR endpoint agent. It enrolls with a
// SIEMBox server, reports host inventory, scans for vulnerabilities, and
// evaluates detection rules against host telemetry, shipping results over
// HTTPS.
//
// Subcommands:
//
//	run                 run the agent (foreground or under the service manager)
//	install|uninstall   register/unregister the system service
//	start|stop|restart  control the installed service
//	status              report service status
//	scan                one-shot vulnerability scan, print JSON (no server)
//	check               one-shot detection check, print JSON (no server)
//	version             print the agent version
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kardianos/service"

	"github.com/cladkins/siembox-edr/internal/agent"
	"github.com/cladkins/siembox-edr/internal/config"
	"github.com/cladkins/siembox-edr/internal/detect"
	"github.com/cladkins/siembox-edr/internal/telemetry/osquery"
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

	if err := dispatch(cmd, *dir, log); err != nil {
		log.Error("command failed", "command", cmd, "err", err)
		os.Exit(1)
	}
}

func dispatch(cmd, dir string, log *slog.Logger) error {
	switch cmd {
	case "version":
		fmt.Println(version.Version)
		return nil
	case "scan":
		return runScan(dir, log)
	case "check":
		return runCheck(dir, log)
	case "run", "install", "uninstall", "start", "stop", "restart", "status":
		return runService(cmd, dir, log)
	default:
		fmt.Fprintf(os.Stderr, "usage: siembox-agent [-dir DIR] [-v] "+
			"(run|install|uninstall|start|stop|restart|status|scan|check|version)\n")
		os.Exit(2)
		return nil
	}
}

// --- service lifecycle ---

// program adapts the agent to the kardianos service interface.
type program struct {
	dir    string
	log    *slog.Logger
	cancel context.CancelFunc
	done   chan struct{}
}

// Start launches the agent in a goroutine and returns immediately, as the
// service contract requires.
func (p *program) Start(s service.Service) error {
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.done = make(chan struct{})
	go func() {
		defer close(p.done)
		if err := runAgent(ctx, p.dir, p.log); err != nil && ctx.Err() == nil {
			p.log.Error("agent exited with error", "err", err)
		}
	}()
	return nil
}

// Stop cancels the agent and waits briefly for a clean shutdown.
func (p *program) Stop(s service.Service) error {
	if p.cancel != nil {
		p.cancel()
	}
	if p.done != nil {
		select {
		case <-p.done:
		case <-time.After(10 * time.Second):
		}
	}
	return nil
}

func newService(dir string, log *slog.Logger) (service.Service, error) {
	cfg := &service.Config{
		Name:        "siembox-agent",
		DisplayName: "SIEMBox EDR Agent",
		Description: "SIEMBox EDR endpoint agent: vulnerability scanning and threat detection.",
		Arguments:   []string{"-dir", dir, "run"},
	}
	return service.New(&program{dir: dir, log: log}, cfg)
}

func runService(cmd, dir string, log *slog.Logger) error {
	svc, err := newService(dir, log)
	if err != nil {
		return fmt.Errorf("init service: %w", err)
	}
	switch cmd {
	case "run":
		// Blocks: runs Start, waits for an OS signal or service stop, then Stop.
		return svc.Run()
	case "status":
		st, err := svc.Status()
		if err != nil {
			return err
		}
		fmt.Println(statusString(st))
		return nil
	default: // install, uninstall, start, stop, restart
		if err := service.Control(svc, cmd); err != nil {
			return err
		}
		log.Info("service control ok", "action", cmd)
		return nil
	}
}

func statusString(s service.Status) string {
	switch s {
	case service.StatusRunning:
		return "running"
	case service.StatusStopped:
		return "stopped"
	default:
		return "unknown"
	}
}

// runAgent loads config, wires the scanner/detection engine, and runs the agent
// until ctx is cancelled. Shared by the service and foreground `run`.
func runAgent(ctx context.Context, dir string, log *slog.Logger) error {
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

	// Vulnerability scanning: enable grype if available.
	grype := vuln.NewGrypeScanner(state.Settings.GrypeBinary, state.Settings.VulnScanTarget)
	if grype.Available() {
		a.WithScanner(grype)
		log.Info("vulnerability scanning enabled", "scanner", "grype")
	} else {
		log.Warn("grype not found on PATH; vulnerability scanning disabled (install grype to enable)")
	}

	// Detection: enable the Sigma engine if osqueryd is available.
	osq := osquery.NewDaemon(state.Settings.OsqueryBinary, filepath.Join(dir, "osquery"), nil)
	if osq.Available() {
		base, err := detect.DefaultRules()
		if err != nil {
			return fmt.Errorf("load default rules: %w", err)
		}
		a.WithEngine(detect.NewSigmaEngine(osq, base, log))
		log.Info("detection enabled", "engine", "sigma", "default_rules", len(base))
	} else {
		log.Warn("osqueryd not found on PATH; detection disabled (install osquery to enable)")
	}

	return a.Run(ctx)
}

// --- one-shot commands (no server, no enrollment) ---

func runScan(dir string, log *slog.Logger) error {
	settings, _ := config.LoadSettingsOnly(dir) // best-effort; zero value is fine
	g := vuln.NewGrypeScanner(settings.GrypeBinary, settings.VulnScanTarget)
	if !g.Available() {
		return fmt.Errorf("grype not found on PATH; install grype to run a scan")
	}
	log.Info("running one-shot vulnerability scan", "target", settings.VulnScanTarget)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	batch, err := g.Scan(ctx, "")
	if err != nil {
		return err
	}
	log.Info("scan complete", "findings", len(batch.Vulnerabilities))
	return printJSON(batch)
}

func runCheck(dir string, log *slog.Logger) error {
	settings, _ := config.LoadSettingsOnly(dir)
	bin := osqueryiBinary(settings.OsqueryBinary)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	records, err := osquery.RunOnce(ctx, bin, nil)
	if err != nil {
		return fmt.Errorf("osquery: %w (install osquery to run a check)", err)
	}

	base, err := detect.DefaultRules()
	if err != nil {
		return err
	}
	engine := detect.NewSigmaEngine(nil, base, log)
	if err := engine.LoadRules(nil); err != nil {
		log.Warn("some default rules failed to load", "err", err)
	}
	events := engine.Evaluate(ctx, records)
	log.Info("check complete", "records", len(records), "detections", len(events))
	return printJSON(events)
}

// osqueryiBinary derives the osqueryi path from a configured binary. If an
// osqueryd path was configured, swap the basename to osqueryi so both live
// together; otherwise rely on PATH.
func osqueryiBinary(configured string) string {
	if configured == "" {
		return "osqueryi"
	}
	d, b := filepath.Split(configured)
	if strings.Contains(b, "osqueryd") {
		return filepath.Join(d, strings.Replace(b, "osqueryd", "osqueryi", 1))
	}
	return configured
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
