//go:build darwin

// Command siembox-tray is the SIEMBox Endpoint macOS menu bar app: the control
// center for the agent. From the menu bar you can run on-demand scans/checks,
// see status, configure the server, and start/stop the background service —
// no CLI needed. Privileged actions (start/stop/configure) use the native
// macOS admin-password prompt via osascript. Built only on macOS (systray
// needs Cocoa + CGO).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"fyne.io/systray"

	"github.com/cladkins/siembox-endpoint/internal/config"
	"github.com/cladkins/siembox-endpoint/internal/models"
	"github.com/cladkins/siembox-endpoint/internal/util"
)

// agentBinary locates the siembox-agent CLI: next to this app first, then the
// standard install location, then PATH.
func agentBinary() string {
	if exe, err := os.Executable(); err == nil {
		cand := filepath.Join(filepath.Dir(exe), "siembox-agent")
		if fi, err := os.Stat(cand); err == nil && !fi.IsDir() {
			return cand
		}
	}
	if fi, err := os.Stat("/usr/local/bin/siembox-agent"); err == nil && !fi.IsDir() {
		return "/usr/local/bin/siembox-agent"
	}
	return "siembox-agent"
}

var (
	busy sync.Mutex // serializes scan/check so two don't overlap

	mStatus    *systray.MenuItem
	mLastScan  *systray.MenuItem
	mLastCheck *systray.MenuItem
	mScan      *systray.MenuItem
	mCheck     *systray.MenuItem
)

func main() { systray.Run(onReady, func() {}) }

func onReady() {
	// Clear a stale TMPDIR before any os.TempDir() use (e.g. staging the config
	// in configureServer). When the menu bar app is launched by the pkg
	// post-install it inherits TMPDIR pointing at the installer's
	// PKInstallSandbox temp, which macOS deletes after install — leaving every
	// os.TempDir() write failing with "no such file or directory".
	util.EnsureSaneTmpdir()

	systray.SetTitle("SIEMBox")
	systray.SetTooltip("SIEMBox Endpoint agent")

	mStatus = systray.AddMenuItem("Service: checking…", "")
	mStatus.Disable()
	mLastScan = systray.AddMenuItem("Last scan: never", "")
	mLastScan.Disable()
	mLastCheck = systray.AddMenuItem("Last check: never", "")
	mLastCheck.Disable()

	systray.AddSeparator()
	mScan = systray.AddMenuItem("Run Vulnerability Scan", "Scan installed software for known CVEs")
	mCheck = systray.AddMenuItem("Run Detection Check", "Evaluate host telemetry against detection rules")

	systray.AddSeparator()
	mConfigure := systray.AddMenuItem("Configure Server…", "Set the SIEMBox server URL and enrollment token")
	mStart := systray.AddMenuItem("Start Background Service", "Start the continuous monitoring service")
	mStop := systray.AddMenuItem("Stop Background Service", "Stop the continuous monitoring service")

	systray.AddSeparator()
	mRefresh := systray.AddMenuItem("Refresh Status", "Re-check the service status")
	mConfig := systray.AddMenuItem("Reveal Config in Finder", "Open the agent config directory")
	mUninstall := systray.AddMenuItem("Uninstall SIEMBox Endpoint…", "Remove the agent, service, and this app")
	mQuit := systray.AddMenuItem("Quit", "Quit the menu bar app")

	go refreshStatus()

	go func() {
		for {
			select {
			case <-mScan.ClickedCh:
				go runScan()
			case <-mCheck.ClickedCh:
				go runCheck()
			case <-mConfigure.ClickedCh:
				go configureServer()
			case <-mStart.ClickedCh:
				go controlService("start", "Starting background service…")
			case <-mStop.ClickedCh:
				go controlService("stop", "Stopping background service…")
			case <-mRefresh.ClickedCh:
				go refreshStatus()
			case <-mConfig.ClickedCh:
				revealConfig()
			case <-mUninstall.ClickedCh:
				go uninstallAll()
			case <-mQuit.ClickedCh:
				systray.Quit()
				return
			}
		}
	}()
}

// serviceRunning reports whether the background daemon is running. It detects
// the process directly (pgrep) rather than asking launchd, because the menu bar
// runs as the user and cannot query the root LaunchDaemon — which made it
// misreport a running service as "stopped".
func serviceRunning() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Matches the long-running daemon ("siembox-agent … run"), not the
	// short-lived scan/check invocations or this tray (siembox-tray).
	return exec.CommandContext(ctx, "pgrep", "-f", "siembox-agent.* run").Run() == nil
}

// refreshStatus updates the service status line from the real process state.
func refreshStatus() {
	state := "stopped"
	if serviceRunning() {
		state = "running"
	}
	mStatus.SetTitle("Service: " + state)
}

func runScan() {
	if !busy.TryLock() {
		notify("A scan or check is already running")
		return
	}
	defer busy.Unlock()

	mScan.Disable()
	mScan.SetTitle("Running Vulnerability Scan…")
	defer func() { mScan.SetTitle("Run Vulnerability Scan"); mScan.Enable() }()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, agentBinary(), "scan").Output()
	if err != nil {
		reason := failureReason(err)
		logFailure("scan", reason)
		notify("Vulnerability scan failed: " + firstLine(reason))
		mLastScan.SetTitle("Last scan: failed at " + nowStamp())
		return
	}
	var batch models.VulnBatch
	_ = json.Unmarshal(out, &batch)
	n := len(batch.Vulnerabilities)
	mLastScan.SetTitle(fmt.Sprintf("Last scan: %d findings at %s", n, nowStamp()))
	notify(fmt.Sprintf("Vulnerability scan complete: %d findings", n))
}

func runCheck() {
	if !busy.TryLock() {
		notify("A scan or check is already running")
		return
	}
	defer busy.Unlock()

	mCheck.Disable()
	mCheck.SetTitle("Running Detection Check…")
	defer func() { mCheck.SetTitle("Run Detection Check"); mCheck.Enable() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, agentBinary(), "check").Output()
	if err != nil {
		reason := failureReason(err)
		logFailure("check", reason)
		notify("Detection check failed: " + firstLine(reason))
		mLastCheck.SetTitle("Last check: failed at " + nowStamp())
		return
	}
	var events []models.Event
	_ = json.Unmarshal(out, &events)
	n := len(events)
	mLastCheck.SetTitle(fmt.Sprintf("Last check: %d detections at %s", n, nowStamp()))
	notify(fmt.Sprintf("Detection check complete: %d detections", n))
}

// controlService runs `siembox-agent <action>` (start/stop) with administrator
// privileges via the native macOS auth prompt, then reports the outcome based
// on the actual process state. launchctl can exit non-zero even when the
// service ends up in the desired state (e.g. already started), so we judge by
// reality, not the exit code.
func controlService(action, progressMsg string) {
	notify(progressMsg)
	_ = runPrivileged(shellQuote(agentBinary()) + " " + action)
	time.Sleep(2 * time.Second) // give launchd a moment to settle
	running := serviceRunning()
	refreshStatus()
	switch {
	case action == "start" && running:
		notify("Background service started")
	case action == "start":
		notify("Could not start the background service (admin cancelled?)")
	case action == "stop" && !running:
		notify("Background service stopped")
	default:
		notify("Could not stop the background service (admin cancelled?)")
	}
}

// configureServer prompts for the server URL + enrollment token and writes
// agent.json (root-owned, 0600) via an administrator-privileged copy.
func configureServer() {
	url, ok := promptText("Enter your SIEMBox server URL (e.g. https://siembox.local:8421):", "https://")
	if !ok || strings.TrimSpace(url) == "" {
		return
	}
	token, ok := promptText("Enter the enrollment token from the SIEMBox UI:", "")
	if !ok || strings.TrimSpace(token) == "" {
		return
	}

	cfgDir := config.DefaultDir()
	cfgPath := filepath.Join(cfgDir, "agent.json")
	body := fmt.Sprintf("{\n  \"server_url\": %q,\n  \"enrollment_token\": %q,\n  \"ca_cert_path\": \"\",\n  \"insecure_skip_verify\": false\n}\n",
		strings.TrimSpace(url), strings.TrimSpace(token))

	tmp := filepath.Join(os.TempDir(), "siembox-agent.json")
	if err := os.WriteFile(tmp, []byte(body), 0o600); err != nil {
		notify("Could not stage config: " + err.Error())
		return
	}
	defer os.Remove(tmp)

	cmd := fmt.Sprintf("mkdir -p %s && cp %s %s && chmod 600 %s",
		shellQuote(cfgDir), shellQuote(tmp), shellQuote(cfgPath), shellQuote(cfgPath))
	if err := runPrivileged(cmd); err != nil {
		notify("Configuration cancelled or failed")
		return
	}
	notify("Server configured. Use “Start Background Service” to begin monitoring.")
}

// revealConfig opens the agent's config directory in Finder.
func revealConfig() {
	_ = exec.Command("open", config.DefaultDir()).Start()
}

const uninstallerPath = "/usr/local/bin/siembox-uninstall"

// uninstallAll fully removes SIEMBox Endpoint after confirmation, using the
// privileged uninstaller the pkg installed, then quits this app.
func uninstallAll() {
	if !confirm("Uninstall SIEMBox Endpoint?\n\nThis removes the agent, the background service, and this menu bar app. osquery and grype are left installed.") {
		return
	}
	if _, err := os.Stat(uninstallerPath); err != nil {
		notify("Uninstaller not found — this app wasn't installed from the package. Quit it and drag it to the Trash.")
		return
	}
	if err := runPrivileged(shellQuote(uninstallerPath)); err != nil {
		notify("Uninstall cancelled or failed")
		return
	}
	notify("SIEMBox Endpoint uninstalled.")
	time.Sleep(time.Second)
	systray.Quit()
}

// confirm shows a two-button dialog; returns true only if the user confirms.
func confirm(msg string) bool {
	script := fmt.Sprintf(`display dialog %q with title "SIEMBox Endpoint" buttons {"Cancel","Uninstall"} default button "Cancel"`, msg)
	out, err := exec.Command("osascript", "-e", script).Output()
	if err != nil {
		return false // Cancel makes osascript exit non-zero
	}
	return strings.Contains(string(out), "button returned:Uninstall")
}

// runPrivileged runs a shell command with administrator privileges via the
// native macOS auth dialog. Returns an error if the user cancels or it fails.
func runPrivileged(shellCmd string) error {
	script := fmt.Sprintf("do shell script %q with administrator privileges", shellCmd)
	return exec.Command("osascript", "-e", script).Run()
}

// promptText shows a text-input dialog and returns the entered value. ok is
// false if the user cancelled.
func promptText(prompt, def string) (string, bool) {
	script := fmt.Sprintf("display dialog %q default answer %q with title \"SIEMBox Endpoint\"", prompt, def)
	out, err := exec.Command("osascript", "-e", script).Output()
	if err != nil {
		return "", false // user cancelled (osascript exits non-zero)
	}
	const marker = "text returned:"
	s := string(out)
	if i := strings.Index(s, marker); i >= 0 {
		return strings.TrimSpace(s[i+len(marker):]), true
	}
	return "", false
}

// shellQuote single-quotes a string for safe embedding in a /bin/sh command.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// notify shows a macOS notification via osascript.
func notify(msg string) {
	script := fmt.Sprintf(`display notification %q with title "SIEMBox Endpoint"`, msg)
	_ = exec.Command("osascript", "-e", script).Run()
}

func nowStamp() string { return time.Now().Format("15:04:05") }

// failureReason extracts the most useful error text from a failed command. The
// agent logs via slog to stderr, so the stderr starts with INFO lines; we pull
// the actual error rather than naively taking the first line.
func failureReason(err error) string {
	s := util.StderrText(err)
	if s == "" {
		return err.Error()
	}
	return bestErrorLine(s)
}

// bestErrorLine finds the most informative line in captured stderr: the value
// of a slog err="…" field (further reduced to the trailing "ERROR …" message if
// present), else a level=ERROR line, else the last non-empty line.
func bestErrorLine(s string) string {
	lines := strings.Split(s, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		l := strings.TrimSpace(lines[i])
		if l == "" {
			continue
		}
		if v := errField(l); v != "" {
			return v
		}
		if strings.Contains(l, "level=ERROR") {
			return l
		}
	}
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(lines[i]); l != "" {
			return l
		}
	}
	return strings.TrimSpace(s)
}

// errField returns the slog err="…" value from a line, trimmed to the trailing
// "ERROR …" message (the real cause) when the wrapped error embeds one.
func errField(l string) string {
	const k = `err="`
	i := strings.Index(l, k)
	if i < 0 {
		return ""
	}
	v := l[i+len(k):]
	if j := strings.LastIndex(v, `"`); j >= 0 {
		v = v[:j]
	}
	if e := strings.LastIndex(v, "ERROR "); e >= 0 {
		return strings.TrimSpace(v[e+len("ERROR "):])
	}
	return v
}

// firstLine returns a trimmed, length-capped first line for a notification.
func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 140 {
		s = s[:140] + "…"
	}
	return s
}

// logFailure appends full failure detail to ~/Library/Logs/SIEMBox/tray.log so
// the cause is recoverable even after the notification disappears.
func logFailure(action, detail string) {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	path := filepath.Join(home, "Library", "Logs", "SIEMBox", "tray.log")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "[%s] %s failed: %s\n", time.Now().Format(time.RFC3339), action, detail)
}
