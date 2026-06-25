//go:build darwin

// Command siembox-tray is the SIEMBox EDR macOS menu bar app: the control
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

	"github.com/cladkins/siembox-edr/internal/config"
	"github.com/cladkins/siembox-edr/internal/models"
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
	systray.SetTitle("SIEMBox")
	systray.SetTooltip("SIEMBox EDR agent")

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
			case <-mQuit.ClickedCh:
				systray.Quit()
				return
			}
		}
	}()
}

// refreshStatus updates the service status line via `siembox-agent status`.
func refreshStatus() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, agentBinary(), "status").CombinedOutput()
	state := "unknown"
	if err == nil {
		if s := lastLine(string(out)); s != "" {
			state = s
		}
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
		notify("Vulnerability scan failed (see Console for details)")
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
		notify("Detection check failed (see Console for details)")
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
// privileges via the native macOS auth prompt, then refreshes status.
func controlService(action, progressMsg string) {
	notify(progressMsg)
	cmd := shellQuote(agentBinary()) + " " + action
	if err := runPrivileged(cmd); err != nil {
		notify(fmt.Sprintf("Failed to %s the service (admin cancelled or error)", action))
		return
	}
	notify("Service " + action + " requested")
	time.Sleep(time.Second) // give launchd a moment
	refreshStatus()
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

// runPrivileged runs a shell command with administrator privileges via the
// native macOS auth dialog. Returns an error if the user cancels or it fails.
func runPrivileged(shellCmd string) error {
	script := fmt.Sprintf("do shell script %q with administrator privileges", shellCmd)
	return exec.Command("osascript", "-e", script).Run()
}

// promptText shows a text-input dialog and returns the entered value. ok is
// false if the user cancelled.
func promptText(prompt, def string) (string, bool) {
	script := fmt.Sprintf("display dialog %q default answer %q with title \"SIEMBox EDR\"", prompt, def)
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
	script := fmt.Sprintf(`display notification %q with title "SIEMBox EDR"`, msg)
	_ = exec.Command("osascript", "-e", script).Run()
}

func nowStamp() string { return time.Now().Format("15:04:05") }

func lastLine(s string) string {
	var last string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			if line := s[start:i]; line != "" {
				last = line
			}
			start = i + 1
		}
	}
	if tail := s[start:]; tail != "" {
		last = tail
	}
	return last
}
