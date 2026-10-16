package update

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/cladkins/siembox-endpoint/internal/config"
	"github.com/cladkins/siembox-endpoint/internal/models"
	"github.com/cladkins/siembox-endpoint/internal/version"
)

const (
	// PendingTimeout is how long after launching the installer the old agent may
	// still be running before the attempt is reported as failed.
	PendingTimeout = 15 * time.Minute
	// attemptTimeout bounds download time.
	attemptTimeout = 45 * time.Minute
	maxErrorLen    = 500
	logTailBytes   = 300
	downloadDir    = "update"
)

// Options configures an Updater. Zero values select production behavior; the
// fields exist so tests can inject a fake release server, command runner and
// launcher.
type Options struct {
	State *config.State
	Log   *slog.Logger

	BaseURL    string       // release download root (default DefaultBaseURL)
	HTTPClient *http.Client // default NewHTTPClient()
	MaxSize    int64        // per-file download cap (default MaxDownloadBytes)
	Runner     Runner       // default ExecRunner
	Launch     func(Command) error

	GOOS           string // default runtime.GOOS
	GOARCH         string // default runtime.GOARCH
	ExePath        string // default: the running executable, symlinks resolved
	ProgramFiles   string // default %ProgramFiles%
	CurrentVersion string // default version.Version
	Now            func() time.Time
}

// Updater runs at most one self-update attempt at a time and tracks its status.
type Updater struct {
	o     Options
	state *config.State
	log   *slog.Logger
	dl    *Downloader

	mu      sync.Mutex
	running bool
	wg      sync.WaitGroup
}

// New builds an Updater.
func New(o Options) *Updater {
	if o.Log == nil {
		o.Log = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	if o.Runner == nil {
		o.Runner = ExecRunner{}
	}
	if o.Launch == nil {
		o.Launch = launchDetached
	}
	if o.GOOS == "" {
		o.GOOS = runtime.GOOS
	}
	if o.GOARCH == "" {
		o.GOARCH = runtime.GOARCH
	}
	if o.ProgramFiles == "" {
		o.ProgramFiles = os.Getenv("ProgramFiles")
	}
	if o.CurrentVersion == "" {
		o.CurrentVersion = version.Version
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Updater{
		o: o, state: o.State, log: o.Log,
		dl: &Downloader{BaseURL: o.BaseURL, Client: o.HTTPClient, MaxSize: o.MaxSize},
	}
}

// Wait blocks until any in-flight attempt goroutine has returned.
func (u *Updater) Wait() { u.wg.Wait() }

func (u *Updater) dir() string { return filepath.Join(u.state.Dir, downloadDir) }

func (u *Updater) logPath() string { return filepath.Join(u.state.Dir, updateLogName) }

// Report returns the status to attach to the next heartbeat, or nil.
func (u *Updater) Report() *models.UpdateReport {
	var r *models.UpdateReport
	u.state.View(func(id *config.Identity) {
		if id.UpdateReport != nil {
			c := *id.UpdateReport
			r = &c
		}
	})
	return r
}

// Prune stops reporting a finished attempt once the server's config no longer
// carries its request id (activeID is the id in the current config, or "").
// In-progress attempts are kept until they finish.
func (u *Updater) Prune(activeID string) {
	r := u.Report()
	if r == nil || r.RequestID == activeID {
		return
	}
	if r.State != models.UpdateStateSucceeded && r.State != models.UpdateStateFailed {
		return
	}
	_ = u.state.Mutate(func(id *config.Identity) {
		if id.UpdateReport != nil && id.UpdateReport.RequestID == r.RequestID {
			id.UpdateReport = nil
		}
	})
}

// Startup resolves an update left in flight by a previous process and tidies
// leftovers. Call once before the first heartbeat. A pending update resolves to
// succeeded when the running version equals the target, failed otherwise.
func (u *Updater) Startup() {
	var pending *config.PendingUpdate
	var report *models.UpdateReport
	u.state.View(func(id *config.Identity) {
		if id.PendingUpdate != nil {
			p := *id.PendingUpdate
			pending = &p
		}
		if id.UpdateReport != nil {
			r := *id.UpdateReport
			report = &r
		}
	})
	switch {
	case pending != nil && u.o.CurrentVersion == pending.Version:
		u.log.Info("self-update succeeded", "version", pending.Version)
		u.finish(pending.RequestID, pending.Version, models.UpdateStateSucceeded, "")
	case pending != nil:
		u.finish(pending.RequestID, pending.Version, models.UpdateStateFailed,
			u.withLogTail(fmt.Sprintf("agent restarted but is still version %s (target %s)", u.o.CurrentVersion, pending.Version)))
	case report != nil && (report.State == models.UpdateStateDownloading || report.State == models.UpdateStateInstalling):
		u.finish(report.RequestID, report.Version, models.UpdateStateFailed, "agent restarted before the update finished")
	}
	// Leftovers: downloaded installers, and the previous exe kept on Windows.
	_ = os.RemoveAll(u.dir())
	if exe, err := u.exe(); err == nil && u.o.GOOS == "windows" {
		_ = os.Remove(exe + ".old")
	}
}

// CheckPending fails an attempt whose installer was launched more than
// PendingTimeout ago without the agent having been replaced. Call before each
// heartbeat.
func (u *Updater) CheckPending() {
	var pending *config.PendingUpdate
	u.state.View(func(id *config.Identity) {
		if id.PendingUpdate != nil {
			p := *id.PendingUpdate
			pending = &p
		}
	})
	if pending == nil || u.o.Now().Sub(pending.StartedAt) < PendingTimeout {
		return
	}
	u.finish(pending.RequestID, pending.Version, models.UpdateStateFailed,
		u.withLogTail(fmt.Sprintf("agent still running version %s %d minutes after the installer was launched",
			u.o.CurrentVersion, int(PendingTimeout.Minutes()))))
}

// Consider acts on the update request from the server's config. It returns
// immediately; the attempt runs in its own goroutine so heartbeats never block.
// A request id is attempted at most once, and only one attempt runs at a time.
// It reports whether an attempt was started.
func (u *Updater) Consider(ctx context.Context, req *models.AgentUpdateRequest) bool {
	if req == nil {
		return false
	}
	if !ValidRequestID(req.RequestID) {
		u.log.Warn("ignoring update request with invalid request_id")
		return false
	}

	u.mu.Lock()
	if u.running {
		u.mu.Unlock()
		return false
	}
	var seen, pending bool
	u.state.View(func(id *config.Identity) {
		seen = id.LastUpdateRequestID == req.RequestID
		pending = id.PendingUpdate != nil
	})
	if seen || pending {
		u.mu.Unlock()
		return false
	}
	u.running = true
	u.mu.Unlock()

	// Record the attempt before doing anything so a crash cannot cause a retry.
	ver := req.Version
	if !ValidVersion(ver) {
		ver = "" // never persist or report server-supplied garbage
	}
	_ = u.state.Mutate(func(id *config.Identity) {
		id.LastUpdateRequestID = req.RequestID
		id.UpdateReport = &models.UpdateReport{RequestID: req.RequestID, Version: ver, State: models.UpdateStateDownloading}
	})

	u.wg.Add(1)
	go func() {
		defer u.wg.Done()
		defer func() { u.mu.Lock(); u.running = false; u.mu.Unlock() }()
		u.attempt(ctx, req.RequestID, ver)
	}()
	return true
}

func (u *Updater) attempt(ctx context.Context, reqID, ver string) {
	if err := u.run(ctx, reqID, ver); err != nil {
		u.log.Warn("self-update failed", "request_id", reqID, "version", ver, "err", err)
		u.finish(reqID, ver, models.UpdateStateFailed, u.withLogTailIf(err))
	}
}

// run performs the update. It returns nil once the installer (or restart) has
// been launched; the outcome is then resolved by Startup or CheckPending.
func (u *Updater) run(ctx context.Context, reqID, ver string) error {
	if ver == "" {
		return errInvalidVersion
	}
	if err := CheckTarget(u.o.CurrentVersion, ver); err != nil {
		return err
	}
	exe, err := u.exe()
	if err != nil {
		return fmt.Errorf("locate running executable: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, attemptTimeout)
	defer cancel()

	method, err := DetectMethod(ctx, u.o.GOOS, exe, u.o.ProgramFiles, u.o.Runner)
	if err != nil {
		return err
	}
	u.log.Info("self-update starting", "version", ver, "method", string(method), "request_id", reqID)

	sums, err := u.dl.FetchSums(ctx, ver)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(sums))
	for n := range sums {
		names = append(names, n)
	}
	asset, err := SelectAsset(method, ver, u.o.GOARCH, names)
	if err != nil {
		return err
	}
	_ = os.RemoveAll(u.dir())
	_ = os.Remove(u.logPath())
	path, err := u.dl.FetchAsset(ctx, ver, asset, sums[asset], u.dir())
	if err != nil {
		return err
	}

	u.setState(reqID, ver, models.UpdateStateInstalling)
	var cmd Command
	if method.IsArchive() {
		if cmd, err = u.swapBinary(ctx, method, path, exe, ver); err != nil {
			return err
		}
	} else if cmd, err = InstallCommand(method, path, u.state.Dir); err != nil {
		return err
	}
	cmd.Argv = append([]string{resolveTool(cmd.Argv[0])}, cmd.Argv[1:]...)

	// Persist the pending marker BEFORE launching: the installer may replace and
	// restart this process before launch even returns.
	started := u.o.Now()
	if err := u.state.Mutate(func(id *config.Identity) {
		id.PendingUpdate = &config.PendingUpdate{RequestID: reqID, Version: ver, StartedAt: started}
	}); err != nil {
		return fmt.Errorf("persist pending update: %w", err)
	}
	if err := u.o.Launch(cmd); err != nil {
		_ = u.state.Mutate(func(id *config.Identity) { id.PendingUpdate = nil })
		return fmt.Errorf("launch installer: %w", err)
	}
	u.log.Info("installer launched", "version", ver, "method", string(method), "log", cmd.LogPath)
	return nil
}

// swapBinary extracts the new executable next to exe, checks that it runs and
// reports the target version, and swaps it in. It returns the restart command.
func (u *Updater) swapBinary(ctx context.Context, m Method, archive, exe, ver string) (Command, error) {
	newPath := exe + ".new"
	win := m == MethodWindowsZip
	if err := ExtractBinary(archive, newPath, win, MaxDownloadBytes); err != nil {
		return Command{}, err
	}
	out, err := u.o.Runner.Output(ctx, newPath, "version")
	if got := strings.TrimSpace(string(out)); err != nil || got != ver {
		os.Remove(newPath)
		return Command{}, fmt.Errorf("downloaded binary failed self-check (reports %q, want %q)", truncate(got, 40), ver)
	}
	if err := ReplaceExecutable(exe, newPath, win); err != nil {
		os.Remove(newPath)
		return Command{}, err
	}
	return RestartCommand(exe, u.state.Dir), nil
}

func (u *Updater) exe() (string, error) {
	if u.o.ExePath != "" {
		return u.o.ExePath, nil
	}
	p, err := os.Executable()
	if err != nil {
		return "", err
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		p = r
	}
	return p, nil
}

func (u *Updater) setState(reqID, ver, st string) {
	_ = u.state.Mutate(func(id *config.Identity) {
		id.UpdateReport = &models.UpdateReport{RequestID: reqID, Version: ver, State: st}
	})
}

// finish records a terminal state and clears any pending marker.
func (u *Updater) finish(reqID, ver, st, msg string) {
	if st != models.UpdateStateFailed {
		msg = ""
	}
	_ = u.state.Mutate(func(id *config.Identity) {
		id.PendingUpdate = nil
		id.UpdateReport = &models.UpdateReport{RequestID: reqID, Version: ver, State: st, Error: truncate(msg, maxErrorLen)}
	})
}

func (u *Updater) withLogTailIf(err error) string {
	var nn *notNewerError
	if errors.As(err, &nn) || errors.Is(err, errInvalidVersion) {
		return err.Error()
	}
	return u.withLogTail(err.Error())
}

// withLogTail appends the tail of update.log, if any, to msg.
func (u *Updater) withLogTail(msg string) string {
	tail := readTail(u.logPath(), logTailBytes)
	if tail == "" {
		return msg
	}
	return truncate(msg, maxErrorLen-logTailBytes-20) + "; update.log tail: " + tail
}

func readTail(path string, n int64) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil && fi.Size() > n {
		_, _ = f.Seek(-n, 2)
	}
	b := make([]byte, n)
	m, _ := f.Read(b)
	return strings.TrimSpace(strings.ToValidUTF8(string(b[:m]), ""))
}

// truncate shortens s to at most max bytes on a rune boundary.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	s = s[:max]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}
