# SIEMBox EDR

A lightweight, cross-platform **endpoint agent** for [SIEMBox](https://github.com/cladkins/SIEMBOX).
It brings endpoint visibility to SIEMBox by doing two jobs and shipping the
results back for correlation and analysis:

1. **Detect potentially malicious activity** on the host (osquery telemetry +
   Sigma rules, evaluated locally).
2. **Scan the host for vulnerabilities** (Syft SBOM of installed packages +
   Grype CVE matching).

This is an **EDR without the response** — by design it observes and reports; it
does not take remediation actions on the endpoint, which keeps it simple and
safe for homelab / self-hosted environments.

Targets: recent **macOS**, **Windows**, and **Ubuntu Server** (single static Go
binary per platform, no runtime to install).

## Status

Phased build (see `docs/EDR_API.md` for the wire contract):

- [x] **Phase 1 — agent skeleton**: enrollment, heartbeat, config polling,
  inventory reporting, offline-resilient spool transport, signal handling.
- [x] **Phase 2 — vulnerability scanning**: Grype integration (runs the bundled
  `grype` binary, parses JSON, maps to the SIEMBox vuln model, ships findings;
  initial scan on startup + on schedule).
- [x] **Phase 3 — detection**: osquery telemetry + `sigma-go` evaluation. The
  agent drives `osqueryd` with a scheduled query pack, tails the results, and
  evaluates each row against an embedded default Sigma rule pack plus any rules
  the server pushes; matches ship as detections.
- [x] **Phase 4 — packaging & service**: cross-platform service integration
  (systemd/SysV/launchd/Windows SCM via `kardianos/service`), `install`/`start`/
  `stop`/`status` subcommands, standalone `scan`/`check` test commands,
  goreleaser + nfpm artifacts (`.deb`/`.rpm`/archives), and OS install scripts.

The agent runs end-to-end: it enrolls, reports inventory, scans for
vulnerabilities, and detects suspicious host activity — installable as a managed
service on Linux, macOS, and Windows.

### Vulnerability scanning

The agent shells out to [`grype`](https://github.com/anchore/grype) (installed
by the package; auto-installs its own CVE database on first run). If `grype` is
not found, vuln scanning is skipped and the rest of the agent still runs.
Configure via `grype_binary` and `vuln_scan_target` in `agent.json`.

The default scan scope is **OS-specific**: Linux scans `dir:/` (reads the OS
package DBs); **macOS** scans installed-software locations (`/Applications`,
`/System/Applications`, `/Library`, `/usr/local`, `/opt`) rather than the whole
disk — this avoids walking TCC-protected user folders (no permission prompts)
and is much faster. Setting `vuln_scan_target` overrides this with a single
target. The binary is located via `PATH` plus common dirs (`/usr/local/bin`,
`/opt/homebrew/bin`), so it works under `sudo`/launchd.

### Detection

The agent drives [`osquery`](https://osquery.io) (`osqueryd`, also shipped by
the installer) with a small cross-platform scheduled query pack
(`internal/telemetry/osquery`), tails its results, and evaluates each row
against [Sigma](https://github.com/SigmaHQ/sigma) rules using
[`sigma-go`](https://github.com/bradleyjkemp/sigma-go). An embedded default rule
pack lives in `internal/detect/rules/` and is always active; the SIEMBox server
can push additional rules via the agent config. Matches are shipped as
detections to `/api/edr/events` and land in SIEMBox's existing alerts. osquery
is installed by the package; if it's not found, detection is skipped and the
rest of the agent still runs. The binary is located via `PATH` plus common
locations (`/usr/local/bin`, `/opt/homebrew/bin`, the official macOS osquery
path), so `check`/detection work under `sudo`/launchd. Configure the binary via
`osquery_binary` in `agent.json`.

#### YARA file detection

The background service scans common malware drop / persistence directories
(temp dirs, user Downloads, local bin, autostart locations — see
`DefaultYaraPaths` in `internal/telemetry/osquery`) with YARA **at startup and
every ~60s**. The agent drives the scan itself by invoking `osqueryi` against
osquery's on-demand `yara` table (`internal/agent` → `osquery.RunYaraScan`),
matching files against a signature file it materializes to
`<state-dir>/yara/siembox.yar`. This agent-driven approach is used rather than an
osqueryd scheduled query or the evented `yara_events`/FSEvents file-monitor: the
FSEvents monitor silently delivers nothing on macOS without Full Disk Access, and
the daemon's scheduled query was unreliable, whereas an on-demand `osqueryi` scan
runs immediately, on a cadence the agent controls and logs, and works the same on
every OS with no special permissions. A small baseline rule set is embedded in
the binary (so a fresh, offline agent detects on day one); the SIEMBox server
delivers the full curated rule packs. A match becomes a `high` detection event
via the `siembox-yara-file-match` Sigma rule (deduped by path per agent run).
YARA detection runs only under the background service (`run`/`start`), not the
one-shot `check`.

**Self-test:** the embedded baseline includes a harmless rule that matches the
marker string `SIEMBOX_YARA_SELFTEST`. With the service running, write that
string to a file in a watched directory to confirm the pipeline end-to-end:

```sh
echo 'SIEMBOX_YARA_SELFTEST' > ~/Downloads/siembox-yara-selftest.txt   # macOS
echo 'SIEMBOX_YARA_SELFTEST' > /tmp/siembox-yara-selftest.txt          # Linux
```

A `siembox-yara-file-match` detection fires on the next scan — within ~60s, or
immediately if you (re)start the agent after creating the file (it scans at
startup). It's logged by the running agent and shipped to SIEMBox. Delete the
file afterward. Re-testing won't re-fire for an already-seen path within the same
agent run — use a fresh filename or restart the agent.

## How it talks to SIEMBox

The agent speaks the HTTP API documented in **[`docs/EDR_API.md`](docs/EDR_API.md)**
(served by the SIEMBox backend on port 8421 under `/api/edr/*`). Endpoint
detections land in SIEMBox's existing **alerts**, vulns in its existing
**vulnerabilities** table, and each endpoint becomes an **asset** of type
`endpoint` — so endpoint data correlates with the logs and network scans
SIEMBox already collects.

> The server-side `/api/edr/*` implementation lives in the `cladkins/SIEMBOX`
> repo. This repo owns the agent and the shared API contract.

## Install

**Linux (one-liner):**
```sh
curl -sSfL https://raw.githubusercontent.com/cladkins/SIEMBOX-EDR/main/scripts/install.sh | sudo sh
```
Or install the native `.deb`/`.rpm` from a release — both fetch osquery + grype
and register the service.

**macOS:** install the `.pkg` from a release (installs the agent + service + the
menu bar app, and fetches osquery + grype).

**Windows:** from an extracted release archive, run in an **elevated PowerShell**:
```powershell
powershell -ExecutionPolicy Bypass -File packaging\windows\install.ps1
```
It installs the agent + Windows service and fetches grype + osquery from their
official downloads. (The `.msi` installs the agent + service but **not** the
dependencies — use `install.ps1` to get a working scan/check, or install grype
and osquery separately.)

Then edit the config (see below) and start the service.

## Configure

Settings file at the platform state directory (or pass `-dir`):

- Linux: `/etc/siembox-agent/agent.json`
- macOS: `/Library/Application Support/SIEMBox/agent/agent.json`
- Windows: `%ProgramData%\SIEMBox\agent\agent.json`

```json
{
  "server_url": "https://siembox.example.lan:8421",
  "enrollment_token": "paste-token-from-siembox-ui",
  "ca_cert_path": "/etc/siembox-agent/ca.pem"
}
```
See [`examples/agent.json`](examples/agent.json). On first run the agent consumes
the enrollment token, persists its identity to `identity.json` (mode 0600), and
reuses it thereafter.

## Run as a service

```sh
sudo siembox-agent -dir /etc/siembox-agent install   # register with the init system
sudo siembox-agent -dir /etc/siembox-agent start
sudo siembox-agent status                            # running | stopped | unknown
sudo siembox-agent -dir /etc/siembox-agent stop
sudo siembox-agent -dir /etc/siembox-agent uninstall
```
Service registration adapts to the host: systemd or SysV (Linux), launchd
(macOS), Service Control Manager (Windows). To run in the foreground instead:
`siembox-agent -dir /etc/siembox-agent run`.

## Uninstall

- **macOS:** use the menu bar app's **Uninstall SIEMBox EDR…** item (removes the
  service, menu bar app, binary, config, and package receipt), or run
  `sudo siembox-uninstall`.
- **Windows:** uninstall from **Settings → Apps** (the MSI removes the service).
- **Linux (.deb/.rpm):** `sudo apt remove siembox-agent` / `sudo dnf remove
  siembox-agent` (the package's pre-remove hook stops + unregisters the service).
- **Linux (script install):** `curl -sSfL …/scripts/uninstall.sh | sudo sh`
  (add `--purge` to also remove config + identity).

osquery and grype are left installed in all cases.

## macOS menu bar app

The `SIEMBox Menu Bar.app` (built in Go with `fyne.io/systray`) is the **control
center** — everything is driven from the menu bar, no Terminal needed:

- **Run Vulnerability Scan** / **Run Detection Check** (with last-run counts + notifications)
- **Configure Server…** — set the server URL + enrollment token
- **Start / Stop Background Service** — privileged actions use the native macOS admin-password prompt
- service status + **Reveal Config in Finder**

It runs menu-bar-only (no Dock icon) and drives the `siembox-agent` CLI. Manual
scans run as your user against the scoped, world-readable software locations, so
they need no `sudo` — and **Full Disk Access is not required**.

The macOS **`.pkg` installs it automatically** to `/Applications`, starts it
right away, and registers a LaunchAgent so it relaunches at login — no extra
download, and (since pkg payloads aren't quarantined) no Gatekeeper prompt. For
manual / non-pkg installs, the standalone `SIEMBox-Menu-Bar-*-macos.zip` release
asset still works: unzip, drag to `/Applications`, right-click → Open.

## Test on an endpoint (no server required)

Validate the agent on a host before any SIEMBox server exists — these run the
real scanners locally and print JSON to stdout:

```sh
sudo siembox-agent scan     # one-shot grype vulnerability scan -> findings JSON
sudo siembox-agent check    # one-shot osquery snapshot + Sigma eval -> detections JSON
```

## Build & test (from source)

```sh
make build        # build ./bin/siembox-agent for the host platform
make test         # go test ./...
make cross        # cross-compile for linux/darwin/windows (amd64+arm64)
make snapshot     # goreleaser: build .deb/.rpm + archives locally (no publish)
```
