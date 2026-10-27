# SIEMBox Endpoint

THIS IS AN ALPHA PROJECT USE WITH CAUTION

A lightweight, cross-platform **endpoint agent** for [SIEMBox](https://github.com/cladkins/SIEMBOX).
It brings endpoint visibility to SIEMBox by doing two jobs and shipping the
results back for correlation and analysis:

1. **Detect potentially malicious activity** on the host (osquery telemetry +
   Sigma rules, evaluated locally).
2. **Scan the host for vulnerabilities** (Syft SBOM of installed packages +
   Grype CVE matching).

By design it **observes and reports only** — it does not take remediation or
response actions on the endpoint, which keeps it simple and safe for homelab /
self-hosted environments.

Targets: recent **macOS**, **Windows**, and **Ubuntu Server** (single static Go
binary per platform, no runtime to install).

## What it does

Installed as a managed service (systemd/SysV on Linux, launchd on macOS, Service
Control Manager on Windows), the agent:

- **Enrolls** with a SIEMBox server (enrollment token → per-agent API key), pulls
  its config, and **reports host inventory** as an `endpoint` asset.
- **Scans for vulnerabilities** with Grype on startup and on a schedule, shipping
  CVE findings to SIEMBox's vulnerability dashboard.
- **Reports installed software** (every package, not only vulnerable ones) at
  startup and every 6 hours, sending the list only when it changed, for
  SIEMBox's Application Monitoring.
- **Detects suspicious activity** with osquery telemetry evaluated against
  [Sigma](https://github.com/SigmaHQ/sigma) rules — an embedded default pack plus
  rules the server pushes — shipping matches as alerts.
- **Scans files with YARA** in common malware-drop / persistence directories,
  using a baseline rule set embedded in the binary plus curated packs the server
  delivers, refreshed without redeploying the agent.
- Ships everything over HTTPS with an **on-disk spool**, so events survive server
  outages and flush on reconnect (custom CA supported for self-signed homelab
  certificates).

The agent↔server wire contract is documented in
[`docs/ENDPOINT_API.md`](docs/ENDPOINT_API.md).

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

### Installed software (package inventory)

The agent reads the platform's package databases directly (no external tool,
a fraction of a second) and sends the full list to `POST /api/edr/packages`:

| Platform | Sources (`type`) |
|----------|------------------|
| Linux    | dpkg `/var/lib/dpkg/status` (`deb`), Alpine `/lib/apk/db/installed` (`apk`), `rpm -qa` when rpm is installed (`rpm`) |
| macOS    | `/Applications` app bundles with their `Info.plist` version (`app`), Homebrew Cellar/Caskroom under `/opt/homebrew` and `/usr/local` (`brew`, `brew-cask`), non-Apple installer receipts from `pkgutil` (`pkg`) |
| Windows  | the Uninstall registry keys — machine-wide 64/32-bit and every loaded user hive (`msi` for Windows Installer products, else `win`); hidden system components and updates are skipped |

It runs at startup and every `package_inventory_interval_seconds` (default
21600, 6 h; minimum 300). The full list goes out only when its hash changed
since the last accepted snapshot, or once a day; otherwise only the hash is
sent, which the server answers without rewriting anything (and asks for the
list if it does not have it). An empty result is never sent. A SIEMBox server
that predates the route answers 404: the agent logs it and tries again a day
later. Turn it off with `"package_inventory": false`. Read-only, like
everything the agent does.

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
every OS with no special permissions.

The scan is kept cheap so it never competes with the host's workload:

- Only the startup pass reads every file. Each later pass reads only files whose
  mtime or ctime changed since the previous pass started (ctime catches files
  dropped with a preserved old mtime). A YARA rule update from the server forces
  one full pass again.
- Files over 50 MB are skipped (disk images, container exports, and build
  caches in `/tmp` would otherwise cost minutes of CPU per pass).
- `osqueryi` runs at the lowest priority the OS offers: nice 19 plus the idle
  I/O class on Linux, nice 19 plus the background band on macOS, and the idle
  priority class on Windows.
- A pass is killed after 10 minutes. A timed-out pass logs a warning and the
  next pass moves on to newer changes rather than retrying it.

A small baseline rule set is embedded in
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

### On-demand scans and scan history

From SIEMBox's *Endpoints* page, analysts can ask an endpoint to run a
vulnerability scan, a YARA file scan, a package inventory or a host inventory
**now** (*Scan now* on one endpoint, *Scan selected* for several). The agent
picks the request up on its next heartbeat (about a minute), runs it without
moving its schedule, and never runs two scans of one type at once. Every scan
it runs, scheduled or on demand, appears in the endpoint's *Scan history* with
its status and a summary. Needs a SIEMBox server with scan history; against
an older server the scans run as before and nothing is reported. Like
everything else, scans only observe.

### Scan policies

With a SIEMBox server that has scan policies (*Endpoints → Scan policies*),
the server decides which scans each endpoint runs and when: a default policy,
named policies and per-endpoint overrides, with calendar or interval schedules
and optional time windows. The agent then runs no scans of its own schedule
(the intervals below and its startup scans stop) and runs each scan the
server issues on a heartbeat, recorded in the scan history as *policy*. While
YARA is enabled, changed files are still checked every minute; full YARA
passes come from the policy. An endpoint that was offline runs each missed
scan once when it reconnects. Against an older server the agent keeps its own
intervals. See `docs/ENDPOINT_API.md` → *Scan policies*.

## How it talks to SIEMBox

The agent speaks the HTTP API documented in **[`docs/ENDPOINT_API.md`](docs/ENDPOINT_API.md)**
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
curl -sSfL https://raw.githubusercontent.com/cladkins/siembox-endpoint/main/scripts/install.sh | sudo sh
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
  "server_url": "http://siembox.example.lan:8421",
  "enrollment_token": "paste-token-from-siembox-ui",
  "ca_cert_path": "/etc/siembox-agent/ca.pem"
}
```
The SIEMBox API on port 8421 serves plain HTTP, so `server_url` starts with
`http://`. An `https://` URL against that port fails the TLS handshake on every
enrollment retry and the endpoint never appears in the console. Use `https://`
(with `ca_cert_path` for a private CA) only when a TLS reverse proxy fronts the
API.

Optional keys: `grype_binary`, `vuln_scan_target`, `osquery_binary` (see above),
`package_inventory` (`false` turns the installed-software report off; default
on) and `package_inventory_interval_seconds` (default 21600; not used while
the server's scan policy schedules scans, though `package_inventory: false`
still keeps the package inventory off on this host).

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

## Updating

**From the SIEMBox console.** An admin can update an endpoint from the Endpoints
page (per-endpoint **Update**, **Update all outdated**, or the auto-update
switch). The server only names a target version; the agent downloads that
release **directly from GitHub** (`github.com/cladkins/siembox-endpoint`), checks
it against the release's `SHA256SUMS`, and updates the way it was installed:

| Installed with | Update |
|---|---|
| `.deb` | `apt-get install -y` of the release `.deb` (falls back to `dpkg -i`) |
| `.rpm` | `rpm -U` of the release `.rpm` |
| `install.sh` / manual binary (Linux) | binary replaced in place, service restarted |
| macOS `.pkg` | `installer -pkg` of the release `.pkg` |
| macOS manual binary | binary replaced in place, service restarted |
| Windows `.msi` | `msiexec /i` of the release `.msi`, silent |
| Windows `install.ps1` / manual | `siembox-agent.exe` replaced in place, service restarted |

The installer runs detached from the service (it restarts the agent), logging to
`update.log` in the state directory (for MSI also `update-msi.log`). Downgrades
and prerelease targets are refused, and a release without `SHA256SUMS` cannot be
installed. **The endpoint needs outbound HTTPS access to `github.com` (and the
`objects.githubusercontent.com` download redirect)**; `HTTPS_PROXY` is honored.
The `ca_cert_path` / `insecure_skip_verify` settings apply to the SIEMBox server
only, never to the GitHub download.

**Manually.** Re-run the install method you used:

```sh
# Linux (script install)
curl -sSfL https://raw.githubusercontent.com/cladkins/siembox-endpoint/main/scripts/install.sh | sudo sh
sudo siembox-agent -dir /etc/siembox-agent restart

# Debian/Ubuntu or RHEL-family: install the newer package from the release
sudo apt-get install -y ./siembox-agent_<version>_amd64.deb
sudo rpm -U siembox-agent-<version>-1.x86_64.rpm

# macOS: install the newer .pkg from the release
sudo installer -pkg siembox-agent-<version>-macos.pkg -target /
```
On Windows, run the newer `.msi` (or extract the release zip and re-run
`packaging\windows\install.ps1` in an elevated PowerShell).

## Uninstall

- **macOS:** use the menu bar app's **Uninstall SIEMBox Endpoint…** item (removes the
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
sudo siembox-agent packages # one-shot installed-package inventory -> packages JSON
```

## Build & test (from source)

```sh
make build        # build ./bin/siembox-agent for the host platform
make test         # go test ./...
make cross        # cross-compile for linux/darwin/windows (amd64+arm64)
make snapshot     # goreleaser: build .deb/.rpm + archives locally (no publish)
```
