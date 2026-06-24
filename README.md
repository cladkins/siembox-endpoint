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

The agent shells out to [`grype`](https://github.com/anchore/grype) (shipped
alongside the agent by the installer; auto-installs its own CVE database on
first run). If `grype` is not found on `PATH`, vuln scanning is skipped and the
rest of the agent still runs. Configure via `grype_binary` and
`vuln_scan_target` in `agent.json` (defaults: `grype`, `dir:/`).

### Detection

The agent drives [`osquery`](https://osquery.io) (`osqueryd`, also shipped by
the installer) with a small cross-platform scheduled query pack
(`internal/telemetry/osquery`), tails its results, and evaluates each row
against [Sigma](https://github.com/SigmaHQ/sigma) rules using
[`sigma-go`](https://github.com/bradleyjkemp/sigma-go). An embedded default rule
pack lives in `internal/detect/rules/` and is always active; the SIEMBox server
can push additional rules via the agent config. Matches are shipped as
detections to `/api/edr/events` and land in SIEMBox's existing alerts. If
`osqueryd` is not found on `PATH`, detection is skipped and the rest of the
agent still runs. Configure the binary via `osquery_binary` in `agent.json`.

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
Or install the native package (`.deb`/`.rpm`) from a release. Both fetch osquery
+ grype if missing and register the service. macOS/Windows installers live under
[`packaging/`](packaging/) (reviewed; validate on those OSes before relying on
them).

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
