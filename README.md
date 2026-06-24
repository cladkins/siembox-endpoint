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
- [ ] **Phase 3 — detection** (bundled osquery + `sigma-go` + default rules).
- [ ] **Phase 4 — packaging & hardening** (goreleaser installers, service
  install, secure key storage).

The detection module currently ships as a no-op implementation behind a stable
interface (`internal/detect`); the agent already runs end-to-end, reports
inventory, and scans for vulnerabilities.

### Vulnerability scanning

The agent shells out to [`grype`](https://github.com/anchore/grype) (shipped
alongside the agent by the installer; auto-installs its own CVE database on
first run). If `grype` is not found on `PATH`, vuln scanning is skipped and the
rest of the agent still runs. Configure via `grype_binary` and
`vuln_scan_target` in `agent.json` (defaults: `grype`, `dir:/`).

## How it talks to SIEMBox

The agent speaks the HTTP API documented in **[`docs/EDR_API.md`](docs/EDR_API.md)**
(served by the SIEMBox backend on port 8421 under `/api/edr/*`). Endpoint
detections land in SIEMBox's existing **alerts**, vulns in its existing
**vulnerabilities** table, and each endpoint becomes an **asset** of type
`endpoint` — so endpoint data correlates with the logs and network scans
SIEMBox already collects.

> The server-side `/api/edr/*` implementation lives in the `cladkins/SIEMBOX`
> repo. This repo owns the agent and the shared API contract.

## Build & test

```sh
make build        # build ./bin/siembox-agent for the host platform
make test         # go test ./...
make cross        # cross-compile for linux/darwin/windows (amd64+arm64)
```

## Configure & run

Create a settings file at the platform state directory (or pass `-dir`):

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

See [`examples/agent.json`](examples/agent.json). Then:

```sh
siembox-agent -dir /etc/siembox-agent run    # enrolls on first run, then runs
```

On first run the agent consumes the enrollment token, persists its identity to
`identity.json` (mode 0600), and begins reporting. Subsequent runs reuse the
stored identity.
