# siembox-endpoint

Cross-platform Go endpoint agent for SIEMBox (alpha): osquery telemetry
evaluated locally against Sigma rules, Grype vulnerability scans, and YARA file
scans, shipped to a SIEMBox server over HTTPS with an on-disk spool. One static
binary per platform from `cmd/siembox-agent`, run as a systemd/launchd/SCM
service. Build with `make build` / `test` / `vet`; `make cross` cross-compiles
all targets; `make snapshot` builds release artifacts via goreleaser. The
agent↔server wire contract is `docs/ENDPOINT_API.md`.

## Gotchas

**Observe and report only.** The agent must never take remediation or response
actions on the host — that is a design boundary, not a missing feature.

**External tools degrade gracefully.** `grype` and osquery are shelled out to,
resolved via `PATH` plus common install dirs (`/usr/local/bin`,
`/opt/homebrew/bin`, the official macOS osquery path) so lookup works under
sudo/launchd. If a binary is missing, that subsystem is skipped and the rest of
the agent keeps running — preserve this in any change.

**YARA scans are agent-driven via on-demand `osqueryi`.** Not osqueryd
scheduled queries, not evented `yara_events`/FSEvents: the FSEvents monitor
silently delivers nothing on macOS without Full Disk Access, and the daemon's
scheduled query was unreliable. The agent invokes `osqueryi` against the
on-demand `yara` table itself (`internal/agent` → `osquery.RunYaraScan`) at
startup and ~every 60s. Don't "simplify" this back to a scheduled or evented
query.

**Wire changes are two-sided.** Payload or endpoint changes must stay in sync
with the SIEMBox server's `/api/edr/*` routes and be reflected in
`docs/ENDPOINT_API.md`.
