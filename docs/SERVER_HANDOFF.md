# SIEMBox Endpoint — Server-Side Implementation Handoff

This brief is for the engineer/agent implementing the **server side** of the
SIEMBox Endpoint feature in the main **`cladkins/SIEMBOX`** repo (Node.js +
TypeScript + Express, PostgreSQL/JSONB, API on port **8421**, Vue 3 + Element
Plus UI on 8420).

The **endpoint agent is complete** (this repo, `cladkins/siembox-endpoint`). It
enrolls, reports inventory, scans for vulnerabilities (Grype), and detects
threats (osquery + Sigma), shipping everything over HTTPS to the endpoints
below. Nothing on the agent needs to change — it just needs a server to talk to.

**Source of truth for the wire format:** [`docs/ENDPOINT_API.md`](ENDPOINT_API.md). The Go
types are in `internal/models/models.go` (mirror them exactly).

---

## Goal

Implement the `/api/edr/*` API + supporting DB + an **Endpoints** UI so endpoint
agents enroll and their data lands in SIEMBox's **existing** pipeline:

| Agent sends      | Store into (REUSE existing)        | Notes                                   |
|------------------|------------------------------------|-----------------------------------------|
| enroll/heartbeat | `edr_agents` (NEW)                 | identity, status, last_seen, config_ver |
| inventory        | `assets` (reuse)                   | `asset_type = 'endpoint'`, agent↔asset  |
| events (detection)| `alerts` (reuse)                  | normalize into existing alert pipeline  |
| vulnerabilities  | `vulnerabilities` (reuse)          | linked to the endpoint asset            |

**Principle: reuse, don't reinvent.** Endpoint detections should appear in the
existing Alerts UI/triage; endpoint vulns in the existing Vulnerabilities
dashboard; each endpoint becomes an `asset` so it correlates with the logs and
Nuclei network-scan data SIEMBox already has.

---

## Authentication

- **Enrollment** (`POST /api/edr/agents/enroll`) is unauthenticated but requires
  a valid, unused **enrollment token** in the body. Generate these in the UI the
  same way shipper API keys are generated today. Single-use or time-boxed at
  your discretion.
- **All other agent endpoints** require the per-agent API key returned at
  enrollment, sent as:
  - `Authorization: Bearer <agent_api_key>`
  - `X-Agent-ID: <agent_id>`
- **Store only a hash** of `agent_api_key` (e.g. SHA-256), like a password. The
  agent persists the plaintext locally (mode 0600); the server keeps the hash.
- Middleware should resolve the agent by `X-Agent-ID`, hash the bearer token,
  constant-time compare, and reject on mismatch (401). Confirm the `:id` in the
  path matches the authenticated agent (403 otherwise).

---

## Endpoints (all under `/api/edr/`, port 8421)

> Full field types and example payloads: [`docs/ENDPOINT_API.md`](ENDPOINT_API.md).
> Request bodies are JSON; respond `202 Accepted` for the ingest endpoints.

### `POST /api/edr/agents/enroll`  (no auth; body carries the token)
Body: `{enrollment_token, hostname, os, os_version, arch, agent_version, ip}`
1. Validate the token (exists, unused/unexpired). Reject → `401`.
2. Create an `edr_agents` row: generate `agent_id` (uuid) + `agent_api_key`
   (64-char hex, like shipper keys); store the **hash**.
3. Upsert an `assets` row (`asset_type='endpoint'`) from the host facts and link
   it to the agent.
4. Mark the token consumed.
5. Respond `{agent_id, agent_api_key, config}` where `config` is the initial
   `AgentConfig` (below). **`agent_api_key` is returned exactly once.**

### `POST /api/edr/agents/:id/heartbeat`  (agent auth)
Body: `{status, agent_version}` → update `last_seen`, `status`, `agent_version`.
Respond `{config_version}` (the current desired version). The agent re-pulls
config when this is greater than what it has.

### `GET /api/edr/agents/:id/config`  (agent auth)
Respond the current `AgentConfig`:
```jsonc
{
  "config_version": 3,
  "heartbeat_interval_seconds": 60,
  "config_poll_interval_seconds": 300,
  "inventory_interval_seconds": 3600,
  "vuln_scan_interval_seconds": 86400,
  "enabled_modules": ["inventory", "vuln", "detect"],
  "rule_set_version": 12,
  "rules": ["<sigma rule YAML>", "..."],   // optional server-pushed Sigma rules
  "yara_rules_version": 7                    // bump when the YARA bundle changes
}
```
`rules` are **Sigma YAML documents** the agent evaluates locally *in addition to*
its built-in default pack. You can start by returning an empty `rules` array and
just the intervals; wire it to the existing `/api/rules` store later (filter to
endpoint/Sigma rules). Bump `config_version` whenever any field changes.

`yara_rules_version` signals YARA signature updates (see the YARA endpoint
below). Start it at `0` (the agent then uses only its embedded baseline). Bump it
— and `config_version` — whenever you publish a new YARA bundle.

### `GET /api/edr/agents/:id/yara`  (agent auth)
Return the curated YARA signature bundle as **raw rule text**
(`Content-Type: text/plain`), `200 OK`. The agent calls this only when
`yara_rules_version` increases; it appends its own embedded baseline, so return
just the server's rules (an empty body is valid → agent runs baseline only).

**How to build the bundle (refresh job):**
1. On a schedule (daily is plenty — YARA-Forge publishes ~weekly), download the
   latest **YARA-Forge Core + Extended** release `.yar` files from
   `https://github.com/YARAHQ/yara-forge/releases` (the
   `yara-forge-rules-core.yar` and `…-extended.yar` package assets).
2. Concatenate them (plus any custom/operator rules), store the text and a
   monotonically increasing version in `edr_yara_bundle`.
3. Bump every agent's `yara_rules_version` (and `config_version`) to the new
   version so the next heartbeat/config-poll triggers the download.

Keep it simple to start: you can commit a single static bundle and serve it with
`yara_rules_version: 1` before automating the refresh. Licensing: prefer the
**Core** (and Extended) tiers — YARA-Forge records each rule's license and these
tiers are curated for permissive, redistributable use.

### `POST /api/edr/inventory`  (agent auth)
Body: `{agent_id, inventory:{hostname, os, os_version, arch, ip, mac, agent_version, software[], collected_at}}`.
Upsert the endpoint `assets` row (keyed by `agent_id`). `software[]` is
`{name, version, source}` (may be large/absent). Idempotent.

### `POST /api/edr/events`  (agent auth)
Body: `{agent_id, events:[Event]}` where `Event` =
`{id, timestamp, type, severity, title, rule_id, rule_name, source, fields}`.
- `type` is `"detection"` or `"telemetry"`.
- **Detections → `alerts`** (reuse): map `severity` (low/medium/high/critical),
  `title`, `rule_id`/`rule_name`, and `fields` (JSONB → `matched_data`), tagged
  with the endpoint asset/agent. They should show up in the existing Alerts UI.
- `event.id` is a stable UUID — **dedupe on it** (the agent retries/replays).
- `telemetry` events (if any) can be stored in the parsed-logs store or ignored
  initially.

### `POST /api/edr/vulnerabilities`  (agent auth)
Body: `{agent_id, scan_started_at, scan_completed_at, vulnerabilities:[...]}`
where each is `{cve, package, installed_version, fixed_version, severity, cvss, description, source}`.
- Upsert into the existing **`vulnerabilities`** table, linked to the endpoint
  `asset`. Treat each scan as the current truth for that asset (e.g. replace the
  agent's previous findings, or upsert by `(asset, cve, package, installed_version)`).
- Reuse the existing CVE/CVSS/severity columns and the vuln dashboard.

---

## Data model

### New tables
```sql
CREATE TABLE edr_agents (
  agent_id        uuid PRIMARY KEY,
  api_key_hash    text NOT NULL,             -- sha256 of the agent api key
  asset_id        bigint REFERENCES assets(id),
  hostname        text,
  os              text,
  os_version      text,
  arch            text,
  agent_version   text,
  ip              text,
  status          text DEFAULT 'enrolled',   -- enrolled | online | offline
  config_version  int  DEFAULT 1,
  last_seen       timestamptz,
  created_at      timestamptz DEFAULT now()
);

CREATE TABLE edr_enrollment_tokens (
  token_hash   text PRIMARY KEY,             -- store a hash, show plaintext once in UI
  label        text,
  created_by   bigint,
  expires_at   timestamptz,
  used_at      timestamptz,                  -- null until consumed (if single-use)
  created_at   timestamptz DEFAULT now()
);

CREATE TABLE edr_yara_bundle (
  version      int PRIMARY KEY,              -- monotonic; mirrors yara_rules_version
  rules        text NOT NULL,               -- concatenated YARA rule text served as-is
  sha256       text NOT NULL,
  source       text,                        -- e.g. 'yara-forge core+extended'
  created_at   timestamptz DEFAULT now()
);
```
Serve the highest-version `edr_yara_bundle.rules` from `GET …/yara`. A single
global bundle is fine to start (all agents get the same rules); per-OS or
per-group bundles can come later by keying on the agent.
Mark `used_at` on enroll if tokens are single-use; otherwise allow reuse until
`expires_at`. (Mirror whatever policy shipper keys use.)

### Reuse (do not duplicate)
- **`assets`** — each endpoint is one asset, `asset_type='endpoint'`. Add that
  enum value if needed. Carry hostname/os/ip from inventory.
- **`vulnerabilities`** — endpoint findings linked to the endpoint asset.
- **`alerts`** — endpoint detections, same schema/status lifecycle
  (new/investigating/closed/false_positive) as today.

---

## Frontend (Vue 3 + Element Plus)

Add an **Endpoints** view:
- **Agent list:** hostname, OS + version, status (online/offline by `last_seen`
  freshness), agent version, last scan time, # open vulns, # recent detections.
- **Per-endpoint drill-down:** reuse the existing **alert** components for its
  detections and the **vulnerability** components for its findings (filter both
  by the endpoint's asset).
- **Enrollment tokens:** a screen to generate a token (show the plaintext once,
  like shipper keys) + the one-line install instructions per OS (link to the
  agent release assets / `scripts/install.sh`).

No new alert/vuln UI should be needed — endpoints feed the existing views.

---

## Cross-cutting requirements

- **Idempotency:** the agent **spools to disk and replays** when the server is
  unreachable, so every ingest endpoint may receive the same payload more than
  once. Dedupe events by `event.id`; make inventory/vuln upserts repeat-safe.
- **Offline-friendly:** the agent retries enrollment with backoff and idles
  until configured, so transient `5xx`/downtime is fine — just don't return
  `2xx` unless you persisted the data.
- **TLS:** agents support a custom CA bundle and (lab-only) insecure skip — your
  existing 8421 TLS is fine.
- **Rate/size limits:** `software[]` and `events[]`/`vulnerabilities[]` batches
  can be sizable; set reasonable body-size limits and paginate/stream if needed.
- **Versioning:** keep request/response shapes in lockstep with
  `internal/models/models.go`; if you change the contract, update `ENDPOINT_API.md`
  and ping the agent side.

---

## Suggested implementation order
1. Migrations: `edr_agents`, `edr_enrollment_tokens`; add `asset_type='endpoint'`.
2. Enrollment-token generation (API + reuse the shipper-key UI pattern).
3. `enroll` + auth middleware (bearer hash + `X-Agent-ID`).
4. `inventory` → upsert endpoint asset. **Milestone: agent shows up under Endpoints.**
5. `heartbeat` + `config` (start with intervals + empty `rules`).
6. `vulnerabilities` → existing vuln table/dashboard.
7. `events` (detections) → existing alerts pipeline.
8. Endpoints UI (list + drill-down reusing alert/vuln components).
9. Wire server-pushed Sigma `rules` into `config` from `/api/rules`.

---

## Verification (end-to-end with the real agent)
The agent can be pointed at a dev server with no packaging:
```sh
# in this repo
go build -o /tmp/siembox-agent ./cmd/siembox-agent
mkdir -p /tmp/agentdir
cat > /tmp/agentdir/agent.json <<EOF
{"server_url":"https://localhost:8421","enrollment_token":"<TOKEN_FROM_UI>","insecure_skip_verify":true}
EOF
/tmp/siembox-agent -dir /tmp/agentdir -v run
```
Then verify:
1. Generate a token in the UI → run the agent → it enrolls and appears under **Endpoints**.
2. Agent posts inventory → the endpoint asset shows host facts.
3. `siembox-agent -dir /tmp/agentdir scan` (or the scheduled scan) → vulns appear
   on the endpoint asset in the vuln dashboard.
4. Trigger a detection (e.g. run a binary from `/tmp`) → an alert appears in the Alerts UI.
5. Stop the server, let the agent generate events, restart → spooled events flush
   (confirms idempotency/dedup).

`curl` smoke test of enroll:
```sh
curl -sk -X POST https://localhost:8421/api/edr/agents/enroll \
  -H 'Content-Type: application/json' \
  -d '{"enrollment_token":"<TOKEN>","hostname":"test","os":"linux","os_version":"Ubuntu 24.04","arch":"amd64","agent_version":"dev","ip":"10.0.0.5"}'
# → {"agent_id":"...","agent_api_key":"...","config":{...}}
```

---

## Open decisions for the implementer
- **Enrollment token policy:** single-use vs reusable-until-expiry (match shipper keys).
- **Vuln reconciliation:** replace-per-scan vs upsert-and-age-out for an asset's findings.
- **Detection storage:** detections → `alerts` only, or also keep raw telemetry in the logs store.
- **Offline status:** the `last_seen` age threshold that flips an agent to "offline".
