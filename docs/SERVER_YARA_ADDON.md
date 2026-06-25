# SIEMBox EDR — YARA rule delivery (add-on to the existing server)

The endpoint agent gained **YARA file-detection** with **server-delivered rule
packs**. The server side that already implements `/api/edr/*` does **not** need
to change to keep working — this is additive and opt-in. If the server doesn't
send `yara_rules_version`, the agent reads it as `0`, uses only its embedded
baseline YARA rules, and never calls the new endpoint.

When you're ready to serve curated YARA rules, add the following. The full
contract lives in [`EDR_API.md`](EDR_API.md) and [`SERVER_HANDOFF.md`](SERVER_HANDOFF.md).

## 1. One new field in the `AgentConfig` response

Add `yara_rules_version` (int) to what you return from
`GET /api/edr/agents/:id/config` (and the `config` object in the enroll
response):

```jsonc
{
  // ...existing fields...
  "yara_rules_version": 1   // 0 or omitted = agent uses embedded baseline only
}
```

**Bump `config_version` whenever `yara_rules_version` changes** — that is what
makes the agent's heartbeat trigger a config re-pull and then download the new
bundle.

## 2. One new endpoint

`GET /api/edr/agents/:id/yara` — **agent-authed** (same
`Authorization: Bearer <agent_api_key>` + `X-Agent-ID` headers as your other
authed routes).

- Return the curated YARA rules as **raw `text/plain`**, `200 OK`.
- Return **only your rules** — the agent appends its own embedded baseline
  automatically. An empty body is valid.
- The agent calls this **only when `yara_rules_version` increased**, so it is
  low-traffic.

## 3. One new table

```sql
CREATE TABLE edr_yara_bundle (
  version     int PRIMARY KEY,   -- monotonic; mirrors yara_rules_version
  rules       text NOT NULL,     -- concatenated YARA rule text, served as-is
  sha256      text NOT NULL,
  source      text,              -- e.g. 'yara-forge core+extended'
  created_at  timestamptz DEFAULT now()
);
```

Serve the highest-version `rules` from the endpoint.

## 4. The rule source (start simple, automate later)

- **Minimum to ship:** insert one static bundle at `version = 1`, set every
  agent's `yara_rules_version = 1` (and bump `config_version`). Agents then
  start pulling it.
- **Then automate:** a daily job that downloads the latest **YARA-Forge Core +
  Extended** `.yar` release assets from
  <https://github.com/YARAHQ/yara-forge/releases>, concatenates them (+ any
  custom rules), stores the text + a new version in `edr_yara_bundle`, and bumps
  `yara_rules_version`/`config_version`. Prefer the Core/Extended tiers — they
  are permissively licensed and redistributable (YARA-Forge records each rule's
  license).

## How the agent behaves (so you can reason about it)

1. On heartbeat/config-poll it reads `yara_rules_version`.
2. If it is higher than the version the agent has applied, it `GET`s the bundle,
   writes it (after its baseline) to `<state-dir>/yara/siembox.yar`, and restarts
   its osquery `yara_events` scanning so the new signatures take effect.
3. The applied version is persisted client-side, so an unchanged bundle is never
   re-downloaded on restart.

## Verify

Set `yara_rules_version: 1` with a small bundle → confirm an enrolled agent
fetches `GET /api/edr/agents/:id/yara` after its next config poll.

Functional smoke test (no server rules required): on the endpoint, drop a file
containing the marker `SIEMBOX_YARA_SELFTEST` into a watched directory (e.g.
`~/Downloads` on macOS, `/tmp` on Linux). The agent's bundled baseline matches
it and a `siembox-yara-file-match` detection should arrive at
`POST /api/edr/events` and surface as an alert.
