# MasterDnsVPN Wrapper Dashboard

Local web dashboard for managing a release-package client without modifying the
Go binary. The dashboard runs as a Node.js wrapper, edits the client TOML and
resolver files, starts/stops the client process, parses stdout logs, and shows
optimizer recommendations.

## Run Against a Release Package

```bash
cd tools/wrapper-dashboard
MDVPN_DASHBOARD_ROOT=/path/to/MasterDnsVPN_Client_Linux_AMD64 npm start
```

Open:

```text
http://127.0.0.1:18080
```

Use a different dashboard port:

```bash
MDVPN_DASHBOARD_ROOT=/path/to/release MDVPN_DASHBOARD_PORT=18081 npm start
```

If `MDVPN_DASHBOARD_ROOT` is omitted, the dashboard uses the current working
directory as the release package root.

## Required Release Package Files

The selected root must contain:

- `client_config.toml`
- `client_resolvers.txt`
- `.config-schema.json`
- `MasterDnsVPN_Client_Linux_AMD64_v...`

Optional files created or read by the dashboard:

- `dashboard-client.log`
- `optimizer-rules.json`
- `dashboard-runs.json`
- `known-good-resolvers.txt`

These runtime files belong in the local release package and should not be
committed unless intentionally adding fixtures.

## Features

- Config and resolver editor with preview-before-apply behavior.
- Balanced optimizer recommendations.
- Dynamic AI optimizer from parsed logs and rules.
- Known-good resolver export.
- Process start/stop wrapper for the headless client.
- SSE-driven UI refresh.
- Tabs for Overview, Optimizer, Editor, Resolvers, and Logs.

The dashboard never silently changes `DOMAINS`, `ENCRYPTION_KEY`, or
`DATA_ENCRYPTION_METHOD`.

## Structure

```text
server.js                 # bootstrap
src/server/               # wrapper server and services
src/server/paths.js       # release root, app root, file paths
src/server/static.js      # static public file serving
src/server/utils/http.js  # JSON/text response helpers
public/app.js             # browser bootstrap
public/js/                # browser modules
public/js/views/          # one view module per dashboard section
```

The project intentionally uses vanilla Node ESM and browser ESM. There is no
frontend build step.

## Validation

```bash
node --check server.js
node --check src/server/app.js
node --check src/server/paths.js
node --check src/server/static.js
node --check src/server/utils/http.js
node --check public/app.js
for f in public/js/*.js public/js/views/*.js; do node --check "$f"; done
```

Smoke-test the API:

```bash
curl -s http://127.0.0.1:18080/api/state
curl -s http://127.0.0.1:18080/api/telemetry
curl -s http://127.0.0.1:18080/api/recommendations/dynamic
curl -s 'http://127.0.0.1:18080/api/resolvers?limit=5'
```
