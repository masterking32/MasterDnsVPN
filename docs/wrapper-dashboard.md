# Wrapper Dashboard Architecture

The wrapper dashboard is a local operational UI for the existing release
package. It is designed for users who have the prebuilt client binary and want
to edit configuration, inspect resolver health, and collect optimizer context
without changing the Go client.

## Design Goals

- Preserve the headless client binary interface: TOML config, resolver file,
  stdout logs, and process signals.
- Keep all config edits explicit. Recommendations are previewed before writing.
- Avoid server-side encryption changes unless the matching server config is
  coordinated.
- Keep the UI dense and operational, with Farsi/RTL support possible from the
  same view model.

## Runtime Model

The dashboard server runs from `tools/wrapper-dashboard` and points at a release
package root through `MDVPN_DASHBOARD_ROOT`.

```text
Browser
  -> dashboard HTTP server
    -> client_config.toml / client_resolvers.txt
    -> MasterDnsVPN client child process
    -> stdout log parser
    -> telemetry and rule recommendations
```

The Go client still owns all tunnel behavior. The wrapper only controls files,
process lifecycle, and derived telemetry.

## Modules

- `server.js` starts the dashboard.
- `src/server/app.js` owns the current API routes and shared runtime state.
- `src/server/paths.js` separates the dashboard app root from the release
  package root.
- `src/server/static.js` serves dashboard assets from the tool directory.
- `public/app.js` bootstraps the browser UI.
- `public/js/views/*` contains one renderer/controller per visible section.

Further extraction can move `app.js` route groups into dedicated services
without changing public endpoints.

## API Stability

Existing local endpoints are kept stable:

- `GET /api/state`
- `GET /api/editor`
- `POST /api/save-editor`
- `GET /api/telemetry`
- `GET /api/recommendations/dynamic`
- `POST /api/recommendations/preview-patch`
- `POST /api/resolvers/export-good`
- `GET /api/events`

Consumers should treat these as local-only wrapper APIs, not as a remote
management API for the Go client.

## Safety Rules

- Never export raw `ENCRYPTION_KEY` in AI context.
- Never auto-apply `DOMAINS`, `ENCRYPTION_KEY`, or `DATA_ENCRYPTION_METHOD`.
- Do not commit local logs, resolver exports, or real client configs.
- Keep generated telemetry in the release package root, not the source repo.
- Treat filtered and unfiltered network logs as separate optimization contexts.
  If one log contains harsh-network failures followed by mass resolver
  reactivation, the dashboard marks it as mixed and defaults recommendations to
  the filtered-safe view until the user explicitly selects another context.
