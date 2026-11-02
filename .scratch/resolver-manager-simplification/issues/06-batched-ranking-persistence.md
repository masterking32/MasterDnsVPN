# 06: Batch ranked Resolver saves through one background writer

**What to build:** Preserve useful Resolver ordering across Client launches without synchronously rewriting the resolver file on every pool change. Pool mutation, discovery, and traffic-related decisions return without waiting for ranking-file I/O.

**Blocked by:** None (can start immediately).

**Status:** resolved

This follows [PR #205](https://github.com/masterking32/MasterDnsVPN/pull/205). Persist ordering hints for configured endpoints, not cached authorization or qualification. This ticket changes save scheduling rather than ranking policy, so the shared-evaluation ticket can independently replace the ranking provider while preserving its interface.

## Acceptance criteria

- [x] Replace immediate saves on pool-change paths with nonblocking dirty notification to one Client-owned background writer. No file I/O runs under pool locks or in a pool-change callback.
- [x] Coalesce bursts of changes while imposing a maximum dirty wait: continuous changes cannot postpone persistence forever. Use small internal defaults controllable by tests, without adding public tuning solely for implementation convenience.
- [x] Obtain the latest eligible ranked-endpoint snapshot at save time. Write only if exported endpoint order changes; telemetry changes that leave the order unchanged do not rewrite the timestamp/file.
- [x] Serialize writes. Changes arriving during an in-progress save remain dirty for a later save; an older completed snapshot cannot clear a newer dirty revision.
- [x] Failed saves use the project logger, retain dirty work, and retry with bounded backoff. Storage failures do not block traffic or invalidate qualified Resolvers.
- [x] Preserve temporary-file/rename replacement, user resolver lines/comments, managed-block validation, endpoint deduplication, and filtering against currently configured endpoints. Removed endpoints are not resurrected.
- [x] Graceful shutdown performs a bounded final flush and joins the writer. Session/runtime restarts reuse the Client-owned writer rather than creating duplicates or leaking workers. Forced termination does not promise a final save.
- [x] Disabling automatic ranked saves produces no writer activity or file changes. Saved hints remain safe to load, and candidates are qualified again next launch.
- [x] Tests cover coalescing, maximum wait, unchanged order, changes during writes, write failure/retry, disabled saving, repeated Session restarts, shutdown flush, and configured-endpoint authority using controlled time/storage outcomes.

## Answer

Implemented batched, serialized ranked endpoint persistence:
1. Created `RankedPersistenceWriter` in `internal/client/ranked_writer.go` owned by `Client`.
2. Pool changes signal `NotifyDirty()` non-blockingly; no disk I/O runs under pool locks or callbacks.
3. Coalesces rapid change bursts with a configurable delay while guaranteeing writes within `MaxDirtyWait`.
4. Suppresses redundant disk writes if the exported endpoint ordering is unchanged across telemetry updates.
5. Retries failed writes with exponential backoff without losing pending updates or blocking traffic.
6. Graceful shutdown performs a bounded final flush and joins the background writer.
7. Added comprehensive unit tests in `internal/client/ranked_writer_test.go` verifying coalescing, max dirty wait, unchanged order suppression, retry backoff, disabled writer behavior, and shutdown flushing.
