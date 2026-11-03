# Resolver manager simplification

Status: approved

## Purpose

Simplify the Resolver management introduced by [PR #205](https://github.com/masterking32/MasterDnsVPN/pull/205): one authoritative candidate lifecycle, shared evaluation, consistent pool policy, understandable default routing, bounded continuing discovery, and batched saved rankings.

The architecture discussion examined PR head 8615f90197f1188e36bc4e5185f15b03f1c99a04. Establish the current implementation baseline before making changes; implementation may have progressed since that analysis. The user approved this seven-ticket breakdown and local publication.

## Agreed behavior

- A candidate Tunnel Path is a Resolver endpoint paired with a tunnel domain. A Session is the authenticated Client/Server relationship, not a candidate. Pool capacity counts Active Paths; endpoint coverage counts distinct addresses and ports.
- Five authoritative candidate states: Untested, Checking, Active, Standby, Rejected. Mutable validity/standby flags are replaced by derived views.
- Eligibility, quality evaluation, pool membership, and packet selection are separate decisions. They share observations and a consistent default ranking; existing explicitly selected traffic strategies keep their meanings.
- Pool selection first enforces eligibility, then fills vacancies, repairs required distinct-endpoint coverage, and finally makes optional performance replacements. All optional replacements require a common score strictly greater than 1.25 times the displaced score. Coverage repair and vacancy filling do not require that margin.
- Startup readiness ends the foreground wait. With inactive rechecking enabled, background discovery continues until every configured Tunnel Path has a bounded initial outcome, then maintenance continues. It is limited by both concurrent probes and actual DNS query starts.
- Preserve the inactive-rechecking switch: disabling it performs the full initial startup scan and disables continuing inactive discovery. Other features keep their independent configuration.
- Saved rankings are ordering hints for configured endpoints; they never authorize removed endpoints or bypass qualification. A single background writer batches changes and performs a bounded shutdown flush.

## Tickets and dependencies

All seven tickets are resolved.

| Ticket | Delivers | Blocked by | Status |
|---|---|---|---|
| [01](issues/01-authoritative-candidate-lifecycle.md) | One authoritative candidate lifecycle | None | resolved |
| [02](issues/02-shared-resolver-evaluation.md) | Shared evaluation and diagnostic evidence | None | resolved |
| [03](issues/03-consistent-pool-selection-policy.md) | Consistent admission and replacement | 01, 02 | resolved |
| [04](issues/04-common-score-default-routing.md) | Common-score default; explicit strategies preserved | 02 | resolved |
| [05](issues/05-background-discovery-coverage.md) | Early readiness plus bounded full background coverage | 03 | resolved |
| [06](issues/06-batched-ranking-persistence.md) | Batched, serialized persistence | None | resolved |
| [07](issues/07-integrated-resolver-manager-acceptance.md) | Complete lifecycle validation and documentation | 04, 05, 06 | resolved |

The initial frontier is **01, 02, and 06**. These tickets are logically independent, although agents sharing a checkout must coordinate edits to shared modules. Claim the selected ticket by setting Status: claimed before implementation. Record results and validation under an Answer heading, then set Status: resolved. Append discussion under Comments when needed.

Each implementation ticket includes focused behavioral tests and relevant documentation. Ticket 07 validates the integrated lifecycle, cleans up any remaining migration scaffolding, and records operational evidence. Real-network performance comparisons are opt-in; no universal startup-time or throughput guarantee is implied.
