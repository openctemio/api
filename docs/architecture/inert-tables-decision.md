# Inert tables — wire-or-drop decision

A DB-redundancy audit (2026-08) found seven tables that exist in the migration
schema but have **no writer** (nothing in the Go codebase ever `INSERT`s into
them) and, in most cases, no reader either. Five have now been **dropped** in
`000213_drop_obsolete_inert_tables`; the remaining two carry latent, half-built
intent and are kept for a follow-up **WIRE**.

Verification for every row below: `grep -rw "<table>" --include='*.go'` (minus
`/migrations/`) = 0 Go refs, `grep -rw "<table>"` across the `agent`, `sdk-go`,
and `ui` repos and across api's non-Go files (yaml/yml/sql/json/toml, seed
included) = 0, and a live `pg_constraint` check = 0 inbound foreign keys.

## DROPPED in `000213`

The five tables below were removed by
`000213_drop_obsolete_inert_tables.up.sql` (fail-loud plain `DROP TABLE IF
EXISTS`, no `CASCADE`). The paired `..._down.sql` recreates each table's
original empty structure, so the change is fully reversible with no data loss
(every table was 0-row).

| Table | Created by | Why it was safe to drop |
|-------|-----------|-------------------------|
| `agent_metrics` | `000016_agents.up.sql` | Agent performance metrics were never collected through this table. 0 refs everywhere, 0 rows, no writer/reader, 0 inbound FK. |
| `email_logs` | `000021_audit_logs.up.sql` | Outbound email is not journaled here. 0 refs everywhere, 0 rows, no writer/reader, 0 inbound FK. |
| `registration_tokens` | `000016_agents.up.sql` | An early agent-registration table the current code never references. The live, wired agent-key table is `agent_api_keys` (used across ~12 Go files); `registration_tokens` has 0 refs everywhere, 0 rows, 0 inbound FK, 0 writer. (This is **not** claimed to be "superseded by a bootstrap-token flow" — no such table/type was found; the drop stands on the four hard facts.) |
| `scan_profile_template_sources` | `000029_finding_data_flows.up.sql` | Scan-profile templates do not resolve through a sources join table. 0 refs everywhere, 0 rows, no writer/reader, 0 inbound FK. |
| `threat_actor_cves` | `000121_threat_actors.up.sql` | Threat-actor ↔ CVE association is not persisted via this join table. 0 refs everywhere, 0 rows, no writer/reader, 0 inbound FK. |

## WIRE (writer pending)

These two are **not** dropped: each has latent intent worth completing rather
than removing.

| Table | Created by | Why inert | Recommendation |
|-------|-----------|-----------|----------------|
| `agent_audit_logs` | `000021_audit_logs.up.sql` | Purpose-built agent-audit table (agent_id, api_key_id, event_type/action/status, duration_ms, …). 0 Go refs — no writer, no reader. The related `AuditService.LogAgentConnected/LogAgentDisconnected` methods (`internal/app/audit/service.go`) exist but have **no callers**, and even they route to the generic `audit_logs` via `LogEvent`, not to this table. | **WIRE.** Clear intent exists: a dedicated schema plus `docs/architecture/agent-audit-logging.md`, which specifies agent-lifecycle auditing and itself flags these methods as never called. Wiring means calling the lifecycle hooks from the agent/platform-agent service and directing them at `agent_audit_logs`. |
| `finding_regression_events` | `000152_business_services_and_regression.up.sql` | 0 Go refs — no writer, no reader. The regression signal is actually carried on `findings.is_regression` / `reopen_count` (17 Go refs, exercised by `finding_regression_db_test.go`); the dedicated events table was never populated. (Note: an earlier belief that the executive dashboard reads this table does **not** hold on current `develop` — it reads the `findings` columns.) | **WIRE.** Append one event row when `is_regression` flips true, to get a regression **history/timeline** the boolean alone can't provide. If a per-event history is judged unnecessary, this becomes a DROP instead — but that is a product call, not an audit one. |

## Relationship to `000212`

`000212_drop_dead_schema` removed schema that needed no product judgement: three
superseded `assets` CIA columns (100% NULL, 0 Go readers, replaced by
`impact_confidentiality/…`), the never-wired `findings.finding_number` column
(100% NULL, 0 Go readers), and the orphan out-of-band backup table
`_bak_ine_20260803`. `000213` extends that same reviewed `expand-contract`
"contract" path to the five never-wired **tables** above, each dropped behind
the `-- expand-contract-ok:` marker with a full 0-ref / 0-inbound-FK proof.
