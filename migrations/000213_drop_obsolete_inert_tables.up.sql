-- Migration 000213: drop 7 obsolete, never-wired tables (DB-redundancy audit, 2026-08).
--
-- expand-contract-ok: contract step — every table below is provably inert:
--   * 0 Go readers/writers (`grep -rw <table> --include='*.go'` minus /migrations/ = 0),
--     and 0 references in the agent / sdk-go / ui repos and in api's non-Go files
--     (yaml/yml/sql/json/toml, seed included);
--   * 0 rows in practice (no writer has ever populated them);
--   * NO inbound foreign key from any other table (pg_constraint confrelid = 0);
--   * NO DB-internal writer — no trigger, function, or view writes to them.
-- Nothing running — no pod, no trigger, no dependent table — references them, so
-- removing them cannot break an old pod mid-rollout.
--
-- Deliberately fail-loud: plain DROP TABLE without CASCADE. The 0-inbound-FK proof
-- above means a bare drop must succeed; if Postgres instead ERRORs on an unexpected
-- dependency, that is a signal to STOP and investigate, not to cascade it away. Each
-- table's own RLS shadow policies (000158) and indexes are dropped with the table
-- itself and do NOT require CASCADE. Each DROP is IF EXISTS so this is idempotent.
-- The 000213_..._down.sql recreates every table's original (empty) structure, so this
-- contract step is fully reversible; no data is lost (all 7 are 0-row).
--
-- Targets (created_by + why inert):
--   1. agent_metrics (000016)          — agent performance metrics were never
--      collected through this table; 0 refs everywhere, 0 rows, no writer/reader.
--   2. email_logs (000021)             — outbound email is not journaled here;
--      0 refs everywhere, 0 rows, no writer/reader.
--   3. registration_tokens (000016)    — an early agent-registration table the
--      current code never references. The live, wired agent-key table is
--      `agent_api_keys` (used across ~12 Go files); registration_tokens has
--      0 refs everywhere, 0 rows, 0 inbound FK, 0 writer.
--   4. scan_profile_template_sources (000029) — scan-profile templates do not
--      resolve through a sources join table; 0 refs everywhere, 0 rows.
--   5. threat_actor_cves (000121)      — threat-actor↔CVE association is not
--      persisted via this join table; 0 refs everywhere, 0 rows.
--   6. finding_regression_events (000152) — NOT a wire candidate. The regression
--      signal the executive dashboard reads is the findings COLUMN, not this
--      table: dashboard_repository.go's "regressions" CTE selects
--      `FROM findings WHERE is_regression = true`, and the is_regression /
--      reopen_count / last_reopened_at columns are maintained by the 000199
--      trigger `mark_finding_regression` (which writes those COLUMNS, never this
--      table). This events table has 0 readers, 0 writers, 0 rows, 0 inbound FK.
--   7. agent_audit_logs (000021)       — abandoned design. Agent lifecycle audit
--      goes to the SHARED `audit_logs` table: AuditService.LogAgentConnected /
--      LogAgentDisconnected (internal/app/audit/service.go) call LogEvent, which
--      writes `audit_logs`, NOT this dedicated table. No api endpoint reads
--      agent_audit_logs (the ui AgentAuditLog component does not hit it). 0 refs
--      everywhere, 0 rows, 0 inbound FK, 0 writer.

DROP TABLE IF EXISTS agent_metrics;
DROP TABLE IF EXISTS email_logs;
DROP TABLE IF EXISTS registration_tokens;
DROP TABLE IF EXISTS scan_profile_template_sources;
DROP TABLE IF EXISTS threat_actor_cves;
DROP TABLE IF EXISTS finding_regression_events;
DROP TABLE IF EXISTS agent_audit_logs;
