# RFC-006 Phase 3 (detail): Bidirectional Jira Status Sync

- **Status**: Proposed
- **Created**: 2026-06-06
- **Owner**: Platform / Mobilization
- **Parent**: [RFC-006 — Ticketing Provider Abstraction + Configurable Mapping](./RFC-006-ticketing-provider-and-mapping.md) (§3.3–3.6, Phase 3)
- **Use case (verbatim)**: *"Create a task in OpenCTEM → it creates a task in Jira; when someone drags the status on the Jira board → OpenCTEM syncs the status back."* Two-way, continuous status sync.

> **TL;DR** — One direction already works. **OpenCTEM→Jira create** and **Jira→OpenCTEM status** are implemented today. The missing half is **OpenCTEM→Jira status** (the Jira client has no transition call) plus the cross-cutting machinery a *bidirectional* loop demands: **echo-guard**, a **typed link table**, **reliable delivery**, and **conflict policy**. This RFC specifies those in detail and stages a generic `remediation_task` so the same sync serves both findings and tasks (user chose *both*).

---

## 1. Current state (verified against code, 2026-06-06)

| Edge | Status | Evidence |
|---|---|---|
| OpenCTEM → Jira **create** | ✅ works | `jira.SyncService.CreateTicketFromFinding` + per-tenant `ClientResolver` (RFC-006 Phase 0, #137); idempotent per finding+project (#134) |
| Jira → OpenCTEM **status** | ✅ works | `SyncService.HandleJiraWebhook` (`sync_service.go:402`): reads changelog `status` item → `mapJiraStatusToFinding` → `finding.TransitionStatus` → `findingRepo.Update`; also fires the post-fix rescan hook on `fix_applied` |
| OpenCTEM → Jira **status** | ❌ missing | `internal/infra/jira/client.go` exposes only `CreateIssue`, `GetIssueStatus`, `TestConnection` — **no transition, no comment** |
| Echo-guard | ❌ missing | only one outbound edge exists today, so no loop yet; adding outbound status creates the loop |
| Typed link | ⚠️ heuristic | a finding↔ticket link is a URL inside `finding.WorkItemURIs()`; webhook resolves via `findingRepo.GetByWorkItemURI` (URL match), create-dedup via `/browse/<KEY>-` substring (#134) |
| Mapping | ⚠️ partial | `internal/app/jira/mapping.go` has `DefaultMappingConfig` + `ParseMappingConfig` (per-integration overlay from `config.ticketing`); **inbound** uses it via defaults; **no outbound map**, not fully wired per-tenant |

So the user's literal scenario ("drag in Jira → OpenCTEM updates") **already functions**. This RFC delivers the *reverse* edge and makes the whole loop safe and reliable.

## 2. The hard problems (why this is not just "call an API")

1. **Jira has no "set status".** You POST a **transition** (`POST /rest/api/3/issue/{key}/transitions`) whose available set depends on the issue's current status and the project workflow. We must `GET /issue/{key}/transitions`, find the transition whose `to.name` equals the target, and POST its `id`.
2. **Every customer's workflow differs** (`To Do/In Progress/Done` vs `Triaging/Patching/Verified/Won't Do`). Status maps must be **per-integration configurable**, both directions.
3. **Echo loop.** OpenCTEM change → push to Jira → Jira fires webhook → `HandleJiraWebhook` updates the finding → (naively) triggers another outbound push → … We must break this deterministically.
4. **Reliability & rate limits.** Jira is a third party that rate-limits and has downtime; an outbound push inside a request handler is wrong. Must be enqueued with retry/backoff/dead-letter.
5. **Conflict.** Both sides change "at once" (analyst sets `false_positive` while a dev drags the card to `Done`). Need a defined resolution.
6. **Tenant isolation.** Per-tenant creds (resolver exists); the inbound webhook must map the event to the right tenant + integration and verify authenticity (HMAC).
7. **Secret leakage.** Secret-type findings embed the raw value in `Description`; outbound create/comment must redact (existing backlog item, reaffirmed here).

## 3. Design

### 3.1 A `WorkItem` seam (serves *both* finding and remediation_task)

The user wants findings **and** a grouping "task" to sync. There is **no `remediation_task` entity today**. Rather than couple the sync to `finding`, introduce a thin port the sync operates on:

```go
// internal/app/ticketsync (new) — provider-agnostic, entity-agnostic.
type WorkItem interface {
    WorkItemID() shared.ID
    Kind() string            // "finding" | "remediation_task"
    Title() string
    Body() string            // already secret-redacted by the producer
    Status() string          // canonical OpenCTEM status (per-kind status vocabulary)
    TenantID() shared.ID
}
```

- **Finding** adapts to `WorkItem` immediately (entity exists).
- **`remediation_task`** is introduced in a later sub-phase (§5, Phase 3e) — a task groups N findings, has its own small status set (`open / in_progress / done / wont_do`), and adapts to the same port. The sync engine, link table, echo-guard, and outbox path are written **once** against `WorkItem`.

### 3.2 Provider transition support (extends RFC-006 §3.1)

Add to the `jira.Client` (and the `TicketProvider` interface):

```go
GetTransitions(ctx, issueKey string) ([]Transition, error)  // GET  /issue/{key}/transitions
DoTransition(ctx, issueKey, transitionID string, comment string) error // POST /issue/{key}/transitions
AddComment(ctx, issueKey, body string) error               // POST /issue/{key}/comment (ADF)
```

`Transition{ID, Name, ToStatusName}`. The sync resolves a **target status name** → transition id via `GetTransitions` (short per-issue cache). If no transition reaches the target (workflow forbids it), **fall back to `AddComment`** ("OpenCTEM marked this <status>") so the human can move it — never hard-fail.

### 3.3 Typed link table `ticket_links` (replaces URL heuristic; required for echo-guard)

```sql
CREATE TABLE ticket_links (
    id              UUID PRIMARY KEY,
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    work_item_kind  TEXT NOT NULL,          -- 'finding' | 'remediation_task'
    work_item_id    UUID NOT NULL,
    integration_id  UUID NOT NULL REFERENCES integrations(id) ON DELETE CASCADE,
    provider        TEXT NOT NULL,          -- 'jira'
    project_key     TEXT NOT NULL,
    issue_key       TEXT NOT NULL,          -- e.g. SEC-123
    issue_url       TEXT NOT NULL,
    -- echo-guard / conflict bookkeeping:
    last_pushed_status   TEXT,              -- last OpenCTEM→Jira target we sent
    last_pushed_at       TIMESTAMPTZ,
    last_inbound_status  TEXT,              -- last Jira→OpenCTEM status we applied
    last_inbound_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, work_item_kind, work_item_id, integration_id),
    UNIQUE (tenant_id, integration_id, issue_key)
);
```

`WorkItemURIs()` stays for back-compat and is **dual-written** during rollout; lookups prefer `ticket_links`. This makes webhook→work-item resolution exact (not URL substring) and gives a home for the sync bookkeeping echo-guard needs.

### 3.4 Echo-guard (the core correctness mechanism)

Two independent, layered defenses — either alone breaks the loop; together they're robust:

1. **State compare (idempotency).** Never act if already in the target state.
   - *Outbound*: before transitioning, if `target == link.last_inbound_status` **or** `target == provider.GetStatus(issueKey)` → skip (Jira is already there; we'd just echo).
   - *Inbound*: if the incoming Jira status maps to the finding's **current** status → skip update (no-op); and if it equals `link.last_pushed_status` **within a short echo window** (`now − last_pushed_at < echoTTL`, e.g. 2 min) → it's our own push reflected back → skip.
2. **Provenance tag.** When the inbound webhook applies a change, mark the status-change event `origin = "jira_webhook"`. The outbound trigger (§3.5) ignores changes whose origin is `jira_webhook`. (Implemented as a context value on the transition call or a field on the emitted domain event — *not* persisted state.)

`last_pushed_status` / `last_inbound_status` on `ticket_links` are updated **in the same tx** as the corresponding change, so the compare is authoritative.

> **Why the echo window matters (bug avoided).** A *bare* "skip inbound if status == last_pushed" wrongly suppresses a **later legitimate** re-set to the same status — e.g. OpenCTEM pushes `Done` (echo skipped, correct), the card later moves away, then weeks later a human drags it back to `Done`: with no time bound, that real change matches the stale `last_pushed = Done` and is silently dropped. Bounding the echo-match to `echoTTL` after `last_pushed_at` (and clearing `last_pushed_status` once the echo is consumed) makes echoes vanish while genuine later changes always apply. The provenance tag (defense #2) is the primary loop-breaker; the windowed compare is the safety net for missed/duplicated webhooks.

### 3.5 Outbound trigger + reliable delivery (reuse the outbox)

- **Trigger**: a single **finding/work-item status-change domain event** (preferred over hooking each call site). Consumers subscribe; the ticket-sync consumer enqueues an outbox row **in the same tx** as the status change (transactional outbox — already built for RFC-005 async ingest).
- **Worker**: the existing bounded worker performs `resolveClient(tenant) → map status → GetTransitions → DoTransition|AddComment`, with retry/backoff, dead-letter, and **per-tenant fair queuing** (one tenant's bulk re-triage can't starve others). The outbox row's id is the idempotency key.
- **Guard**: the consumer drops events with `origin = jira_webhook` (§3.4) and events whose `status_outbound` map has no entry (not all OpenCTEM statuses should move the card).

### 3.6 Mapping config — add the outbound direction (extends RFC-006 §3.2)

```jsonc
"ticketing": {
  "status_inbound":  { "Done": "fix_applied", "QA": "in_progress", "Won't Do": "false_positive" },
  "status_outbound": { "resolved": "Done", "false_positive": "Won't Do", "risk_accepted": "Acknowledged", "in_progress": "In Progress" },
  "sync_enabled": true            // per-integration master switch, default false
}
```

`ParseMappingConfig` (exists) gains `status_outbound` (case-insensitive; unknown OpenCTEM statuses ignored → no push). Defaults preserve today's inbound behavior; **outbound defaults to disabled** (`sync_enabled:false`) so no tenant gets surprise Jira writes until they opt in.

### 3.7 Conflict resolution

- **Per-field, last-writer-wins by event time.** Status is the only synced field in this RFC. The `*_at` columns let the worker drop a stale push (if `last_inbound_at` is newer than the event that triggered the outbound, skip — Jira already moved).
- **Blocked transitions never fail the loop.** If OpenCTEM and the Jira workflow disagree (target unreachable), we comment instead of erroring — the human reconciles.
- **`false_positive` / `risk_accepted`** are OpenCTEM-authoritative: we always try to reflect them outbound; we never let an inbound Jira move *out* of `false_positive` (the existing `TransitionStatus` guard already blocks invalid transitions — reaffirmed by test).

### 3.8 Security & tenant isolation

- Per-tenant creds via the existing `IntegrationClientResolver` (decrypt AES-256-GCM); misconfigured integrations skipped, not fatal.
- Inbound webhook: **HMAC verify per tenant** (existing `JiraSecret`, fail-closed) + resolve tenant/integration from the link table by `issue_key`, not from request-controlled fields.
- **Secret redaction** on every outbound create/comment body (reuse the exposures-UI masking policy) — a secret-type finding must never push its raw value to Jira.
- Rate-limit/backoff handled by the worker; respect Jira `Retry-After`.

## 4. Data flow

```
OpenCTEM status change ──► domain event (origin≠jira_webhook)
        │  same tx
        ▼
   outbox row ──► worker ──► resolveClient(tenant)
                              │  map status_outbound[s] = target
                              │  GetTransitions(issueKey) → id (or AddComment fallback)
                              ▼
                          Jira issue moves ──► Jira webhook ──► /jira/webhook (HMAC)
                                                                   │ resolve link by issue_key
                                                                   │ status_inbound[jira] = s'
                                                                   │ if s' == link.last_pushed_status → SKIP (echo)
                                                                   ▼
                                                          finding.TransitionStatus(s', origin=jira_webhook)
                                                                   │ (origin tag ⇒ no re-trigger)
                                                                   ▼  loop terminates
```

## 5. Rollout — sub-phases (each its own PR, tests, CI-green, tenant-isolated)

- **3a — Provider transitions** *(small, safe, independent)*: `GetTransitions`/`DoTransition`/`AddComment` on `jira.Client` + the `TicketProvider` interface; httptest-mocked (verify REST shapes against the Jira Cloud v3 docs; flag for live verification). No behavior change (nothing calls them yet).
- **3b — `ticket_links` table + dual-write**: migration + repo; `CreateTicketFromFinding` and the inbound webhook write/read links (keep `WorkItemURIs` dual-write). Lookups become exact. No outbound yet.
- **3c — Echo-guard + outbound status sync (findings) behind `sync_enabled`**: status-change event → outbox consumer → transition with both echo-guard layers. Default **off**. This delivers the user's missing half for findings.
- **3d — Configurable maps wired per-tenant (both directions)** (RFC-006 Phase 2 closure): inbound + outbound read `config.ticketing` per integration; mapping UI later.
- **3e — `remediation_task` entity + WorkItem adapter**: introduce the task domain (groups findings; status set; CRUD + UI), adapt it to `WorkItem`, and the *same* sync engine handles task↔Jira. (Larger; depends on 3a–3d.)

> Findings get full bidirectional sync at the end of **3c/3d**; tasks at **3e**. Shipping order respects "finding first, task second" while writing the engine once.

## 6. Test plan

- **Unit**: transition resolution (target→id, fallback to comment); `status_outbound` parsing (case-insensitive, unknown ignored); echo-guard compares (skip-on-equal, skip-on-last-pushed); conflict (stale push dropped).
- **Echo-loop test (key)**: simulate outbound push → synthesized inbound webhook with the pushed status → assert **no second outbound** and finding status stable.
- **Integration**: `ticket_links` dual-write + exact lookup; HMAC fail-closed; per-tenant resolver isolation (tenant A's event never uses tenant B's client).
- **Reliability**: worker retry/backoff on 429/5xx; dead-letter after max attempts; idempotent re-delivery (same outbox id ⇒ no duplicate transition).

## 7. Open questions

- **Multiple linked tickets per work item** (multi-project): push to all, or a designated *primary*? Proposed: primary link drives status; others get a comment.
- **Comment mirroring** (platform notes ↔ Jira comments): deferred — high noise + echo risk; status-only in this RFC.
- **Assignee/priority outbound**: out of scope here (status only); routing already covered in parent RFC §3.2.
- **Polling fallback** for tenants who can't configure Jira webhooks: a low-frequency `GetStatus` reconcile cron — deferred; webhook is primary.

## 8. Decision summary

Bidirectional finding↔Jira status sync is ~70% built; this RFC specifies the missing outbound edge + the safety machinery (echo-guard, typed links, outbox delivery, conflict policy) and a `WorkItem` seam so the **same engine** later serves the grouping `remediation_task`. Sub-phases 3a/3b are low-risk and independently mergeable; 3c is the behavioral milestone (opt-in, default off); 3e adds tasks.
