# RFC-007: License-Aware Continuous Scan Coverage (Tenable / Nessus)

- **Status**: Proposed
- **Created**: 2026-06-04
- **Owner**: Platform / Discovery
- **Problem**: A customer must cover **3000 IPs** but a vulnerability scanner has a smaller active license (e.g. **500**). The operational idea is to scan in 6 rolling batches of 500, push each batch's results into OpenCTEM for durable storage/processing, then free the scanner (delete/age the 500) and scan the next 500 — looping until the whole estate is covered. We want OpenCTEM to be the **inventory system-of-record + coverage orchestrator** so a small scan license can continuously cover a large estate, *without* wrongly resolving findings for the assets that weren't in the current batch.

---

## 0. License reality check (decides what's even necessary)

The rolling "delete-and-rescan" plan's feasibility is entirely a function of the Tenable product's license model. The customer runs **both Tenable.sc and Nessus Professional**:

| Product | License unit | Reclaim behaviour | Implication for this RFC |
|---|---|---|---|
| **Nessus Professional/Expert** | Per *scanner*, **unlimited IPs** | n/a | **No license rotation needed.** Nessus Pro can scan all 3000. Batching becomes a *performance/scheduling* concern, not a license hack. |
| **Tenable.sc / SecurityCenter** | **Active IPs** (e.g. 500) | IPs **age out** after inactivity (configurable) or manual removal | Rotation is viable here via **aging**, not hard-delete. Keep ≤ cap by aging unscanned IPs out of the active count. |
| *(ref)* Tenable.io / VM | Assets, 90-day count | Deletion lag ~90 days | Rotation would **not** reclaim license in time — not the customer's case, noted for completeness. |

**Headline recommendation:** because the customer **already owns Nessus Pro (unlimited)**, the safest design uses **Nessus Pro as the unlimited scan engine for the full estate** and treats the 3000→batches split as load/time-window scheduling — *not* as a license-evasion delete loop (which risks data loss and is fragile). **Tenable.sc** is used where .sc-specific value is needed (managed scanners, compliance/dashboards, repositories), kept under its active-IP cap by **aging**. The hard delete-rotate-to-dodge-a-cap pattern is the last resort, only on .sc and only via aging.

## 1. Current state (grounded)

What **exists** and is reusable:

- **Asset inventory as system-of-record** — `pkg/domain/asset` with `Criticality` (`critical|high|medium|low|none`), `ownerRef`/`ownerID`, and **`LastScannedAt`** (`repository_extension.go`) — the natural rotation cursor.
- **Nessus XML parsing scaffold** — `internal/app/asset/import.go` `ImportNessus` parses `NessusClientData_v2 → Report>ReportHost → ReportItem` (it already models `pluginName`/`severity`), exposed at `POST /api/v1/assets/import/nessus`. **But it only creates host *assets* — it discards the `ReportItem` vulnerabilities. There is no findings ingestion from .nessus today.**
- **Ingest pipeline (CTIS)** — multi-row insert, async `ingest_jobs` queue + worker (RFC-005), correlation/dedup, idempotent upsert.
- **Batch-scoped auto-resolve** — `FindingRepository.AutoResolveStaleByAssets(tenantID, assetIDs, toolName, scanID, branchID)` resolves stale findings **only across the supplied asset set** — the exact primitive needed for partial-coverage scanning.
- **Integration model** — per-tenant, `ProviderTenable` already in the enum (`pkg/domain/integration`), encrypted credentials (AES-256-GCM), `Config()`/`Metadata()` JSONB. No Tenable *connector* is wired yet.
- **Scan orchestration + agent + platform jobs + smart filtering** (`internal/app/scan`).

What is **missing** (the build):

1. **.nessus → CTIS *findings* adapter** (vulnerabilities, not just hosts).
2. **Tenable connector** (`ProviderTenable`): authenticate, push target list, launch scan, poll, export results, reclaim/age.
3. **Coverage rotation scheduler** (license-aware, criticality-weighted).
4. **Coverage observability** (last-scanned age, license utilisation, sweep cadence).

## 2. Goals / Non-goals

**Goals**
1. OpenCTEM holds the **full estate** (all 3000) durably; the scanner is treated as ephemeral capacity.
2. **Partial-coverage-safe ingestion**: a batch scan of N assets must never resolve findings on assets outside that batch.
3. **License-aware scheduling**: select the next batch to fit the active license, prioritising by criticality + staleness.
4. **Engine-appropriate**: use Nessus Pro (unlimited) for breadth; .sc aging where .sc is used. No fragile delete loops on products that don't reclaim in time.
5. **No data loss**: never free a scanner slot before results are verifiably stored.

**Non-goals**
- Replacing Tenable as the scan engine.
- A general scanner-orchestration framework for every vendor now (Tenable first; the seam should generalise later).
- Real-time scanning — this is scheduled rolling coverage.

## 3. Proposed design

### 3.1 OpenCTEM as inventory + coverage cursor

The 3000 assets live in OpenCTEM permanently with `criticality` and `LastScannedAt`. A **coverage cursor** = "least-recently-scanned, criticality-weighted" ordering. The scanner never holds the source of truth; it holds at most one batch at a time.

### 3.2 Engine selection (per scan profile)

A scan profile declares its engine:

- **`nessus_pro`** — unlimited. Batches exist only to bound scan duration/load. **No reclaim step.** Simplest and recommended default for breadth coverage of the 3000.
- **`tenable_sc`** — active-IP capped. Batches map to .sc asset lists/repositories; "reclaim" = **aging** config so prior batches drop out of the active count. Respect the cap as a hard scheduler constraint.

### 3.3 Coverage rotation scheduler

```
select next batch B (size = license_headroom, e.g. 500):
  order assets by  ( criticality_weight DESC, LastScannedAt ASC NULLS FIRST )
  take first N not currently in-flight
emit scan job for B (engine per profile)
on completion:
  ingest results with scan_session_id = J
  AutoResolveStaleByAssets(tenant, assetIDs=B, toolName="tenable", scanID=J)   // SCOPED TO B ONLY
  set LastScannedAt = now for assets in B
  advance cursor
  (tenable_sc only) reclaim/age B in the scanner — GATED on verified ingest
```

Criticality-weighting means a `critical` asset is re-scanned more often than `none`, instead of a flat 6-cycle round-robin. Batch size is `min(license_headroom, configured_batch)`.

### 3.4 Findings ingestion + the partial-coverage safety rule

Extend the existing Nessus parser into a **.nessus → CTIS findings** adapter (host + ReportItem → asset + finding, mapping Nessus `severity 0–4`/CVSS → platform severity, plugin id/CVE → finding identity). Route through the existing async ingest pipeline so dedup/correlation/idempotency come for free.

**The one rule that must not be gotten wrong:** auto-resolve is called as `AutoResolveStaleByAssets(..., assetIDs = <the batch>, scanID = <session>)`. It resolves stale findings **only for assets in the batch**. The other 2500 assets are *not in this scan* — they must be left untouched (not resolved). A naive "resolve everything not seen in this scan" would wrongly close 2500 assets' findings every cycle. This is the central correctness invariant of the whole feature.

### 3.5 Tenable connector (`ProviderTenable`)

A new connector under the integration model (encrypted creds, mirrors the Jira client resolver wired in RFC-006 Phase 0):

- **Auth**: Nessus Pro REST (`X-ApiKeys: accessKey=…; secretKey=…`) and/or Tenable.sc API (`x-apikey access/secret`), stored encrypted in the integration.
- **Capabilities**: `LaunchScan(targets []string)`, `PollStatus(scanID)`, `ExportResults(scanID) → .nessus`, and `tenable_sc` only: `AgeOut(assetList)` / `Remove(targets)`.
- Reuses SSRF-safe HTTP (`pkg/httpsec`) like the Jira client.

### 3.6 Reclaim/aging gated on verified ingest

Freeing a scanner slot happens **only after** the batch's results are exported, ingested, and ACKed (and the raw .nessus archived). The reclaim is the last step of a successful cycle, never speculative. On ingest failure the cycle retries; the scanner keeps the batch.

### 3.7 Coverage observability

- Per-asset **last-scanned age**; histogram of estate freshness.
- **Sweep cadence** (time to cover all 3000) and per-criticality cadence.
- **License utilisation** for `tenable_sc` (active IPs vs cap) so the scheduler's headroom is visible.
- Metrics via the existing `internal/metrics` (Prometheus) like RFC-005.

## 4. Rollout (phased)

0. **Phase 0 (no code)** — confirm engine per estate: default the 3000 breadth sweep to **Nessus Pro (unlimited)**; reserve **.sc** for its specific value, capped via aging.
1. **Phase 1 — findings ingestion + safety** — `.nessus → CTIS findings` adapter; verify **batch-scoped auto-resolve** with `scan_session_id`. Validate the full loop on a 2-batch subset (manual export + import). Lowest build, highest de-risking.
2. **Phase 2 — Tenable connector** (`ProviderTenable`): encrypted creds + launch/poll/export (Nessus Pro first; .sc + aging next).
3. **Phase 3 — coverage scheduler**: criticality-weighted least-recently-scanned batch selection, license headroom, in-flight guard, `LastScannedAt` advance, reclaim/age step.
4. **Phase 4 — observability**: coverage/freshness/utilisation dashboard + metrics; generalise the connector seam for a second scanner.

## 5. Alternatives considered

- **Buy a 3000-IP .sc license / scan everything on Nessus Pro** — the cleanest "fix": with Nessus Pro unlimited, the license problem is largely moot for breadth. Recommended as the baseline; rotation is then only a perf concern.
- **Tenable Nessus Agents** — licensed by agent count; for 3000 internal hosts often cheaper and removes network-scan license pressure. Worth evaluating commercially.
- **Hard delete-and-rescan to dodge a cap** — the original idea. Rejected as a *primary* strategy: data-loss risk, fragile, and on asset-counted products (`.io`) it doesn't reclaim in time and may breach licensing terms. On `.sc`, aging achieves the same safely.
- **External cron script does rotation, OpenCTEM only ingests** — fine for a Phase 1 pilot (asset import already exists; findings adapter is the gap), but leaves coverage/scheduling invisible. Fold into Phase 1 validation, then move orchestration into OpenCTEM (Phases 2–3).

## 6. Open questions

- Nessus Pro standalone vs scanners managed by .sc — do we talk to the Nessus REST API directly, or drive everything through the .sc API? (Affects connector surface.)
- Severity mapping: trust Nessus severity, CVSS base, or platform re-scoring (RFC-004 EPSS/KEV)? Likely re-score downstream and keep raw.
- Batch size vs scan duration: a 500-IP authenticated scan can take hours — what sweep SLA per criticality tier?
- Asset identity on .sc aging/re-add: confirm continuity keys on IP/hostname (RFC-001), independent of the scanner's internal id (which changes on re-add).
- Where to store the `scan_session_id` ↔ batch mapping for auditing coverage.

## 7. Risks

- **Partial-coverage mis-resolve** (§3.4) — the central invariant; covered by scoping `AutoResolveStaleByAssets` to the batch.
- **Data loss on premature reclaim** — mitigated by gating reclaim on verified ingest (§3.6).
- **Licensing/TOS** — only `.sc` aging is endorsed; no churn-to-dodge on asset-counted products.
- **Detection latency** — an asset is only re-scanned each sweep; criticality-weighting bounds it for the assets that matter most, and the dashboard makes it visible.
