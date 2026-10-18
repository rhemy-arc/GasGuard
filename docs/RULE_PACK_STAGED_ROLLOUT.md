# Staged Rule-Pack Rollout

Part of the **Release and Governance** workstream.

A new rule-pack version can change findings for every repository GasGuard scans. Shipping it to all
tenants at once means a bad rule (a crash, a false-positive flood) hits everyone before anyone
notices. Staged rollout ships a candidate version to a growing, deterministic cohort of tenants,
gates each stage on observed scan outcomes, and rolls back automatically when the gate is breached.

| Piece | Location |
| --- | --- |
| Types and error codes | `apps/api/src/rule-pack-rollout/rule-pack-rollout-types.ts` |
| Configuration (`RULE_PACK_ROLLOUT_*`) | `apps/api/src/rule-pack-rollout/rule-pack-rollout-config.ts` |
| Pure planning: validation, cohorts, gate, state machine | `apps/api/src/rule-pack-rollout/rule-pack-rollout-planner.ts` |
| Persistence boundary (in-memory and file stores) | `apps/api/src/rule-pack-rollout/rule-pack-rollout-store.ts` |
| Operator and worker API | `apps/api/src/rule-pack-rollout/rule-pack-rollout.service.ts` |
| Worker adapter | `apps/api/src/rule-pack-rollout/rule-pack-rollout-worker.ts` |
| Metrics and structured logs | `apps/api/src/rule-pack-rollout/rule-pack-rollout-metrics.ts` |
| Fixtures (realistic repository, cohort regression snapshot) | `apps/api/src/rule-pack-rollout/__fixtures__/` |

The module is self-contained: it depends on no other GasGuard module, and existing scan paths are
unchanged until a worker opts in through `runScanWithRulePacks`.

## Concepts

- **Pack**: a versioned bundle of rules, identified by a slug such as `soroban-core`
  (`^[a-z0-9][a-z0-9._-]{0,63}$`). Versions are SemVer `MAJOR.MINOR.PATCH[-PRERELEASE]`; build
  metadata (`+build`) is rejected because it does not affect precedence, so two distinct versions
  could otherwise compare equal.
- **Channel**: the platform-scoped record for one pack: its stable version plus the current or most
  recent rollout.
- **Rollout**: moves the pack from a *baseline* (the stable version when it started) to a
  *candidate*, through stages that give the candidate to a cumulative percentage of tenants.
- **Pin**: the versions fixed for one scan the first time it resolves rule packs. Retries of that scan
  always use its pin.

### Lifecycle

```
             advance (gate passed, or force + reason)
          ┌───────────────┐
          ▼               │
 start ─► active ─────────┴─► (last stage) advance ─► completed   stable := candidate
          │   ▲
    pause │   │ resume
          ▼   │
          paused
          │
 rollback │ (operator, or automatic on a gate breach from active/paused)
          ▼
      rolled_back                                                  stable unchanged
```

Only one live (`active` or `paused`) rollout per pack. `completed` and `rolled_back` are terminal; start
a new rollout to try again (it gets a new `rolloutId`, e.g. `soroban-core#2`).

### Who gets the candidate

For a live rollout, in order:

1. Tenant on `denyTenants`: baseline (`reason: "deny_list"`).
2. Tenant on `allowTenants`: candidate (`reason: "allow_list"`).
3. Otherwise `tenantBucket(packId, candidateVersion, tenantId) < stage threshold`: candidate, else
   baseline (`reason: "cohort"`).

`tenantBucket` is the first 32 bits of
`SHA-256("gasguard-rule-pack-rollout\0" + packId + "\0" + candidateVersion + "\0" + tenantId)`
modulo 10,000. Stage thresholds are basis points (a stage of `12.5` is 1,250). Consequences:

- **Monotonic**: thresholds only grow, so a tenant on the candidate stays on it for every later stage.
- **Rotating**: the candidate version is in the hash, so successive releases sample different tenants.
- **Stable across processes and machines**: no randomness, no clock, no locale.

With no live rollout (none started, completed, rolled back, or the kill switch on), every tenant gets
the stable version (`channel: "stable"`, `reason: "no_active_rollout"`).

## Determinism

Findings are reproducible for the same commit, configuration and rule-pack versions because:

1. Selection is a pure function of the channel record and the tenant id.
2. `resolveForScan` pins the selection per `(tenantId, scanId)` on first call. Later calls for the same
   scan, including retries after the rollout advanced, paused, completed, rolled back or was disabled,
   return the pinned versions (`pin: "reused"`).
3. The resolution's `fingerprint` (`pack@version` pairs in pack-id order, e.g.
   `soroban-core@1.5.0,soroban-security@2.0.1`) identifies the exact rule set. **Include it in any
   cache key for scan results**: a cache keyed only on repository and commit would serve findings
   computed with a different rule-pack version.

The `cohort-assignments.json` fixture freezes bucket values and stage membership for a set of tenant
ids. If that test fails, cohorts would reshuffle mid-rollout; change the snapshot only together with a
documented migration (finish or roll back every live rollout first).

## Interface

### Operator

```ts
import {
  FileRulePackRolloutStore,
  RulePackRolloutService,
  loadRulePackRolloutConfigFromEnv,
} from './rule-pack-rollout';

const rollouts = new RulePackRolloutService({
  store: new FileRulePackRolloutStore('/var/lib/gasguard/rule-pack-rollout'),
  config: loadRulePackRolloutConfigFromEnv(),
});

await rollouts.registerPack('soroban-core', '1.4.2');      // idempotent for the same version
await rollouts.startRollout({
  packId: 'soroban-core',
  candidateVersion: '1.5.0',                                 // must be newer than stable
  stages: [1, 10, 50, 100],                                  // strictly increasing, ends at 100
  allowTenants: ['gasguard-dogfood'],
  denyTenants: ['regulated-bank-eu'],
  gate: { minSamples: 50, maxFailureRatio: 0.02, autoRollback: true },
}, 'storage-rent rules, RFC-31');

await rollouts.advance('soroban-core');                      // GATE_NOT_MET until the gate passes
await rollouts.advance('soroban-core', { force: true, reason: 'SEC-12 hotfix' }); // audited override
await rollouts.pause('soroban-core', 'investigating spike');
await rollouts.resume('soroban-core');
await rollouts.rollback('soroban-core', 'false positives on AMM repos');

await rollouts.getChannel('soroban-core');                   // full record incl. events history
await rollouts.listChannels();
```

`getChannel` and `listChannels` return operator data (including allow and deny lists, which name
tenants) and must only be exposed to platform operators.

### Worker

```ts
import { runScanWithRulePacks } from './rule-pack-rollout';

const findings = await runScanWithRulePacks(
  rollouts,
  {
    tenantId: job.data.tenantId,
    scanId: job.data.scanId,                 // stable across retries of the same scan
    packIds: ['soroban-core', 'soroban-security', 'evm-gas'],
    isFinalAttempt: job.attemptsMade + 1 >= job.opts.attempts,
  },
  async ({ selections, unmanagedPackIds, fingerprint }) =>
    analyze(repository, commit, selections, unmanagedPackIds, fingerprint),
);
```

The adapter resolves (or re-reads) the pin, runs the scan, and reports the outcome. Lower-level calls
are available as `resolveForScan` and `recordScanOutcome`; `resolve(tenantId, packId)` previews a
selection without pinning.

### Housekeeping

`purgeExpiredPins()` deletes pins older than `pinRetentionMs`. Run it periodically, for example from
the existing scheduled-maintenance job. Keep the retention longer than the longest a scan can be
retried.

## Configuration and secure defaults

| Option | Env variable | Default | Notes |
| --- | --- | --- | --- |
| `enabled` | `RULE_PACK_ROLLOUT_ENABLED` | `true` | Kill switch. See below. |
| `defaultMinSamples` | `RULE_PACK_ROLLOUT_MIN_SAMPLES` | `20` | Gate default when a plan omits it. |
| `defaultMaxFailureRatio` | `RULE_PACK_ROLLOUT_MAX_FAILURE_RATIO` | `0.05` | 0-1. |
| `defaultAutoRollback` | `RULE_PACK_ROLLOUT_AUTO_ROLLBACK` | `true` | |
| `maxStages` | `RULE_PACK_ROLLOUT_MAX_STAGES` | `10` | |
| `maxListedTenants` | `RULE_PACK_ROLLOUT_MAX_LISTED_TENANTS` | `1000` | Allow plus deny list size. |
| `maxConflictRetries` | `RULE_PACK_ROLLOUT_MAX_CONFLICT_RETRIES` | `5` | Re-reads after an optimistic write conflict. |
| `pinRetentionMs` | `RULE_PACK_ROLLOUT_PIN_RETENTION_MS` | 7 days | |
| `maxEventsPerRollout` | `RULE_PACK_ROLLOUT_MAX_EVENTS` | `100` | History cap, oldest dropped first. |

Unset or empty variables keep their defaults. A set but unparseable or out-of-range value throws a
`RangeError` naming the option at startup; nothing silently falls back.

**Kill switch** (`enabled: false`): new resolutions return the stable version for every tenant, so the
candidate is withdrawn instantly without touching stored state, and every mutation fails with
`ROLLOUT_DISABLED`. Existing pins are still honoured so in-flight retries stay deterministic.
Re-enabling restores the rollout exactly where it was.

### Gate

A stage gate counts the final outcomes of candidate scans **pinned during that stage**. Scans pinned
in an earlier stage, baseline scans and duplicate reports are ignored (and counted in
`gasguard_rule_pack_outcomes_ignored_total`).

- **Passed**: at least `minSamples` outcomes and `failed / total <= maxFailureRatio`. Required for
  `advance` unless forced.
- **Breached**: at least `minSamples` outcomes and `failed / total > maxFailureRatio`. With
  `autoRollback`, the outcome that breaches it rolls the rollout back.
- Below `minSamples`, the gate is neither, so a single early failure cannot roll back a stage.

Advancing resets the stage counters.

## Failure semantics

All service errors are `RulePackRolloutError` with a stable `code` and a `retryable` flag.

| Code | Retryable | When |
| --- | --- | --- |
| `ROLLOUT_DISABLED` | no | Mutation while the kill switch is on. |
| `INVALID_INPUT` | no | Malformed pack id, tenant or scan id, version, outcome, or a forced advance without a reason. |
| `INVALID_PLAN` | no | Stages not strictly increasing, not ending at 100, too many, more than two decimals; overlapping or oversized tenant lists; bad gate; candidate not newer than stable. |
| `INVALID_TRANSITION` | no | Action not allowed from the current state, or no rollout. |
| `PACK_NOT_FOUND` | no | Rollout operation on an unregistered pack. |
| `PACK_ALREADY_REGISTERED` | no | `registerPack` with a different stable version. Use a rollout to change versions. |
| `ROLLOUT_IN_PROGRESS` | no | `startRollout` while a rollout is live. |
| `GATE_NOT_MET` | no | `advance` before the gate passes. The message gives samples and failure ratio. |
| `PIN_MISMATCH` | no | The scan was already pinned with a different set of packs. Use a new scan id. |
| `CONFLICT` | yes | Optimistic write conflicts exceeded `maxConflictRetries`. Nothing was written. |
| `STORE_UNAVAILABLE` | yes | The store threw. The store's message is deliberately discarded (it may contain paths or connection strings). |

### Unsupported input

Packs that were never registered are **unmanaged**: `resolve` returns `undefined` and
`resolveForScan` lists them in `unmanagedPackIds` with no selection, so callers keep using whatever
version they used before. This is the backward-compatibility path: adopting the module changes nothing
until a pack is registered. Malformed identifiers fail fast with `INVALID_INPUT` before any I/O.

### Retries and partial failure

- **Resolution failure**: `runScanWithRulePacks` throws before running the scan, so the queue's normal
  retry policy applies (`STORE_UNAVAILABLE` is retryable). No analysis runs on an unknown rule set.
- **Concurrent attempts of the same scan**: pins are write-once; the loser of a race reads and uses
  the winner's pin.
- **Failed attempts**: the adapter reports `failed` only when `isFinalAttempt` is true, so a transient
  failure that a retry recovers from counts as one success, not a failure plus a success.
- **Duplicate reports**: a pin's outcome is set once; later reports return `{ status: "duplicate" }`.
- **Outcome recording is best-effort and at most once**: the pin is marked before the stage counter is
  incremented. If the store fails in between, that sample is dropped rather than double-counted on
  retry; this can only delay a gate decision. A failure to record never changes the scan's own result.
- **Concurrent outcomes**: counters are incremented with the store's atomic `addStageOutcome`, never a
  client-side read-modify-write, so heavy outcome traffic neither loses increments nor starves
  operator writes. If an automatic rollback loses its optimistic write race repeatedly, it logs
  `auto_rollback_deferred` and the next outcome for that stage retries it.
- **Operator races**: channel writes are conditional on the revision read, retried up to
  `maxConflictRetries`, then fail with `CONFLICT` having written nothing.

## Tenant isolation

- Channels are platform data. The tenant-facing result (`RulePackSelection`) contains only the pack,
  version, channel, reason, rollout id and stage, never other tenants or the allow/deny lists.
- Pins are keyed by `(tenantId, scanId)`. Every pin read and write takes the tenant id, so a tenant
  cannot read, reuse or report an outcome for another tenant's scan even when scan ids collide.
- `FileRulePackRolloutStore` derives every path from SHA-256 digests, so crafted ids cannot traverse
  outside the root, and each tenant's pins live in their own directory. Files are written `0600` via
  temp-file-and-rename and verified against their key on read.

## Metrics and logs

`service.metrics.toPrometheus(await service.listChannels())`:

| Metric | Type | Labels | Use |
| --- | --- | --- | --- |
| `gasguard_rule_pack_resolutions_total` | counter | `channel`, `reason` | Candidate share per reason. |
| `gasguard_rule_pack_pins_reused_total` | counter | | Retry volume. |
| `gasguard_rule_pack_rollout_transitions_total` | counter | `action` | Alert on `auto_rolled_back`. |
| `gasguard_rule_pack_candidate_outcomes_total` | counter | `outcome` | Candidate failure rate. |
| `gasguard_rule_pack_outcomes_ignored_total` | counter | `reason` | `not_pinned`, `duplicate`, `not_candidate`, `stale_stage`. |
| `gasguard_rule_pack_rollout_conflicts_total` | counter | | Write contention. |
| `gasguard_rule_pack_rollout_errors_total` | counter | `code` | Alert on `STORE_UNAVAILABLE`. |
| `gasguard_rule_pack_rollout_stage_percent` | gauge | `pack` | Current exposure, 0 when not live. |
| `gasguard_rule_pack_rollout_state` | gauge | `pack`, `state` | |

Labels come from closed sets plus the validated pack slug; tenant, repository and scan ids never
become labels.

Logs are one JSON object per line with `component: "rule-pack-rollout"`. Events: `pack_registered`,
`rollout_started`, `rollout_advanced` (`warn` when forced past the gate), `rollout_completed`,
`rollout_paused`, `rollout_resumed`, `rollout_rolled_back`, `rollout_auto_rolled_back` (`warn`, with
samples and failure ratio), `auto_rollback_deferred`, `scan_pinned`, `pins_purged`, and
`operation_failed` (`error` when retryable, with `operation` and `code`). Fields are identifiers,
versions, counts, codes and sanitized operator reasons only. Every logger, including a custom one, is
wrapped in `sanitizeLogFields`, which drops keys that look like payloads, source or credentials and
truncates strings to 200 characters. Store error messages and scan content are never logged.

## Limitations

- `FileRulePackRolloutStore` serializes writes per key **within one process**. Several API or worker
  processes sharing storage need a database store that implements `putChannel` and `addStageOutcome`
  as single conditional updates and `createPin` as an insert-if-absent.
- The gate measures scan failures, not finding quality. Use small early stages and the allow list
  (dogfood tenants) to review finding diffs before widening.

## Verification

```bash
npx jest apps/api/src/rule-pack-rollout          # unit + integration
npx jest apps/api/src/rule-pack-rollout/rule-pack-rollout.integration.spec.ts
npx eslint apps/api/src/rule-pack-rollout
```
