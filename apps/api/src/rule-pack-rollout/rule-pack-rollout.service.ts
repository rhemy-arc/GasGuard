/**
 * Staged rollout of rule-pack updates.
 *
 * Operators register a pack's stable version, start a rollout for a candidate
 * version, and move it through its stages with `advance`, `pause`, `resume`
 * and `rollback`. Workers call `resolveForScan` before analysing a repository
 * and `recordScanOutcome` once the scan has finished; outcomes from candidate
 * scans feed the stage gate, which can roll a bad candidate back on its own.
 *
 * Determinism: a scan's versions are pinned the first time it resolves, so a
 * retry of the same scan always runs the same rule-pack versions, and the
 * pin's `fingerprint` belongs in any cache key for scan results.
 *
 * Backward compatibility: packs that were never registered are "unmanaged".
 * `resolve` returns `undefined` and `resolveForScan` lists them in
 * `unmanagedPackIds`, so callers keep using whatever version they used before.
 */

import {
  DEFAULT_RULE_PACK_ROLLOUT_CONFIG,
  RulePackRolloutConfig,
  resolveRulePackRolloutConfig,
} from "./rule-pack-rollout-config";
import {
  RulePackRolloutLogger,
  RulePackRolloutMetrics,
  consoleRulePackRolloutLogger,
  sanitizeLogFields,
} from "./rule-pack-rollout-metrics";
import {
  TransitionAction,
  buildRollout,
  compareStrings,
  evaluateGate,
  isLive,
  requireIdentifier,
  requirePackId,
  requireVersion,
  rulePackFingerprint,
  sanitizeReason,
  selectForTenant,
  transition,
} from "./rule-pack-rollout-planner";
import { RulePackRolloutStore } from "./rule-pack-rollout-store";
import {
  RulePackChannel,
  RulePackRolloutError,
  RulePackRolloutPlan,
  RulePackSelection,
  ScanOutcome,
  ScanRulePackPin,
} from "./rule-pack-rollout-types";

/** Largest number of packs one scan may resolve. */
export const MAX_PACKS_PER_SCAN = 64;

export interface RulePackRolloutServiceOptions {
  store: RulePackRolloutStore;
  config?: Partial<RulePackRolloutConfig>;
  logger?: RulePackRolloutLogger;
  metrics?: RulePackRolloutMetrics;
  clock?: () => number;
}

export interface ScanRulePackRequest {
  tenantId: string;
  scanId: string;
  packIds: string[];
}

export interface ScanRulePackResolution {
  /** Managed packs, sorted by `packId`. */
  selections: RulePackSelection[];
  /** Requested packs with no channel; callers keep their existing default. */
  unmanagedPackIds: string[];
  fingerprint: string;
  /** `reused` when the scan was already pinned (a retry). */
  pin: "created" | "reused";
}

export interface ScanOutcomeRequest {
  tenantId: string;
  scanId: string;
  outcome: ScanOutcome;
}

export type ScanOutcomeResult =
  | { status: "not_pinned" }
  | { status: "duplicate" }
  | {
      status: "recorded";
      /** Packs whose current stage gate counted this outcome. */
      countedPackIds: string[];
      /** Packs whose rollout this outcome rolled back. */
      autoRolledBackPackIds: string[];
    };

export interface AdvanceOptions {
  /** Advance even though the gate has not passed. Requires `reason`. */
  force?: boolean;
  reason?: string;
}

export class RulePackRolloutService {
  readonly config: RulePackRolloutConfig;
  readonly metrics: RulePackRolloutMetrics;
  private readonly store: RulePackRolloutStore;
  private readonly logger: RulePackRolloutLogger;
  private readonly clock: () => number;

  constructor(options: RulePackRolloutServiceOptions) {
    this.config = resolveRulePackRolloutConfig(
      options.config ?? DEFAULT_RULE_PACK_ROLLOUT_CONFIG,
    );
    this.store = options.store;
    // Sanitize here as well as in the default logger, so a custom logger can
    // never receive more than identifiers, versions, counts, and codes.
    const logger = options.logger ?? consoleRulePackRolloutLogger;
    this.logger = {
      log: (level, event, fields) =>
        logger.log(level, event, sanitizeLogFields(fields)),
    };
    this.metrics = options.metrics ?? new RulePackRolloutMetrics();
    this.clock = options.clock ?? Date.now;
  }

  /**
   * Put a pack under rollout management with its current stable version.
   * Idempotent for the same version.
   *
   * @throws RulePackRolloutError ROLLOUT_DISABLED, INVALID_INPUT,
   *   PACK_ALREADY_REGISTERED, CONFLICT or STORE_UNAVAILABLE
   */
  registerPack(
    packId: string,
    stableVersion: string,
  ): Promise<RulePackChannel> {
    return this.guard("register_pack", async () => {
      this.requireEnabled();
      requirePackId(packId);
      requireVersion(stableVersion, "stableVersion");
      // A create only conflicts when someone else created the channel, so a
      // second pass always finds it and settles on whatever won.
      for (let attempt = 0; attempt < 2; attempt++) {
        const existing = await this.store.getChannel(packId);
        if (existing) {
          if (existing.stableVersion === stableVersion) {
            return existing;
          }
          throw new RulePackRolloutError(
            "PACK_ALREADY_REGISTERED",
            "pack is registered with a different stable version; start a rollout to change it",
          );
        }
        const channel: RulePackChannel = {
          packId,
          stableVersion,
          revision: 1,
          rolloutSequence: 0,
          updatedAt: this.clock(),
        };
        if ((await this.store.putChannel(channel, 0)) === "written") {
          this.logger.log("info", "pack_registered", { packId, stableVersion });
          return channel;
        }
        this.metrics.recordConflict();
      }
      throw new RulePackRolloutError(
        "CONFLICT",
        "channel was modified concurrently; retry the operation",
      );
    });
  }

  /**
   * Start a rollout at its first stage.
   *
   * @throws RulePackRolloutError ROLLOUT_DISABLED, INVALID_INPUT, INVALID_PLAN,
   *   PACK_NOT_FOUND, ROLLOUT_IN_PROGRESS, CONFLICT or STORE_UNAVAILABLE
   */
  startRollout(
    plan: RulePackRolloutPlan,
    reason?: string,
  ): Promise<RulePackChannel> {
    return this.guard("start_rollout", async () => {
      this.requireEnabled();
      if (typeof plan !== "object" || plan === null) {
        throw new RulePackRolloutError(
          "INVALID_PLAN",
          "plan must be an object",
        );
      }
      const packId = requirePackId(plan.packId);
      const channel = await this.mutateChannel(packId, (current, now) => {
        const rollout = buildRollout(current, plan, this.config, now);
        const sanitized = sanitizeReason(reason);
        if (sanitized) {
          rollout.events[0].reason = sanitized;
        }
        return {
          ...current,
          rolloutSequence: current.rolloutSequence + 1,
          rollout,
        };
      });
      const rollout = channel.rollout!;
      this.metrics.recordTransition("started");
      this.logger.log("info", "rollout_started", {
        packId,
        rolloutId: rollout.rolloutId,
        baselineVersion: rollout.baselineVersion,
        candidateVersion: rollout.candidateVersion,
        stages: rollout.stagesBasisPoints.length,
        stagePercent: rollout.stagesBasisPoints[0] / 100,
        reason: sanitizeReason(reason),
      });
      return channel;
    });
  }

  /**
   * Move to the next stage, or complete the rollout from the last stage, which
   * makes the candidate the new stable version.
   *
   * @throws RulePackRolloutError GATE_NOT_MET unless `force`, plus the codes
   *   of `startRollout` and INVALID_TRANSITION
   */
  advance(
    packId: string,
    options: AdvanceOptions = {},
  ): Promise<RulePackChannel> {
    return this.guard("advance", async () => {
      this.requireEnabled();
      requirePackId(packId);
      const reason = sanitizeReason(options.reason);
      if (options.force && !reason) {
        throw new RulePackRolloutError(
          "INVALID_INPUT",
          "a reason is required to force an advance",
        );
      }
      let forcedPastGate = false;
      const channel = await this.mutateChannel(packId, (current, now) => {
        const rollout = this.requireRollout(current);
        if (rollout.state === "active") {
          const gate = evaluateGate(rollout);
          if (!gate.passed && !options.force) {
            throw new RulePackRolloutError(
              "GATE_NOT_MET",
              `stage gate not met: ${gate.samples}/${rollout.gate.minSamples} samples, ` +
                `failure ratio ${gate.failureRatio.toFixed(4)} (max ${rollout.gate.maxFailureRatio})`,
            );
          }
          forcedPastGate = !gate.passed;
        }
        const next = transition(
          rollout,
          "advance",
          now,
          this.config.maxEventsPerRollout,
          { reason },
        );
        return {
          ...current,
          stableVersion:
            next.state === "completed"
              ? next.candidateVersion
              : current.stableVersion,
          rollout: next,
        };
      });
      const rollout = channel.rollout!;
      const completed = rollout.state === "completed";
      this.metrics.recordTransition(completed ? "completed" : "advanced");
      this.logger.log(
        forcedPastGate ? "warn" : "info",
        completed ? "rollout_completed" : "rollout_advanced",
        {
          packId,
          rolloutId: rollout.rolloutId,
          stageIndex: rollout.stageIndex,
          stagePercent: rollout.stagesBasisPoints[rollout.stageIndex] / 100,
          stableVersion: channel.stableVersion,
          forced: forcedPastGate,
          reason,
        },
      );
      return channel;
    });
  }

  /** Hold the current stage. Tenants already on the candidate stay on it. */
  pause(packId: string, reason?: string): Promise<RulePackChannel> {
    return this.operatorTransition("pause", packId, reason);
  }

  resume(packId: string, reason?: string): Promise<RulePackChannel> {
    return this.operatorTransition("resume", packId, reason);
  }

  /** Return every tenant to the baseline version and end the rollout. */
  rollback(packId: string, reason?: string): Promise<RulePackChannel> {
    return this.operatorTransition("rollback", packId, reason);
  }

  /** Operator view of a channel, including allow and deny lists. */
  getChannel(packId: string): Promise<RulePackChannel | undefined> {
    return this.guard("get_channel", async () =>
      this.store.getChannel(requirePackId(packId)),
    );
  }

  listChannels(): Promise<RulePackChannel[]> {
    return this.guard("list_channels", () => this.store.listChannels());
  }

  /**
   * The version `tenantId` would get for `packId` right now, without pinning.
   * `undefined` for unmanaged packs.
   */
  resolve(
    tenantId: string,
    packId: string,
  ): Promise<RulePackSelection | undefined> {
    return this.guard("resolve", async () => {
      requireIdentifier(tenantId, "tenantId");
      requirePackId(packId);
      const channel = await this.store.getChannel(packId);
      return channel
        ? selectForTenant(channel, tenantId, this.config.enabled)
        : undefined;
    });
  }

  /**
   * Resolve and pin rule-pack versions for one scan. Calling again with the
   * same tenant, scan and packs returns the pinned versions unchanged.
   *
   * @throws RulePackRolloutError INVALID_INPUT, PIN_MISMATCH (the scan was
   *   pinned with a different pack set) or STORE_UNAVAILABLE
   */
  resolveForScan(
    request: ScanRulePackRequest,
  ): Promise<ScanRulePackResolution> {
    return this.guard("resolve_for_scan", async () => {
      const tenantId = requireIdentifier(request?.tenantId, "tenantId");
      const scanId = requireIdentifier(request.scanId, "scanId");
      const packIds = requirePackIds(request.packIds);

      const existing = await this.store.getPin(tenantId, scanId);
      if (existing) {
        return this.reusePin(existing, packIds);
      }

      const selections: RulePackSelection[] = [];
      for (const packId of packIds) {
        const channel = await this.store.getChannel(packId);
        if (channel) {
          selections.push(
            selectForTenant(channel, tenantId, this.config.enabled),
          );
        }
      }
      const pin: ScanRulePackPin = {
        tenantId,
        scanId,
        packIds,
        selections,
        fingerprint: rulePackFingerprint(selections),
        pinnedAt: this.clock(),
      };
      if ((await this.store.createPin(pin)) === "exists") {
        // A concurrent attempt of the same scan pinned first; use its versions.
        const winner = await this.store.getPin(tenantId, scanId);
        if (winner) {
          return this.reusePin(winner, packIds);
        }
      }
      for (const selection of selections) {
        this.metrics.recordResolution(selection.channel, selection.reason);
      }
      this.logger.log("info", "scan_pinned", {
        tenantId,
        scanId,
        fingerprint: pin.fingerprint,
        candidatePacks: selections.filter((s) => s.channel === "candidate")
          .length,
        unmanagedPacks: packIds.length - selections.length,
      });
      return toResolution(pin, "created");
    });
  }

  /**
   * Record a scan's final outcome. Only the first report per scan counts, and
   * only candidate selections pinned during the rollout's current stage feed
   * its gate. Report failure only once the scan will not be retried.
   *
   * Counting is at most once: if the store fails after the pin is marked but
   * before the gate is updated, that sample is dropped rather than counted
   * twice on retry.
   */
  recordScanOutcome(request: ScanOutcomeRequest): Promise<ScanOutcomeResult> {
    return this.guard("record_outcome", async () => {
      const tenantId = requireIdentifier(request?.tenantId, "tenantId");
      const scanId = requireIdentifier(request.scanId, "scanId");
      const outcome = request.outcome;
      if (outcome !== "succeeded" && outcome !== "failed") {
        throw new RulePackRolloutError(
          "INVALID_INPUT",
          "outcome must be 'succeeded' or 'failed'",
        );
      }

      const pin = await this.store.getPin(tenantId, scanId);
      if (!pin) {
        this.metrics.recordOutcomeIgnored("not_pinned");
        return { status: "not_pinned" };
      }
      const marked = await this.store.setPinOutcome(
        tenantId,
        scanId,
        outcome,
        this.clock(),
      );
      if (marked !== "written") {
        this.metrics.recordOutcomeIgnored(
          marked === "already_recorded" ? "duplicate" : "not_pinned",
        );
        return marked === "already_recorded"
          ? { status: "duplicate" }
          : { status: "not_pinned" };
      }

      const countedPackIds: string[] = [];
      const autoRolledBackPackIds: string[] = [];
      for (const selection of pin.selections) {
        if (selection.channel !== "candidate") {
          this.metrics.recordOutcomeIgnored("not_candidate");
          continue;
        }
        const result = await this.countCandidateOutcome(selection, outcome);
        if (result === "ignored") {
          this.metrics.recordOutcomeIgnored("stale_stage");
          continue;
        }
        countedPackIds.push(selection.packId);
        this.metrics.recordCandidateOutcome(outcome);
        if (result === "rolled_back") {
          autoRolledBackPackIds.push(selection.packId);
        }
      }
      return { status: "recorded", countedPackIds, autoRolledBackPackIds };
    });
  }

  /** Remove pins older than `pinRetentionMs`. */
  purgeExpiredPins(): Promise<number> {
    return this.guard("purge_pins", async () => {
      const removed = await this.store.deletePinsBefore(
        this.clock() - this.config.pinRetentionMs,
      );
      if (removed > 0) {
        this.logger.log("info", "pins_purged", { removed });
      }
      return removed;
    });
  }

  private async countCandidateOutcome(
    selection: RulePackSelection,
    outcome: ScanOutcome,
  ): Promise<"counted" | "rolled_back" | "ignored"> {
    const updated = await this.store.addStageOutcome(
      selection.packId,
      selection.rolloutId!,
      selection.stageIndex!,
      outcome,
      this.clock(),
    );
    if (!updated) {
      return "ignored";
    }
    const rollout = updated.rollout!;
    if (!rollout.gate.autoRollback || !evaluateGate(rollout).breached) {
      return "counted";
    }
    return (await this.autoRollback(selection)) ? "rolled_back" : "counted";
  }

  /**
   * Roll back a rollout whose gate is breached. Returns false when another
   * worker got there first or the stage moved on. A CONFLICT here is not an
   * error for the caller: the outcome is already counted, and the next
   * outcome for this stage re-checks the gate and retries the rollback.
   */
  private async autoRollback(selection: RulePackSelection): Promise<boolean> {
    const state = { rolledBack: false, samples: 0, failureRatio: 0 };
    try {
      await this.mutateChannel(selection.packId, (current, now) => {
        const rollout = current.rollout;
        state.rolledBack = false;
        if (
          !rollout ||
          !isLive(rollout) ||
          rollout.rolloutId !== selection.rolloutId ||
          rollout.stageIndex !== selection.stageIndex
        ) {
          return undefined;
        }
        const gate = evaluateGate(rollout);
        if (!gate.breached) {
          return undefined;
        }
        state.rolledBack = true;
        state.samples = gate.samples;
        state.failureRatio = gate.failureRatio;
        return {
          ...current,
          rollout: transition(
            rollout,
            "rollback",
            now,
            this.config.maxEventsPerRollout,
            {
              auto: true,
              reason: `gate breached: failure ratio ${gate.failureRatio.toFixed(4)} over ${gate.samples} samples`,
            },
          ),
        };
      });
    } catch (error) {
      if (error instanceof RulePackRolloutError && error.code === "CONFLICT") {
        this.logger.log("warn", "auto_rollback_deferred", {
          packId: selection.packId,
          rolloutId: selection.rolloutId,
        });
        return false;
      }
      throw error;
    }
    if (state.rolledBack) {
      this.metrics.recordTransition("auto_rolled_back");
      this.logger.log("warn", "rollout_auto_rolled_back", {
        packId: selection.packId,
        rolloutId: selection.rolloutId,
        stageIndex: selection.stageIndex,
        samples: state.samples,
        failureRatio: state.failureRatio,
      });
    }
    return state.rolledBack;
  }

  private operatorTransition(
    action: Exclude<TransitionAction, "advance">,
    packId: string,
    reason?: string,
  ): Promise<RulePackChannel> {
    return this.guard(action, async () => {
      this.requireEnabled();
      requirePackId(packId);
      const sanitized = sanitizeReason(reason);
      const channel = await this.mutateChannel(packId, (current, now) => ({
        ...current,
        rollout: transition(
          this.requireRollout(current),
          action,
          now,
          this.config.maxEventsPerRollout,
          { reason: sanitized },
        ),
      }));
      const event =
        action === "pause"
          ? "paused"
          : action === "resume"
            ? "resumed"
            : "rolled_back";
      this.metrics.recordTransition(event);
      this.logger.log(
        action === "rollback" ? "warn" : "info",
        `rollout_${event}`,
        {
          packId,
          rolloutId: channel.rollout!.rolloutId,
          stageIndex: channel.rollout!.stageIndex,
          reason: sanitized,
        },
      );
      return channel;
    });
  }

  /**
   * Read-modify-write a channel with optimistic concurrency, retrying on
   * conflict. `mutate` returns `undefined` to leave the channel unchanged.
   */
  private async mutateChannel(
    packId: string,
    mutate: (
      channel: RulePackChannel,
      now: number,
    ) => RulePackChannel | undefined,
  ): Promise<RulePackChannel> {
    for (
      let attempt = 0;
      attempt <= this.config.maxConflictRetries;
      attempt++
    ) {
      const current = await this.store.getChannel(packId);
      if (!current) {
        throw new RulePackRolloutError(
          "PACK_NOT_FOUND",
          "pack is not registered",
        );
      }
      const now = this.clock();
      const next = mutate(current, now);
      if (!next) {
        return current;
      }
      const written: RulePackChannel = {
        ...next,
        revision: current.revision + 1,
        updatedAt: now,
      };
      if (
        (await this.store.putChannel(written, current.revision)) === "written"
      ) {
        return written;
      }
      this.metrics.recordConflict();
    }
    throw new RulePackRolloutError(
      "CONFLICT",
      "channel was modified concurrently; retry the operation",
    );
  }

  private reusePin(
    pin: ScanRulePackPin,
    packIds: string[],
  ): ScanRulePackResolution {
    if (
      pin.packIds.length !== packIds.length ||
      pin.packIds.some((packId, i) => packId !== packIds[i])
    ) {
      throw new RulePackRolloutError(
        "PIN_MISMATCH",
        "scan is already pinned with a different set of rule packs",
      );
    }
    this.metrics.recordPinReused();
    return toResolution(pin, "reused");
  }

  private requireRollout(channel: RulePackChannel) {
    if (!channel.rollout) {
      throw new RulePackRolloutError(
        "INVALID_TRANSITION",
        "pack has no rollout",
      );
    }
    return channel.rollout;
  }

  private requireEnabled(): void {
    if (!this.config.enabled) {
      throw new RulePackRolloutError(
        "ROLLOUT_DISABLED",
        "rule-pack rollouts are disabled",
      );
    }
  }

  /**
   * Run `task`, mapping unexpected (store) errors to STORE_UNAVAILABLE and
   * counting every failure by code. Store error messages are never logged:
   * they can contain file paths or connection strings.
   */
  private async guard<T>(
    operation: string,
    task: () => Promise<T>,
  ): Promise<T> {
    try {
      return await task();
    } catch (error) {
      const mapped =
        error instanceof RulePackRolloutError
          ? error
          : new RulePackRolloutError(
              "STORE_UNAVAILABLE",
              "rule-pack rollout storage is unavailable",
            );
      this.metrics.recordError(mapped.code);
      this.logger.log(mapped.retryable ? "error" : "warn", "operation_failed", {
        operation,
        code: mapped.code,
        retryable: mapped.retryable,
      });
      throw mapped;
    }
  }
}

function requirePackIds(value: unknown): string[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new RulePackRolloutError(
      "INVALID_INPUT",
      "packIds must be a non-empty array",
    );
  }
  if (value.length > MAX_PACKS_PER_SCAN) {
    throw new RulePackRolloutError(
      "INVALID_INPUT",
      `a scan may resolve at most ${MAX_PACKS_PER_SCAN} packs`,
    );
  }
  return [...new Set(value.map(requirePackId))].sort(compareStrings);
}

function toResolution(
  pin: ScanRulePackPin,
  status: "created" | "reused",
): ScanRulePackResolution {
  const managed = new Set(pin.selections.map((s) => s.packId));
  return {
    selections: pin.selections,
    unmanagedPackIds: pin.packIds.filter((packId) => !managed.has(packId)),
    fingerprint: pin.fingerprint,
    pin: status,
  };
}
