/**
 * Pure planning logic for staged rule-pack rollouts.
 *
 * Nothing here performs I/O or reads the clock; callers pass `now`. Given the
 * same channel record and tenant id, `selectForTenant` always returns the same
 * selection, which is what makes findings reproducible for the same commit,
 * configuration and rule-pack version.
 *
 * Cohort membership comes from `tenantBucket`: a SHA-256 of the pack id,
 * candidate version and tenant id, reduced to a bucket in [0, 10000). A tenant
 * is on the candidate when its bucket is below the current stage threshold.
 * Because thresholds only grow, a tenant that joins the cohort at one stage
 * stays in it for every later stage, and because the candidate version is part
 * of the hash, successive releases do not always land on the same tenants.
 */

import * as crypto from "crypto";
import { RulePackRolloutConfig } from "./rule-pack-rollout-config";
import {
  RolloutAction,
  RolloutGate,
  RolloutState,
  RulePackChannel,
  RulePackRollout,
  RulePackRolloutError,
  RulePackRolloutPlan,
  RulePackSelection,
  ScanOutcome,
} from "./rule-pack-rollout-types";

export const BUCKET_COUNT = 10_000;

/** Pack ids are platform-controlled slugs, e.g. `soroban-core`. */
const PACK_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,63}$/;
/** Tenant and scan ids: 1-256 chars, no whitespace or control chars. */
const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$/;
/**
 * SemVer 2.0 without build metadata: build metadata does not affect
 * precedence, so allowing it would let two distinct versions compare equal.
 */
const VERSION_PATTERN =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?$/;
const MAX_VERSION_LENGTH = 64;
const MAX_REASON_LENGTH = 200;
const BUCKET_DOMAIN = "gasguard-rule-pack-rollout";

const LIVE_STATES: ReadonlySet<RolloutState> = new Set(["active", "paused"]);

export function isLive(rollout: RulePackRollout | undefined): boolean {
  return rollout !== undefined && LIVE_STATES.has(rollout.state);
}

export function requirePackId(value: unknown): string {
  if (typeof value !== "string" || !PACK_ID_PATTERN.test(value)) {
    throw new RulePackRolloutError(
      "INVALID_INPUT",
      "packId must be 1-64 lower-case letters, digits, '.', '_' or '-'",
    );
  }
  return value;
}

export function requireIdentifier(value: unknown, field: string): string {
  if (typeof value !== "string" || !IDENTIFIER_PATTERN.test(value)) {
    throw new RulePackRolloutError(
      "INVALID_INPUT",
      `${field} must be 1-256 characters without whitespace or control characters`,
    );
  }
  return value;
}

export function requireVersion(value: unknown, field: string): string {
  if (
    typeof value !== "string" ||
    value.length > MAX_VERSION_LENGTH ||
    !VERSION_PATTERN.test(value)
  ) {
    throw new RulePackRolloutError(
      "INVALID_INPUT",
      `${field} must be a semantic version (MAJOR.MINOR.PATCH[-PRERELEASE])`,
    );
  }
  return value;
}

/** SemVer precedence: negative when `left` < `right`, 0 when equal. */
export function compareVersions(left: string, right: string): number {
  const a = VERSION_PATTERN.exec(left);
  const b = VERSION_PATTERN.exec(right);
  if (!a || !b) {
    throw new RulePackRolloutError("INVALID_INPUT", "invalid version");
  }
  for (let i = 1; i <= 3; i++) {
    const diff = compareNumeric(a[i], b[i]);
    if (diff !== 0) {
      return diff;
    }
  }
  const preA = a[4];
  const preB = b[4];
  if (preA === undefined || preB === undefined) {
    // A version without a prerelease ranks above one with a prerelease.
    return preA === preB ? 0 : preA === undefined ? 1 : -1;
  }
  const partsA = preA.split(".");
  const partsB = preB.split(".");
  for (let i = 0; i < Math.min(partsA.length, partsB.length); i++) {
    const diff = comparePrereleasePart(partsA[i], partsB[i]);
    if (diff !== 0) {
      return diff;
    }
  }
  return partsA.length - partsB.length;
}

/** Deterministic bucket in [0, BUCKET_COUNT) for a tenant in one release. */
export function tenantBucket(
  packId: string,
  candidateVersion: string,
  tenantId: string,
): number {
  const hash = crypto
    .createHash("sha256")
    .update(
      `${BUCKET_DOMAIN}\u0000${packId}\u0000${candidateVersion}\u0000${tenantId}`,
      "utf8",
    )
    .digest();
  return hash.readUInt32BE(0) % BUCKET_COUNT;
}

/** Convert a stage percentage (two decimals at most) to basis points. */
export function percentToBasisPoints(percent: unknown): number {
  if (typeof percent !== "number" || !Number.isFinite(percent)) {
    throw new RulePackRolloutError(
      "INVALID_PLAN",
      "stage percentages must be finite numbers",
    );
  }
  const basisPoints = Math.round(percent * 100);
  if (Math.abs(percent * 100 - basisPoints) > 1e-6) {
    throw new RulePackRolloutError(
      "INVALID_PLAN",
      "stage percentages allow at most two decimals",
    );
  }
  if (basisPoints <= 0 || basisPoints > BUCKET_COUNT) {
    throw new RulePackRolloutError(
      "INVALID_PLAN",
      "stage percentages must be greater than 0 and at most 100",
    );
  }
  return basisPoints;
}

/**
 * Validate `plan` against the channel it applies to and build the initial
 * rollout record, starting at stage 0 in the `active` state.
 *
 * @throws RulePackRolloutError INVALID_INPUT, INVALID_PLAN or ROLLOUT_IN_PROGRESS
 */
export function buildRollout(
  channel: RulePackChannel,
  plan: RulePackRolloutPlan,
  config: RulePackRolloutConfig,
  now: number,
): RulePackRollout {
  if (isLive(channel.rollout)) {
    throw new RulePackRolloutError(
      "ROLLOUT_IN_PROGRESS",
      "a rollout is already live for this pack",
    );
  }
  const candidateVersion = requireVersion(
    plan.candidateVersion,
    "candidateVersion",
  );
  if (compareVersions(candidateVersion, channel.stableVersion) <= 0) {
    throw new RulePackRolloutError(
      "INVALID_PLAN",
      "candidateVersion must be newer than the stable version",
    );
  }

  if (!Array.isArray(plan.stages) || plan.stages.length === 0) {
    throw new RulePackRolloutError(
      "INVALID_PLAN",
      "stages must be a non-empty array",
    );
  }
  if (plan.stages.length > config.maxStages) {
    throw new RulePackRolloutError(
      "INVALID_PLAN",
      `stages may have at most ${config.maxStages} entries`,
    );
  }
  const stagesBasisPoints = plan.stages.map(percentToBasisPoints);
  for (let i = 1; i < stagesBasisPoints.length; i++) {
    if (stagesBasisPoints[i] <= stagesBasisPoints[i - 1]) {
      throw new RulePackRolloutError(
        "INVALID_PLAN",
        "stages must be strictly increasing",
      );
    }
  }
  if (stagesBasisPoints[stagesBasisPoints.length - 1] !== BUCKET_COUNT) {
    throw new RulePackRolloutError(
      "INVALID_PLAN",
      "the last stage must be 100",
    );
  }

  const allowTenants = tenantList(plan.allowTenants, "allowTenants");
  const denyTenants = tenantList(plan.denyTenants, "denyTenants");
  if (allowTenants.length + denyTenants.length > config.maxListedTenants) {
    throw new RulePackRolloutError(
      "INVALID_PLAN",
      `allowTenants and denyTenants may list at most ${config.maxListedTenants} tenants`,
    );
  }
  const denied = new Set(denyTenants);
  if (allowTenants.some((tenant) => denied.has(tenant))) {
    throw new RulePackRolloutError(
      "INVALID_PLAN",
      "a tenant cannot be on both allowTenants and denyTenants",
    );
  }

  const sequence = channel.rolloutSequence + 1;
  return {
    rolloutId: `${channel.packId}#${sequence}`,
    baselineVersion: channel.stableVersion,
    candidateVersion,
    stagesBasisPoints,
    stageIndex: 0,
    state: "active",
    allowTenants,
    denyTenants,
    gate: resolveGate(plan.gate, config),
    stageStats: { succeeded: 0, failed: 0 },
    startedAt: now,
    updatedAt: now,
    events: [{ at: now, action: "started", stageIndex: 0, state: "active" }],
  };
}

/**
 * Pick the rule-pack version for `tenantId`.
 *
 * `enabled = false` is the kill switch: every tenant gets the stable version.
 */
export function selectForTenant(
  channel: RulePackChannel,
  tenantId: string,
  enabled: boolean,
): RulePackSelection {
  const rollout = channel.rollout;
  if (!enabled || !rollout || !isLive(rollout)) {
    return {
      packId: channel.packId,
      version: channel.stableVersion,
      channel: "stable",
      reason: "no_active_rollout",
    };
  }
  const base = {
    packId: channel.packId,
    rolloutId: rollout.rolloutId,
    stageIndex: rollout.stageIndex,
  };
  if (binaryIncludes(rollout.denyTenants, tenantId)) {
    return {
      ...base,
      version: rollout.baselineVersion,
      channel: "baseline",
      reason: "deny_list",
    };
  }
  if (binaryIncludes(rollout.allowTenants, tenantId)) {
    return {
      ...base,
      version: rollout.candidateVersion,
      channel: "candidate",
      reason: "allow_list",
    };
  }
  const inCohort =
    tenantBucket(channel.packId, rollout.candidateVersion, tenantId) <
    rollout.stagesBasisPoints[rollout.stageIndex];
  return inCohort
    ? {
        ...base,
        version: rollout.candidateVersion,
        channel: "candidate",
        reason: "cohort",
      }
    : {
        ...base,
        version: rollout.baselineVersion,
        channel: "baseline",
        reason: "cohort",
      };
}

export interface GateEvaluation {
  samples: number;
  failureRatio: number;
  /** Enough samples and failure ratio within the limit. */
  passed: boolean;
  /** Enough samples and failure ratio above the limit. */
  breached: boolean;
}

export function evaluateGate(rollout: RulePackRollout): GateEvaluation {
  const { succeeded, failed } = rollout.stageStats;
  const samples = succeeded + failed;
  const failureRatio = samples === 0 ? 0 : failed / samples;
  const enough = samples >= rollout.gate.minSamples;
  return {
    samples,
    failureRatio,
    passed: enough && failureRatio <= rollout.gate.maxFailureRatio,
    breached: enough && failureRatio > rollout.gate.maxFailureRatio,
  };
}

/**
 * Add one scan outcome to the current stage of `channel`'s rollout, returning
 * the updated channel with its revision bumped, or `undefined` when the
 * rollout is no longer live at the stage the scan was pinned in.
 */
export function applyStageOutcome(
  channel: RulePackChannel,
  rolloutId: string,
  stageIndex: number,
  outcome: ScanOutcome,
  now: number,
): RulePackChannel | undefined {
  const rollout = channel.rollout;
  if (
    !rollout ||
    !isLive(rollout) ||
    rollout.rolloutId !== rolloutId ||
    rollout.stageIndex !== stageIndex
  ) {
    return undefined;
  }
  return {
    ...channel,
    revision: channel.revision + 1,
    updatedAt: now,
    rollout: {
      ...rollout,
      stageStats: {
        succeeded:
          rollout.stageStats.succeeded + (outcome === "succeeded" ? 1 : 0),
        failed: rollout.stageStats.failed + (outcome === "failed" ? 1 : 0),
      },
      updatedAt: now,
    },
  };
}

export type TransitionAction = "advance" | "pause" | "resume" | "rollback";

/**
 * Apply an operator action to a rollout, returning a new record.
 *
 * `advance` from the last stage completes the rollout. `auto` marks a rollback
 * triggered by the gate rather than an operator. Gate checks are the caller's
 * responsibility so they can be forced.
 *
 * @throws RulePackRolloutError INVALID_TRANSITION
 */
export function transition(
  rollout: RulePackRollout,
  action: TransitionAction,
  now: number,
  maxEvents: number,
  options: { reason?: string; auto?: boolean } = {},
): RulePackRollout {
  let state: RolloutState = rollout.state;
  let stageIndex = rollout.stageIndex;
  let event: RolloutAction;
  let stageStats = rollout.stageStats;

  if (action === "advance" && rollout.state === "active") {
    if (stageIndex === rollout.stagesBasisPoints.length - 1) {
      state = "completed";
      event = "completed";
    } else {
      stageIndex++;
      stageStats = { succeeded: 0, failed: 0 };
      event = "advanced";
    }
  } else if (action === "pause" && rollout.state === "active") {
    state = "paused";
    event = "paused";
  } else if (action === "resume" && rollout.state === "paused") {
    state = "active";
    event = "resumed";
  } else if (action === "rollback" && isLive(rollout)) {
    state = "rolled_back";
    event = options.auto ? "auto_rolled_back" : "rolled_back";
  } else {
    throw new RulePackRolloutError(
      "INVALID_TRANSITION",
      `cannot ${action} a rollout that is ${rollout.state}`,
    );
  }

  const reason = sanitizeReason(options.reason);
  const events = [
    ...rollout.events,
    {
      at: now,
      action: event,
      stageIndex,
      state,
      ...(reason ? { reason } : {}),
    },
  ].slice(-maxEvents);
  return {
    ...rollout,
    state,
    stageIndex,
    stageStats,
    updatedAt: now,
    ...(LIVE_STATES.has(state) ? {} : { endedAt: now }),
    events,
  };
}

/** `pack@version` pairs in pack-id order; include in scan cache keys. */
export function rulePackFingerprint(
  selections: readonly RulePackSelection[],
): string {
  return [...selections]
    .sort((left, right) => compareStrings(left.packId, right.packId))
    .map((selection) => `${selection.packId}@${selection.version}`)
    .join(",");
}

/** Strip control characters and truncate operator-supplied reasons. */
export function sanitizeReason(reason: unknown): string | undefined {
  if (typeof reason !== "string") {
    return undefined;
  }
  const cleaned = reason.replace(/[\u0000-\u001f\u007f]+/g, " ").trim();
  if (cleaned === "") {
    return undefined;
  }
  return cleaned.length > MAX_REASON_LENGTH
    ? cleaned.slice(0, MAX_REASON_LENGTH)
    : cleaned;
}

export function compareStrings(left: string, right: string): number {
  if (left === right) {
    return 0;
  }
  return left < right ? -1 : 1;
}

function resolveGate(
  gate: Partial<RolloutGate> | undefined,
  config: RulePackRolloutConfig,
): RolloutGate {
  const resolved: RolloutGate = {
    minSamples: gate?.minSamples ?? config.defaultMinSamples,
    maxFailureRatio: gate?.maxFailureRatio ?? config.defaultMaxFailureRatio,
    autoRollback: gate?.autoRollback ?? config.defaultAutoRollback,
  };
  if (!Number.isInteger(resolved.minSamples) || resolved.minSamples <= 0) {
    throw new RulePackRolloutError(
      "INVALID_PLAN",
      "gate.minSamples must be a positive integer",
    );
  }
  if (
    typeof resolved.maxFailureRatio !== "number" ||
    !Number.isFinite(resolved.maxFailureRatio) ||
    resolved.maxFailureRatio < 0 ||
    resolved.maxFailureRatio > 1
  ) {
    throw new RulePackRolloutError(
      "INVALID_PLAN",
      "gate.maxFailureRatio must be a number between 0 and 1",
    );
  }
  if (typeof resolved.autoRollback !== "boolean") {
    throw new RulePackRolloutError(
      "INVALID_PLAN",
      "gate.autoRollback must be a boolean",
    );
  }
  return resolved;
}

function tenantList(value: unknown, field: string): string[] {
  if (value === undefined) {
    return [];
  }
  if (!Array.isArray(value)) {
    throw new RulePackRolloutError("INVALID_PLAN", `${field} must be an array`);
  }
  const tenants = value.map((tenant) => {
    if (typeof tenant !== "string" || !IDENTIFIER_PATTERN.test(tenant)) {
      throw new RulePackRolloutError(
        "INVALID_PLAN",
        `${field} contains an invalid tenant id`,
      );
    }
    return tenant;
  });
  return [...new Set(tenants)].sort(compareStrings);
}

function binaryIncludes(sorted: readonly string[], value: string): boolean {
  let low = 0;
  let high = sorted.length - 1;
  while (low <= high) {
    const mid = (low + high) >> 1;
    const order = compareStrings(sorted[mid], value);
    if (order === 0) {
      return true;
    }
    if (order < 0) {
      low = mid + 1;
    } else {
      high = mid - 1;
    }
  }
  return false;
}

function compareNumeric(left: string, right: string): number {
  // Compare as digit strings so huge components never lose precision.
  if (left.length !== right.length) {
    return left.length - right.length;
  }
  return compareStrings(left, right);
}

function comparePrereleasePart(left: string, right: string): number {
  const leftNumeric = /^\d+$/.test(left);
  const rightNumeric = /^\d+$/.test(right);
  if (leftNumeric && rightNumeric) {
    return compareNumeric(left, right);
  }
  if (leftNumeric !== rightNumeric) {
    // Numeric identifiers have lower precedence than alphanumeric ones.
    return leftNumeric ? -1 : 1;
  }
  return compareStrings(left, right);
}
