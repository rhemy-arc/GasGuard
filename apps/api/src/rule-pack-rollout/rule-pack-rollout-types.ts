/**
 * Shared types for staged rule-pack rollouts.
 *
 * A rule pack (a versioned bundle of analyzer rules, e.g. `soroban-core`) has
 * one stable version. A rollout introduces a candidate version to a growing,
 * deterministic cohort of tenants in stages, and ends either `completed` (the
 * candidate becomes stable) or `rolled_back` (everyone stays on the baseline).
 *
 * Rule packs are platform-scoped: the channel record is operator data. The
 * tenant-facing surface is `RulePackSelection`, which never names other tenants
 * or the allow/deny lists.
 */

export const ROLLOUT_STATES = [
  "active",
  "paused",
  "completed",
  "rolled_back",
] as const;
export type RolloutState = (typeof ROLLOUT_STATES)[number];

export type RolloutAction =
  | "started"
  | "advanced"
  | "paused"
  | "resumed"
  | "completed"
  | "rolled_back"
  | "auto_rolled_back";

export interface RolloutGate {
  /** Candidate scan outcomes needed in a stage before it can pass or fail. */
  minSamples: number;
  /** Highest tolerated failed / (failed + succeeded) ratio in a stage (0-1). */
  maxFailureRatio: number;
  /** Roll back automatically as soon as a stage breaches the gate. */
  autoRollback: boolean;
}

/** Operator input to `startRollout`. */
export interface RulePackRolloutPlan {
  packId: string;
  candidateVersion: string;
  /**
   * Cumulative percentage of tenants on the candidate at each stage, strictly
   * increasing and ending at 100. Up to two decimals, e.g. `[1, 10, 50, 100]`.
   */
  stages: number[];
  /** Tenants that always get the candidate while the rollout is live. */
  allowTenants?: string[];
  /** Tenants that always stay on the baseline while the rollout is live. */
  denyTenants?: string[];
  gate?: Partial<RolloutGate>;
}

export interface RolloutStageStats {
  succeeded: number;
  failed: number;
}

export interface RolloutEvent {
  at: number;
  action: RolloutAction;
  stageIndex: number;
  state: RolloutState;
  /** Operator-supplied reason, truncated; never contains scan content. */
  reason?: string;
}

export interface RulePackRollout {
  /** `${packId}#${sequence}`; unique per pack. */
  rolloutId: string;
  baselineVersion: string;
  candidateVersion: string;
  /** Stage thresholds in basis points (1/100 of a percent), last is 10000. */
  stagesBasisPoints: number[];
  stageIndex: number;
  state: RolloutState;
  /** Sorted and unique. */
  allowTenants: string[];
  /** Sorted and unique. */
  denyTenants: string[];
  gate: RolloutGate;
  /** Candidate outcomes for scans pinned during the current stage. */
  stageStats: RolloutStageStats;
  startedAt: number;
  updatedAt: number;
  endedAt?: number;
  /** Most recent events, oldest first, capped by `maxEventsPerRollout`. */
  events: RolloutEvent[];
}

export interface RulePackChannel {
  packId: string;
  stableVersion: string;
  /** Optimistic-concurrency revision, incremented on every write. */
  revision: number;
  /** Number of rollouts ever started for this pack. */
  rolloutSequence: number;
  updatedAt: number;
  /** Current rollout, or the most recent finished one. */
  rollout?: RulePackRollout;
}

export type SelectionChannel = "stable" | "baseline" | "candidate";

export type SelectionReason =
  /** No live rollout (none started, completed, rolled back, or disabled). */
  "no_active_rollout" | "allow_list" | "deny_list" | "cohort";

/** Rule-pack version chosen for one tenant. Safe to return to that tenant. */
export interface RulePackSelection {
  packId: string;
  version: string;
  channel: SelectionChannel;
  reason: SelectionReason;
  rolloutId?: string;
  stageIndex?: number;
}

export type ScanOutcome = "succeeded" | "failed";

/**
 * Versions fixed for one scan the first time it resolves rule packs, so
 * retries of that scan run the same rules even if the rollout moves on.
 */
export interface ScanRulePackPin {
  tenantId: string;
  scanId: string;
  /** Every pack the scan asked for, sorted and unique. */
  packIds: string[];
  /** Managed packs only, sorted by `packId`. */
  selections: RulePackSelection[];
  /** `pack@version` pairs joined by `,`, in `packId` order. */
  fingerprint: string;
  pinnedAt: number;
  outcome?: ScanOutcome;
  outcomeAt?: number;
}

export type RulePackRolloutErrorCode =
  | "ROLLOUT_DISABLED"
  | "INVALID_INPUT"
  | "INVALID_PLAN"
  | "INVALID_TRANSITION"
  | "PACK_NOT_FOUND"
  | "PACK_ALREADY_REGISTERED"
  | "ROLLOUT_IN_PROGRESS"
  | "GATE_NOT_MET"
  | "PIN_MISMATCH"
  | "CONFLICT"
  | "STORE_UNAVAILABLE";

const RETRYABLE_CODES: ReadonlySet<RulePackRolloutErrorCode> = new Set([
  "CONFLICT",
  "STORE_UNAVAILABLE",
]);

export class RulePackRolloutError extends Error {
  readonly code: RulePackRolloutErrorCode;
  /** True when the same call may succeed if retried unchanged. */
  readonly retryable: boolean;

  constructor(code: RulePackRolloutErrorCode, message: string) {
    super(message);
    this.name = "RulePackRolloutError";
    this.code = code;
    this.retryable = RETRYABLE_CODES.has(code);
  }
}
