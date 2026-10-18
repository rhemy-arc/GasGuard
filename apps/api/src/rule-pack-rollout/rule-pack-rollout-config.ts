/**
 * Configuration surface for staged rule-pack rollouts.
 *
 * Every option has a conservative default so the feature is safe to enable
 * without tuning. Values are validated once at construction; an invalid value
 * fails fast with a `RangeError` naming the offending option rather than
 * silently falling back.
 */

export interface RulePackRolloutConfig {
  /**
   * Master switch and kill switch. When false, new resolutions return the
   * stable version for every tenant and rollout mutations are refused with
   * ROLLOUT_DISABLED. Existing scan pins are still honoured so in-flight
   * retries stay deterministic.
   */
  enabled: boolean;
  /** Gate default: candidate outcomes needed before a stage passes or fails. */
  defaultMinSamples: number;
  /** Gate default: highest tolerated failure ratio in a stage (0-1). */
  defaultMaxFailureRatio: number;
  /** Gate default: roll back automatically when a stage breaches the gate. */
  defaultAutoRollback: boolean;
  /** Largest number of stages a plan may have. */
  maxStages: number;
  /** Largest allow list plus deny list size. */
  maxListedTenants: number;
  /** Attempts to re-read and re-apply a channel write after a conflict. */
  maxConflictRetries: number;
  /** How long scan pins are kept before `purgeExpiredPins` removes them. */
  pinRetentionMs: number;
  /** Rollout history entries kept per rollout (oldest dropped first). */
  maxEventsPerRollout: number;
}

export const DEFAULT_RULE_PACK_ROLLOUT_CONFIG: Readonly<RulePackRolloutConfig> =
  Object.freeze({
    enabled: true,
    defaultMinSamples: 20,
    defaultMaxFailureRatio: 0.05,
    defaultAutoRollback: true,
    maxStages: 10,
    maxListedTenants: 1_000,
    maxConflictRetries: 5,
    pinRetentionMs: 7 * 24 * 60 * 60 * 1000,
    maxEventsPerRollout: 100,
  });

const ENV_KEYS: Record<keyof RulePackRolloutConfig, string> = {
  enabled: "RULE_PACK_ROLLOUT_ENABLED",
  defaultMinSamples: "RULE_PACK_ROLLOUT_MIN_SAMPLES",
  defaultMaxFailureRatio: "RULE_PACK_ROLLOUT_MAX_FAILURE_RATIO",
  defaultAutoRollback: "RULE_PACK_ROLLOUT_AUTO_ROLLBACK",
  maxStages: "RULE_PACK_ROLLOUT_MAX_STAGES",
  maxListedTenants: "RULE_PACK_ROLLOUT_MAX_LISTED_TENANTS",
  maxConflictRetries: "RULE_PACK_ROLLOUT_MAX_CONFLICT_RETRIES",
  pinRetentionMs: "RULE_PACK_ROLLOUT_PIN_RETENTION_MS",
  maxEventsPerRollout: "RULE_PACK_ROLLOUT_MAX_EVENTS",
};

const BOOLEAN_FIELDS: ReadonlySet<keyof RulePackRolloutConfig> = new Set([
  "enabled",
  "defaultAutoRollback",
]);

/** Merge `overrides` over the defaults and validate the result. */
export function resolveRulePackRolloutConfig(
  overrides: Partial<RulePackRolloutConfig> = {},
): RulePackRolloutConfig {
  const config: RulePackRolloutConfig = {
    ...DEFAULT_RULE_PACK_ROLLOUT_CONFIG,
    ...stripUndefined(overrides),
  };

  for (const field of BOOLEAN_FIELDS) {
    if (typeof config[field] !== "boolean") {
      throw new RangeError(`${field} must be a boolean`);
    }
  }
  requirePositiveInteger(config.defaultMinSamples, "defaultMinSamples");
  requireRatio(config.defaultMaxFailureRatio, "defaultMaxFailureRatio");
  requirePositiveInteger(config.maxStages, "maxStages");
  requireNonNegativeInteger(config.maxListedTenants, "maxListedTenants");
  requireNonNegativeInteger(config.maxConflictRetries, "maxConflictRetries");
  requirePositiveInteger(config.pinRetentionMs, "pinRetentionMs");
  requirePositiveInteger(config.maxEventsPerRollout, "maxEventsPerRollout");
  return config;
}

/**
 * Build a config from `RULE_PACK_ROLLOUT_*` environment variables.
 *
 * Unset or empty variables keep their defaults; set-but-unparseable values
 * throw so a typo in deployment config is caught at startup.
 */
export function loadRulePackRolloutConfigFromEnv(
  env: Record<string, string | undefined> = process.env,
): RulePackRolloutConfig {
  const overrides: Partial<RulePackRolloutConfig> = {};
  for (const [field, envKey] of Object.entries(ENV_KEYS) as [
    keyof RulePackRolloutConfig,
    string,
  ][]) {
    const raw = env[envKey];
    if (raw === undefined || raw.trim() === "") {
      continue;
    }
    const value = raw.trim();
    if (BOOLEAN_FIELDS.has(field)) {
      (overrides as Record<string, boolean>)[field] = parseBoolean(
        value,
        envKey,
      );
    } else {
      const parsed = Number(value);
      if (!Number.isFinite(parsed)) {
        throw new RangeError(`${envKey} must be a number`);
      }
      (overrides as Record<string, number>)[field] = parsed;
    }
  }
  return resolveRulePackRolloutConfig(overrides);
}

function parseBoolean(value: string, envKey: string): boolean {
  const lowered = value.toLowerCase();
  if (["true", "1", "yes", "on"].includes(lowered)) {
    return true;
  }
  if (["false", "0", "no", "off"].includes(lowered)) {
    return false;
  }
  throw new RangeError(`${envKey} must be a boolean`);
}

function stripUndefined<T extends object>(value: T): Partial<T> {
  return Object.fromEntries(
    Object.entries(value).filter(([, v]) => v !== undefined),
  ) as Partial<T>;
}

function requirePositiveInteger(value: number, field: string): void {
  if (!Number.isInteger(value) || value <= 0) {
    throw new RangeError(`${field} must be a positive integer`);
  }
}

function requireNonNegativeInteger(value: number, field: string): void {
  if (!Number.isInteger(value) || value < 0) {
    throw new RangeError(`${field} must be a non-negative integer`);
  }
}

function requireRatio(value: number, field: string): void {
  if (
    typeof value !== "number" ||
    !Number.isFinite(value) ||
    value < 0 ||
    value > 1
  ) {
    throw new RangeError(`${field} must be a number between 0 and 1`);
  }
}
