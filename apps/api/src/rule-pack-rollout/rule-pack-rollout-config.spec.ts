import {
  DEFAULT_RULE_PACK_ROLLOUT_CONFIG,
  loadRulePackRolloutConfigFromEnv,
  resolveRulePackRolloutConfig,
} from "./rule-pack-rollout-config";

describe("resolveRulePackRolloutConfig", () => {
  it("returns the defaults when given no overrides", () => {
    expect(resolveRulePackRolloutConfig()).toEqual(
      DEFAULT_RULE_PACK_ROLLOUT_CONFIG,
    );
  });

  it("merges overrides and ignores undefined values", () => {
    const config = resolveRulePackRolloutConfig({
      defaultMinSamples: 50,
      maxStages: undefined,
    });
    expect(config.defaultMinSamples).toBe(50);
    expect(config.maxStages).toBe(DEFAULT_RULE_PACK_ROLLOUT_CONFIG.maxStages);
  });

  it("accepts boundary values", () => {
    expect(() =>
      resolveRulePackRolloutConfig({
        defaultMaxFailureRatio: 0,
        maxConflictRetries: 0,
        maxListedTenants: 0,
        defaultMinSamples: 1,
      }),
    ).not.toThrow();
    expect(() =>
      resolveRulePackRolloutConfig({ defaultMaxFailureRatio: 1 }),
    ).not.toThrow();
  });

  it.each([
    [{ enabled: "yes" as unknown as boolean }, "enabled"],
    [{ defaultAutoRollback: 1 as unknown as boolean }, "defaultAutoRollback"],
    [{ defaultMinSamples: 0 }, "defaultMinSamples"],
    [{ defaultMinSamples: 1.5 }, "defaultMinSamples"],
    [{ defaultMaxFailureRatio: -0.1 }, "defaultMaxFailureRatio"],
    [{ defaultMaxFailureRatio: 1.01 }, "defaultMaxFailureRatio"],
    [{ defaultMaxFailureRatio: Number.NaN }, "defaultMaxFailureRatio"],
    [{ maxStages: 0 }, "maxStages"],
    [{ maxListedTenants: -1 }, "maxListedTenants"],
    [{ maxConflictRetries: -1 }, "maxConflictRetries"],
    [{ pinRetentionMs: 0 }, "pinRetentionMs"],
    [{ maxEventsPerRollout: 0 }, "maxEventsPerRollout"],
  ])("rejects %j naming %s", (overrides, field) => {
    expect(() => resolveRulePackRolloutConfig(overrides)).toThrow(
      new RegExp(`^${field} `),
    );
  });
});

describe("loadRulePackRolloutConfigFromEnv", () => {
  it("keeps defaults for unset and empty variables", () => {
    expect(
      loadRulePackRolloutConfigFromEnv({ RULE_PACK_ROLLOUT_MAX_STAGES: " " }),
    ).toEqual(DEFAULT_RULE_PACK_ROLLOUT_CONFIG);
  });

  it("parses booleans and numbers", () => {
    const config = loadRulePackRolloutConfigFromEnv({
      RULE_PACK_ROLLOUT_ENABLED: "off",
      RULE_PACK_ROLLOUT_AUTO_ROLLBACK: "FALSE",
      RULE_PACK_ROLLOUT_MIN_SAMPLES: "100",
      RULE_PACK_ROLLOUT_MAX_FAILURE_RATIO: "0.01",
    });
    expect(config.enabled).toBe(false);
    expect(config.defaultAutoRollback).toBe(false);
    expect(config.defaultMinSamples).toBe(100);
    expect(config.defaultMaxFailureRatio).toBe(0.01);
  });

  it("throws on unparseable values, naming the variable", () => {
    expect(() =>
      loadRulePackRolloutConfigFromEnv({ RULE_PACK_ROLLOUT_ENABLED: "maybe" }),
    ).toThrow("RULE_PACK_ROLLOUT_ENABLED must be a boolean");
    expect(() =>
      loadRulePackRolloutConfigFromEnv({ RULE_PACK_ROLLOUT_MAX_STAGES: "ten" }),
    ).toThrow("RULE_PACK_ROLLOUT_MAX_STAGES must be a number");
  });

  it("validates parsed values", () => {
    expect(() =>
      loadRulePackRolloutConfigFromEnv({ RULE_PACK_ROLLOUT_MIN_SAMPLES: "0" }),
    ).toThrow("defaultMinSamples must be a positive integer");
  });
});
