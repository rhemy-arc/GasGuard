import {
  RulePackRolloutMetrics,
  consoleRulePackRolloutLogger,
  sanitizeLogFields,
} from "./rule-pack-rollout-metrics";
import { RulePackChannel } from "./rule-pack-rollout-types";

describe("RulePackRolloutMetrics", () => {
  it("counts by closed label sets", () => {
    const metrics = new RulePackRolloutMetrics();
    metrics.recordResolution("candidate", "cohort");
    metrics.recordResolution("candidate", "cohort");
    metrics.recordResolution("baseline", "deny_list");
    metrics.recordPinReused();
    metrics.recordTransition("started");
    metrics.recordCandidateOutcome("failed");
    metrics.recordOutcomeIgnored("duplicate");
    metrics.recordConflict();
    metrics.recordError("GATE_NOT_MET");

    expect(metrics.snapshot()).toEqual({
      resolutions: { "candidate:cohort": 2, "baseline:deny_list": 1 },
      pinsReused: 1,
      transitions: { started: 1 },
      candidateOutcomes: { failed: 1 },
      outcomesIgnored: { duplicate: 1 },
      conflicts: 1,
      errors: { GATE_NOT_MET: 1 },
    });
  });

  it("renders Prometheus text with stage gauges", () => {
    const metrics = new RulePackRolloutMetrics();
    metrics.recordResolution("candidate", "cohort");
    const live: RulePackChannel = {
      packId: "soroban-core",
      stableVersion: "1.4.2",
      revision: 3,
      rolloutSequence: 1,
      updatedAt: 0,
      rollout: {
        rolloutId: "soroban-core#1",
        baselineVersion: "1.4.2",
        candidateVersion: "1.5.0",
        stagesBasisPoints: [100, 1_250, 10_000],
        stageIndex: 1,
        state: "paused",
        allowTenants: ["secret-customer"],
        denyTenants: [],
        gate: { minSamples: 1, maxFailureRatio: 0, autoRollback: true },
        stageStats: { succeeded: 0, failed: 0 },
        startedAt: 0,
        updatedAt: 0,
        events: [],
      },
    };
    const idle: RulePackChannel = {
      ...live,
      packId: "evm-gas",
      rollout: undefined,
    };
    const text = metrics.toPrometheus([live, idle]);

    expect(text).toContain(
      'gasguard_rule_pack_resolutions_total{channel="candidate",reason="cohort"} 1',
    );
    expect(text).toContain(
      'gasguard_rule_pack_rollout_stage_percent{pack="soroban-core"} 12.5',
    );
    expect(text).toContain(
      'gasguard_rule_pack_rollout_stage_percent{pack="evm-gas"} 0',
    );
    expect(text).toContain(
      'gasguard_rule_pack_rollout_state{pack="soroban-core",state="paused"} 1',
    );
    expect(text).toContain(
      'gasguard_rule_pack_rollout_state{pack="evm-gas",state="none"} 1',
    );
    // Tenant identifiers from allow lists never become labels.
    expect(text).not.toContain("secret-customer");
    expect(text.endsWith("\n")).toBe(true);
  });

  it("omits gauges when no channels are passed", () => {
    expect(new RulePackRolloutMetrics().toPrometheus()).not.toContain(
      "stage_percent",
    );
  });
});

describe("sanitizeLogFields", () => {
  it("drops sensitive keys and non-primitive values, truncating long strings", () => {
    const safe = sanitizeLogFields({
      packId: "soroban-core",
      samples: 3,
      forced: true,
      apiToken: "ghp_abc",
      privateKey: "0xdead",
      sourceCode: "contract Foo {}",
      payload: "{...}",
      authorization: "Bearer x",
      nested: { a: 1 },
      reason: "r".repeat(300),
    });
    expect(Object.keys(safe).sort()).toEqual([
      "forced",
      "packId",
      "reason",
      "samples",
    ]);
    expect((safe.reason as string).length).toBe(201);
  });
});

describe("consoleRulePackRolloutLogger", () => {
  it("writes one sanitized JSON line, info to stdout and others to stderr", () => {
    const out = jest.spyOn(console, "log").mockImplementation(() => undefined);
    const err = jest
      .spyOn(console, "error")
      .mockImplementation(() => undefined);
    try {
      consoleRulePackRolloutLogger.log("info", "scan_pinned", {
        tenantId: "t1",
        secret: "x",
      });
      consoleRulePackRolloutLogger.log("warn", "rollout_rolled_back", {});
      expect(JSON.parse(out.mock.calls[0][0] as string)).toEqual({
        level: "info",
        component: "rule-pack-rollout",
        event: "scan_pinned",
        tenantId: "t1",
      });
      expect(err).toHaveBeenCalledTimes(1);
    } finally {
      out.mockRestore();
      err.mockRestore();
    }
  });
});
