import { readFileSync } from "fs";
import * as path from "path";
import {
  DEFAULT_RULE_PACK_ROLLOUT_CONFIG,
  resolveRulePackRolloutConfig,
} from "./rule-pack-rollout-config";
import {
  BUCKET_COUNT,
  buildRollout,
  compareVersions,
  evaluateGate,
  percentToBasisPoints,
  requireIdentifier,
  requirePackId,
  requireVersion,
  rulePackFingerprint,
  sanitizeReason,
  selectForTenant,
  tenantBucket,
  transition,
} from "./rule-pack-rollout-planner";
import {
  RulePackChannel,
  RulePackRollout,
  RulePackRolloutError,
  RulePackRolloutPlan,
} from "./rule-pack-rollout-types";

const config = DEFAULT_RULE_PACK_ROLLOUT_CONFIG;

function channel(overrides: Partial<RulePackChannel> = {}): RulePackChannel {
  return {
    packId: "soroban-core",
    stableVersion: "1.4.2",
    revision: 1,
    rolloutSequence: 0,
    updatedAt: 0,
    ...overrides,
  };
}

function plan(
  overrides: Partial<RulePackRolloutPlan> = {},
): RulePackRolloutPlan {
  return {
    packId: "soroban-core",
    candidateVersion: "1.5.0",
    stages: [1, 10, 50, 100],
    ...overrides,
  };
}

function withRollout(rollout: RulePackRollout): RulePackChannel {
  return channel({ rolloutSequence: 1, rollout });
}

function expectCode(fn: () => unknown, code: string): void {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(RulePackRolloutError);
    expect((error as RulePackRolloutError).code).toBe(code);
    return;
  }
  throw new Error(`expected ${code}`);
}

describe("identifier and version validation", () => {
  it.each(["soroban-core", "evm.gas_v2", "a", "x".repeat(64)])(
    "accepts pack id %s",
    (id) => expect(requirePackId(id)).toBe(id),
  );

  it.each(["", "Soroban", "-lead", "has space", "../etc", "x".repeat(65), 7])(
    "rejects pack id %p",
    (id) => expectCode(() => requirePackId(id), "INVALID_INPUT"),
  );

  it.each(["tenant-1", "org:acme/project", "a@b.c", "x".repeat(256)])(
    "accepts identifier %s",
    (id) => expect(requireIdentifier(id, "tenantId")).toBe(id),
  );

  it.each(["", " lead", "line\nbreak", "x".repeat(257), null, {}])(
    "rejects identifier %p",
    (id) =>
      expectCode(() => requireIdentifier(id, "tenantId"), "INVALID_INPUT"),
  );

  it.each(["0.0.0", "1.5.0", "10.20.30", "1.0.0-rc.1", "1.0.0-alpha-beta"])(
    "accepts version %s",
    (version) => expect(requireVersion(version, "v")).toBe(version),
  );

  it.each(["1.5", "v1.5.0", "01.0.0", "1.0.0+build.1", "1.0.0-01", "", 150])(
    "rejects version %p",
    (version) =>
      expectCode(() => requireVersion(version, "v"), "INVALID_INPUT"),
  );

  it("orders versions by SemVer precedence", () => {
    const ordered = [
      "1.0.0-alpha",
      "1.0.0-alpha.1",
      "1.0.0-alpha.beta",
      "1.0.0-beta",
      "1.0.0-beta.2",
      "1.0.0-beta.11",
      "1.0.0-rc.1",
      "1.0.0",
      "1.0.1",
      "1.2.0",
      "1.10.0",
      "2.0.0",
    ];
    for (let i = 1; i < ordered.length; i++) {
      expect(compareVersions(ordered[i - 1], ordered[i])).toBeLessThan(0);
      expect(compareVersions(ordered[i], ordered[i - 1])).toBeGreaterThan(0);
    }
    expect(compareVersions("1.5.0", "1.5.0")).toBe(0);
  });
});

describe("tenantBucket", () => {
  it("is deterministic and within range", () => {
    const first = tenantBucket("soroban-core", "1.5.0", "acme-defi");
    expect(tenantBucket("soroban-core", "1.5.0", "acme-defi")).toBe(first);
    expect(first).toBeGreaterThanOrEqual(0);
    expect(first).toBeLessThan(BUCKET_COUNT);
  });

  it("differs between releases so cohorts rotate", () => {
    const tenants = Array.from({ length: 200 }, (_, i) => `tenant-${i}`);
    const same = tenants.filter(
      (t) =>
        tenantBucket("soroban-core", "1.5.0", t) ===
        tenantBucket("soroban-core", "1.6.0", t),
    );
    expect(same.length).toBeLessThan(5);
  });

  it("spreads tenants roughly uniformly", () => {
    const n = 20_000;
    let underTenPercent = 0;
    for (let i = 0; i < n; i++) {
      if (tenantBucket("soroban-core", "1.5.0", `tenant-${i}`) < 1_000) {
        underTenPercent++;
      }
    }
    // 10% +/- 1.5 percentage points.
    expect(underTenPercent / n).toBeGreaterThan(0.085);
    expect(underTenPercent / n).toBeLessThan(0.115);
  });

  it("matches the frozen cohort snapshot (regression)", () => {
    const fixture = JSON.parse(
      readFileSync(
        path.join(__dirname, "__fixtures__", "cohort-assignments.json"),
        "utf8",
      ),
    ) as {
      packId: string;
      candidateVersion: string;
      stagesBasisPoints: number[];
      assignments: {
        tenantId: string;
        bucket: number;
        candidateFromStage: number;
      }[];
    };
    const rollout = buildRollout(
      channel(),
      plan({ stages: fixture.stagesBasisPoints.map((bp) => bp / 100) }),
      config,
      0,
    );
    for (const assignment of fixture.assignments) {
      expect(
        tenantBucket(
          fixture.packId,
          fixture.candidateVersion,
          assignment.tenantId,
        ),
      ).toBe(assignment.bucket);
      for (let stage = 0; stage < fixture.stagesBasisPoints.length; stage++) {
        const selection = selectForTenant(
          withRollout({ ...rollout, stageIndex: stage }),
          assignment.tenantId,
          true,
        );
        expect(selection.channel).toBe(
          stage >= assignment.candidateFromStage ? "candidate" : "baseline",
        );
      }
    }
  });
});

describe("percentToBasisPoints", () => {
  it.each([
    [0.01, 1],
    [1, 100],
    [12.5, 1250],
    [33.33, 3333],
    [100, 10_000],
  ])("converts %p%% to %p basis points", (percent, bp) =>
    expect(percentToBasisPoints(percent)).toBe(bp),
  );

  it.each([0, -1, 100.01, 0.001, 33.333, Number.NaN, Infinity, "10"])(
    "rejects %p",
    (percent) =>
      expectCode(() => percentToBasisPoints(percent), "INVALID_PLAN"),
  );
});

describe("buildRollout", () => {
  it("builds an active rollout at stage 0 from a valid plan", () => {
    const rollout = buildRollout(
      channel(),
      plan({
        allowTenants: ["z-tenant", "a-tenant", "a-tenant"],
        denyTenants: ["blocked"],
        gate: { minSamples: 3 },
      }),
      config,
      1_000,
    );
    expect(rollout).toEqual({
      rolloutId: "soroban-core#1",
      baselineVersion: "1.4.2",
      candidateVersion: "1.5.0",
      stagesBasisPoints: [100, 1_000, 5_000, 10_000],
      stageIndex: 0,
      state: "active",
      allowTenants: ["a-tenant", "z-tenant"],
      denyTenants: ["blocked"],
      gate: {
        minSamples: 3,
        maxFailureRatio: config.defaultMaxFailureRatio,
        autoRollback: config.defaultAutoRollback,
      },
      stageStats: { succeeded: 0, failed: 0 },
      startedAt: 1_000,
      updatedAt: 1_000,
      events: [
        { at: 1_000, action: "started", stageIndex: 0, state: "active" },
      ],
    });
  });

  it("accepts a single 100% stage (direct cut-over with a gate)", () => {
    expect(
      buildRollout(channel(), plan({ stages: [100] }), config, 0)
        .stagesBasisPoints,
    ).toEqual([10_000]);
  });

  it("numbers rollout ids from the channel sequence", () => {
    expect(
      buildRollout(channel({ rolloutSequence: 4 }), plan(), config, 0)
        .rolloutId,
    ).toBe("soroban-core#5");
  });

  it.each<[string, Partial<RulePackRolloutPlan>]>([
    ["no stages", { stages: [] }],
    ["non-array stages", { stages: "1,100" as unknown as number[] }],
    ["decreasing stages", { stages: [10, 5, 100] }],
    ["repeated stages", { stages: [10, 10, 100] }],
    ["not ending at 100", { stages: [1, 50] }],
    ["too many stages", { stages: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 100] }],
    ["overlapping lists", { allowTenants: ["t1"], denyTenants: ["t1"] }],
    ["invalid tenant in list", { allowTenants: ["bad tenant"] }],
    ["non-array list", { denyTenants: "t1" as unknown as string[] }],
    ["zero min samples", { gate: { minSamples: 0 } }],
    ["ratio over 1", { gate: { maxFailureRatio: 2 } }],
    [
      "non-boolean autoRollback",
      { gate: { autoRollback: "no" as unknown as boolean } },
    ],
    ["candidate equal to stable", { candidateVersion: "1.4.2" }],
    ["candidate older than stable", { candidateVersion: "1.4.1" }],
    ["prerelease of stable", { candidateVersion: "1.4.2-rc.1" }],
  ])("rejects %s with INVALID_PLAN", (_label, overrides) => {
    expectCode(
      () => buildRollout(channel(), plan(overrides), config, 0),
      "INVALID_PLAN",
    );
  });

  it("rejects a malformed candidate version with INVALID_INPUT", () => {
    expectCode(
      () =>
        buildRollout(
          channel(),
          plan({ candidateVersion: "latest" }),
          config,
          0,
        ),
      "INVALID_INPUT",
    );
  });

  it("enforces maxListedTenants across both lists", () => {
    const small = resolveRulePackRolloutConfig({ maxListedTenants: 2 });
    expect(() =>
      buildRollout(
        channel(),
        plan({ allowTenants: ["a"], denyTenants: ["b"] }),
        small,
        0,
      ),
    ).not.toThrow();
    expectCode(
      () =>
        buildRollout(
          channel(),
          plan({ allowTenants: ["a", "c"], denyTenants: ["b"] }),
          small,
          0,
        ),
      "INVALID_PLAN",
    );
  });

  it("refuses a second live rollout", () => {
    const live = buildRollout(channel(), plan(), config, 0);
    expectCode(
      () =>
        buildRollout(
          withRollout(live),
          plan({ candidateVersion: "1.6.0" }),
          config,
          0,
        ),
      "ROLLOUT_IN_PROGRESS",
    );
    const ended = transition(live, "rollback", 1, 100);
    expect(() =>
      buildRollout(
        withRollout(ended),
        plan({ candidateVersion: "1.6.0" }),
        config,
        2,
      ),
    ).not.toThrow();
  });
});

describe("selectForTenant", () => {
  const rollout = buildRollout(
    channel(),
    plan({ allowTenants: ["early"], denyTenants: ["opted-out"] }),
    config,
    0,
  );

  it("returns stable when there is no rollout", () => {
    expect(selectForTenant(channel(), "t1", true)).toEqual({
      packId: "soroban-core",
      version: "1.4.2",
      channel: "stable",
      reason: "no_active_rollout",
    });
  });

  it("returns stable for every tenant when disabled (kill switch)", () => {
    const c = withRollout({ ...rollout, stageIndex: 3 });
    for (const tenant of ["early", "t1", "t2"]) {
      expect(selectForTenant(c, tenant, false).channel).toBe("stable");
    }
  });

  it("applies the deny list before the allow list and cohort", () => {
    const c = withRollout({ ...rollout, stageIndex: 3 });
    expect(selectForTenant(c, "opted-out", true)).toMatchObject({
      version: "1.4.2",
      channel: "baseline",
      reason: "deny_list",
    });
    expect(selectForTenant(c, "early", true)).toMatchObject({
      version: "1.5.0",
      channel: "candidate",
      reason: "allow_list",
      rolloutId: "soroban-core#1",
      stageIndex: 3,
    });
  });

  it("puts everyone not denied on the candidate at 100%", () => {
    const c = withRollout({ ...rollout, stageIndex: 3 });
    for (let i = 0; i < 100; i++) {
      expect(selectForTenant(c, `tenant-${i}`, true).version).toBe("1.5.0");
    }
  });

  it("only ever grows the cohort as stages advance", () => {
    const tenants = Array.from({ length: 500 }, (_, i) => `tenant-${i}`);
    let previous = new Set<string>();
    for (let stage = 0; stage < rollout.stagesBasisPoints.length; stage++) {
      const c = withRollout({ ...rollout, stageIndex: stage });
      const cohort = new Set(
        tenants.filter(
          (t) => selectForTenant(c, t, true).channel === "candidate",
        ),
      );
      for (const tenant of previous) {
        expect(cohort.has(tenant)).toBe(true);
      }
      previous = cohort;
    }
  });

  it("keeps serving the current stage while paused", () => {
    const paused = transition(rollout, "pause", 1, 100);
    expect(selectForTenant(withRollout(paused), "early", true).channel).toBe(
      "candidate",
    );
  });

  it("returns the new stable after completion and the baseline after rollback", () => {
    const completed = channel({
      stableVersion: "1.5.0",
      rollout: { ...rollout, state: "completed" },
    });
    expect(selectForTenant(completed, "opted-out", true)).toMatchObject({
      version: "1.5.0",
      channel: "stable",
    });
    const rolledBack = withRollout(transition(rollout, "rollback", 1, 100));
    expect(selectForTenant(rolledBack, "early", true)).toMatchObject({
      version: "1.4.2",
      channel: "stable",
    });
  });
});

describe("evaluateGate", () => {
  const base = buildRollout(
    channel(),
    plan({ gate: { minSamples: 10, maxFailureRatio: 0.1 } }),
    config,
    0,
  );
  const withStats = (succeeded: number, failed: number) =>
    evaluateGate({ ...base, stageStats: { succeeded, failed } });

  it("neither passes nor breaches below minSamples", () => {
    expect(withStats(0, 0)).toEqual({
      samples: 0,
      failureRatio: 0,
      passed: false,
      breached: false,
    });
    expect(withStats(0, 9)).toMatchObject({ passed: false, breached: false });
  });

  it("passes at exactly the limit and breaches just above it", () => {
    expect(withStats(9, 1)).toMatchObject({ passed: true, breached: false });
    expect(withStats(8, 2)).toMatchObject({ passed: false, breached: true });
  });
});

describe("transition", () => {
  const rollout = buildRollout(
    channel(),
    plan({ stages: [50, 100] }),
    config,
    0,
  );

  it("advances, resets stage stats, then completes", () => {
    const counted = { ...rollout, stageStats: { succeeded: 5, failed: 1 } };
    const second = transition(counted, "advance", 10, 100);
    expect(second).toMatchObject({
      stageIndex: 1,
      state: "active",
      stageStats: { succeeded: 0, failed: 0 },
      updatedAt: 10,
    });
    expect(second.endedAt).toBeUndefined();
    const done = transition(second, "advance", 20, 100);
    expect(done).toMatchObject({
      stageIndex: 1,
      state: "completed",
      endedAt: 20,
    });
    expect(done.events.map((e) => e.action)).toEqual([
      "started",
      "advanced",
      "completed",
    ]);
  });

  it("pauses, resumes and rolls back with a sanitized reason", () => {
    const paused = transition(rollout, "pause", 1, 100, {
      reason: "  investigate\n\tspike ",
    });
    expect(paused.state).toBe("paused");
    expect(paused.events[1].reason).toBe("investigate spike");
    const resumed = transition(paused, "resume", 2, 100);
    expect(resumed.state).toBe("active");
    const back = transition(resumed, "rollback", 3, 100, { auto: true });
    expect(back).toMatchObject({ state: "rolled_back", endedAt: 3 });
    expect(back.events[3].action).toBe("auto_rolled_back");
  });

  it("does not mutate its input", () => {
    const snapshot = JSON.stringify(rollout);
    transition(rollout, "advance", 1, 100);
    expect(JSON.stringify(rollout)).toBe(snapshot);
  });

  it.each<[string, "advance" | "pause" | "resume" | "rollback"]>([
    ["active", "resume"],
    ["paused", "advance"],
    ["paused", "pause"],
    ["completed", "rollback"],
    ["rolled_back", "advance"],
    ["rolled_back", "resume"],
  ])("rejects %s -> %s", (state, action) => {
    expectCode(
      () =>
        transition(
          { ...rollout, state: state as RulePackRollout["state"] },
          action,
          1,
          100,
        ),
      "INVALID_TRANSITION",
    );
  });

  it("caps the event history", () => {
    let current = rollout;
    for (let i = 0; i < 10; i++) {
      current = transition(current, i % 2 === 0 ? "pause" : "resume", i, 3);
    }
    expect(current.events).toHaveLength(3);
    expect(current.events[2].at).toBe(9);
  });
});

describe("helpers", () => {
  it("fingerprints selections in pack-id order", () => {
    expect(
      rulePackFingerprint([
        {
          packId: "soroban-security",
          version: "2.0.1",
          channel: "stable",
          reason: "no_active_rollout",
        },
        {
          packId: "soroban-core",
          version: "1.5.0",
          channel: "candidate",
          reason: "cohort",
        },
      ]),
    ).toBe("soroban-core@1.5.0,soroban-security@2.0.1");
    expect(rulePackFingerprint([])).toBe("");
  });

  it("sanitizes reasons", () => {
    expect(sanitizeReason(undefined)).toBeUndefined();
    expect(sanitizeReason("   ")).toBeUndefined();
    expect(sanitizeReason(42)).toBeUndefined();
    expect(sanitizeReason("x".repeat(500))).toHaveLength(200);
    expect(sanitizeReason("a\u0000b")).toBe("a b");
  });
});
