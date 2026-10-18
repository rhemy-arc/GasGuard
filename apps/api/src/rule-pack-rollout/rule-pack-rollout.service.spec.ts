import {
  RulePackRolloutLogFields,
  RulePackRolloutLogLevel,
  RulePackRolloutLogger,
} from "./rule-pack-rollout-metrics";
import { selectForTenant, tenantBucket } from "./rule-pack-rollout-planner";
import {
  ChannelWriteResult,
  InMemoryRulePackRolloutStore,
  RulePackRolloutStore,
} from "./rule-pack-rollout-store";
import {
  RulePackRolloutService,
  RulePackRolloutServiceOptions,
} from "./rule-pack-rollout.service";
import {
  RulePackChannel,
  RulePackRolloutError,
  RulePackRolloutPlan,
} from "./rule-pack-rollout-types";

class CapturingLogger implements RulePackRolloutLogger {
  readonly entries: {
    level: RulePackRolloutLogLevel;
    event: string;
    fields: RulePackRolloutLogFields;
  }[] = [];
  log(
    level: RulePackRolloutLogLevel,
    event: string,
    fields: RulePackRolloutLogFields,
  ): void {
    this.entries.push({ level, event, fields });
  }
  events(): string[] {
    return this.entries.map((e) => e.event);
  }
}

/** Store whose methods can be made to throw or to report conflicts. */
class FaultyStore extends InMemoryRulePackRolloutStore {
  failAll = false;
  conflictsRemaining = 0;

  async getChannel(packId: string) {
    this.maybeFail();
    return super.getChannel(packId);
  }
  async putChannel(
    channel: RulePackChannel,
    expectedRevision: number,
  ): Promise<ChannelWriteResult> {
    this.maybeFail();
    if (this.conflictsRemaining > 0) {
      this.conflictsRemaining--;
      return "conflict";
    }
    return super.putChannel(channel, expectedRevision);
  }
  async getPin(tenantId: string, scanId: string) {
    this.maybeFail();
    return super.getPin(tenantId, scanId);
  }
  private maybeFail(): void {
    if (this.failAll) {
      throw new Error("connect ECONNREFUSED postgres://admin:hunter2@db:5432");
    }
  }
}

const PLAN: RulePackRolloutPlan = {
  packId: "soroban-core",
  candidateVersion: "1.5.0",
  stages: [10, 50, 100],
  gate: { minSamples: 3, maxFailureRatio: 0.34, autoRollback: true },
};

/** First tenant (in index order) whose bucket satisfies `predicate`. */
function tenantWhere(
  predicate: (bucket: number) => boolean,
  version = "1.5.0",
): string {
  for (let i = 0; ; i++) {
    const id = `tenant-${i}`;
    if (predicate(tenantBucket("soroban-core", version, id))) {
      return id;
    }
  }
}

const IN_FIRST_STAGE = tenantWhere((b) => b < 1_000);
const IN_SECOND_STAGE_ONLY = tenantWhere((b) => b >= 1_000 && b < 5_000);

function setup(overrides: Partial<RulePackRolloutServiceOptions> = {}) {
  let now = 1_000;
  const store = new FaultyStore();
  const logger = new CapturingLogger();
  const service = new RulePackRolloutService({
    store,
    logger,
    clock: () => now,
    ...overrides,
  });
  return {
    store,
    logger,
    service,
    tick: (ms = 1) => (now += ms),
  };
}

async function expectCode(promise: Promise<unknown>, code: string) {
  await expect(promise).rejects.toMatchObject({
    name: "RulePackRolloutError",
    code,
  });
}

/** Record `n` candidate outcomes for fresh scans of first-stage tenants. */
async function feed(
  service: RulePackRolloutService,
  outcomes: ("succeeded" | "failed")[],
  tenant = IN_FIRST_STAGE,
) {
  const results = [];
  for (const outcome of outcomes) {
    const scanId = `scan-${Math.random().toString(36).slice(2)}`;
    await service.resolveForScan({
      tenantId: tenant,
      scanId,
      packIds: ["soroban-core"],
    });
    results.push(
      await service.recordScanOutcome({ tenantId: tenant, scanId, outcome }),
    );
  }
  return results;
}

describe("registerPack", () => {
  it("registers a pack and is idempotent for the same version", async () => {
    const { service } = setup();
    const first = await service.registerPack("soroban-core", "1.4.2");
    expect(first).toMatchObject({
      stableVersion: "1.4.2",
      revision: 1,
      rolloutSequence: 0,
    });
    expect(await service.registerPack("soroban-core", "1.4.2")).toEqual(first);
  });

  it("refuses to change the stable version outside a rollout", async () => {
    const { service } = setup();
    await service.registerPack("soroban-core", "1.4.2");
    await expectCode(
      service.registerPack("soroban-core", "2.0.0"),
      "PACK_ALREADY_REGISTERED",
    );
  });

  it.each([
    ["Bad Pack", "1.0.0"],
    ["soroban-core", "1.0"],
    ["soroban-core", ""],
  ])("rejects invalid input (%p, %p)", async (packId, version) => {
    const { service } = setup();
    await expectCode(service.registerPack(packId, version), "INVALID_INPUT");
  });

  it("settles on the winner when two registrations race", async () => {
    // A competing process registers between our read and our write.
    class RacingStore extends InMemoryRulePackRolloutStore {
      competitorVersion = "1.4.2";
      async putChannel(channel: RulePackChannel, expected: number) {
        if (expected === 0 && !(await this.getChannel(channel.packId))) {
          await super.putChannel(
            {
              ...channel,
              stableVersion: this.competitorVersion,
              updatedAt: -1,
            },
            0,
          );
        }
        return super.putChannel(channel, expected);
      }
    }
    const same = new RacingStore();
    const service = new RulePackRolloutService({
      store: same,
      logger: new CapturingLogger(),
    });
    await expect(
      service.registerPack("soroban-core", "1.4.2"),
    ).resolves.toMatchObject({
      stableVersion: "1.4.2",
      updatedAt: -1,
    });

    const different = new RacingStore();
    different.competitorVersion = "1.4.3";
    const loser = new RulePackRolloutService({
      store: different,
      logger: new CapturingLogger(),
    });
    await expectCode(
      loser.registerPack("soroban-core", "1.4.2"),
      "PACK_ALREADY_REGISTERED",
    );
  });
});

describe("rollout lifecycle", () => {
  it("starts, advances through gated stages and completes", async () => {
    const { service, logger } = setup();
    await service.registerPack("soroban-core", "1.4.2");
    const started = await service.startRollout(PLAN, "storage-rent rules");
    expect(started.rollout).toMatchObject({
      rolloutId: "soroban-core#1",
      state: "active",
      stageIndex: 0,
    });
    expect(started.rollout!.events[0].reason).toBe("storage-rent rules");

    await expectCode(service.advance("soroban-core"), "GATE_NOT_MET");
    await feed(service, ["succeeded", "succeeded", "succeeded"]);
    expect((await service.advance("soroban-core")).rollout!.stageIndex).toBe(1);

    await feed(
      service,
      ["succeeded", "succeeded", "succeeded"],
      IN_SECOND_STAGE_ONLY,
    );
    await service.advance("soroban-core");
    await feed(service, ["succeeded", "succeeded", "failed"]);
    const done = await service.advance("soroban-core");
    expect(done).toMatchObject({
      stableVersion: "1.5.0",
      rollout: { state: "completed" },
    });
    expect(await service.resolve("anyone", "soroban-core")).toMatchObject({
      version: "1.5.0",
      channel: "stable",
    });
    expect(logger.events()).toEqual(
      expect.arrayContaining([
        "rollout_started",
        "rollout_advanced",
        "rollout_completed",
      ]),
    );
    expect(service.metrics.snapshot().transitions).toEqual({
      started: 1,
      advanced: 2,
      completed: 1,
    });
  });

  it("allows a new rollout once the previous one has ended", async () => {
    const { service } = setup();
    await service.registerPack("soroban-core", "1.4.2");
    await service.startRollout(PLAN);
    await expectCode(
      service.startRollout({ ...PLAN, candidateVersion: "1.6.0" }),
      "ROLLOUT_IN_PROGRESS",
    );
    await service.rollback("soroban-core", "bad findings");
    const next = await service.startRollout({
      ...PLAN,
      candidateVersion: "1.5.1",
    });
    expect(next.rollout).toMatchObject({
      rolloutId: "soroban-core#2",
      baselineVersion: "1.4.2",
    });
  });

  it("forces an advance past the gate only with a reason, logging a warning", async () => {
    const { service, logger } = setup();
    await service.registerPack("soroban-core", "1.4.2");
    await service.startRollout(PLAN);
    await expectCode(
      service.advance("soroban-core", { force: true }),
      "INVALID_INPUT",
    );
    await expectCode(
      service.advance("soroban-core", { force: true, reason: "  " }),
      "INVALID_INPUT",
    );
    const forced = await service.advance("soroban-core", {
      force: true,
      reason: "hotfix SEC-12",
    });
    expect(forced.rollout!.stageIndex).toBe(1);
    expect(logger.entries.at(-1)).toMatchObject({
      level: "warn",
      event: "rollout_advanced",
      fields: { forced: true, reason: "hotfix SEC-12" },
    });
  });

  it("pauses and resumes, refusing advance while paused", async () => {
    const { service } = setup();
    await service.registerPack("soroban-core", "1.4.2");
    await service.startRollout(PLAN);
    await service.pause("soroban-core");
    await expectCode(
      service.advance("soroban-core", { force: true, reason: "x" }),
      "INVALID_TRANSITION",
    );
    await expectCode(service.pause("soroban-core"), "INVALID_TRANSITION");
    expect((await service.resume("soroban-core")).rollout!.state).toBe(
      "active",
    );
  });

  it("rolls back to the baseline for every tenant", async () => {
    const { service } = setup();
    await service.registerPack("soroban-core", "1.4.2");
    await service.startRollout({ ...PLAN, allowTenants: ["early"] });
    expect((await service.resolve("early", "soroban-core"))!.channel).toBe(
      "candidate",
    );
    await service.rollback("soroban-core");
    expect(await service.resolve("early", "soroban-core")).toMatchObject({
      version: "1.4.2",
      channel: "stable",
    });
    await expectCode(service.rollback("soroban-core"), "INVALID_TRANSITION");
  });

  it("reports PACK_NOT_FOUND and INVALID_TRANSITION for missing packs and rollouts", async () => {
    const { service } = setup();
    await expectCode(service.startRollout(PLAN), "PACK_NOT_FOUND");
    await expectCode(service.advance("soroban-core"), "PACK_NOT_FOUND");
    await service.registerPack("soroban-core", "1.4.2");
    await expectCode(service.pause("soroban-core"), "INVALID_TRANSITION");
  });

  it.each([null, "plan", { ...PLAN, packId: "BAD" }])(
    "rejects malformed plan %p",
    async (plan) => {
      const { service } = setup();
      await expect(
        service.startRollout(plan as unknown as RulePackRolloutPlan),
      ).rejects.toBeInstanceOf(RulePackRolloutError);
    },
  );
});

describe("resolveForScan", () => {
  it("pins versions so retries are unaffected by later stage changes", async () => {
    const { service } = setup();
    await service.registerPack("soroban-core", "1.4.2");
    await service.startRollout(PLAN);
    const request = {
      tenantId: IN_SECOND_STAGE_ONLY,
      scanId: "scan-1",
      packIds: ["soroban-core"],
    };
    const first = await service.resolveForScan(request);
    expect(first).toMatchObject({
      pin: "created",
      fingerprint: "soroban-core@1.4.2",
    });

    await service.advance("soroban-core", { force: true, reason: "test" });
    expect(
      (await service.resolve(IN_SECOND_STAGE_ONLY, "soroban-core"))!.version,
    ).toBe("1.5.0");
    const retry = await service.resolveForScan(request);
    expect(retry).toEqual({ ...first, pin: "reused" });
    expect(service.metrics.snapshot().pinsReused).toBe(1);
  });

  it("normalizes pack order and lists unmanaged packs for backward compatibility", async () => {
    const { service } = setup();
    await service.registerPack("soroban-core", "1.4.2");
    await service.registerPack("soroban-security", "2.0.1");
    const result = await service.resolveForScan({
      tenantId: "t1",
      scanId: "s1",
      packIds: ["soroban-security", "evm-gas", "soroban-core", "soroban-core"],
    });
    expect(result.selections.map((s) => s.packId)).toEqual([
      "soroban-core",
      "soroban-security",
    ]);
    expect(result.unmanagedPackIds).toEqual(["evm-gas"]);
    expect(result.fingerprint).toBe(
      "soroban-core@1.4.2,soroban-security@2.0.1",
    );
    // Same set in a different order is the same pin.
    await expect(
      service.resolveForScan({
        tenantId: "t1",
        scanId: "s1",
        packIds: ["evm-gas", "soroban-core", "soroban-security"],
      }),
    ).resolves.toMatchObject({ pin: "reused" });
  });

  it("treats every pack as unmanaged when none are registered", async () => {
    const { service } = setup();
    expect(await service.resolve("t1", "soroban-core")).toBeUndefined();
    expect(
      await service.resolveForScan({
        tenantId: "t1",
        scanId: "s1",
        packIds: ["soroban-core"],
      }),
    ).toEqual({
      selections: [],
      unmanagedPackIds: ["soroban-core"],
      fingerprint: "",
      pin: "created",
    });
  });

  it("refuses to re-pin a scan with a different pack set", async () => {
    const { service } = setup();
    await service.resolveForScan({
      tenantId: "t1",
      scanId: "s1",
      packIds: ["soroban-core"],
    });
    await expectCode(
      service.resolveForScan({
        tenantId: "t1",
        scanId: "s1",
        packIds: ["soroban-core", "evm-gas"],
      }),
      "PIN_MISMATCH",
    );
  });

  it("keeps pins tenant-scoped when scan ids collide", async () => {
    const { service } = setup();
    await service.registerPack("soroban-core", "1.4.2");
    await service.startRollout({
      ...PLAN,
      allowTenants: ["tenant-a"],
      denyTenants: ["tenant-b"],
    });
    const a = await service.resolveForScan({
      tenantId: "tenant-a",
      scanId: "shared",
      packIds: ["soroban-core"],
    });
    const b = await service.resolveForScan({
      tenantId: "tenant-b",
      scanId: "shared",
      packIds: ["soroban-core"],
    });
    expect(a.selections[0].version).toBe("1.5.0");
    expect(b).toMatchObject({
      pin: "created",
      selections: [{ version: "1.4.2", reason: "deny_list" }],
    });
  });

  it.each([
    [{ tenantId: "", scanId: "s", packIds: ["p"] }],
    [{ tenantId: "t", scanId: "has space", packIds: ["p"] }],
    [{ tenantId: "t", scanId: "s", packIds: [] }],
    [{ tenantId: "t", scanId: "s", packIds: "p" }],
    [{ tenantId: "t", scanId: "s", packIds: ["Upper"] }],
    [
      {
        tenantId: "t",
        scanId: "s",
        packIds: Array.from({ length: 65 }, (_, i) => `p${i}`),
      },
    ],
    [undefined],
  ])("rejects invalid request %#", async (request) => {
    const { service } = setup();
    await expectCode(service.resolveForScan(request as never), "INVALID_INPUT");
  });
});

describe("recordScanOutcome", () => {
  async function started(gate = PLAN.gate) {
    const ctx = setup();
    await ctx.service.registerPack("soroban-core", "1.4.2");
    await ctx.service.startRollout({ ...PLAN, gate });
    return ctx;
  }

  it("counts candidate outcomes once per scan", async () => {
    const { service } = await started();
    await service.resolveForScan({
      tenantId: IN_FIRST_STAGE,
      scanId: "s1",
      packIds: ["soroban-core"],
    });
    expect(
      await service.recordScanOutcome({
        tenantId: IN_FIRST_STAGE,
        scanId: "s1",
        outcome: "succeeded",
      }),
    ).toEqual({
      status: "recorded",
      countedPackIds: ["soroban-core"],
      autoRolledBackPackIds: [],
    });
    expect(
      await service.recordScanOutcome({
        tenantId: IN_FIRST_STAGE,
        scanId: "s1",
        outcome: "failed",
      }),
    ).toEqual({ status: "duplicate" });
    const channel = await service.getChannel("soroban-core");
    expect(channel!.rollout!.stageStats).toEqual({ succeeded: 1, failed: 0 });
  });

  it("ignores unpinned scans, baseline scans and other tenants' scans", async () => {
    const { service } = await started();
    expect(
      await service.recordScanOutcome({
        tenantId: "t1",
        scanId: "never",
        outcome: "failed",
      }),
    ).toEqual({ status: "not_pinned" });
    await service.resolveForScan({
      tenantId: IN_SECOND_STAGE_ONLY,
      scanId: "s1",
      packIds: ["soroban-core"],
    });
    expect(
      await service.recordScanOutcome({
        tenantId: IN_SECOND_STAGE_ONLY,
        scanId: "s1",
        outcome: "failed",
      }),
    ).toEqual({
      status: "recorded",
      countedPackIds: [],
      autoRolledBackPackIds: [],
    });
    expect(
      await service.recordScanOutcome({
        tenantId: "intruder",
        scanId: "s1",
        outcome: "failed",
      }),
    ).toEqual({ status: "not_pinned" });
    expect(service.metrics.snapshot().outcomesIgnored).toEqual({
      not_pinned: 2,
      not_candidate: 1,
    });
  });

  it("ignores outcomes from scans pinned in an earlier stage", async () => {
    const { service } = await started();
    await service.resolveForScan({
      tenantId: IN_FIRST_STAGE,
      scanId: "old",
      packIds: ["soroban-core"],
    });
    await service.advance("soroban-core", { force: true, reason: "test" });
    expect(
      await service.recordScanOutcome({
        tenantId: IN_FIRST_STAGE,
        scanId: "old",
        outcome: "failed",
      }),
    ).toMatchObject({ countedPackIds: [] });
    expect(service.metrics.snapshot().outcomesIgnored).toEqual({
      stale_stage: 1,
    });
  });

  it("rolls back automatically when the gate is breached", async () => {
    const { service, logger } = await started();
    const results = await feed(service, ["succeeded", "failed", "failed"]);
    expect(results[2]).toEqual({
      status: "recorded",
      countedPackIds: ["soroban-core"],
      autoRolledBackPackIds: ["soroban-core"],
    });
    const channel = await service.getChannel("soroban-core");
    expect(channel).toMatchObject({
      stableVersion: "1.4.2",
      rollout: { state: "rolled_back" },
    });
    expect(channel!.rollout!.events.at(-1)).toMatchObject({
      action: "auto_rolled_back",
    });
    expect(
      logger.entries.find((e) => e.event === "rollout_auto_rolled_back"),
    ).toMatchObject({
      level: "warn",
      fields: { packId: "soroban-core", samples: 3 },
    });
    expect(
      (await service.resolve(IN_FIRST_STAGE, "soroban-core"))!.version,
    ).toBe("1.4.2");
  });

  it("holds the stage instead of rolling back when autoRollback is off", async () => {
    const { service } = await started({
      minSamples: 2,
      maxFailureRatio: 0,
      autoRollback: false,
    });
    await feed(service, ["failed", "failed"]);
    const channel = await service.getChannel("soroban-core");
    expect(channel!.rollout!.state).toBe("active");
    await expectCode(service.advance("soroban-core"), "GATE_NOT_MET");
  });

  it("rejects an invalid outcome", async () => {
    const { service } = await started();
    await expectCode(
      service.recordScanOutcome({
        tenantId: "t",
        scanId: "s",
        outcome: "maybe" as never,
      }),
      "INVALID_INPUT",
    );
  });
});

describe("kill switch", () => {
  it("serves stable to everyone, refuses mutations, and still honours pins", async () => {
    const store = new InMemoryRulePackRolloutStore();
    const live = new RulePackRolloutService({
      store,
      logger: new CapturingLogger(),
    });
    await live.registerPack("soroban-core", "1.4.2");
    await live.startRollout({ ...PLAN, allowTenants: ["early"] });
    const pinned = await live.resolveForScan({
      tenantId: "early",
      scanId: "s1",
      packIds: ["soroban-core"],
    });
    expect(pinned.selections[0].version).toBe("1.5.0");

    const disabled = new RulePackRolloutService({
      store,
      logger: new CapturingLogger(),
      config: { enabled: false },
    });
    expect(await disabled.resolve("early", "soroban-core")).toMatchObject({
      version: "1.4.2",
      channel: "stable",
    });
    expect(
      (
        await disabled.resolveForScan({
          tenantId: "early",
          scanId: "s2",
          packIds: ["soroban-core"],
        })
      ).selections[0].version,
    ).toBe("1.4.2");
    expect(
      await disabled.resolveForScan({
        tenantId: "early",
        scanId: "s1",
        packIds: ["soroban-core"],
      }),
    ).toEqual({ ...pinned, pin: "reused" });
    await expectCode(disabled.advance("soroban-core"), "ROLLOUT_DISABLED");
    await expectCode(disabled.rollback("soroban-core"), "ROLLOUT_DISABLED");
    await expectCode(
      disabled.registerPack("other", "1.0.0"),
      "ROLLOUT_DISABLED",
    );
  });
});

describe("failure handling", () => {
  it("maps store errors to retryable STORE_UNAVAILABLE without logging their message", async () => {
    const { service, store, logger } = setup();
    await service.registerPack("soroban-core", "1.4.2");
    store.failAll = true;
    const error = await service
      .resolveForScan({
        tenantId: "t1",
        scanId: "s1",
        packIds: ["soroban-core"],
      })
      .catch((e) => e);
    expect(error).toMatchObject({ code: "STORE_UNAVAILABLE", retryable: true });
    expect(error.message).not.toContain("hunter2");
    expect(JSON.stringify(logger.entries)).not.toMatch(
      /hunter2|postgres|ECONNREFUSED/,
    );
    expect(logger.entries.at(-1)).toMatchObject({
      level: "error",
      event: "operation_failed",
      fields: {
        operation: "resolve_for_scan",
        code: "STORE_UNAVAILABLE",
        retryable: true,
      },
    });
    expect(service.metrics.snapshot().errors).toEqual({ STORE_UNAVAILABLE: 1 });

    store.failAll = false;
    await expect(
      service.resolveForScan({
        tenantId: "t1",
        scanId: "s1",
        packIds: ["soroban-core"],
      }),
    ).resolves.toMatchObject({ pin: "created" });
  });

  it("retries channel writes on conflict and gives up with CONFLICT", async () => {
    const { service, store } = setup({ config: { maxConflictRetries: 2 } });
    await service.registerPack("soroban-core", "1.4.2");
    store.conflictsRemaining = 2;
    await expect(service.startRollout(PLAN)).resolves.toBeDefined();
    expect(service.metrics.snapshot().conflicts).toBe(2);

    store.conflictsRemaining = 3;
    const error = await service.pause("soroban-core").catch((e) => e);
    expect(error).toMatchObject({ code: "CONFLICT", retryable: true });
    expect((await service.getChannel("soroban-core"))!.rollout!.state).toBe(
      "active",
    );
  });

  it("does not leak another tenant's identity through selections", async () => {
    const { service } = setup();
    await service.registerPack("soroban-core", "1.4.2");
    await service.startRollout({
      ...PLAN,
      allowTenants: ["confidential-customer"],
    });
    const selection = await service.resolve("someone-else", "soroban-core");
    expect(JSON.stringify(selection)).not.toContain("confidential-customer");
  });
});

describe("purgeExpiredPins", () => {
  it("removes pins older than the retention window", async () => {
    const { service, store, tick } = setup({ config: { pinRetentionMs: 100 } });
    await service.resolveForScan({
      tenantId: "t1",
      scanId: "old",
      packIds: ["p"],
    });
    tick(60);
    await service.resolveForScan({
      tenantId: "t1",
      scanId: "new",
      packIds: ["p"],
    });
    tick(60);
    expect(await service.purgeExpiredPins()).toBe(1);
    expect(store.pinCount()).toBe(1);
  });
});

describe("determinism", () => {
  it("resolves identically across service instances over the same state", async () => {
    const store = new InMemoryRulePackRolloutStore();
    const a = new RulePackRolloutService({
      store,
      logger: new CapturingLogger(),
    });
    await a.registerPack("soroban-core", "1.4.2");
    await a.startRollout(PLAN);
    const b = new RulePackRolloutService({
      store,
      logger: new CapturingLogger(),
    });
    const channel = (await store.getChannel("soroban-core"))!;
    for (let i = 0; i < 50; i++) {
      const tenant = `tenant-${i}`;
      const expected = selectForTenant(channel, tenant, true);
      expect(await a.resolve(tenant, "soroban-core")).toEqual(expected);
      expect(await b.resolve(tenant, "soroban-core")).toEqual(expected);
    }
  });
});
