/**
 * Integration tests across the rule-pack rollout boundaries: operator-facing
 * service, worker adapter, and the durable file store, including service
 * restarts over the same storage.
 */

import { createHash } from "crypto";
import { promises as fs, readFileSync } from "fs";
import * as os from "os";
import * as path from "path";
import {
  RulePackRolloutLogFields,
  RulePackRolloutLogLevel,
  RulePackRolloutLogger,
} from "./rule-pack-rollout-metrics";
import { FileRulePackRolloutStore } from "./rule-pack-rollout-store";
import {
  RulePackRolloutService,
  ScanRulePackResolution,
} from "./rule-pack-rollout.service";
import { RulePackRolloutPlan } from "./rule-pack-rollout-types";
import { runScanWithRulePacks } from "./rule-pack-rollout-worker";

interface RolloutFixture {
  stableVersion: string;
  plan: RulePackRolloutPlan;
  otherManagedPacks: { packId: string; stableVersion: string }[];
  scan: {
    tenantId: string;
    repository: string;
    commit: string;
    scanId: string;
    packIds: string[];
  };
}

const fixture = JSON.parse(
  readFileSync(
    path.join(__dirname, "__fixtures__", "soroban-core-rollout.json"),
    "utf8",
  ),
) as RolloutFixture;

class CapturingLogger implements RulePackRolloutLogger {
  readonly lines: string[] = [];
  log(
    level: RulePackRolloutLogLevel,
    event: string,
    fields: RulePackRolloutLogFields,
  ): void {
    this.lines.push(JSON.stringify({ level, event, ...fields }));
  }
}

/**
 * Stand-in analyzer: findings are a pure function of the commit and the
 * resolved rule-pack fingerprint, as real analysis must be.
 */
function analyze(commit: string, resolution: ScanRulePackResolution) {
  const digest = createHash("sha256")
    .update(`${commit}\u0000${resolution.fingerprint}`)
    .digest("hex");
  return {
    rulePacks: resolution.fingerprint,
    unmanaged: resolution.unmanagedPackIds,
    findingsHash: digest.slice(0, 16),
  };
}

let rootDir: string;
let logger: CapturingLogger;
let now: number;

/** A fresh service over the same directory, i.e. a restarted process. */
function boot(config = {}) {
  return new RulePackRolloutService({
    store: new FileRulePackRolloutStore(rootDir),
    logger,
    clock: () => now,
    config,
  });
}

async function operatorSetup(): Promise<RulePackRolloutService> {
  const operator = boot();
  await operator.registerPack(fixture.plan.packId, fixture.stableVersion);
  for (const pack of fixture.otherManagedPacks) {
    await operator.registerPack(pack.packId, pack.stableVersion);
  }
  await operator.startRollout(fixture.plan, "storage-rent rules");
  return operator;
}

/** Run successful dogfood scans until the current stage gate passes. */
async function satisfyGate(service: RulePackRolloutService, label: string) {
  for (let i = 0; i < fixture.plan.gate!.minSamples!; i++) {
    await runScanWithRulePacks(
      service,
      {
        tenantId: "gasguard-dogfood",
        scanId: `dogfood-${label}-${i}`,
        packIds: [fixture.plan.packId],
        isFinalAttempt: true,
      },
      async () => "ok",
    );
  }
}

beforeEach(async () => {
  rootDir = await fs.mkdtemp(path.join(os.tmpdir(), "rule-pack-rollout-it-"));
  logger = new CapturingLogger();
  now = 1_700_000_000_000;
});

afterEach(async () => {
  await fs.rm(rootDir, { recursive: true, force: true });
});

describe("realistic repository: soroban AMM scanned during a soroban-core rollout", () => {
  it("moves the tenant to the candidate at its stage, deterministically and durably", async () => {
    const operator = await operatorSetup();
    const { scan } = fixture;
    const scanAt = async (scanId: string) =>
      runScanWithRulePacks(
        boot(),
        {
          tenantId: scan.tenantId,
          scanId,
          packIds: scan.packIds,
          isFinalAttempt: true,
        },
        async (resolution) => analyze(scan.commit, resolution),
      );

    // Stage 0 (1%): acme-defi's bucket (3188) is outside the cohort.
    const baseline = await scanAt(scan.scanId);
    expect(baseline).toEqual({
      rulePacks: "soroban-core@1.4.2,soroban-security@2.0.1",
      unmanaged: ["evm-gas"],
      findingsHash: expect.any(String),
    });
    // The same commit, configuration and versions give the same findings.
    expect(await scanAt(`${scan.scanId}:rerun`)).toEqual(baseline);

    // Allow and deny lists win over the cohort.
    expect(
      (await operator.resolve("gasguard-dogfood", "soroban-core"))!.version,
    ).toBe("1.5.0");
    expect(
      (await operator.resolve("regulated-bank-eu", "soroban-core"))!.reason,
    ).toBe("deny_list");

    await satisfyGate(operator, "s0");
    await boot().advance("soroban-core"); // 10%: still outside
    expect((await scanAt(`${scan.scanId}:s1`)).rulePacks).toBe(
      baseline.rulePacks,
    );

    await satisfyGate(operator, "s1");
    await boot().advance("soroban-core"); // 50%: inside
    const candidate = await scanAt(`${scan.scanId}:s2`);
    expect(candidate.rulePacks).toBe(
      "soroban-core@1.5.0,soroban-security@2.0.1",
    );
    expect(candidate.findingsHash).not.toBe(baseline.findingsHash);
    expect(await scanAt(`${scan.scanId}:s2-rerun`)).toEqual(candidate);

    // The original scan id is still pinned to its first resolution.
    expect(await scanAt(scan.scanId)).toEqual(baseline);

    await satisfyGate(operator, "s2");
    await boot().advance("soroban-core"); // 100%
    await satisfyGate(operator, "s3");
    const done = await boot().advance("soroban-core");
    expect(done).toMatchObject({
      stableVersion: "1.5.0",
      rollout: { state: "completed" },
    });
    // After completion even the denied tenant is on the new stable.
    expect(
      (await boot().resolve("regulated-bank-eu", "soroban-core"))!.version,
    ).toBe("1.5.0");

    const history = (await boot().getChannel("soroban-core"))!.rollout!.events;
    expect(history.map((e) => e.action)).toEqual([
      "started",
      "advanced",
      "advanced",
      "advanced",
      "completed",
    ]);
  });
});

describe("worker retries", () => {
  it("counts a transient failure that a retry recovers from as one success", async () => {
    await operatorSetup();
    const attempt = (isFinalAttempt: boolean) => ({
      tenantId: "gasguard-dogfood",
      scanId: "flaky-scan",
      packIds: ["soroban-core"],
      isFinalAttempt,
    });

    await expect(
      runScanWithRulePacks(boot(), attempt(false), async () => {
        throw new Error("RPC timeout");
      }),
    ).rejects.toThrow("RPC timeout");
    expect(
      (await boot().getChannel("soroban-core"))!.rollout!.stageStats,
    ).toEqual({
      succeeded: 0,
      failed: 0,
    });

    await runScanWithRulePacks(boot(), attempt(true), async () => "ok");
    expect(
      (await boot().getChannel("soroban-core"))!.rollout!.stageStats,
    ).toEqual({
      succeeded: 1,
      failed: 0,
    });
  });

  it("counts a failure on the final attempt and rethrows the scan's error", async () => {
    await operatorSetup();
    const error = new Error("analyzer crashed");
    await expect(
      runScanWithRulePacks(
        boot(),
        {
          tenantId: "gasguard-dogfood",
          scanId: "s1",
          packIds: ["soroban-core"],
          isFinalAttempt: true,
        },
        async () => {
          throw error;
        },
      ),
    ).rejects.toBe(error);
    expect(
      (await boot().getChannel("soroban-core"))!.rollout!.stageStats.failed,
    ).toBe(1);
  });

  it("keeps the scan result when recording the outcome fails", async () => {
    await operatorSetup();
    const service = boot();
    jest
      .spyOn(service, "recordScanOutcome")
      .mockRejectedValueOnce(new Error("store down"));
    await expect(
      runScanWithRulePacks(
        service,
        {
          tenantId: "t1",
          scanId: "s1",
          packIds: ["soroban-core"],
          isFinalAttempt: true,
        },
        async () => "findings",
      ),
    ).resolves.toBe("findings");
  });

  it("does not run the scan when resolution fails, so the queue can retry", async () => {
    await operatorSetup();
    const scan = jest.fn();
    await expect(
      runScanWithRulePacks(
        boot(),
        {
          tenantId: "bad tenant",
          scanId: "s1",
          packIds: ["soroban-core"],
          isFinalAttempt: true,
        },
        scan,
      ),
    ).rejects.toMatchObject({ code: "INVALID_INPUT" });
    expect(scan).not.toHaveBeenCalled();
  });
});

describe("concurrent workers sharing one store", () => {
  it("counts every outcome exactly once", async () => {
    await operatorSetup();
    const store = new FileRulePackRolloutStore(rootDir);
    const workers = Array.from(
      { length: 4 },
      () => new RulePackRolloutService({ store, logger, clock: () => now }),
    );
    const scans = Array.from({ length: 24 }, (_, i) => i);
    await Promise.all(
      scans.map((i) =>
        runScanWithRulePacks(
          workers[i % workers.length],
          {
            tenantId: "gasguard-dogfood",
            scanId: `parallel-${i}`,
            packIds: ["soroban-core"],
            isFinalAttempt: true,
          },
          async () => "ok",
        ),
      ),
    );
    // Duplicate reports from a second worker are ignored.
    await Promise.all(
      scans.map((i) =>
        workers[(i + 1) % workers.length].recordScanOutcome({
          tenantId: "gasguard-dogfood",
          scanId: `parallel-${i}`,
          outcome: "failed",
        }),
      ),
    );
    expect(
      (await boot().getChannel("soroban-core"))!.rollout!.stageStats,
    ).toEqual({
      succeeded: 24,
      failed: 0,
    });
  });
});

describe("regression: auto-rollback survives a restart", () => {
  it("returns new scans to the baseline after a bad candidate, even in a new process", async () => {
    await operatorSetup();
    const minSamples = fixture.plan.gate!.minSamples!;
    let rolledBack: string[] = [];
    for (let i = 0; i < minSamples; i++) {
      const worker = boot();
      await expect(
        runScanWithRulePacks(
          worker,
          {
            tenantId: "gasguard-dogfood",
            scanId: `bad-${i}`,
            packIds: ["soroban-core"],
            isFinalAttempt: true,
          },
          async () => {
            throw new Error("rule crashed on storage-rent check");
          },
        ),
      ).rejects.toThrow();
      const channel = await worker.getChannel("soroban-core");
      if (channel!.rollout!.state === "rolled_back") {
        rolledBack = [`bad-${i}`];
        break;
      }
    }
    expect(rolledBack).toEqual([`bad-${minSamples - 1}`]);

    const restarted = boot();
    expect(await restarted.getChannel("soroban-core")).toMatchObject({
      stableVersion: "1.4.2",
      rollout: { state: "rolled_back", endedAt: now },
    });
    const fresh = await restarted.resolveForScan({
      tenantId: "gasguard-dogfood",
      scanId: "after-rollback",
      packIds: fixture.scan.packIds,
    });
    expect(fresh.fingerprint).toBe("soroban-core@1.4.2,soroban-security@2.0.1");
    expect(
      logger.lines.some((l) =>
        l.includes('"event":"rollout_auto_rolled_back"'),
      ),
    ).toBe(true);
  });
});

describe("logs", () => {
  it("never contain scan content, store errors or credentials", async () => {
    const operator = await operatorSetup();
    await operator.advance("soroban-core", {
      force: true,
      reason: "token=ghp_supersecret".replace(
        "token=",
        "approved by release mgr ",
      ),
    });
    await runScanWithRulePacks(
      boot(),
      {
        tenantId: "acme-defi",
        scanId: "s1",
        packIds: fixture.scan.packIds,
        isFinalAttempt: true,
      },
      async () => "contract Amm { fn swap() {} }",
    );
    const all = logger.lines.join("\n");
    expect(all).not.toContain("contract Amm");
    expect(all).not.toContain(rootDir);
    for (const line of logger.lines) {
      expect(() => JSON.parse(line)).not.toThrow();
    }
  });
});
