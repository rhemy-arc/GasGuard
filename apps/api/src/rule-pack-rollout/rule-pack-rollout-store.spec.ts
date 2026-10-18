import { promises as fs } from "fs";
import * as os from "os";
import * as path from "path";
import {
  FileRulePackRolloutStore,
  InMemoryRulePackRolloutStore,
  RulePackRolloutStore,
} from "./rule-pack-rollout-store";
import { RulePackChannel, ScanRulePackPin } from "./rule-pack-rollout-types";

function channel(packId: string, revision: number): RulePackChannel {
  return {
    packId,
    stableVersion: "1.0.0",
    revision,
    rolloutSequence: 0,
    updatedAt: revision,
  };
}

function pin(tenantId: string, scanId: string, pinnedAt = 0): ScanRulePackPin {
  return {
    tenantId,
    scanId,
    packIds: ["soroban-core"],
    selections: [
      {
        packId: "soroban-core",
        version: "1.0.0",
        channel: "stable",
        reason: "no_active_rollout",
      },
    ],
    fingerprint: "soroban-core@1.0.0",
    pinnedAt,
  };
}

const tmpDirs: string[] = [];

afterAll(async () => {
  await Promise.all(
    tmpDirs.map((dir) => fs.rm(dir, { recursive: true, force: true })),
  );
});

const factories: [string, () => Promise<RulePackRolloutStore>][] = [
  [
    "InMemoryRulePackRolloutStore",
    async () => new InMemoryRulePackRolloutStore(),
  ],
  [
    "FileRulePackRolloutStore",
    async () => {
      const dir = await fs.mkdtemp(path.join(os.tmpdir(), "rule-pack-store-"));
      tmpDirs.push(dir);
      return new FileRulePackRolloutStore(dir);
    },
  ],
];

describe.each(factories)("%s contract", (_name, create) => {
  let store: RulePackRolloutStore;

  beforeEach(async () => {
    store = await create();
  });

  describe("channels", () => {
    it("returns undefined for an unknown pack", async () => {
      expect(await store.getChannel("missing")).toBeUndefined();
    });

    it("creates with expectedRevision 0 and rejects a second create", async () => {
      expect(await store.putChannel(channel("p", 1), 0)).toBe("written");
      expect(await store.putChannel(channel("p", 1), 0)).toBe("conflict");
      expect(await store.getChannel("p")).toEqual(channel("p", 1));
    });

    it("only writes when the stored revision matches", async () => {
      await store.putChannel(channel("p", 1), 0);
      expect(await store.putChannel(channel("p", 2), 1)).toBe("written");
      expect(await store.putChannel(channel("p", 3), 1)).toBe("conflict");
      expect((await store.getChannel("p"))?.revision).toBe(2);
    });

    it("lets exactly one of several concurrent writers win", async () => {
      await store.putChannel(channel("p", 1), 0);
      const results = await Promise.all(
        Array.from({ length: 8 }, () => store.putChannel(channel("p", 2), 1)),
      );
      expect(results.filter((r) => r === "written")).toHaveLength(1);
    });

    it("lists channels in pack-id order", async () => {
      for (const id of ["zeta", "alpha", "mid"]) {
        await store.putChannel(channel(id, 1), 0);
      }
      expect((await store.listChannels()).map((c) => c.packId)).toEqual([
        "alpha",
        "mid",
        "zeta",
      ]);
    });

    it("returns copies that callers cannot use to mutate stored state", async () => {
      await store.putChannel(channel("p", 1), 0);
      const read = (await store.getChannel("p"))!;
      read.stableVersion = "9.9.9";
      expect((await store.getChannel("p"))?.stableVersion).toBe("1.0.0");
    });
  });

  describe("addStageOutcome", () => {
    const live = (): RulePackChannel => ({
      ...channel("p", 1),
      rolloutSequence: 1,
      rollout: {
        rolloutId: "p#1",
        baselineVersion: "1.0.0",
        candidateVersion: "1.1.0",
        stagesBasisPoints: [5_000, 10_000],
        stageIndex: 0,
        state: "active",
        allowTenants: [],
        denyTenants: [],
        gate: { minSamples: 1, maxFailureRatio: 0, autoRollback: false },
        stageStats: { succeeded: 0, failed: 0 },
        startedAt: 0,
        updatedAt: 0,
        events: [],
      },
    });

    it("counts toward the matching live stage and bumps the revision", async () => {
      await store.putChannel(live(), 0);
      const updated = await store.addStageOutcome("p", "p#1", 0, "failed", 7);
      expect(updated).toMatchObject({
        revision: 2,
        updatedAt: 7,
        rollout: { stageStats: { succeeded: 0, failed: 1 } },
      });
      expect(await store.getChannel("p")).toEqual(updated);
    });

    it("ignores unknown packs, other rollouts, other stages and ended rollouts", async () => {
      expect(
        await store.addStageOutcome("p", "p#1", 0, "failed", 1),
      ).toBeUndefined();
      await store.putChannel(live(), 0);
      expect(
        await store.addStageOutcome("p", "p#0", 0, "failed", 1),
      ).toBeUndefined();
      expect(
        await store.addStageOutcome("p", "p#1", 1, "failed", 1),
      ).toBeUndefined();
      const ended = live();
      ended.revision = 2;
      ended.rollout!.state = "rolled_back";
      await store.putChannel(ended, 1);
      expect(
        await store.addStageOutcome("p", "p#1", 0, "failed", 1),
      ).toBeUndefined();
      expect((await store.getChannel("p"))!.revision).toBe(2);
    });

    it("never loses a concurrent increment", async () => {
      await store.putChannel(live(), 0);
      await Promise.all(
        Array.from({ length: 30 }, (_, i) =>
          store.addStageOutcome(
            "p",
            "p#1",
            0,
            i % 3 ? "succeeded" : "failed",
            i,
          ),
        ),
      );
      expect(await store.getChannel("p")).toMatchObject({
        revision: 31,
        rollout: { stageStats: { succeeded: 20, failed: 10 } },
      });
    });
  });

  describe("pins", () => {
    it("creates once and reports later creates as existing", async () => {
      expect(await store.createPin(pin("t1", "s1"))).toBe("written");
      const second = { ...pin("t1", "s1"), fingerprint: "other" };
      expect(await store.createPin(second)).toBe("exists");
      expect((await store.getPin("t1", "s1"))?.fingerprint).toBe(
        "soroban-core@1.0.0",
      );
    });

    it("isolates tenants that share a scan id", async () => {
      await store.createPin(pin("tenant-a", "scan-1"));
      expect(await store.getPin("tenant-b", "scan-1")).toBeUndefined();
      expect(await store.createPin(pin("tenant-b", "scan-1"))).toBe("written");
      expect(await store.setPinOutcome("tenant-b", "scan-1", "failed", 5)).toBe(
        "written",
      );
      expect(
        (await store.getPin("tenant-a", "scan-1"))?.outcome,
      ).toBeUndefined();
    });

    it("sets an outcome at most once", async () => {
      expect(await store.setPinOutcome("t1", "s1", "failed", 1)).toBe(
        "not_found",
      );
      await store.createPin(pin("t1", "s1"));
      expect(await store.setPinOutcome("t1", "s1", "succeeded", 2)).toBe(
        "written",
      );
      expect(await store.setPinOutcome("t1", "s1", "failed", 3)).toBe(
        "already_recorded",
      );
      expect(await store.getPin("t1", "s1")).toMatchObject({
        outcome: "succeeded",
        outcomeAt: 2,
      });
    });

    it("records exactly one of several concurrent outcomes", async () => {
      await store.createPin(pin("t1", "s1"));
      const results = await Promise.all(
        Array.from({ length: 6 }, (_, i) =>
          store.setPinOutcome("t1", "s1", i % 2 ? "failed" : "succeeded", i),
        ),
      );
      expect(results.filter((r) => r === "written")).toHaveLength(1);
    });

    it("deletes only pins created before the cutoff", async () => {
      await store.createPin(pin("t1", "old", 10));
      await store.createPin(pin("t2", "edge", 100));
      await store.createPin(pin("t2", "new", 200));
      expect(await store.deletePinsBefore(100)).toBe(1);
      expect(await store.getPin("t1", "old")).toBeUndefined();
      expect(await store.getPin("t2", "edge")).toBeDefined();
      expect(await store.deletePinsBefore(100)).toBe(0);
    });
  });
});

describe("FileRulePackRolloutStore", () => {
  let dir: string;

  beforeEach(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), "rule-pack-file-"));
    tmpDirs.push(dir);
  });

  it("rejects an empty root directory", () => {
    expect(() => new FileRulePackRolloutStore(" ")).toThrow(TypeError);
  });

  it("persists across instances", async () => {
    await new FileRulePackRolloutStore(dir).putChannel(channel("p", 1), 0);
    await new FileRulePackRolloutStore(dir).createPin(pin("t1", "s1"));
    const reopened = new FileRulePackRolloutStore(dir);
    expect((await reopened.getChannel("p"))?.revision).toBe(1);
    expect((await reopened.getPin("t1", "s1"))?.scanId).toBe("s1");
  });

  it("keeps crafted identifiers inside the root directory", async () => {
    const store = new FileRulePackRolloutStore(dir);
    await store.createPin(pin("../../escape", "../../../etc/passwd"));
    const walk = async (d: string): Promise<string[]> => {
      const entries = await fs.readdir(d, { withFileTypes: true });
      const nested = await Promise.all(
        entries.map((e) =>
          e.isDirectory() ? walk(path.join(d, e.name)) : [path.join(d, e.name)],
        ),
      );
      return nested.flat();
    };
    const files = await walk(dir);
    expect(files).toHaveLength(1);
    expect(path.relative(dir, files[0])).toMatch(
      /^pins\/[0-9a-f]{64}\/[0-9a-f]{64}\.json$/,
    );
  });

  it("writes files readable only by the owner", async () => {
    const store = new FileRulePackRolloutStore(dir);
    await store.putChannel(channel("p", 1), 0);
    const [name] = await fs.readdir(path.join(dir, "channels"));
    const stat = await fs.stat(path.join(dir, "channels", name));
    expect(stat.mode & 0o077).toBe(0);
  });

  it("throws on a corrupt record instead of treating it as missing", async () => {
    const store = new FileRulePackRolloutStore(dir);
    await store.putChannel(channel("p", 1), 0);
    const [name] = await fs.readdir(path.join(dir, "channels"));
    await fs.writeFile(path.join(dir, "channels", name), "{not json");
    await expect(store.getChannel("p")).rejects.toThrow();
    await expect(store.putChannel(channel("p", 1), 0)).rejects.toThrow();
  });

  it("throws when a file holds a different key's record", async () => {
    const store = new FileRulePackRolloutStore(dir);
    await store.putChannel(channel("a", 1), 0);
    await store.putChannel(channel("b", 1), 0);
    const names = await fs.readdir(path.join(dir, "channels"));
    const contents = await Promise.all(
      names.map((n) => fs.readFile(path.join(dir, "channels", n), "utf8")),
    );
    await fs.writeFile(path.join(dir, "channels", names[0]), contents[1]);
    await expect(store.listChannels()).resolves.toHaveLength(2);
    const victim = JSON.parse(contents[0]).packId as string;
    await expect(store.getChannel(victim)).rejects.toThrow(/does not match/);
  });
});
