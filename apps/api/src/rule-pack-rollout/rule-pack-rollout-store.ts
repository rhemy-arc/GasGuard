/**
 * Persistence boundary for rule-pack channels and scan pins.
 *
 * Channels are platform-scoped and keyed by pack id. Writes are optimistic:
 * `putChannel` only succeeds when the stored revision still equals the one the
 * caller read, so two operators (or an operator and the auto-rollback path)
 * can never silently overwrite each other.
 *
 * Pins are tenant-scoped and keyed by `(tenantId, scanId)`. Every pin read and
 * write takes the tenant id explicitly, and implementations must never resolve
 * a pin across tenants, so one tenant cannot read or alter another's pin even
 * when scan ids collide. Pins are write-once (`createPin`), and their outcome
 * is set at most once, which makes retries and duplicate reports idempotent.
 *
 * Implementations throw plain errors on storage failure; the service maps them
 * to the retryable STORE_UNAVAILABLE code.
 */

import * as crypto from "crypto";
import { promises as fs } from "fs";
import * as path from "path";
import { applyStageOutcome } from "./rule-pack-rollout-planner";
import {
  RulePackChannel,
  ScanOutcome,
  ScanRulePackPin,
} from "./rule-pack-rollout-types";

export type ChannelWriteResult = "written" | "conflict";
export type PinCreateResult = "written" | "exists";
export type PinOutcomeResult = "written" | "already_recorded" | "not_found";

export interface RulePackRolloutStore {
  getChannel(packId: string): Promise<RulePackChannel | undefined>;
  /**
   * Write `channel` when the stored revision equals `expectedRevision`
   * (`0` means the channel must not exist yet).
   */
  putChannel(
    channel: RulePackChannel,
    expectedRevision: number,
  ): Promise<ChannelWriteResult>;
  /**
   * Atomically count one outcome toward the live rollout's current stage when
   * `rolloutId` and `stageIndex` still match (see `applyStageOutcome`),
   * bumping the revision. Returns the updated channel, or `undefined` when it
   * did not match. A database store implements this as one conditional
   * `UPDATE`; it must never be a client-side read-modify-write, because
   * outcome traffic is far heavier than operator traffic.
   */
  addStageOutcome(
    packId: string,
    rolloutId: string,
    stageIndex: number,
    outcome: ScanOutcome,
    at: number,
  ): Promise<RulePackChannel | undefined>;
  /** All channels, sorted by pack id. */
  listChannels(): Promise<RulePackChannel[]>;
  getPin(
    tenantId: string,
    scanId: string,
  ): Promise<ScanRulePackPin | undefined>;
  /** Store `pin` unless a pin already exists for its tenant and scan. */
  createPin(pin: ScanRulePackPin): Promise<PinCreateResult>;
  /** Set the outcome once; later calls leave the first outcome in place. */
  setPinOutcome(
    tenantId: string,
    scanId: string,
    outcome: ScanOutcome,
    at: number,
  ): Promise<PinOutcomeResult>;
  /** Remove pins created before `cutoff`; returns how many were removed. */
  deletePinsBefore(cutoff: number): Promise<number>;
}

export class InMemoryRulePackRolloutStore implements RulePackRolloutStore {
  // Stored serialized so callers can never mutate persisted state by reference.
  private readonly channels: Map<string, string> = new Map();
  private readonly pins: Map<string, string> = new Map();

  async getChannel(packId: string): Promise<RulePackChannel | undefined> {
    const raw = this.channels.get(packId);
    return raw === undefined ? undefined : (JSON.parse(raw) as RulePackChannel);
  }

  async putChannel(
    channel: RulePackChannel,
    expectedRevision: number,
  ): Promise<ChannelWriteResult> {
    const raw = this.channels.get(channel.packId);
    const current =
      raw === undefined ? 0 : (JSON.parse(raw) as RulePackChannel).revision;
    if (current !== expectedRevision) {
      return "conflict";
    }
    this.channels.set(channel.packId, JSON.stringify(channel));
    return "written";
  }

  async addStageOutcome(
    packId: string,
    rolloutId: string,
    stageIndex: number,
    outcome: ScanOutcome,
    at: number,
  ): Promise<RulePackChannel | undefined> {
    const raw = this.channels.get(packId);
    if (raw === undefined) {
      return undefined;
    }
    const next = applyStageOutcome(
      JSON.parse(raw) as RulePackChannel,
      rolloutId,
      stageIndex,
      outcome,
      at,
    );
    if (next) {
      this.channels.set(packId, JSON.stringify(next));
    }
    return next;
  }

  async listChannels(): Promise<RulePackChannel[]> {
    return [...this.channels.keys()]
      .sort()
      .map((key) => JSON.parse(this.channels.get(key)!) as RulePackChannel);
  }

  async getPin(
    tenantId: string,
    scanId: string,
  ): Promise<ScanRulePackPin | undefined> {
    const raw = this.pins.get(pinKey(tenantId, scanId));
    return raw === undefined ? undefined : (JSON.parse(raw) as ScanRulePackPin);
  }

  async createPin(pin: ScanRulePackPin): Promise<PinCreateResult> {
    const key = pinKey(pin.tenantId, pin.scanId);
    if (this.pins.has(key)) {
      return "exists";
    }
    this.pins.set(key, JSON.stringify(pin));
    return "written";
  }

  async setPinOutcome(
    tenantId: string,
    scanId: string,
    outcome: ScanOutcome,
    at: number,
  ): Promise<PinOutcomeResult> {
    const key = pinKey(tenantId, scanId);
    const raw = this.pins.get(key);
    if (raw === undefined) {
      return "not_found";
    }
    const pin = JSON.parse(raw) as ScanRulePackPin;
    if (pin.outcome !== undefined) {
      return "already_recorded";
    }
    this.pins.set(key, JSON.stringify({ ...pin, outcome, outcomeAt: at }));
    return "written";
  }

  async deletePinsBefore(cutoff: number): Promise<number> {
    let removed = 0;
    for (const [key, raw] of this.pins) {
      if ((JSON.parse(raw) as ScanRulePackPin).pinnedAt < cutoff) {
        this.pins.delete(key);
        removed++;
      }
    }
    return removed;
  }

  pinCount(): number {
    return this.pins.size;
  }
}

/**
 * Durable store writing one JSON file per channel and per scan pin under
 * `rootDir`.
 *
 * Paths are derived from SHA-256 digests of the identifiers, never from the
 * identifiers themselves, so crafted ids cannot traverse outside `rootDir`, and
 * each tenant's pins live in their own directory. Files are written to a
 * temporary name and renamed into place, so a crash mid-write leaves either the
 * old record or the new one, never a torn file.
 *
 * Conditional writes are serialized per key within this process. Deployments
 * that run several API processes against shared storage should use a database
 * store that performs the revision check as a single conditional update.
 */
export class FileRulePackRolloutStore implements RulePackRolloutStore {
  private readonly rootDir: string;
  private readonly locks: Map<string, Promise<unknown>> = new Map();

  constructor(rootDir: string) {
    if (typeof rootDir !== "string" || rootDir.trim() === "") {
      throw new TypeError("rootDir must be a non-empty string");
    }
    this.rootDir = path.resolve(rootDir);
  }

  getChannel(packId: string): Promise<RulePackChannel | undefined> {
    return this.readChannel(this.channelPath(packId), packId);
  }

  putChannel(
    channel: RulePackChannel,
    expectedRevision: number,
  ): Promise<ChannelWriteResult> {
    const file = this.channelPath(channel.packId);
    return this.withLock(file, async () => {
      const existing = await this.readChannel(file, channel.packId);
      if ((existing?.revision ?? 0) !== expectedRevision) {
        return "conflict";
      }
      await this.writeAtomic(file, channel);
      return "written";
    });
  }

  addStageOutcome(
    packId: string,
    rolloutId: string,
    stageIndex: number,
    outcome: ScanOutcome,
    at: number,
  ): Promise<RulePackChannel | undefined> {
    const file = this.channelPath(packId);
    return this.withLock(file, async () => {
      const existing = await this.readChannel(file, packId);
      const next =
        existing &&
        applyStageOutcome(existing, rolloutId, stageIndex, outcome, at);
      if (next) {
        await this.writeAtomic(file, next);
      }
      return next;
    });
  }

  async listChannels(): Promise<RulePackChannel[]> {
    const dir = path.join(this.rootDir, "channels");
    const names = await readDirOrEmpty(dir);
    const channels: RulePackChannel[] = [];
    for (const name of names.filter((n) => n.endsWith(".json")).sort()) {
      channels.push(
        JSON.parse(await fs.readFile(path.join(dir, name), "utf8")),
      );
    }
    return channels.sort((a, b) =>
      a.packId === b.packId ? 0 : a.packId < b.packId ? -1 : 1,
    );
  }

  getPin(
    tenantId: string,
    scanId: string,
  ): Promise<ScanRulePackPin | undefined> {
    return this.readPin(this.pinPath(tenantId, scanId), tenantId, scanId);
  }

  createPin(pin: ScanRulePackPin): Promise<PinCreateResult> {
    const file = this.pinPath(pin.tenantId, pin.scanId);
    return this.withLock(file, async () => {
      if (await this.readPin(file, pin.tenantId, pin.scanId)) {
        return "exists";
      }
      await this.writeAtomic(file, pin);
      return "written";
    });
  }

  setPinOutcome(
    tenantId: string,
    scanId: string,
    outcome: ScanOutcome,
    at: number,
  ): Promise<PinOutcomeResult> {
    const file = this.pinPath(tenantId, scanId);
    return this.withLock(file, async () => {
      const pin = await this.readPin(file, tenantId, scanId);
      if (!pin) {
        return "not_found";
      }
      if (pin.outcome !== undefined) {
        return "already_recorded";
      }
      await this.writeAtomic(file, { ...pin, outcome, outcomeAt: at });
      return "written";
    });
  }

  async deletePinsBefore(cutoff: number): Promise<number> {
    const pinsDir = path.join(this.rootDir, "pins");
    let removed = 0;
    for (const tenantDir of (await readDirOrEmpty(pinsDir)).sort()) {
      const dir = path.join(pinsDir, tenantDir);
      for (const name of (await readDirOrEmpty(dir)).sort()) {
        if (!name.endsWith(".json")) {
          continue;
        }
        const file = path.join(dir, name);
        const deleted = await this.withLock(file, async () => {
          let pin: ScanRulePackPin;
          try {
            pin = JSON.parse(await fs.readFile(file, "utf8"));
          } catch (error) {
            if (isNotFound(error)) {
              return false;
            }
            throw error;
          }
          if (pin.pinnedAt >= cutoff) {
            return false;
          }
          await fs.rm(file, { force: true });
          return true;
        });
        if (deleted) {
          removed++;
        }
      }
    }
    return removed;
  }

  private async readChannel(
    file: string,
    packId: string,
  ): Promise<RulePackChannel | undefined> {
    const channel = await readJson<RulePackChannel>(file);
    // Defence in depth: the digest path must hold the record it was asked for.
    if (channel && channel.packId !== packId) {
      throw new Error("Stored rule-pack channel does not match its key");
    }
    return channel;
  }

  private async readPin(
    file: string,
    tenantId: string,
    scanId: string,
  ): Promise<ScanRulePackPin | undefined> {
    const pin = await readJson<ScanRulePackPin>(file);
    if (pin && (pin.tenantId !== tenantId || pin.scanId !== scanId)) {
      throw new Error("Stored scan pin does not match its key");
    }
    return pin;
  }

  private async writeAtomic(file: string, value: unknown): Promise<void> {
    await fs.mkdir(path.dirname(file), { recursive: true });
    const tmp = `${file}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`;
    try {
      await fs.writeFile(tmp, JSON.stringify(value), {
        encoding: "utf8",
        mode: 0o600,
      });
      await fs.rename(tmp, file);
    } catch (error) {
      await fs.rm(tmp, { force: true }).catch(() => undefined);
      throw error;
    }
  }

  private channelPath(packId: string): string {
    return path.join(this.rootDir, "channels", `${digest(packId)}.json`);
  }

  private pinPath(tenantId: string, scanId: string): string {
    return path.join(
      this.rootDir,
      "pins",
      digest(tenantId),
      `${digest(scanId)}.json`,
    );
  }

  private withLock<T>(key: string, task: () => Promise<T>): Promise<T> {
    const previous = this.locks.get(key) ?? Promise.resolve();
    const run = previous.then(task, task);
    const settled = run.catch(() => undefined);
    this.locks.set(key, settled);
    void settled.then(() => {
      if (this.locks.get(key) === settled) {
        this.locks.delete(key);
      }
    });
    return run;
  }
}

function pinKey(tenantId: string, scanId: string): string {
  return `${tenantId}\u0000${scanId}`;
}

function digest(value: string): string {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

async function readJson<T>(file: string): Promise<T | undefined> {
  let raw: string;
  try {
    raw = await fs.readFile(file, "utf8");
  } catch (error) {
    if (isNotFound(error)) {
      return undefined;
    }
    throw error;
  }
  return JSON.parse(raw) as T;
}

async function readDirOrEmpty(dir: string): Promise<string[]> {
  try {
    return await fs.readdir(dir);
  } catch (error) {
    if (isNotFound(error)) {
      return [];
    }
    throw error;
  }
}

function isNotFound(error: unknown): boolean {
  return (error as NodeJS.ErrnoException)?.code === "ENOENT";
}
