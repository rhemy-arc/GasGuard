/**
 * Metrics and structured logging for staged rule-pack rollouts.
 *
 * Labels are drawn from closed sets (channels, reasons, actions, outcomes and
 * error codes) plus the pack id, which is a validated, platform-controlled
 * slug. Tenant, repository and scan ids never become labels, so cardinality
 * stays bounded and no customer identifiers reach a metrics backend.
 *
 * Log fields pass through `sanitizeLogFields`, which keeps only primitive
 * values, truncates long strings, and drops keys that look like they carry
 * payloads or credentials. The service logs identifiers, versions, counts and
 * error codes only; it never logs scan content or error messages from stores.
 */

import {
  RolloutAction,
  RolloutState,
  RulePackChannel,
  ScanOutcome,
  SelectionChannel,
  SelectionReason,
} from "./rule-pack-rollout-types";
import { BUCKET_COUNT } from "./rule-pack-rollout-planner";

export interface RulePackRolloutMetricsSnapshot {
  /** Keyed by `${channel}:${reason}`. */
  resolutions: Record<string, number>;
  pinsReused: number;
  transitions: Record<string, number>;
  /** Candidate outcomes counted toward a gate, keyed by outcome. */
  candidateOutcomes: Record<string, number>;
  /** Outcomes not counted (baseline, stale stage, duplicate...), keyed by reason. */
  outcomesIgnored: Record<string, number>;
  conflicts: number;
  errors: Record<string, number>;
}

export class RulePackRolloutMetrics {
  private readonly resolutions: Map<string, number> = new Map();
  private readonly transitions: Map<string, number> = new Map();
  private readonly candidateOutcomes: Map<string, number> = new Map();
  private readonly outcomesIgnored: Map<string, number> = new Map();
  private readonly errors: Map<string, number> = new Map();
  private pinsReused = 0;
  private conflicts = 0;

  recordResolution(channel: SelectionChannel, reason: SelectionReason): void {
    increment(this.resolutions, `${channel}:${reason}`);
  }

  recordPinReused(): void {
    this.pinsReused++;
  }

  recordTransition(action: RolloutAction): void {
    increment(this.transitions, action);
  }

  recordCandidateOutcome(outcome: ScanOutcome): void {
    increment(this.candidateOutcomes, outcome);
  }

  recordOutcomeIgnored(reason: string): void {
    increment(this.outcomesIgnored, reason);
  }

  recordConflict(): void {
    this.conflicts++;
  }

  recordError(code: string): void {
    increment(this.errors, code);
  }

  snapshot(): RulePackRolloutMetricsSnapshot {
    return {
      resolutions: Object.fromEntries(this.resolutions),
      pinsReused: this.pinsReused,
      transitions: Object.fromEntries(this.transitions),
      candidateOutcomes: Object.fromEntries(this.candidateOutcomes),
      outcomesIgnored: Object.fromEntries(this.outcomesIgnored),
      conflicts: this.conflicts,
      errors: Object.fromEntries(this.errors),
    };
  }

  /** Prometheus text exposition of the counters, plus optional channel gauges. */
  toPrometheus(channels: readonly RulePackChannel[] = []): string {
    const lines: string[] = [];
    const header = (name: string, type: string, help: string) => {
      lines.push(`# HELP ${name} ${help}`, `# TYPE ${name} ${type}`);
    };

    header(
      "gasguard_rule_pack_resolutions_total",
      "counter",
      "Rule-pack version resolutions by channel and reason.",
    );
    for (const [key, value] of this.resolutions) {
      const [channel, reason] = key.split(":");
      lines.push(
        `gasguard_rule_pack_resolutions_total{channel="${channel}",reason="${reason}"} ${value}`,
      );
    }
    header(
      "gasguard_rule_pack_pins_reused_total",
      "counter",
      "Scan resolutions served from an existing pin (retries).",
    );
    lines.push(`gasguard_rule_pack_pins_reused_total ${this.pinsReused}`);
    header(
      "gasguard_rule_pack_rollout_transitions_total",
      "counter",
      "Rollout state transitions by action.",
    );
    for (const [action, value] of this.transitions) {
      lines.push(
        `gasguard_rule_pack_rollout_transitions_total{action="${action}"} ${value}`,
      );
    }
    header(
      "gasguard_rule_pack_candidate_outcomes_total",
      "counter",
      "Candidate scan outcomes counted toward a rollout gate.",
    );
    for (const [outcome, value] of this.candidateOutcomes) {
      lines.push(
        `gasguard_rule_pack_candidate_outcomes_total{outcome="${outcome}"} ${value}`,
      );
    }
    header(
      "gasguard_rule_pack_outcomes_ignored_total",
      "counter",
      "Scan outcomes not counted toward a gate, by reason.",
    );
    for (const [reason, value] of this.outcomesIgnored) {
      lines.push(
        `gasguard_rule_pack_outcomes_ignored_total{reason="${reason}"} ${value}`,
      );
    }
    header(
      "gasguard_rule_pack_rollout_conflicts_total",
      "counter",
      "Concurrent channel writes that had to be retried.",
    );
    lines.push(`gasguard_rule_pack_rollout_conflicts_total ${this.conflicts}`);
    header(
      "gasguard_rule_pack_rollout_errors_total",
      "counter",
      "Rollout operations that failed, by error code.",
    );
    for (const [code, value] of this.errors) {
      lines.push(
        `gasguard_rule_pack_rollout_errors_total{code="${code}"} ${value}`,
      );
    }

    if (channels.length > 0) {
      header(
        "gasguard_rule_pack_rollout_stage_percent",
        "gauge",
        "Percentage of tenants targeted by the live rollout (0 when none).",
      );
      for (const channel of channels) {
        const rollout = channel.rollout;
        const live =
          rollout && (rollout.state === "active" || rollout.state === "paused");
        const percent = live
          ? (rollout.stagesBasisPoints[rollout.stageIndex] / BUCKET_COUNT) * 100
          : 0;
        lines.push(
          `gasguard_rule_pack_rollout_stage_percent{pack="${channel.packId}"} ${percent}`,
        );
      }
      header(
        "gasguard_rule_pack_rollout_state",
        "gauge",
        "1 for the state of the most recent rollout per pack.",
      );
      for (const channel of channels) {
        const state: RolloutState | "none" = channel.rollout?.state ?? "none";
        lines.push(
          `gasguard_rule_pack_rollout_state{pack="${channel.packId}",state="${state}"} 1`,
        );
      }
    }
    return `${lines.join("\n")}\n`;
  }
}

export type RulePackRolloutLogLevel = "info" | "warn" | "error";
export type RulePackRolloutLogFields = Record<
  string,
  string | number | boolean | undefined
>;

export interface RulePackRolloutLogger {
  log(
    level: RulePackRolloutLogLevel,
    event: string,
    fields: RulePackRolloutLogFields,
  ): void;
}

/** Emits one JSON object per line on stdout/stderr. */
export const consoleRulePackRolloutLogger: RulePackRolloutLogger = {
  log(level, event, fields) {
    const line = JSON.stringify({
      level,
      component: "rule-pack-rollout",
      event,
      ...sanitizeLogFields(fields),
    });
    if (level === "info") {
      console.log(line);
    } else {
      console.error(line);
    }
  },
};

const MAX_LOG_STRING = 200;
/** Keys that must never reach a log line, even if a caller passes them. */
const FORBIDDEN_LOG_KEY =
  /payload|document|content|source|body|secret|token|password|key|credential|authorization/i;

export function sanitizeLogFields(
  fields: Record<string, unknown>,
): RulePackRolloutLogFields {
  const safe: RulePackRolloutLogFields = {};
  for (const [field, value] of Object.entries(fields)) {
    if (FORBIDDEN_LOG_KEY.test(field)) {
      continue;
    }
    if (typeof value === "number" || typeof value === "boolean") {
      safe[field] = value;
    } else if (typeof value === "string") {
      safe[field] =
        value.length > MAX_LOG_STRING
          ? `${value.slice(0, MAX_LOG_STRING)}…`
          : value;
    }
  }
  return safe;
}

function increment(map: Map<string, number>, key: string): void {
  map.set(key, (map.get(key) ?? 0) + 1);
}
