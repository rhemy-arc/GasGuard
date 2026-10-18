/**
 * Worker-side adapter for staged rule-pack rollouts.
 *
 * `runScanWithRulePacks` wraps one scan attempt: it resolves (or re-reads)
 * the scan's pinned rule-pack versions, runs the scan with them, and reports
 * the outcome. A failed attempt is only reported when the queue will not retry
 * it (`isFinalAttempt`), so a transient failure that a retry recovers from
 * never counts against a candidate.
 *
 * Reporting is best-effort: a failure to record an outcome is logged by the
 * service but never changes the scan's own result or error.
 */

import {
  RulePackRolloutService,
  ScanRulePackResolution,
} from "./rule-pack-rollout.service";

export interface ScanAttempt {
  tenantId: string;
  scanId: string;
  packIds: string[];
  /** True when this attempt's failure will not be retried. */
  isFinalAttempt: boolean;
}

export async function runScanWithRulePacks<T>(
  service: RulePackRolloutService,
  attempt: ScanAttempt,
  scan: (resolution: ScanRulePackResolution) => Promise<T>,
): Promise<T> {
  // Resolution errors propagate unchanged: STORE_UNAVAILABLE is retryable,
  // so the queue's normal retry policy applies before any analysis runs.
  const resolution = await service.resolveForScan({
    tenantId: attempt.tenantId,
    scanId: attempt.scanId,
    packIds: attempt.packIds,
  });

  let result: T;
  try {
    result = await scan(resolution);
  } catch (error) {
    if (attempt.isFinalAttempt) {
      await report(service, attempt, "failed");
    }
    throw error;
  }
  await report(service, attempt, "succeeded");
  return result;
}

async function report(
  service: RulePackRolloutService,
  attempt: ScanAttempt,
  outcome: "succeeded" | "failed",
): Promise<void> {
  try {
    await service.recordScanOutcome({
      tenantId: attempt.tenantId,
      scanId: attempt.scanId,
      outcome,
    });
  } catch {
    // Already counted and logged by the service; the scan result stands.
  }
}
