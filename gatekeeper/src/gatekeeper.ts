// Deterministic decision logic for Proof Gatekeeper.
//
// APPROVE only when EVERY check on the /build Security checklist passes.
// Anything else is REJECT with a reason_code. No language model is involved
// in the final call: every rule below is plain code over the envelope.
//
// Order of checks (cheapest first; proof generation is last and only runs
// when all deterministic checks already passed):
//   1. envelope structure            -> INVALID_ENVELOPE
//   2. deadline still open           -> DEADLINE_PASSED
//   3. vk hashes match the platform-registered hash -> VK_SUBSTITUTION
//   4. balance / amount / recipient / expiry -> INSUFFICIENT_BALANCE,
//      AMOUNT_EXCEEDS_MAX, RECIPIENT_MISMATCH, EXPIRED
//   5. proof_tx present and unused   -> PROOF_TX_REUSED
//   6. local Groth16 proof generates and verifies -> PROOF_GENERATION_FAILED
//   7. Kurier Finalized (when required) -> PROOF_NOT_FINALIZED
//
// The proof_tx is marked used only at the moment we APPROVE — after the
// proof is locally verified and (when required) Kurier reports Finalized.
import type { Groth16Proof } from "snarkjs";
import {
  CLOCK_SKEW_MS,
  type GatekeeperConfig,
} from "./config";
import { generateAndVerifyProof, buildCircuitInput, type TaskNumbers } from "./prover";
import { pollUntilFinalized, submitProof } from "./kurier";
import type { ReplayStore } from "./replay";
import { info, warn } from "./logger";

export type ReasonCode =
  | "OK"
  | "INVALID_ENVELOPE"
  | "DEADLINE_PASSED"
  | "VK_SUBSTITUTION"
  | "INSUFFICIENT_BALANCE"
  | "AMOUNT_EXCEEDS_MAX"
  | "RECIPIENT_MISMATCH"
  | "EXPIRED"
  | "PROOF_TX_REUSED"
  | "PROOF_GENERATION_FAILED"
  | "PROOF_NOT_FINALIZED"
  | "INTERNAL_ERROR";

export const TASK_TYPE = "agent-games.proof-gatekeeper.v1";
export const PREFLIGHT_TYPE = "agent-games.preflight.v1";

export interface TaskEnvelope {
  type: string;
  task_id: string;
  mode: string;
  issued_at: string;
  deadline_at: string;
  input: {
    registered_vk: string;
    proof_vk: string;
    minimum: string | number;
    public_balance: string | number;
    expiry_block: string | number;
    current_block: string | number;
    recipient: string;
    condition_recipient: string;
    amount: string | number;
    max_transfer: string | number;
    proof_tx: string;
  };
}

export interface DecisionOutcome {
  decision: "APPROVE" | "REJECT";
  reasonCode: ReasonCode;
  /** Present only on APPROVE. */
  proof?: Groth16Proof;
  /** Present only on APPROVE. */
  publicSignals?: string[];
  /** Echo of input.proof_tx when the envelope had one. */
  proofTx?: string;
  /** Kurier job id when a proof was submitted. */
  kurierJobId?: string;
  /** True when Kurier reported Finalized for this task's proof. */
  kurierFinalized?: boolean;
}

export interface EvaluationDeps {
  config: GatekeeperConfig;
  replay: ReplayStore;
}

const HEX_ADDRESS = /^0x[0-9a-fA-F]+$/;

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function toBigInt(value: unknown): bigint | null {
  if (typeof value === "bigint") return value;
  if (typeof value === "number") {
    if (!Number.isInteger(value) || value < 0) return null;
    return BigInt(value);
  }
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (/^-?\d+$/.test(trimmed)) {
      try {
        const n = BigInt(trimmed);
        return n >= 0n ? n : null;
      } catch {
        return null;
      }
    }
    if (HEX_ADDRESS.test(trimmed)) {
      try {
        return BigInt(trimmed);
      } catch {
        return null;
      }
    }
  }
  return null;
}

/** Validate the envelope shape and extract typed values (or reject). */
function parseEnvelope(
  body: unknown,
): { envelope: TaskEnvelope; numbers: TaskNumbers } | { reason: ReasonCode } {
  if (!isObject(body)) return { reason: "INVALID_ENVELOPE" };
  if (body.type !== TASK_TYPE) return { reason: "INVALID_ENVELOPE" };
  if (typeof body.task_id !== "string" || body.task_id.length === 0) {
    return { reason: "INVALID_ENVELOPE" };
  }
  if (body.mode !== "competition" && body.mode !== "practice") {
    return { reason: "INVALID_ENVELOPE" };
  }
  if (typeof body.issued_at !== "string" || typeof body.deadline_at !== "string") {
    return { reason: "INVALID_ENVELOPE" };
  }
  if (!isObject(body.input)) return { reason: "INVALID_ENVELOPE" };
  const input = body.input;

  const numbers: Partial<TaskNumbers> = {};
  const intFields: Array<[string, keyof TaskNumbers]> = [
    ["minimum", "minimum"],
    ["public_balance", "publicBalance"],
    ["amount", "amount"],
    ["max_transfer", "maxTransfer"],
    ["expiry_block", "expiryBlock"],
    ["current_block", "currentBlock"],
  ];
  for (const [field, key] of intFields) {
    const value = toBigInt(input[field]);
    if (value === null) return { reason: "INVALID_ENVELOPE" };
    numbers[key] = value;
  }

  const recipient = input.recipient;
  const conditionRecipient = input.condition_recipient;
  if (
    typeof recipient !== "string" ||
    !HEX_ADDRESS.test(recipient) ||
    typeof conditionRecipient !== "string" ||
    !HEX_ADDRESS.test(conditionRecipient)
  ) {
    return { reason: "INVALID_ENVELOPE" };
  }
  numbers.recipient = BigInt(recipient);
  numbers.conditionRecipient = BigInt(conditionRecipient);

  const registeredVk = input.registered_vk;
  const proofVk = input.proof_vk;
  if (
    typeof registeredVk !== "string" ||
    !/^0x[0-9a-fA-F]{64}$/.test(registeredVk) ||
    typeof proofVk !== "string" ||
    !/^0x[0-9a-fA-F]{64}$/.test(proofVk)
  ) {
    return { reason: "INVALID_ENVELOPE" };
  }
  numbers.registeredVkHash = BigInt(registeredVk);
  numbers.proofVkHash = BigInt(proofVk);

  if (
    typeof input.proof_tx !== "string" ||
    input.proof_tx.trim().length === 0 ||
    !HEX_ADDRESS.test(input.proof_tx.trim())
  ) {
    return { reason: "INVALID_ENVELOPE" };
  }

  const envelope = body as unknown as TaskEnvelope;
  return { envelope, numbers: numbers as TaskNumbers };
}

function reject(reasonCode: ReasonCode, proofTx?: string): DecisionOutcome {
  const outcome: DecisionOutcome = { decision: "REJECT", reasonCode };
  if (proofTx !== undefined && proofTx !== "") outcome.proofTx = proofTx;
  return outcome;
}

/**
 * Evaluate one task envelope. `deadlineMs` is the absolute wall-clock
 * deadline for all remaining work (proving + Kurier), already capped to
 * min(envelope deadline - 2s, receipt + 55s) by the caller.
 */
export async function evaluateTask(
  body: unknown,
  deps: EvaluationDeps,
  deadlineMs: number,
): Promise<DecisionOutcome> {
  const { config, replay } = deps;
  const startedAt = Date.now();
  const finishLog = (outcome: DecisionOutcome, taskId: string | undefined) => {
    info("task_decided", {
      taskId: taskId ?? "?",
      decision: outcome.decision,
      reasonCode: outcome.reasonCode,
      durationMs: Date.now() - startedAt,
      ...(outcome.kurierJobId ? { kurierJobId: outcome.kurierJobId } : {}),
      ...(outcome.kurierFinalized !== undefined
        ? { kurierFinalized: outcome.kurierFinalized }
        : {}),
    });
    return outcome;
  };

  // 1. Structure.
  const parsed = parseEnvelope(body);
  if ("reason" in parsed) {
    const proofTx =
      isObject(body) && isObject(body.input) && typeof body.input.proof_tx === "string"
        ? body.input.proof_tx
        : undefined;
    return finishLog(reject(parsed.reason, proofTx), undefined);
  }
  const { envelope, numbers } = parsed;
  const taskId = envelope.task_id;
  const proofTx = envelope.input.proof_tx.trim();

  // 2. Timestamps: issued_at must parse and not be absurdly in the future;
  //    the deadline must still be open (with the 2 s safety margin the
  //    caller already applied — re-check here in case of queueing delay).
  const issuedMs = Date.parse(envelope.issued_at);
  const deadlineAtMs = Date.parse(envelope.deadline_at);
  if (!Number.isFinite(issuedMs) || !Number.isFinite(deadlineAtMs)) {
    return finishLog(reject("INVALID_ENVELOPE", proofTx), taskId);
  }
  if (issuedMs > Date.now() + CLOCK_SKEW_MS) {
    return finishLog(reject("INVALID_ENVELOPE", proofTx), taskId);
  }
  if (Date.now() > deadlineAtMs - 2000 || Date.now() > deadlineMs) {
    return finishLog(reject("DEADLINE_PASSED", proofTx), taskId);
  }

  // 3. Verification keys: BOTH must equal the platform-registered hash.
  //    Never trust a key that arrives inside the request.
  const registeredVk = config.registeredVkHash;
  if (
    envelope.input.registered_vk.toLowerCase() !== registeredVk ||
    envelope.input.proof_vk.toLowerCase() !== registeredVk
  ) {
    return finishLog(reject("VK_SUBSTITUTION", proofTx), taskId);
  }

  // 4. Business rules (all BigInt, exact).
  if (numbers.publicBalance < numbers.minimum) {
    return finishLog(reject("INSUFFICIENT_BALANCE", proofTx), taskId);
  }
  if (numbers.amount <= 0n || numbers.amount > numbers.maxTransfer) {
    return finishLog(reject("AMOUNT_EXCEEDS_MAX", proofTx), taskId);
  }
  if (numbers.recipient !== numbers.conditionRecipient) {
    return finishLog(reject("RECIPIENT_MISMATCH", proofTx), taskId);
  }
  if (numbers.expiryBlock <= numbers.currentBlock) {
    return finishLog(reject("EXPIRED", proofTx), taskId);
  }

  // 5. Proof reference: present and never reused.
  if (replay.isUsed(proofTx)) {
    return finishLog(reject("PROOF_TX_REUSED", proofTx), taskId);
  }

  // 6. Local Groth16 proof (decision = APPROVE) + local verification.
  const circuitInput = buildCircuitInput(numbers, taskId, 1);
  let generated;
  try {
    generated = await withDeadline(
      generateAndVerifyProof(config, circuitInput),
      deadlineMs,
      "PROOF_GENERATION_FAILED",
    );
  } catch {
    return finishLog(reject("PROOF_GENERATION_FAILED", proofTx), taskId);
  }

  // 7. Kurier submission + Finalized (when required).
  let kurierJobId: string | undefined;
  let kurierFinalized: boolean | undefined;
  if (config.kurierApiKey === "") {
    warn("kurier_unconfigured", { taskId });
    if (config.requireKurierFinalized) {
      return finishLog(reject("PROOF_NOT_FINALIZED", proofTx), taskId);
    }
    // No Kurier configured and finality not required: the locally verified
    // proof stands on its own; the submission step is skipped.
  } else {
    try {
      const submitted = await withDeadline(
        submitProof(
          config.kurierApiKey,
          generated.proof,
          generated.publicSignals,
          config.registeredVkHash,
        ),
        deadlineMs,
        "PROOF_NOT_FINALIZED",
      );
      kurierJobId = submitted.jobId;
    } catch {
      return finishLog(
        reject("PROOF_NOT_FINALIZED", proofTx),
        taskId,
      );
    }
    if (config.requireKurierFinalized) {
      const poll = await pollUntilFinalized(
        config.kurierApiKey,
        kurierJobId,
        config.kurierPollBudgetMs,
        config.kurierPollIntervalMs,
        deadlineMs,
      );
      kurierFinalized = poll.finalized;
      if (!poll.finalized) {
        return finishLog(reject("PROOF_NOT_FINALIZED", proofTx), taskId);
      }
    }
  }

  // All checks passed: mark the proof reference used, then APPROVE.
  if (!replay.markUsed(proofTx, taskId)) {
    // Lost a race with an identical proof_tx (should be impossible with
    // serialised handling, but fail closed all the same).
    return finishLog(reject("PROOF_TX_REUSED", proofTx), taskId);
  }
  return finishLog(
    {
      decision: "APPROVE",
      reasonCode: "OK",
      proof: generated.proof,
      publicSignals: generated.publicSignals,
      proofTx,
      kurierJobId,
      kurierFinalized,
    },
    taskId,
  );
}

/** Race a promise against an absolute deadline; on timeout throw `error`. */
export async function withDeadline<T>(
  promise: Promise<T>,
  deadlineMs: number,
  error: string,
): Promise<T> {
  const remaining = deadlineMs - Date.now();
  if (remaining <= 0) throw new Error(error);
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, rejectTimeout) => {
        timer = setTimeout(() => rejectTimeout(new Error(error)), remaining);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}
