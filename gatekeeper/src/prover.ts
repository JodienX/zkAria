// Local Groth16 proving with snarkjs.
//
// Circuit input mapping — discovered empirically against
// circuits/gatekeeper.wasm (see CIRCUIT.md and scripts/probe-circuit-inputs.ts).
// The spec does not publish signal names; these were found by probing the
// wasm's input-signal table and verified by generating a proof that verifies
// against circuits/verification_key.json:
//
//   envelope input            circuit input signal
//   -------------------------  --------------------
//   input.public_balance      publicBalance
//   input.minimum             minimum
//   input.amount              amount
//   input.max_transfer        maxTransfer
//   input.recipient           recipient
//   input.condition_recipient conditionRecipient
//   input.expiry_block        expiryBlock
//   input.current_block       currentBlock
//   input.registered_vk       registeredVkHash
//   input.proof_vk            proofVkHash
//   (derived) decision        decision        (1 = APPROVE, 0 = REJECT)
//   (derived) task id         taskId          (see taskIdToField below)
//   (derived) per-task salt   salt            (see saltForTask below)
//
// Values that have no direct circuit counterpart and are NOT published in
// the spec are derived deterministically and documented here:
//  - taskId: the task_id string is hashed with SHA-256 and reduced mod the
//    BN128 field prime. The platform's own conversion (if any) is not
//    published; the value only needs to be stable per task for our proof.
//  - salt: SHA-256 of `${taskId}:gatekeeper-salt:v1`, reduced mod p. It
//    makes each task's proof distinct even when every other input is equal.
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as snarkjs from "snarkjs";
import type { GatekeeperConfig } from "./config";
import { error as logError } from "./logger";

/** BN128 (alt_bn128) field prime. */
export const FIELD_PRIME = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617",
);

export interface CircuitInput {
  publicBalance: bigint;
  minimum: bigint;
  amount: bigint;
  maxTransfer: bigint;
  recipient: bigint;
  conditionRecipient: bigint;
  expiryBlock: bigint;
  currentBlock: bigint;
  registeredVkHash: bigint;
  proofVkHash: bigint;
  decision: bigint;
  taskId: bigint;
  salt: bigint;
}

export interface TaskNumbers {
  publicBalance: bigint;
  minimum: bigint;
  amount: bigint;
  maxTransfer: bigint;
  recipient: bigint;
  conditionRecipient: bigint;
  expiryBlock: bigint;
  currentBlock: bigint;
  registeredVkHash: bigint;
  proofVkHash: bigint;
}

/** SHA-256 of a UTF-8 string, reduced mod the field prime. */
export function hashToField(input: string): bigint {
  const digest = crypto.createHash("sha256").update(input, "utf8").digest();
  return BigInt("0x" + digest.toString("hex")) % FIELD_PRIME;
}

export function taskIdToField(taskId: string): bigint {
  return hashToField(`gatekeeper:taskId:${taskId}`);
}

export function saltForTask(taskId: string): bigint {
  return hashToField(`gatekeeper:salt:v1:${taskId}`);
}

export function buildCircuitInput(
  numbers: TaskNumbers,
  taskId: string,
  decision: 0 | 1,
): CircuitInput {
  return {
    publicBalance: numbers.publicBalance,
    minimum: numbers.minimum,
    amount: numbers.amount,
    maxTransfer: numbers.maxTransfer,
    recipient: numbers.recipient,
    conditionRecipient: numbers.conditionRecipient,
    expiryBlock: numbers.expiryBlock,
    currentBlock: numbers.currentBlock,
    registeredVkHash: numbers.registeredVkHash,
    proofVkHash: numbers.proofVkHash,
    decision: BigInt(decision),
    taskId: taskIdToField(taskId),
    salt: saltForTask(taskId),
  };
}

export interface GeneratedProof {
  proof: snarkjs.Groth16Proof;
  publicSignals: string[];
}

/** Lazily loaded verification key (read once, reused). */
let cachedVk: unknown = null;

export function loadVerificationKey(config: GatekeeperConfig): unknown {
  if (cachedVk !== null) return cachedVk;
  const raw = fs.readFileSync(config.verificationKeyPath, "utf8");
  cachedVk = JSON.parse(raw) as unknown;
  return cachedVk;
}

/**
 * Generate a Groth16 proof for a full circuit input, then verify it locally
 * against the extracted verification key. A proof that fails local
 * verification is never sent anywhere: the caller must REJECT.
 *
 * snarkjs's fullProve input values must be JSON-safe: BigInts are accepted
 * (they are unstringified internally), but we pass decimal strings to be
 * explicit and to keep the input inspectable in logs if ever dumped.
 */
export async function generateAndVerifyProof(
  config: GatekeeperConfig,
  input: CircuitInput,
): Promise<GeneratedProof> {
  const snarkInput: Record<string, string> = {};
  for (const [key, value] of Object.entries(input)) {
    snarkInput[key] = (value as bigint).toString(10);
  }
  let result: { proof: snarkjs.Groth16Proof; publicSignals: string[] };
  try {
    result = await snarkjs.groth16.fullProve(
      snarkInput,
      config.wasmPath,
      config.zkeyPath,
    );
  } catch (err) {
    logError("proof_generation_failed", {
      error: err instanceof Error ? err.message : String(err),
    });
    throw new Error("PROOF_GENERATION_FAILED");
  }
  const vKey = loadVerificationKey(config);
  let ok = false;
  try {
    ok = await snarkjs.groth16.verify(vKey, result.publicSignals, result.proof);
  } catch (err) {
    logError("proof_local_verification_error", {
      error: err instanceof Error ? err.message : String(err),
    });
    throw new Error("PROOF_GENERATION_FAILED");
  }
  if (!ok) {
    logError("proof_local_verification_failed", {});
    throw new Error("PROOF_GENERATION_FAILED");
  }
  return { proof: result.proof, publicSignals: result.publicSignals };
}
