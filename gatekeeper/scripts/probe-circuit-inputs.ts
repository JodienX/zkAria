// Circuit input discovery for the gatekeeper circuit.
//
// The spec does not publish the circuit's witness input signal names, so
// they were discovered empirically against circuits/gatekeeper.wasm using
// the witness calculator's own behaviour:
//
//   - The wasm exports getInputSignalSize(fnvHash(name)) which returns 0
//     for unknown names (NOT -1). Passing a single scalar value therefore
//     throws "Too many values for input signal X" for UNKNOWN names.
//   - A name EXISTS iff the error is "Not all inputs have been set"
//     (scalar signal, size 1) or "Not enough values" (array signal).
//
// This script re-runs that classification over the candidate list, then
// generates a proof for the tournament's published example values and
// verifies it against circuits/verification_key.json.
//
// Usage: npm run probe
import { readFile } from "node:fs/promises";
import * as path from "node:path";
import { WitnessCalculatorBuilder } from "circom_runtime";
import * as snarkjs from "snarkjs";

const CIRCUITS_DIR = path.join(process.cwd(), "circuits");
const WASM_PATH = path.join(CIRCUITS_DIR, "gatekeeper.wasm");
const ZKEY_PATH = path.join(CIRCUITS_DIR, "gatekeeper_final.zkey");
const VK_PATH = path.join(CIRCUITS_DIR, "verification_key.json");

const VK_HASH =
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";

const CANDIDATES: string[] = [
  // balance
  "balance", "publicBalance", "public_balance", "publicbalance", "bal",
  "accountBalance", "account_balance", "currentBalance", "current_balance",
  // minimum
  "minimum", "minBalance", "min_balance", "minbalance", "min", "threshold",
  "minThreshold", "min_threshold", "requiredMinimum", "required_balance",
  "minRequired", "min_required",
  // amount
  "amount", "transferAmount", "transfer_amount", "transferamount", "value",
  "transferValue", "transfer_value",
  // max transfer
  "maxTransfer", "max_transfer", "maxtransfer", "maximum", "maxAmount",
  "max_amount", "maxamount", "max", "transferMax", "transfer_max",
  "maxTransferAmount",
  // recipient
  "recipient", "conditionRecipient", "condition_recipient",
  "conditionrecipient", "expectedRecipient", "expected_recipient",
  "expectedrecipient", "to", "target", "receiver", "payee", "toAddress",
  // expiry block
  "expiryBlock", "expiry_block", "expiryblock", "expiry", "expirationBlock",
  "expiration_block", "expireBlock", "deadline", "deadlineBlock",
  "deadline_block", "expiryHeight",
  // current block
  "currentBlock", "current_block", "currentblock", "blockNumber",
  "block_number", "blocknumber", "current", "now", "block",
  // vk hash
  "vkHash", "vk_hash", "vkhash", "registeredVk", "registered_vk",
  "registeredVkHash", "registered_vk_hash", "vk", "verificationKeyHash",
  "verification_key_hash", "expectedVkHash", "expected_vk_hash",
  "expectedVk", "vkHex", "proofVkHash", "proof_vk_hash", "proofVk",
  "proof_vk", "submittedVkHash", "providedVkHash", "inputVkHash",
  // task / salt
  "taskId", "task_id", "salt", "nonce", "taskSalt", "taskNonce",
  // decision
  "decision", "isValid", "valid", "approved", "isApproved", "approve",
  // control: definitely bogus
  "zzzz_not_a_signal",
];

async function probeNames(): Promise<string[]> {
  const wasm = await readFile(WASM_PATH);
  const wc = await WitnessCalculatorBuilder(wasm, { sanityCheck: false });
  const totalInputs = wc.instance.exports.getInputSize() as number;
  console.log(`circuit inputs expected: ${totalInputs}`);
  console.log(`witness size: ${wc.instance.exports.getWitnessSize() as number}`);

  const accepted: string[] = [];
  for (const name of CANDIDATES) {
    try {
      await wc.calculateWitness({ [name]: 1n }, false);
      // A full witness from one name would mean a 1-input circuit.
      accepted.push(name);
      console.log(`  ACCEPTED (full witness): ${name}`);
    } catch (err) {
      const msg =
        String((err as Error)?.message ?? err).trim().split("\n")[0] ?? "";
      if (msg.includes("Not all inputs") || msg.includes("Not enough values")) {
        accepted.push(name);
        console.log(`  ACCEPTED: ${name} (${msg})`);
      } else if (msg.includes("Too many values")) {
        // Unknown name: getInputSignalSize() returned 0 for it.
      } else {
        console.log(`  OTHER: ${name} — ${msg}`);
      }
    }
  }
  return accepted;
}

async function proveExample(): Promise<void> {
  const recipient = 0x1234567890abcdef1234567890abcdef12345678n;
  const vk = BigInt(VK_HASH);
  const input = {
    publicBalance: "1460",
    minimum: "1000",
    amount: "500",
    maxTransfer: "1000",
    recipient: recipient.toString(10),
    conditionRecipient: recipient.toString(10),
    expiryBlock: "8430000",
    currentBlock: "8420000",
    registeredVkHash: vk.toString(10),
    proofVkHash: vk.toString(10),
    decision: "1",
    taskId: "1",
    salt: "42",
  };
  const started = Date.now();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    input,
    WASM_PATH,
    ZKEY_PATH,
  );
  console.log(`\nfullProve OK in ${Date.now() - started} ms`);
  console.log(`publicSignals (${publicSignals.length}):`);
  publicSignals.forEach((s, i) => console.log(`  [${i}] ${s}`));
  const vKey = JSON.parse(await readFile(VK_PATH, "utf8")) as unknown;
  const ok = await snarkjs.groth16.verify(vKey, publicSignals, proof);
  console.log(`groth16.verify: ${ok}`);
  if (!ok) throw new Error("local proof verification FAILED");
}

async function main(): Promise<void> {
  console.log("== Gatekeeper circuit input discovery ==");
  const accepted = await probeNames();
  console.log(`\naccepted names (${accepted.length}): ${JSON.stringify(accepted)}`);
  console.log("\n== Example proof (tournament values, decision=1) ==");
  await proveExample();
  console.log("\nProbe PASSED: input names discovered and proof verifies.");
  // snarkjs leaves the event loop alive after proving; exit explicitly.
  process.exit(0);
}

main().catch((err: unknown) => {
  console.error("Probe FAILED:", err instanceof Error ? err.message : String(err));
  process.exit(1);
});
