// Local test harness for the Proof Gatekeeper service.
//
// Starts two in-process server instances on ephemeral ports with an
// ephemeral test HMAC secret (never a real secret):
//   A: REQUIRE_KURIER_FINALIZED=true, no KURIER_API_KEY
//      -> a valid task must be REJECT / PROOF_NOT_FINALIZED (fail closed).
//      (If KURIER_API_KEY *is* set in the environment, A submits for real
//      and a valid task must APPROVE after Finalized.)
//   B: REQUIRE_KURIER_FINALIZED=false, no KURIER_API_KEY
//      -> a valid task must APPROVE with a real, locally verifiable proof.
//      The harness re-verifies the returned proof against
//      circuits/verification_key.json and asserts the public-signal
//      mapping discovered in CIRCUIT.md.
//
// Every response signature is verified (HMAC over the raw response body).
// Every REJECT response is asserted to carry no proof fields.
//
// Usage: npm test
import * as fs from "node:fs";
import * as http from "node:http";
import * as os from "node:os";
import * as path from "node:path";
import * as crypto from "node:crypto";
import * as snarkjs from "snarkjs";
import { loadConfig, REGISTERED_VK_HASH, type GatekeeperConfig } from "../src/config";
import { createGatekeeperServer, listen, type RunningServer } from "../src/index";
import { signBody } from "../src/hmac";
import { FIELD_PRIME, taskIdToField } from "../src/prover";

const ROOT = path.join(__dirname, "..", "..");
const FIXTURES_DIR = path.join(ROOT, "test", "fixtures");
const VK_PATH = path.join(ROOT, "circuits", "verification_key.json");

const TEST_SECRET = "test-hmac-secret-do-not-use-in-production";
const FIELD_PRIME_BIG = FIELD_PRIME;

let failures = 0;
let passes = 0;

function check(name: string, cond: boolean, detail?: string): void {
  if (cond) {
    passes++;
    console.log(`  PASS ${name}`);
  } else {
    failures++;
    console.log(`  FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
}

interface Fixture {
  name: string;
  description?: string;
  type?: string;
  mode?: string;
  task_id?: string;
  deadlineOffsetSec?: number;
  input: Record<string, string>;
}

function loadFixture(file: string): Fixture {
  return JSON.parse(
    fs.readFileSync(path.join(FIXTURES_DIR, file), "utf8"),
  ) as Fixture;
}

function buildEnvelope(fixture: Fixture): Record<string, unknown> {
  const now = new Date();
  const deadlineOffsetSec = fixture.deadlineOffsetSec ?? 120;
  return {
    type: fixture.type ?? "agent-games.proof-gatekeeper.v1",
    task_id: fixture.task_id ?? `gk_test_${fixture.name}`,
    mode: fixture.mode ?? "competition",
    issued_at: now.toISOString(),
    deadline_at: new Date(now.getTime() + deadlineOffsetSec * 1000).toISOString(),
    input: fixture.input,
  };
}

interface HttpResult {
  status: number;
  headers: http.IncomingHttpHeaders;
  raw: Buffer;
  json: unknown;
}

function request(
  port: number,
  method: string,
  pathName: string,
  body: Buffer | null,
  extraHeaders: Record<string, string> = {},
): Promise<HttpResult> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: "127.0.0.1",
        port,
        path: pathName,
        method,
        headers: {
          ...(body !== null
            ? {
                "Content-Type": "application/json",
                "Content-Length": body.length,
              }
            : {}),
          ...extraHeaders,
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () => {
          const raw = Buffer.concat(chunks);
          let json: unknown = null;
          try {
            json = JSON.parse(raw.toString("utf8")) as unknown;
          } catch {
            // leave json null
          }
          resolve({ status: res.statusCode ?? 0, headers: res.headers, raw, json });
        });
      },
    );
    req.setTimeout(65_000, () => req.destroy(new Error("request timeout")));
    req.on("error", reject);
    if (body !== null) req.write(body);
    req.end();
  });
}

function postSigned(
  port: number,
  bodyObject: unknown,
  secret: string,
): Promise<HttpResult> {
  const raw = Buffer.from(JSON.stringify(bodyObject), "utf8");
  return request(port, "POST", "/agent", raw, {
    "x-agent-games-signature": signBody(Buffer.from(secret, "utf8"), raw),
  });
}

function verifyResponseSignature(
  result: HttpResult,
  secret: string,
): boolean {
  const header = result.headers["x-agent-games-signature"];
  if (typeof header !== "string") return false;
  const expected = signBody(Buffer.from(secret, "utf8"), result.raw);
  try {
    const a = Buffer.from(header, "hex");
    const b = Buffer.from(expected, "hex");
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

function decisionOf(result: HttpResult): { decision?: unknown; reasonCode?: unknown } {
  const json = result.json as Record<string, unknown> | null;
  if (json === null || typeof json !== "object") return {};
  return { decision: json.decision, reasonCode: json.reason_code };
}

async function startInstance(
  requireFinalized: boolean,
  kurierKey: string,
): Promise<{ running: RunningServer; port: number }> {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "gk-test-"));
  process.env.AGENT_GAMES_HMAC_SECRET = TEST_SECRET;
  process.env.GATEKEEPER_TEST_MODE = "true";
  process.env.GATEKEEPER_DATA_DIR = dataDir;
  process.env.REQUIRE_KURIER_FINALIZED = requireFinalized ? "true" : "false";
  process.env.KURIER_API_KEY = kurierKey;
  process.env.PORT = "0";
  const config: GatekeeperConfig = loadConfig({ baseDir: ROOT });
  const running = createGatekeeperServer(config);
  const port = await listen(running, 0, "127.0.0.1");
  return { running, port };
}

async function stopInstance(running: RunningServer): Promise<void> {
  await new Promise<void>((resolve) => {
    running.server.close(() => resolve());
  });
}

async function main(): Promise<void> {
  console.log("== Proof Gatekeeper test harness ==");
  const kurierConfigured = (process.env.KURIER_API_KEY ?? "") !== "";
  console.log(
    `Kurier key present in harness env: ${kurierConfigured} ` +
      `(instance A expects ${kurierConfigured ? "APPROVE (live Kurier)" : "PROOF_NOT_FINALIZED"})`,
  );

  const valid = loadFixture("valid.json");
  const vKey = JSON.parse(fs.readFileSync(VK_PATH, "utf8")) as unknown;

  // ---------- Instance A: require Finalized, Kurier as configured ----------
  const a = await startInstance(true, process.env.KURIER_API_KEY ?? "");
  try {
    console.log(`\n[instance A] port ${a.port} (requireFinalized=true)`);

    // health
    {
      const res = await request(a.port, "GET", "/health", null);
      check("A health 200 {ok:true}", res.status === 200 && (res.json as { ok?: unknown })?.ok === true);
    }

    // preflight
    {
      const res = await postSigned(a.port, {
        type: "agent-games.preflight.v1",
        agent_id: "agt_test",
        issued_at: new Date().toISOString(),
        nonce: "abc123",
      }, TEST_SECRET);
      const json = res.json as Record<string, unknown> | null;
      check("A preflight 200 {ok:true,protocolVersion:v1}",
        res.status === 200 && json?.ok === true && json?.protocolVersion === "v1");
      check("A preflight response signature valid", verifyResponseSignature(res, TEST_SECRET));
    }

    // bad HMAC
    {
      const res = await postSigned(a.port, buildEnvelope(valid), "wrong-secret");
      check("A bad HMAC -> 401 invalid_signature",
        res.status === 401 && (res.json as { error?: unknown })?.error === "invalid_signature");
      check("A 401 response is signed", verifyResponseSignature(res, TEST_SECRET));
    }

    // trap matrix
    const traps: Array<{ file: string; reason: string }> = [
      { file: "vk-substitution.json", reason: "VK_SUBSTITUTION" },
      { file: "insufficient-balance.json", reason: "INSUFFICIENT_BALANCE" },
      { file: "amount-exceeds-max.json", reason: "AMOUNT_EXCEEDS_MAX" },
      { file: "recipient-mismatch.json", reason: "RECIPIENT_MISMATCH" },
      { file: "expired.json", reason: "EXPIRED" },
      { file: "wrong-type.json", reason: "INVALID_ENVELOPE" },
      { file: "past-deadline.json", reason: "DEADLINE_PASSED" },
    ];
    for (const trap of traps) {
      const fixture = loadFixture(trap.file);
      const res = await postSigned(a.port, buildEnvelope(fixture), TEST_SECRET);
      const { decision, reasonCode } = decisionOf(res);
      check(
        `A ${fixture.name} -> REJECT/${trap.reason}`,
        res.status === 200 && decision === "REJECT" && reasonCode === trap.reason,
        `got ${decision}/${String(reasonCode)}`,
      );
      check(`A ${fixture.name} response signature valid`, verifyResponseSignature(res, TEST_SECRET));
      const json = res.json as Record<string, unknown> | null;
      check(`A ${fixture.name} carries no proof fields`,
        json !== null && !("proof" in json) && !("public_signals" in json));
    }

    // valid task on A
    {
      const res = await postSigned(a.port, buildEnvelope(valid), TEST_SECRET);
      const { decision, reasonCode } = decisionOf(res);
      if (kurierConfigured) {
        check("A valid -> APPROVE (live Kurier Finalized)",
          res.status === 200 && decision === "APPROVE" && reasonCode === "OK",
          `got ${decision}/${String(reasonCode)}`);
      } else {
        check("A valid -> REJECT/PROOF_NOT_FINALIZED (no Kurier key, fail closed)",
          res.status === 200 && decision === "REJECT" && reasonCode === "PROOF_NOT_FINALIZED",
          `got ${decision}/${String(reasonCode)}`);
      }
      check("A valid response signature valid", verifyResponseSignature(res, TEST_SECRET));
    }
  } finally {
    await stopInstance(a.running);
  }

  // ---------- Instance B: Finalized not required -> real APPROVE ----------
  const b = await startInstance(false, "");
  try {
    console.log(`\n[instance B] port ${b.port} (requireFinalized=false)`);

    // valid task -> APPROVE with a verifiable proof
    const res = await postSigned(b.port, buildEnvelope(valid), TEST_SECRET);
    const { decision, reasonCode } = decisionOf(res);
    check("B valid -> APPROVE/OK",
      res.status === 200 && decision === "APPROVE" && reasonCode === "OK",
      `got ${decision}/${String(reasonCode)}`);
    check("B valid response signature valid", verifyResponseSignature(res, TEST_SECRET));
    const json = res.json as Record<string, unknown> | null;
    const proof = json?.proof as snarkjs.Groth16Proof | undefined;
    const publicSignals = json?.public_signals as string[] | undefined;
    check("B APPROVE carries proof + public_signals",
      proof !== undefined && Array.isArray(publicSignals) && publicSignals.length === 13);
    if (proof !== undefined && Array.isArray(publicSignals)) {
      const verified = await snarkjs.groth16.verify(vKey, publicSignals, proof);
      check("B returned proof verifies against circuits/verification_key.json", verified === true);

      // Public-signal mapping (see CIRCUIT.md).
      const input = valid.input;
      const mustStr = (value: string | undefined, label: string): string => {
        if (typeof value !== "string") throw new Error(`fixture missing ${label}`);
        return value;
      };
      const vkMod = (BigInt(REGISTERED_VK_HASH) % FIELD_PRIME_BIG).toString(10);
      const recipientDec = BigInt(mustStr(input.recipient, "recipient")).toString(10);
      const expected: Array<[number, string, string]> = [
        [1, "proofVkHash mod p", vkMod],
        [2, "registeredVkHash mod p", vkMod],
        [3, "minimum", mustStr(input.minimum, "minimum")],
        [4, "publicBalance", mustStr(input.public_balance, "public_balance")],
        [5, "expiryBlock", mustStr(input.expiry_block, "expiry_block")],
        [6, "currentBlock", mustStr(input.current_block, "current_block")],
        [7, "recipient", recipientDec],
        [8, "conditionRecipient", recipientDec],
        [9, "amount", mustStr(input.amount, "amount")],
        [10, "maxTransfer", mustStr(input.max_transfer, "max_transfer")],
        [11, "decision", "1"],
        [12, "taskId (sha256 of task_id string, mod p)", taskIdToField(mustStr(valid.task_id, "task_id")).toString(10)],
      ];
      for (const [index, label, value] of expected) {
        check(`B publicSignals[${index}] = ${label} (${value})`,
          publicSignals[index] === value,
          `got ${String(publicSignals[index])}`);
      }
      check("B publicSignals[0] is a non-empty field element",
        typeof publicSignals[0] === "string" && /^[0-9]+$/.test(publicSignals[0] ?? ""));
      check("B proof_tx echoes the envelope",
        json?.proof_tx === input.proof_tx);
    }

    // same proof_tx again -> reuse
    {
      const res2 = await postSigned(b.port, buildEnvelope(valid), TEST_SECRET);
      const d2 = decisionOf(res2);
      check("B reused proof_tx -> REJECT/PROOF_TX_REUSED",
        res2.status === 200 && d2.decision === "REJECT" && d2.reasonCode === "PROOF_TX_REUSED",
        `got ${String(d2.decision)}/${String(d2.reasonCode)}`);
      check("B reuse response signature valid", verifyResponseSignature(res2, TEST_SECRET));
    }
  } finally {
    await stopInstance(b.running);
  }

  console.log(`\n${passes} passed, ${failures} failed.`);
  if (failures > 0) {
    console.log("HARNESS FAILED");
    process.exit(1);
  }
  console.log("HARNESS PASSED");
  // snarkjs leaves the event loop alive after proving; exit explicitly.
  process.exit(0);
}

main().catch((err: unknown) => {
  console.error("Harness crashed:", err instanceof Error ? err.stack ?? err.message : String(err));
  process.exit(1);
});
