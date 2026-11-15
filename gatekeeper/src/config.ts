// Environment configuration. All secrets come from the environment only.
// Never hardcode or log a secret value.
export interface GatekeeperConfig {
  /** TCP port to listen on. */
  port: number;
  /** HMAC secret from the Agent Games dashboard ("Rotate Secret"). UTF-8 bytes. */
  hmacSecret: Buffer;
  /** Kurier API key (mainnet). Empty string = Kurier unconfigured. */
  kurierApiKey: string;
  /** When true, APPROVE requires the Kurier job to reach "Finalized". */
  requireKurierFinalized: boolean;
  /** Max ms spent polling Kurier for Finalized (must fit inside the 60 s task deadline). */
  kurierPollBudgetMs: number;
  /** Poll interval for Kurier job status. */
  kurierPollIntervalMs: number;
  /** The platform's registered gatekeeper verification-key hash (from /api/circuit-info). */
  registeredVkHash: string;
  /** Absolute paths to the circuit artifacts. */
  wasmPath: string;
  zkeyPath: string;
  verificationKeyPath: string;
  /** Directory holding the persistent replay store (used proof_tx values). */
  dataDir: string;
  /** Wall-clock cap for reading a request body. */
  maxBodyBytes: number;
  /** True when running under the local test harness. */
  testMode: boolean;
}

export const REGISTERED_VK_HASH =
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";

/** Hard response deadline enforced by the platform (60 s). */
export const HARD_DEADLINE_MS = 60_000;
/** Safety margin: never plan work past deadline - this. */
export const DEADLINE_SAFETY_MS = 2_000;
/** Clock-skew tolerance when judging timestamps. */
export const CLOCK_SKEW_MS = 5_000;

function envInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n) || n < 0) {
    throw new Error(`Invalid integer for ${name}: ${JSON.stringify(raw)}`);
  }
  return n;
}

function envBool(name: string, fallback: boolean): boolean {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  if (raw === "true") return true;
  if (raw === "false") return false;
  throw new Error(`Invalid boolean for ${name}: ${JSON.stringify(raw)}`);
}

export interface LoadConfigOptions {
  /** When false (production default), a missing HMAC secret is fatal. */
  allowMissingHmacSecret?: boolean;
  /** Base directory for resolving relative artifact/data paths. Defaults to process.cwd(). */
  baseDir?: string;
}

/**
 * Load and validate configuration. Throws on any invalid value.
 * In production a missing AGENT_GAMES_HMAC_SECRET is fatal: the service
 * must never run in a mode where it cannot verify inbound signatures.
 */
export function loadConfig(options: LoadConfigOptions = {}): GatekeeperConfig {
  const baseDir = options.baseDir ?? process.cwd();
  const path = require("node:path") as typeof import("node:path");

  const secret = process.env.AGENT_GAMES_HMAC_SECRET ?? "";
  if (secret === "" && !options.allowMissingHmacSecret) {
    throw new Error(
      "AGENT_GAMES_HMAC_SECRET is not set. Refusing to start: the service cannot verify inbound signatures without it. " +
        "Copy .env.example to .env and fill in the secret from the Agent Games dashboard (Rotate Secret).",
    );
  }

  const vkHash = (
    process.env.GATEKEEPER_VK_HASH ?? REGISTERED_VK_HASH
  ).toLowerCase();
  if (!/^0x[0-9a-f]{64}$/.test(vkHash)) {
    throw new Error(
      `GATEKEEPER_VK_HASH must be a 0x-prefixed 32-byte hex string, got ${JSON.stringify(vkHash)}`,
    );
  }
  if (vkHash !== REGISTERED_VK_HASH) {
    // The registered hash is a protocol constant from /api/circuit-info.
    // Refuse to run against a different one — a wrong constant would make
    // every proof fail the platform's re-verification.
    throw new Error(
      "GATEKEEPER_VK_HASH does not match the platform-registered gatekeeper " +
        `vk hash ${REGISTERED_VK_HASH}. Refusing to start.`,
    );
  }

  const kurierPollBudgetMs = envInt("KURIER_POLL_BUDGET_MS", 40_000);
  if (kurierPollBudgetMs >= HARD_DEADLINE_MS - DEADLINE_SAFETY_MS) {
    throw new Error(
      `KURIER_POLL_BUDGET_MS (${kurierPollBudgetMs}) must leave room inside the 60 s task deadline.`,
    );
  }

  return {
    port: envInt("PORT", 3000),
    hmacSecret: Buffer.from(secret, "utf8"),
    kurierApiKey: process.env.KURIER_API_KEY ?? "",
    requireKurierFinalized: envBool("REQUIRE_KURIER_FINALIZED", true),
    kurierPollBudgetMs,
    kurierPollIntervalMs: envInt("KURIER_POLL_INTERVAL_MS", 2000),
    registeredVkHash: vkHash,
    wasmPath:
      process.env.GATEKEEPER_WASM_PATH ??
      path.join(baseDir, "circuits", "gatekeeper.wasm"),
    zkeyPath:
      process.env.GATEKEEPER_ZKEY_PATH ??
      path.join(baseDir, "circuits", "gatekeeper_final.zkey"),
    verificationKeyPath:
      process.env.GATEKEEPER_VK_PATH ??
      path.join(baseDir, "circuits", "verification_key.json"),
    dataDir: process.env.GATEKEEPER_DATA_DIR ?? path.join(baseDir, "data"),
    maxBodyBytes: envInt("MAX_BODY_BYTES", 1_048_576),
    testMode: envBool("GATEKEEPER_TEST_MODE", false),
  };
}
