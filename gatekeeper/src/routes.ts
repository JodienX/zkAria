// HTTP routing: GET /health and POST /agent.
//
// POST /agent flow:
//   1. Read the raw body (size-capped).
//   2. Verify x-agent-games-signature over the RAW body BEFORE parsing.
//      Mismatch -> 401 {"error":"invalid_signature"} (also signed).
//   3. Parse JSON. Unparseable -> 400 {"error":"invalid_json"} (signed).
//   4. Route by the `type` field:
//        - "agent-games.preflight.v1" -> 200 {"ok":true,"protocolVersion":"v1"} (signed)
//        - "agent-games.proof-gatekeeper.v1" (or any other object) -> the
//          deterministic decision pipeline; every decision response is
//          signed over its raw body.
//
// Tasks are handled strictly one at a time (a promise queue). The platform
// sends at most one live task per agent, and serialising keeps proof
// generation (CPU-heavy) from pushing another task past its deadline. A
// queued task whose deadline passes while waiting is rejected with
// DEADLINE_PASSED by the evaluator.
import * as http from "node:http";
import type { GatekeeperConfig } from "./config";
import { DEADLINE_SAFETY_MS, HARD_DEADLINE_MS } from "./config";
import { SIGNATURE_HEADER, signBody, verifySignature } from "./hmac";
import { evaluateTask, PREFLIGHT_TYPE, type DecisionOutcome } from "./gatekeeper";
import type { ReplayStore } from "./replay";
import { error as logError, info } from "./logger";

export interface RouteDeps {
  config: GatekeeperConfig;
  replay: ReplayStore;
}

function sendJson(
  res: http.ServerResponse,
  status: number,
  secret: Buffer,
  payload: unknown,
): void {
  const raw = Buffer.from(JSON.stringify(payload), "utf8");
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": raw.length,
    [SIGNATURE_HEADER]: signBody(secret, raw),
  });
  res.end(raw);
}

function sendUnsigned(
  res: http.ServerResponse,
  status: number,
  payload: unknown,
): void {
  const raw = Buffer.from(JSON.stringify(payload), "utf8");
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": raw.length,
  });
  res.end(raw);
}

function readRawBody(
  req: http.IncomingMessage,
  maxBytes: number,
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let overflowed = false;
    req.on("data", (chunk: Buffer) => {
      total += chunk.length;
      if (total > maxBytes) {
        overflowed = true;
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (overflowed) reject(new Error("BODY_TOO_LARGE"));
      else resolve(Buffer.concat(chunks));
    });
    req.on("error", reject);
  });
}

function decisionToResponse(outcome: DecisionOutcome): Record<string, unknown> {
  if (outcome.decision === "APPROVE") {
    return {
      decision: "APPROVE",
      reason_code: "OK",
      proof: outcome.proof,
      public_signals: outcome.publicSignals,
      proof_tx: outcome.proofTx,
    };
  }
  const response: Record<string, unknown> = {
    decision: "REJECT",
    reason_code: outcome.reasonCode,
  };
  if (outcome.proofTx !== undefined) response.proof_tx = outcome.proofTx;
  return response;
}

export function createRequestHandler(deps: RouteDeps): http.RequestListener {
  const { config, replay } = deps;

  // Serialisation queue for task handling (see module comment).
  let queue: Promise<void> = Promise.resolve();

  const handleTask = async (
    body: unknown,
    receiptMs: number,
  ): Promise<DecisionOutcome> => {
    // Budget: min(envelope deadline - 2s, receipt + 55s). When the envelope
    // has no parseable deadline, the receipt-based cap still applies.
    let deadlineMs = receiptMs + (HARD_DEADLINE_MS - 5000);
    try {
      const parsed = body as { deadline_at?: unknown };
      if (typeof parsed?.deadline_at === "string") {
        const at = Date.parse(parsed.deadline_at);
        if (Number.isFinite(at)) {
          deadlineMs = Math.min(at - DEADLINE_SAFETY_MS, deadlineMs);
        }
      }
    } catch {
      // Keep the receipt-based cap.
    }
    return evaluateTask(body, { config, replay }, deadlineMs);
  };

  return (req, res) => {
    void (async () => {
      try {
        const url = new URL(req.url ?? "/", "http://localhost");
        if (req.method === "GET" && url.pathname === "/health") {
          sendUnsigned(res, 200, { ok: true });
          return;
        }
        if (req.method !== "POST" || url.pathname !== "/agent") {
          sendUnsigned(res, 404, { error: "not_found" });
          return;
        }

        const receiptMs = Date.now();
        let raw: Buffer;
        try {
          raw = await readRawBody(req, config.maxBodyBytes);
        } catch (err) {
          if (err instanceof Error && err.message === "BODY_TOO_LARGE") {
            sendJson(res, 413, config.hmacSecret, { error: "body_too_large" });
          } else {
            sendJson(res, 400, config.hmacSecret, { error: "bad_request" });
          }
          return;
        }

        // HMAC verification BEFORE any JSON parsing.
        const signature = req.headers[SIGNATURE_HEADER];
        if (
          !verifySignature(
            config.hmacSecret,
            raw,
            typeof signature === "string" ? signature : undefined,
          )
        ) {
          sendJson(res, 401, config.hmacSecret, { error: "invalid_signature" });
          return;
        }

        let body: unknown;
        try {
          body = JSON.parse(raw.toString("utf8")) as unknown;
        } catch {
          sendJson(res, 400, config.hmacSecret, { error: "invalid_json" });
          return;
        }
        if (body === null || typeof body !== "object" || Array.isArray(body)) {
          sendJson(res, 400, config.hmacSecret, { error: "invalid_json" });
          return;
        }

        // Preflight handshake.
        if ((body as { type?: unknown }).type === PREFLIGHT_TYPE) {
          sendJson(res, 200, config.hmacSecret, {
            ok: true,
            protocolVersion: "v1",
          });
          return;
        }

        // Task handling, serialised through the queue.
        const run = queue.then(() => handleTask(body, receiptMs));
        queue = run.then(
          () => undefined,
          () => undefined,
        );
        let outcome: DecisionOutcome;
        try {
          outcome = await run;
        } catch (err) {
          logError("task_handler_error", {
            error: err instanceof Error ? err.message : String(err),
          });
          outcome = { decision: "REJECT", reasonCode: "INTERNAL_ERROR" };
        }
        sendJson(res, 200, config.hmacSecret, decisionToResponse(outcome));
      } catch (err) {
        // Last-resort catch: never leave a signed task hanging. If headers
        // are already sent there is nothing more we can do.
        logError("request_handler_error", {
          error: err instanceof Error ? err.message : String(err),
        });
        try {
          if (!res.headersSent) {
            sendJson(res, 500, config.hmacSecret, { error: "internal_error" });
          } else {
            res.end();
          }
        } catch {
          // ignore
        }
      }
    })();
  };
}

/** Create an http.Server without starting to listen (used by the harness). */
export function createServer(deps: RouteDeps): http.Server {
  const server = http.createServer(createRequestHandler(deps));
  server.headersTimeout = 65_000;
  server.requestTimeout = 65_000;
  return server;
}

export function logStartup(config: GatekeeperConfig, port: number): void {
  info("gatekeeper_listening", {
    port,
    kurierConfigured: config.kurierApiKey !== "",
    requireKurierFinalized: config.requireKurierFinalized,
    registeredVkHash: config.registeredVkHash,
  });
}
