// HMAC-SHA256 helpers for the Agent Games signature header.
// The header x-agent-games-signature is the hex HMAC-SHA256 of the RAW
// request/response body, keyed with AGENT_GAMES_HMAC_SECRET (UTF-8 bytes).
import * as crypto from "node:crypto";

export const SIGNATURE_HEADER = "x-agent-games-signature";

/** Hex HMAC-SHA256 of `body` under `secret`. */
export function signBody(secret: Buffer, body: Buffer): string {
  return crypto.createHmac("sha256", secret).update(body).digest("hex");
}

/**
 * Timing-safe verification of a hex signature against the expected HMAC.
 * Any malformed input (non-hex, wrong length) is a clean `false`, never a throw.
 */
export function verifySignature(
  secret: Buffer,
  body: Buffer,
  signature: string | undefined,
): boolean {
  if (typeof signature !== "string" || signature.length === 0) return false;
  if (!/^[0-9a-fA-F]+$/.test(signature)) return false;
  let provided: Buffer;
  try {
    provided = Buffer.from(signature, "hex");
  } catch {
    return false;
  }
  const expected = Buffer.from(signBody(secret, body), "hex");
  if (provided.length !== expected.length) return false;
  return crypto.timingSafeEqual(provided, expected);
}
