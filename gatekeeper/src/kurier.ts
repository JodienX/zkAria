// Kurier REST client (zkVerify verification path recommended by /build).
//
// Endpoints (from the official zkVerify quickstart docs, which /build links
// as the source of truth; /build itself prints no job-status URL):
//   POST https://api.kurier.xyz/api/v1/submit-proof/${API_KEY}
//   GET  https://api.kurier.xyz/api/v1/job-status/${API_KEY}/${jobId}
//
// Request body (exactly as printed on /build):
//   {
//     "proofType": "groth16",
//     "vkRegistered": true,
//     "proofOptions": { "library": "snarkjs", "curve": "bn128" },
//     "proofData": { "proof": <snarkjs proof>, "publicSignals": [...], "vk": "<vk hash>" }
//   }
//
// `vkRegistered: true` is used because the gatekeeper vk is already
// registered on zkVerify mainnet (its hash is served by /api/circuit-info).
// The register-vk endpoint is not printed on /build, so no register call is
// implemented here.
//
// Only job ids and statuses are ever logged — never the API key.
import type { Groth16Proof } from "snarkjs";
import { error as logError, info } from "./logger";

export const KURIER_BASE = "https://api.kurier.xyz/api/v1";

/** Terminal job statuses reported by Kurier (per /build). */
export type KurierJobStatus =
  | "Submitted"
  | "IncludedInBlock"
  | "Finalized"
  | "Failed"
  | string;

export interface KurierSubmitResult {
  jobId: string;
}

const FETCH_TIMEOUT_MS = 15_000;

async function fetchWithTimeout(
  url: string,
  init: RequestInit,
  timeoutMs: number,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

function readJobId(body: unknown): string | null {
  if (body !== null && typeof body === "object") {
    const obj = body as Record<string, unknown>;
    for (const key of ["jobId", "job_id", "id"]) {
      const value = obj[key];
      if (typeof value === "string" && value.length > 0) return value;
    }
  }
  return null;
}

function readStatus(body: unknown): string | null {
  if (body !== null && typeof body === "object") {
    const obj = body as Record<string, unknown>;
    const candidates: unknown[] = [
      obj.status,
      obj.state,
      (obj.job as Record<string, unknown> | undefined)?.status,
      (obj.data as Record<string, unknown> | undefined)?.status,
    ];
    for (const value of candidates) {
      if (typeof value === "string" && value.length > 0) return value;
    }
  }
  return null;
}

/** Submit a locally verified proof. Returns the Kurier job id. */
export async function submitProof(
  apiKey: string,
  proof: Groth16Proof,
  publicSignals: string[],
  vkHash: string,
): Promise<KurierSubmitResult> {
  const url = `${KURIER_BASE}/submit-proof/${apiKey}`;
  let res: Response;
  try {
    res = await fetchWithTimeout(
      url,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          proofType: "groth16",
          vkRegistered: true,
          proofOptions: { library: "snarkjs", curve: "bn128" },
          proofData: { proof, publicSignals, vk: vkHash },
        }),
      },
      FETCH_TIMEOUT_MS,
    );
  } catch (err) {
    throw new Error(
      `Kurier submit failed: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  const text = await res.text();
  let body: unknown = null;
  try {
    body = JSON.parse(text) as unknown;
  } catch {
    // Non-JSON response: keep the raw text out of logs; treat as failure.
  }
  if (!res.ok) {
    logError("kurier_submit_rejected", { httpStatus: res.status });
    throw new Error(`Kurier submit rejected (HTTP ${res.status})`);
  }
  const jobId = readJobId(body);
  if (jobId === null) {
    logError("kurier_submit_no_job_id", { httpStatus: res.status });
    throw new Error("Kurier submit returned no job id");
  }
  info("kurier_job_submitted", { jobId });
  return { jobId };
}

/** Fetch one job status. Returns null when the response is unusable. */
export async function fetchJobStatus(
  apiKey: string,
  jobId: string,
): Promise<string | null> {
  const url = `${KURIER_BASE}/job-status/${apiKey}/${jobId}`;
  let res: Response;
  try {
    res = await fetchWithTimeout(url, { method: "GET" }, FETCH_TIMEOUT_MS);
  } catch {
    return null;
  }
  if (!res.ok) return null;
  try {
    const body: unknown = await res.json();
    return readStatus(body);
  } catch {
    return null;
  }
}

export interface PollOutcome {
  status: string;
  /** True only when the job reached "Finalized" inside the budget. */
  finalized: boolean;
  /** True when the job reported a terminal failure. */
  failed: boolean;
}

/**
 * Poll until the job is Finalized, fails, or the budget is exhausted.
 * `deadlineMs` is an absolute epoch-ms wall: polling stops at
 * min(budget end, deadlineMs). Returns the last seen status.
 */
export async function pollUntilFinalized(
  apiKey: string,
  jobId: string,
  budgetMs: number,
  intervalMs: number,
  deadlineMs: number,
): Promise<PollOutcome> {
  const start = Date.now();
  const budgetEnd = Math.min(start + budgetMs, deadlineMs);
  let lastStatus = "Submitted";
  for (;;) {
    const now = Date.now();
    if (now >= budgetEnd) {
      return { status: lastStatus, finalized: false, failed: false };
    }
    const status = await fetchJobStatus(apiKey, jobId);
    if (status !== null) {
      lastStatus = status;
      if (status === "Finalized") {
        info("kurier_job_finalized", { jobId });
        return { status, finalized: true, failed: false };
      }
      if (status === "Failed") {
        logError("kurier_job_failed", { jobId });
        return { status, finalized: false, failed: true };
      }
    }
    const remaining = budgetEnd - Date.now();
    if (remaining <= 0) break;
    await new Promise((resolve) =>
      setTimeout(resolve, Math.min(intervalMs, remaining)),
    );
  }
  return { status: lastStatus, finalized: false, failed: false };
}
