// Persistent replay store for proof_tx values.
// A proof reference must never be reused for a second task (Security
// checklist). Values are marked used ONLY when we APPROVE, and the record
// is kept for later dispute resolution.
//
// Storage: a single JSON file under the data directory. Writes are atomic
// (write to a temp file, then rename) so a crash cannot corrupt the store.
import * as fs from "node:fs";
import * as path from "node:path";
import { info, warn } from "./logger";

export interface UsedProofTxEntry {
  taskId: string;
  usedAt: string;
  decision: "APPROVE";
}

export class ReplayStore {
  private readonly filePath: string;
  private readonly entries: Map<string, UsedProofTxEntry> = new Map();

  constructor(dataDir: string) {
    this.filePath = path.join(dataDir, "used-proof-tx.json");
    this.load();
  }

  private load(): void {
    try {
      if (!fs.existsSync(this.filePath)) return;
      const raw = fs.readFileSync(this.filePath, "utf8");
      const parsed: unknown = JSON.parse(raw);
      if (parsed !== null && typeof parsed === "object") {
        for (const [key, value] of Object.entries(
          parsed as Record<string, unknown>,
        )) {
          if (
            value !== null &&
            typeof value === "object" &&
            typeof (value as UsedProofTxEntry).taskId === "string" &&
            typeof (value as UsedProofTxEntry).usedAt === "string"
          ) {
            this.entries.set(key, value as UsedProofTxEntry);
          }
        }
      }
      info("replay_store_loaded", { entries: this.entries.size });
    } catch (err) {
      // A corrupt store must not block startup, but it must not silently
      // forget used references either: fail LOUDLY in the log and start
      // with an empty in-memory set. The operator must reconcile the file.
      warn("replay_store_load_failed_starting_empty", {
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  private persist(): void {
    try {
      fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
      const tmp = `${this.filePath}.tmp-${process.pid}`;
      fs.writeFileSync(
        tmp,
        JSON.stringify(Object.fromEntries(this.entries), null, 2),
        "utf8",
      );
      fs.renameSync(tmp, this.filePath);
    } catch (err) {
      warn("replay_store_persist_failed", {
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  /** Normalised (lowercase) lookup. */
  isUsed(proofTx: string): boolean {
    return this.entries.has(normalize(proofTx));
  }

  /**
   * Mark a proof_tx as used by an APPROVED task. Call only on APPROVE.
   * Returns false if it was already used (the caller must REJECT instead).
   */
  markUsed(proofTx: string, taskId: string): boolean {
    const key = normalize(proofTx);
    if (this.entries.has(key)) return false;
    this.entries.set(key, {
      taskId,
      usedAt: new Date().toISOString(),
      decision: "APPROVE",
    });
    this.persist();
    return true;
  }

  get size(): number {
    return this.entries.size;
  }
}

export function normalize(proofTx: string): string {
  return proofTx.trim().toLowerCase();
}
