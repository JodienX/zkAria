# Proof Gatekeeper — zkVerify Agent Games (Season 01)

A production-ready public HTTPS endpoint that plays the **Proof Gatekeeper**
event in [zkVerify Agent Games](https://agentgames.zkverify.io/).

The platform POSTs signed transfer tasks to this service. The service
decides **APPROVE** or **REJECT** using deterministic code only, generates
a Groth16 zero-knowledge proof of the decision locally with snarkjs,
submits it to zkVerify (Kurier) until it is **Finalized**, and returns the
proof — signed — within the 60-second deadline.

The circuit is the referee: a proof for `decision = APPROVE` can only be
generated when every Security-checklist condition actually holds (verified
— see `CIRCUIT.md`). The service can never fake a decision.

## How it works

```
platform --signed task--> POST /agent
  1. HMAC-SHA256 over the RAW body, checked BEFORE parsing (401 on mismatch)
  2. Preflight? -> {"ok": true, "protocolVersion": "v1"} (signed)
  3. Task: deterministic checks, fail closed
       structure -> deadline -> vk hashes -> balance -> amount ->
       recipient -> expiry -> proof_tx replay
  4. Groth16 proof (snarkjs, local wasm/zkey) + local verification
  5. Kurier submit + poll until Finalized (when required)
  6. Mark proof_tx used, reply signed {decision, reason_code, proof,
     public_signals, proof_tx}
```

- `GET /health` returns `{"ok": true}` (unsigned).
- `POST /agent` is the registered endpoint path.
- Tasks are handled strictly one at a time; each is bounded by
  `min(deadline_at - 2s, receipt + 55s)`.

## Decision rules (deterministic, no model in the loop)

APPROVE only if **all** of these hold; otherwise REJECT with the code:

| check | reason_code on failure |
| --- | --- |
| envelope structure (`agent-games.proof-gatekeeper.v1`, task_id, mode, parseable fields/timestamps) | `INVALID_ENVELOPE` |
| deadline still open | `DEADLINE_PASSED` |
| `registered_vk` **and** `proof_vk` equal the platform-registered hash (never the key in the request) | `VK_SUBSTITUTION` |
| `public_balance >= minimum` | `INSUFFICIENT_BALANCE` |
| `0 < amount <= max_transfer` | `AMOUNT_EXCEEDS_MAX` |
| `recipient == condition_recipient` (case-insensitive hex) | `RECIPIENT_MISMATCH` |
| `expiry_block > current_block` | `EXPIRED` |
| `proof_tx` present, hex, never used before | `PROOF_TX_REUSED` |
| local Groth16 proof generates **and** verifies | `PROOF_GENERATION_FAILED` |
| Kurier job reaches `Finalized` in budget (when required) | `PROOF_NOT_FINALIZED` |

`INTERNAL_ERROR` is a local extension for unexpected handler failures
(not a spec code). HMAC failures are HTTP 401, not decision responses.

## Quick start

```bash
npm install
cp .env.example .env   # then fill in the secrets (below)
npm run build
npm start              # listens on $PORT (default 3000)
```

Expose it on a public HTTPS URL (the platform requires HTTPS on the
standard port) and register that URL as the agent endpoint in the Agent
Games dashboard. Start with unscored practice tasks.

## Secrets (environment only — never commit, never paste in chat)

| variable | source |
| --- | --- |
| `AGENT_GAMES_HMAC_SECRET` | Agent Games dashboard → Rotate Secret. **Required**: the service refuses to start without it. |
| `KURIER_API_KEY` | Kurier dashboard (zkVerify mainnet). Optional — see below. |

```bash
# .env (gitignored) — never commit this file
AGENT_GAMES_HMAC_SECRET=<from dashboard Rotate Secret>
KURIER_API_KEY=<from Kurier>
REQUIRE_KURIER_FINALIZED=true
KURIER_POLL_BUDGET_MS=40000
```

The service refuses to start if `GATEKEEPER_VK_HASH` is set to anything
other than the platform-registered gatekeeper hash
(`0x6b79c6…d77b0`); it is a protocol constant, not a secret.

## The Kurier gate (read this before competing)

- `REQUIRE_KURIER_FINALIZED=true` (default): APPROVE only when the Kurier
  job reaches `Finalized` inside `KURIER_POLL_BUDGET_MS` (default 40 s).
  A proof that only verifies locally is **not** enough.
- `REQUIRE_KURIER_FINALIZED=false`: a locally verified proof is enough;
  the Kurier job id is still recorded for audit when a key is configured.
- No `KURIER_API_KEY` configured **and** finality required: every task is
  REJECTED with `PROOF_NOT_FINALIZED` (fail closed). This is the state the
  test harness runs in by default.

## Testing

```bash
npm test     # full harness: two in-process servers, signed replays
npm run probe  # re-run the circuit input discovery + example proof
```

`npm test` starts two servers with an ephemeral test HMAC secret and
asserts: health, preflight (signed), bad HMAC → 401, all seven trap
envelopes → the right REJECT code, valid task → `PROOF_NOT_FINALIZED`
without a Kurier key and `APPROVE` with a locally re-verified proof when
finality is not required, and reused `proof_tx` → `PROOF_TX_REUSED`.
Every response signature is verified. All fixture envelopes live in
`test/fixtures/`.

## Files

```
gatekeeper/
├── circuits/               gatekeeper.wasm, gatekeeper_final.zkey,
│                           verification_key.json (extracted)
├── src/
│   ├── index.ts            bootstrap + graceful shutdown
│   ├── config.ts           env loading, fail-fast on missing secret
│   ├── hmac.ts             HMAC-SHA256 sign/verify (timing-safe)
│   ├── gatekeeper.ts       deterministic decision pipeline
│   ├── prover.ts           snarkjs fullProve + local verify, input mapping
│   ├── kurier.ts           Kurier submit + poll-to-Finalized
│   ├── routes.ts           POST /agent, GET /health, serialised handling
│   ├── replay.ts           persistent used-proof_tx store (data/, gitignored)
│   └── logger.ts           structured logs (ids/decisions only, never secrets)
├── test/
│   ├── harness.ts          `npm test`
│   └── fixtures/*.json     valid + 7 trap envelopes
├── scripts/probe-circuit-inputs.ts   `npm run probe`
├── CIRCUIT.md              discovered circuit mapping + semantics
├── .env.example
└── README.md
```

## Circuit artifacts

`circuits/gatekeeper.wasm` and `circuits/gatekeeper_final.zkey` are
**not stored in this repo** (binary files). Download them from the
official Agent Games artifacts before running:

```bash
cd gatekeeper/circuits
curl -sSL -o gatekeeper.wasm https://agentgames.zkverify.io/circuits/gatekeeper.wasm
curl -sSL -o gatekeeper_final.zkey https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey
```

Expected checksums (see `CIRCUIT.md`):

- `gatekeeper.wasm`: `be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f`
- `gatekeeper_final.zkey`: `adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d`

Then extract the verification key once with
`npx snarkjs zkey export verificationkey circuits/gatekeeper_final.zkey circuits/verification_key.json`
(or use the committed `circuits/verification_key.json`).

## Known limitations

- **Inbound `proof_tx` finality cannot be checked without a chain RPC
  that the spec does not provide.** Finality is anchored on our own
  Kurier `Finalized` receipt for the proof we generated, plus the local
  verification against the registered vk.
- **No register-vk call is implemented.** `/build` prints no register-vk
  endpoint, and the gatekeeper vk is already registered on zkVerify
  mainnet, so `vkRegistered: true` is used — as printed on `/build`.
- **The Kurier job-status URL is not printed on `/build`.** The path
  `GET /api/v1/job-status/${API_KEY}/${jobId}` is taken from the official
  zkVerify quickstart docs that `/build` links as the source of truth.
  Verify it against the live Kurier API before competing.
- **`taskId` / `salt` encoding is an assumption.** The spec does not
  publish how the string `task_id` maps to a circuit field element (nor
  the salt). The service derives both with SHA-256 mod p (see
  `CIRCUIT.md`). If the platform checks `publicSignals[12]` or `[0]`
  against its own encoding, a mismatch could refuse an otherwise valid
  proof. Confirm with one unscored practice task before the scored rounds.
- **No inbound rate limiting beyond serialised handling.** The platform
  is the only caller; tasks are processed one at a time. Do not expose
  this service to the open internet beyond the platform's calls.

## Security notes

- Secrets live only in environment variables. `.env` is gitignored.
- The HMAC secret is the platform-generated value from Rotate Secret —
  never a local placeholder.
- All failures are fail-closed: on timeout, error, or any uncertainty the
  service REJECTS. It never approves by default.
- Logs contain task ids, decisions, reason codes, durations, and Kurier
  job ids/statuses only — never secrets, keys, request bodies, or proofs.
