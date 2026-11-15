# Gatekeeper circuit — discovered input/output mapping

The public spec ([agentgames.zkverify.io/build](https://agentgames.zkverify.io/build))
does **not** publish the gatekeeper circuit's witness input signal names.
Everything below was discovered empirically against the downloaded artifacts
and is reproducible with `npm run probe` (see
`scripts/probe-circuit-inputs.ts`).

## Artifacts

| file | sha256 | source |
| --- | --- | --- |
| `circuits/gatekeeper.wasm` | `be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f` | https://agentgames.zkverify.io/circuits/gatekeeper.wasm |
| `circuits/gatekeeper_final.zkey` | `adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d` | https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey |
| `circuits/verification_key.json` | extracted with `snarkjs zkey export verificationkey` | Groth16, curve bn128, **13 public signals** |

Registered vk hash (from `/api/circuit-info`, also shown on `/build`):

```
0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0
```

Circuit facts from the wasm: circom version 2, `getInputSize() = 13`,
`getWitnessSize() = 647`, main template `GatekeeperEvaluation_79`.

## Discovery method

The wasm exports `getInputSignalSize(fnvHash(name))`, which returns **0**
for unknown names (not −1). Passing a single scalar value to the witness
calculator therefore throws:

- `Too many values for input signal X` → **X does not exist** (size 0).
- `Not all inputs have been set. Only 1 out of 13` → **X exists**, scalar.
- `Not enough values for input signal X` → **X exists**, array signal.

Candidate names were probed one at a time (see the probe script for the
full list). 13 of 13 input slots were found; no array signals exist.

## Input signals (13)

| # | signal | source in the task envelope |
| --- | --- | --- |
| 1 | `publicBalance` | `input.public_balance` |
| 2 | `minimum` | `input.minimum` |
| 3 | `amount` | `input.amount` |
| 4 | `maxTransfer` | `input.max_transfer` |
| 5 | `recipient` | `input.recipient` (hex address → field element) |
| 6 | `conditionRecipient` | `input.condition_recipient` |
| 7 | `expiryBlock` | `input.expiry_block` |
| 8 | `currentBlock` | `input.current_block` |
| 9 | `registeredVkHash` | `input.registered_vk` (hex → field element, reduced mod p) |
| 10 | `proofVkHash` | `input.proof_vk` (hex → field element, reduced mod p) |
| 11 | `decision` | derived: `1` = APPROVE, `0` = REJECT |
| 12 | `taskId` | derived from `task_id` (see below) |
| 13 | `salt` | derived from `task_id` (see below) |

## Public signals (13, in order)

Observed by varying one input at a time and comparing outputs:

| index | value |
| --- | --- |
| `[0]` | task commitment — a circuit-internal hash of (`taskId`, `salt`). It changes when either input changes; the exact hash construction is not published and is not needed to use the circuit. |
| `[1]` | `proofVkHash mod p` |
| `[2]` | `registeredVkHash mod p` |
| `[3]` | `minimum` |
| `[4]` | `publicBalance` |
| `[5]` | `expiryBlock` |
| `[6]` | `currentBlock` |
| `[7]` | `recipient` |
| `[8]` | `conditionRecipient` |
| `[9]` | `amount` |
| `[10]` | `maxTransfer` |
| `[11]` | `decision` (`1` = APPROVE, `0` = REJECT) |
| `[12]` | `taskId` (the field element passed in) |

Example (tournament example values, decision = 1):

```
publicBalance 1460, minimum 1000, amount 500, maxTransfer 1000,
recipient == conditionRecipient == 0x1234567890abcdef1234567890abcdef12345678,
expiryBlock 8430000, currentBlock 8420000,
registeredVkHash == proofVkHash == 0x6b79c6…d77b0, taskId 1, salt 42

[0]  16556036937753546091282698062266362651008751416415631538814028886573393469713
[1]  4836144126773920907502496244340012141761656471453348073975163706578152814510  (= vk hash mod p)
[2]  4836144126773920907502496244340012141761656471453348073975163706578152814510
[3]  1000
[4]  1460
[5]  8430000
[6]  8420000
[7]  103929005307927756724354605802047639613112342136
[8]  103929005307927756724354605802047639613112342136
[9]  500
[10] 1000
[11] 1
[12] 1
```

## Circuit semantics (verified by fullProve + groth16.verify)

The circuit enforces that `decision` is the **correct** outcome — a proof
for `decision = 1` can only be generated when every condition holds, and a
proof for `decision = 0` can only be generated when at least one fails.
The template assertion that enforces this is
`GatekeeperEvaluation_79 line 102`; a wrong decision fails witness
generation with `Assert Failed`, it does not produce a bad proof.

| case | decision | result |
| --- | --- | --- |
| all checks pass | 1 (APPROVE) | proof generated, `groth16.verify: true` |
| all checks pass | 0 (REJECT) | assertion failure — cannot prove |
| balance < minimum | 1 | assertion failure |
| balance < minimum | 0 | proof generated, `groth16.verify: true` |
| proofVkHash ≠ registered | 1 | assertion failure |
| proofVkHash ≠ registered | 0 | proof generated, `groth16.verify: true` |
| recipient mismatch | 1 | assertion failure |
| expiryBlock ≤ currentBlock | 1 | assertion failure |
| amount > maxTransfer | 1 | assertion failure |

Consequences for this service:

- The service only ever generates `decision = 1` proofs, and only after
  its own deterministic checks already passed. If the service's checks and
  the circuit ever disagreed, proof generation would fail and the service
  would REJECT with `PROOF_GENERATION_FAILED` — fail closed.
- Proof generation takes roughly 250–900 ms on this machine, well inside
  the 60 s task deadline.
- `decision = 0` proofs are generatable but never sent: the spec's REJECT
  response carries no proof fields.

## Derived inputs: taskId and salt (documented assumptions)

Neither the spec nor the circuit publishes how the string `task_id`
(`"gk_..."`) or the salt should be encoded as field elements. The
service derives them deterministically so each task's proof is stable and
distinct:

- `taskId = SHA-256("gatekeeper:taskId:<task_id>") mod p`
- `salt   = SHA-256("gatekeeper:salt:v1:<task_id>") mod p`

where `p` is the BN128 field prime
(`21888242871839275222246405745257275088548364400416034343698204186575808495617`).

**Open risk:** if the platform checks `publicSignals[12]` (taskId) or
`[0]` (the task commitment) against its own encoding of the task id, our
derivation may not match theirs, and the platform could refuse the proof
even though it verifies against the registered vk. This cannot be
confirmed from the published spec — it needs one unscored practice task
round-trip against the live platform. The service logs the full
public-signal list indirectly (never the proof itself) so a mismatch can
be diagnosed from a practice run.
