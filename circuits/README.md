# farewell-core / circuits

The Groth16 circuit that backs Farewell's `proveDelivery` flow lives here.
The claimer (`farewell-claimer`) uses it to prove a DKIM-signed email was
delivered to a specific recipient; the Farewell contract verifies the
proof on-chain before accepting a `claimReward` call.

This directory contains the circuit source. All build artifacts
(`.r1cs`, `.wasm`, `.zkey`, `verification_key.json`) are **not** committed
(see `.gitignore`) — they're regenerated from source on demand, and the
final proving/verification artifacts for each circuit version are attached
to that release's GitHub Release.

## Files

- `farewell_delivery.circom` — the circuit (~130 lines). Wraps
  `@zk-email/circuits::EmailVerifier` with Farewell-specific signal
  extraction (recipient Poseidon, content-hash passthrough).
- `build.sh` — compiles the circuit and prints the constraint count.
- `setup.sh` — downloads the Hermez Powers of Tau Phase 1 file and runs
  the single-party Phase 2 contribution.
- `README.md` — this file.
- `.gitignore` — everything in `build/` and any `.ptau` file.

## Public signals

The circuit emits three public outputs, in order — these are the
`publicSignals` array the Farewell contract inspects in
`FarewellExtension.sol::_verifyZkEmailProof`:

| Index | Signal | Source | On-chain check |
|-------|--------|--------|---|
| `[0]` | `recipientHash` | `PoseidonModular(PackBytes(recipientEmail))` from the signed `To:` header | `publicSignals[0] == m.recipientEmailHashes[recipientIndex]` |
| `[1]` | `dkimKeyHash`   | `EmailVerifier.pubkeyHash` — native `Poseidon` over the RSA pubkey chunks | `_isTrustedDkimKey(publicSignals[1])` (membership in `trustedDkimKeys[bytes32(0)]`) |
| `[2]` | `contentHash`   | Private input passed through | `publicSignals[2] == m.payloadContentHash` |

### v1 security caveat

`contentHash` is a pass-through: the circuit does not assert the hash
appears in the email body. A claimer could therefore reuse any
DKIM-signed email they've received from the recipient, sign a proof
against an unrelated message's `payloadContentHash`, and claim its
reward. The body itself is still DKIM-signed, so it can't be forged — but
it isn't bound to the specific message the claim is for.

V2 hardening (follow-up work, tracked separately): extract the
`Farewell-Hash: 0x…` marker from the email body, ASCII-hex-decode the 64
chars into a 256-bit value, and constrain it to equal `publicSignals[2]`.

## Prerequisites

- `circom` 2.1.x or 2.2.x on `PATH` (Rust binary — no npm install).
  Install from https://github.com/iden3/circom/releases, or via Cargo:
  `cargo install --git https://github.com/iden3/circom.git`.
- `node` with the dev dependencies installed: `npm ci` at the repo root.
  This installs `circomlib`, `@zk-email/circuits`, `@zk-email/helpers`,
  `snarkjs`, and `poseidon-lite`.
- About 4 GB free disk for the Phase 1 `.ptau` file (temporary — deleted
  after Phase 2 completes).

## Build

```bash
bash circuits/build.sh
```

This compiles to `circuits/build/farewell_delivery.{r1cs,sym}` and
`circuits/build/farewell_delivery_js/farewell_delivery.wasm`, then prints
the constraint count. Last measured: ~2.87 M non-linear constraints +
479 K linear, requiring a Powers of Tau of at least 2^22.

## Trusted setup

```bash
bash circuits/setup.sh
```

Downloads `powersOfTau28_hez_final_22.ptau` from the Hermez ceremony,
runs `snarkjs groth16 setup`, contributes a single-party randomness
beacon, and exports `circuits/build/verification_key.json`.

The resulting `farewell_delivery_final.zkey` is large (~400 MB). It is
not committed; it's attached to the corresponding GitHub Release as a
versioned asset, alongside `farewell_delivery.wasm` (~17 MB) and
`verification_key.json` (~10 KB).

### Trust model

This is a single-party Phase 2 contribution. It is suitable for Sepolia
POC work — the contribution randomness is an identifier the user
provides at setup time, and the only trust you need is "Pedro ran this
once and threw away the randomness". A production mainnet deployment
would coordinate a multi-party ceremony with independent contributors
and publish the contribution transcript.

## Bounds and their justification

Declared in the `component main = FarewellDelivery(…)` line at the end
of `farewell_delivery.circom`:

| Parameter | Value | Rationale |
|---|---|---|
| `maxHeadersLength` | 1024 | Covers standard Gmail / Outlook / Yahoo headers. Must be a multiple of 64 (SHA-256 block size). |
| `maxBodyLength`    | 1024 | Our Farewell-Hash-marker bodies are short boilerplate; tune up if bodies grow. Must be multiple of 64. |
| `maxRecipientBytes`| 256  | Matches `@zk-email`'s `EMAIL_ADDR_MAX_BYTES`. Comfortably covers RFC 5321's 64-byte local-part + 253-byte domain. |
| `n`, `k`           | 121, 17 | 2048-bit RSA chunking; standard `@zk-email` convention. Supports Gmail / Outlook / Yahoo / iCloud DKIM keys. |

Increasing any of these recompiles the circuit, invalidates the Powers
of Tau ceiling (may need a larger ptau), regenerates the verifier
contract, and requires a redeploy. Treat bounds as a committed
interface.
