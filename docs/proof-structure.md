# Farewell Delivery Proof Structure

This document explains the complete Farewell delivery proof architecture, including the zk-email proof format, contract verification flow, and data structures that bridge the off-chain claimer tool with on-chain verification.

## Overview

The Farewell protocol uses a Groth16 zero-knowledge proof (via the zk-email framework) to prove that:
1. A claimer actually sent an email to a recipient (DKIM signature verification)
2. The recipient email address matches the on-chain Poseidon commitment
3. The message content matches the stored content hash

This eliminates the need for centralized delivery tracking while maintaining privacy.

## End-to-End Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        FAREWELL MESSAGE LIFECYCLE                        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  1. MESSAGE CREATION (Sender on Farewell UI)                            │
│     └─> Encrypts message → Stores recipients[].emailHash               │
│         (Poseidon(PackBytes(normalized_email)))                         │
│         Stores payloadContentHash = keccak256(decrypted content)        │
│                                                                          │
│  2. MESSAGE RELEASE (After grace period, Council votes)                 │
│     └─> Contract marks user deceased                                   │
│         Message becomes claimable                                       │
│                                                                          │
│  3. CLAIM & RETRIEVE (Claimer on Farewell UI)                           │
│     └─> Calls claim() → retrieve()                                      │
│         Downloads claim package JSON                                    │
│                                                                          │
│  4. SEND & PROVE (Claimer tool: farewell-claimer)                       │
│     └─> Sends email to recipient with Farewell-Hash                     │
│         Attaches claim package JSON to the email                        │
│         Saves .eml file                                                 │
│         Generates Groth16 proof via FAREWELL_PROVER_CMD                 │
│                                                                          │
│  5. PROOF SUBMISSION (Claimer on Farewell UI)                           │
│     └─> Uploads DeliveryProofJson for each recipient                    │
│         Calls _verifyZkEmailProof() for each                            │
│         Bitmap updated to track proven recipients                       │
│                                                                          │
│  6. REWARD CLAIM (Claimer on Farewell UI)                               │
│     └─> When all recipients proven (bitmap complete)                    │
│         Calls claimReward() to withdraw ETH                             │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## Claim Package (Input to Claimer)

The claim package is downloaded from the Farewell UI and contains the encrypted message and verification data:

```json
{
  "type": "farewell-claim-package",
  "owner": "0x1234567890123456789012345678901234567890",
  "messageIndex": 0,
  "recipients": ["alice@example.com", "bob@example.com"],
  "skShare": "0x75554596171405...",
  "encryptedPayload": "0x...",
  "contentHash": "0x1234...",
  "subject": "Farewell Message"
}
```

**Field Descriptions:**
- `type`: Must be `"farewell-claim-package"` (identifies format to claimer)
- `owner`: Message creator's wallet address
- `messageIndex`: ID of the message within owner's message list
- `recipients`: Array of email addresses (one entry per recipient)
- `skShare`: Hex-encoded on-chain half of AES-128 key (generated randomly)
- `encryptedPayload`: AES-128-GCM packed format: `0x` + IV(12 bytes) + ciphertext + GCM-tag
- `contentHash`: keccak256(decrypted message content) — stored on-chain for verification
- `subject`: Email subject line

## Decryption Flow (Recipient Side)

The claimer does NOT decrypt the message — only the **recipient** can, using their off-chain secret (s').

```
┌──────────────────────────────────────────────────────────────────┐
│         MESSAGE DECRYPTION (farewell-decrypter / web UI)          │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  claim_package.skShare   (on-chain half, in JSON attachment)     │
│  +                                                               │
│  recipient.s'            (off-chain half, from sender)           │
│  ═════════════════════════════════════════════════════════════  │
│  sk = skShare XOR s'     (AES-128 decryption key)               │
│                                                                  │
│  sk + encryptedPayload (AES-128-GCM)                             │
│  └─> Decrypt at farewell.world/decrypt/ or CLI tool            │
│      Format: 0x + IV(12 bytes) + ciphertext + GCM-tag          │
│      ═════════════════════════════════════════════              │
│      Yields: plaintext message content                          │
│                                                                  │
│  keccak256(plaintext) == contentHash ✓                           │
│  (recipient can verify against on-chain stored hash)             │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

## Circuit: FarewellDelivery

The Groth16 circuit (`circuits/farewell_delivery.circom`) wraps `@zk-email/circuits::EmailVerifier` with Farewell-specific signal extraction:

**Parameters:** `maxHeadersLength=1024, maxBodyLength=1024, maxRecipientBytes=256, n=121, k=17`

**Public Outputs:**

| Index | Signal | Computation | On-chain check |
|-------|--------|-------------|----------------|
| `[0]` | `recipientHash` | `PoseidonModular(PackBytes(recipient_email_bytes))` | `== m.recipientEmailHashes[i]` |
| `[1]` | `dkimKeyHash` | `PoseidonLarge(121,17)(rsa_pubkey_chunks)` — native `@zk-email` pubkeyHash | `_isTrustedDkimKey(pubkeyHash)` |
| `[2]` | `contentHash` | Private input passed through (v1) | `== m.payloadContentHash` |

**v1 Security Note:** `contentHash` is a pass-through — the circuit does not assert it appears in the email body. V2 will bind it via an in-circuit ASCII-hex-decode of the `Farewell-Hash` marker.

## Contract Verification

When `_verifyZkEmailProof()` is called:

```
┌────────────────────────────────────────────────────────────────┐
│          CONTRACT VERIFICATION FLOW                            │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  Input: DeliveryProofJson {                                   │
│    owner, messageIndex, recipients[], proof {pA,pB,pC,...}   │
│  }                                                             │
│                                                                │
│  1. Load on-chain message m = messages[owner][messageIndex]   │
│                                                                │
│  2. For each recipient in recipients[]:                       │
│     ┌──────────────────────────────────────────────────────┐  │
│     │ a. publicSignals[0] == m.recipientEmailHashes[i]?   │  │
│     │    (Proves correct recipient — Poseidon commitment)  │  │
│     │                                                      │  │
│     │ b. Is publicSignals[1] in trustedDkimKeys registry?  │  │
│     │    (Proves authentic DKIM signature)                │  │
│     │                                                      │  │
│     │ c. publicSignals[2] == m.payloadContentHash?        │  │
│     │    (Proves correct message content)                 │  │
│     │                                                      │  │
│     │ d. Verify(proof, verificationKey) == true?          │  │
│     │    (Groth16 proof — FarewellGroth16Verifier)        │  │
│     │                                                      │  │
│     │ If ALL checks pass:                                 │  │
│     │   ✓ Set provenRecipients bitmap bit i to 1         │  │
│     │   ✓ Emit DeliveryProven(owner, messageIndex, i)    │  │
│     └──────────────────────────────────────────────────────┘  │
│                                                                │
│  3. When all N recipients proven (provenRecipients == 2^N-1): │
│     ✓ claimReward() becomes callable                          │
│     ✓ Initiates reward transfer                               │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

## DeliveryProofJson Format

The proof JSON uploaded to the contract for each recipient:

```json
{
  "version": 1,
  "type": "farewell-delivery-proof",
  "owner": "0x1234567890123456789012345678901234567890",
  "messageIndex": 0,
  "recipients": [
    {
      "recipientIndex": 0,
      "email": "alice@example.com",
      "proof": {
        "pA": ["0x...", "0x..."],
        "pB": [["0x...", "0x..."], ["0x...", "0x..."]],
        "pC": ["0x...", "0x..."],
        "publicSignals": [
          "0x1234...",
          "0x5678...",
          "0xabcd..."
        ]
      }
    }
  ],
  "metadata": {
    "generatedAt": "2026-02-24T15:30:45.123Z",
    "toolVersion": "farewell-claimer v1.0.0"
  }
}
```

**Field Descriptions:**
- `pA`, `pB`, `pC`: Groth16 proof elliptic curve points (BN254)
- `publicSignals`: The 3 public signals output by the circuit
- `recipientIndex`: Position in the original recipients[] array
- `email`: Recipient email address (for reference and verification)

## Multi-Recipient Bitmap

The contract tracks proof completion using a bitmap:

```
N = number of recipients in message
provenRecipients = uint256 bitmap

For each proven recipient at index i:
  ┌─ Set bit i to 1
  │
  provenRecipients |= (1 << i)

Example: 3 recipients, all proven
  Bit:  0 1 2
       ├─────┤
  Value: 1 1 1  →  uint256(0b111) = 7

Reward claimable when:
  provenRecipients == (2^N - 1)

  For N=3: (1 << 3) - 1 = 0b111 = 7 ✓
```

## DKIM Key Registry

Trusted DKIM public key hashes are seeded on-chain via `setTrustedDkimKey(bytes32(0), hash, true)`. The hashes are `PoseidonLarge(121, 17)` of the RSA modulus chunked into 121-bit × 17 chunks — the same hash the circuit produces via `EmailVerifier.pubkeyHash`.

Currently seeded providers: Gmail, Outlook, Yahoo, iCloud, Hotmail, Protonmail, Proton.me.

Rotation: run `scripts/fetch-dkim-keys.ts --refresh` to diff DNS against the registry, then `wire-zkemail.ts` to seed new hashes on-chain.

## Prover Integration (FAREWELL_PROVER_CMD)

The claimer calls `generate_proof_data()` per recipient. When the env var
`FAREWELL_PROVER_CMD` is set, we shell out to that command and expect it to
produce the full Groth16 proof:

- **stdin**: a single line of JSON `{"recipient":…, "contentHash":…, "publicSignals":[…]}`
  followed by the raw .eml bytes.
- **stdout**: a JSON object with `pA` (uint256[2]), `pB` (uint256[2][2]), `pC` (uint256[2]),
  and `publicSignals` (the 3 circuit outputs as hex strings).
- Non-zero exit, malformed JSON, or missing fields raise `RuntimeError` and
  abort the claim flow.

The reference implementation is `tools/prove_zkemail.mjs` in farewell-claimer:

```bash
FAREWELL_PROVER_CMD="node tools/prove_zkemail.mjs" python farewell_claimer.py claim-package.json
```

It requires circuit artifacts at `tools/artifacts/farewell_delivery.wasm` and
`tools/artifacts/farewell_delivery_final.zkey` (symlinked from farewell-core build output
or downloaded from the GitHub Release).

## Deployed Contracts (Sepolia)

| Contract | Address |
|----------|---------|
| Farewell (proxy) | `0xe59562a989Cc656ec4400902D59cf34A72041c22` |
| FarewellGroth16Verifier | `0xF73400562fc1EFf15de8F4b6be142b7B9d66bD01` |

## Security Properties

**Proven:**
- Email was signed by a DKIM-verified server (no forgery possible)
- Recipient email matches on-chain Poseidon commitment (no address spoofing)
- DKIM public key is in the trusted registry (authentic provider)
- Groth16 proof is valid (circuit constraints satisfied)

**Not Proven (v1):**
- Content hash is not bound to the email body (pass-through only)
- Recipient may not have read or understood the message
- No coercion or fraud in message creation
- No key material compromise during transit

## Related Documentation

- [Claimer User Guide](./claimer-guide.md) — Step-by-step workflow
- [farewell-core Protocol](https://github.com/farewell-world/farewell-core) — Smart contract implementation
- [zk.email Documentation](https://docs.zk.email/) — Circuit design and verification
