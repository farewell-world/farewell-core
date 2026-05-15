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
│         (Poseidon(PackBytes(normalized_email), senderAddress))          │
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
  "subject": "Farewell Message",
  "senderName": "Alice"
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
- `senderName`: FHE-decrypted sender display name (optional, may be empty)

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

**Parameters:** `maxHeadersLength=1024, maxBodyLength=1024, maxRecipientBytes=256, n=121, k=17, markerLen=17`

**Public Outputs/Inputs:**

| Index | Signal | Computation | On-chain check |
|-------|--------|-------------|----------------|
| `[0]` | `recipientHash` | `PoseidonModular(PackBytes(recipient_email_bytes), senderAddress)` | `== m.recipientEmailHashes[i]` |
| `[1]` | `dkimKeyHash` | `PoseidonLarge(121,17)(rsa_pubkey_chunks)` — native `@zk-email` pubkeyHash | `_isTrustedDkimKey(pubkeyHash)` |
| `[2]` | `contentHash` | Decoded from `Farewell-Hash: 0x<64 hex>` in DKIM-signed body | `== m.payloadContentHash` |
| `[3]` | `senderAddress` | Message creator's Ethereum address (public input to circuit) | `== message owner address` |

**Salted Recipient Hash:** The recipient hash is salted with the sender's Ethereum address (`senderAddress`) to prevent dictionary attacks. Without the salt, an attacker could precompute Poseidon hashes of common email addresses and match them against on-chain commitments across all users. The salt ensures that the same email address produces different hashes for different senders. The circuit declaration uses `{public [senderAddress]}` to expose the sender address as a public input.

**Content Hash Body Binding:** The circuit extracts the marker `Farewell-Hash: 0x` (17 bytes) from the DKIM-signed email body at a prover-supplied offset (`contentHashMarkerStart`), ASCII-hex-decodes the following 64 lowercase hex characters into a 256-bit value, and constrains it to equal the private `contentHashIn` input. This binds `publicSignals[2]` to actual email content the recipient saw.

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
│     │    (Proves correct recipient — salted Poseidon)     │  │
│     │                                                      │  │
│     │ b. Is publicSignals[1] in trustedDkimKeys registry?  │  │
│     │    (Proves authentic DKIM signature)                │  │
│     │                                                      │  │
│     │ c. publicSignals[2] == m.payloadContentHash?        │  │
│     │    (Proves correct message content)                 │  │
│     │                                                      │  │
│     │ d. publicSignals[3] == owner?                       │  │
│     │    (Proves correct sender — binds to user)          │  │
│     │                                                      │  │
│     │ e. Verify(proof, verificationKey) == true?          │  │
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
          "0xabcd...",
          "0xdead..."
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
- `publicSignals`: The 4 public signals: `[recipientHash, dkimKeyHash, contentHash, senderAddress]`
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

- **stdin**: a single line of JSON `{"recipient":…, "contentHash":…, "senderAddress":…, "publicSignals":[…]}`
  followed by the raw .eml bytes. The `senderAddress` field is the message creator's Ethereum address (used as salt for the recipient hash).
- **stdout**: a JSON object with `pA` (uint256[2]), `pB` (uint256[2][2]), `pC` (uint256[2]),
  and `publicSignals` (the 4 circuit outputs as hex strings: recipientHash, dkimKeyHash, contentHash, senderAddress).
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
| Farewell (proxy) | `0xE494835ffd293E57655e61Ed854CA7a39130174e` |
| FarewellGroth16Verifier | `0xF73400562fc1EFf15de8F4b6be142b7B9d66bD01` |

## Security Properties

**Proven:**
- Email was signed by a DKIM-verified server (no forgery possible)
- Recipient email matches on-chain salted Poseidon commitment (no address spoofing, no cross-user dictionary attacks)
- Sender address in proof matches the message owner (prevents proof reuse across users)
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
