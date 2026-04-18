# Farewell Delivery Proof Structure

This document explains the complete Farewell delivery proof architecture, including the zk-email proof format, contract verification flow, and data structures that bridge the off-chain claimer tool with on-chain verification.

## Overview

The Farewell protocol uses a Groth16 zero-knowledge proof (via the zk-email framework) to prove that:
1. A claimer actually sent an email to a recipient
2. The recipient email address matches the on-chain commitment (keccak256 placeholder today; Poseidon once the Circom circuit ships)
3. The message content matches the stored content hash

This eliminates the need for centralized delivery tracking while maintaining privacy.

## End-to-End Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        FAREWELL MESSAGE LIFECYCLE                        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  1. MESSAGE CREATION (Sender on Farewell UI)                            │
│     └─> Encrypts message → Stores recipients[].emailHash (keccak256     │
│         placeholder; will migrate to Poseidon with the circuit)         │
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
│         Generates proof structure (placeholder Groth16)                 │
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

## Public Signals (What the Proof Proves)

The zk-email circuit produces a Groth16 proof with 3 public signals:

```
publicSignals[0] = Recipient_Email_Hash
                   Current: keccak256(email_normalized)                    ← placeholder
                   Future:  Poseidon(email_normalized) from the zk circuit
                   (normalized: lowercased, whitespace stripped)
                   Must match m.recipientEmailHashes[i] on-chain. The site
                   computes the same keccak256 when posting the message, so
                   claimer and site agree on the commitment until the real
                   Poseidon circuit ships.

publicSignals[1] = DKIM_Key_Hash
                   Current: value from shared placeholder map per provider
                            domain (gmail.com, outlook.com, …), with
                            keccak256("<selector>._domainkey.<domain>")
                            fallback for unknown providers. Extracted from
                            the .eml DKIM-Signature header.
                   Future:  SHA3-256(dkim_public_key) fetched via DNS and
                            checked by the circuit.
                   Verified against the trustedDkimKeys registry on-chain;
                   the contract owner must seed that registry via
                   setTrustedDkimKey before proveDelivery accepts it.

publicSignals[2] = Content_Hash
                   keccak256(email_body_content)
                   Must match claim_package.contentHash (and on-chain
                   m.payloadContentHash). Embedded in the email body as
                   the Farewell-Hash marker.
```

## Contract Verification

When the `_verifyZkEmailProof()` function is called:

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
│     │    (Proves correct recipient)                        │  │
│     │                                                      │  │
│     │ b. Is publicSignals[1] in trustedDkimKeys registry?  │  │
│     │    (Proves authentic DKIM signature)                │  │
│     │                                                      │  │
│     │ c. publicSignals[2] == m.payloadContentHash?        │  │
│     │    (Proves correct message content)                 │  │
│     │                                                      │  │
│     │ d. Verify(proof, verificationKey) == true?          │  │
│     │    (Proves zk-email circuit integrity)              │  │
│     │                                                      │  │
│     │ If ALL checks pass:                                 │  │
│     │   ✓ Set provenRecipients bitmap bit i to 1         │  │
│     │   ✓ Emit ProofVerified(owner, messageIndex, i)     │  │
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
    },
    {
      "recipientIndex": 1,
      "email": "bob@example.com",
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

## Current Status: Proof-of-Concept

The current implementation ships correct public signals but still emits a
zero Groth16 proof by default. Each signal's present vs. eventual behavior:

```
┌──────────────────────────────────────────────────────────────┐
│               CURRENT POC IMPLEMENTATION                     │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ⚠ Groth16 Proof (pA, pB, pC): Zeros unless a prover is    │
│    wired via the FAREWELL_PROVER_CMD env var (see below).  │
│    When wired: real zk-email circuit output.               │
│                                                              │
│  ✓ Recipient Hash (publicSignals[0]):                      │
│    keccak256(email_normalized) — matches the site's        │
│    on-chain commitment today. Will migrate to Poseidon     │
│    once the Circom circuit is available (both sides        │
│    flip together to preserve compatibility).               │
│                                                              │
│  ✓ DKIM Key Hash (publicSignals[1]):                       │
│    Extracted from the .eml DKIM-Signature header and       │
│    resolved via the shared placeholder map, with a         │
│    keccak256("<selector>._domainkey.<domain>") fallback.   │
│    On-chain trustedDkimKeys must be seeded with the same   │
│    hashes by the contract owner.                           │
│                                                              │
│  ✓ Content Hash (publicSignals[2]):                        │
│    keccak256(decrypted_payload) — already real.            │
│                                                              │
│  ⚠ On-Chain Verifier: Not yet deployed on Sepolia.         │
│    Owner must setZkEmailVerifier(<address>) before         │
│    proveDelivery stops reverting with VerifierNotConfigured│
│    (selector 0x637873a6).                                  │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

## Plugging in a Real Prover (FAREWELL_PROVER_CMD)

The claimer calls `generate_proof_data()` per recipient. When the env var
`FAREWELL_PROVER_CMD` is set, we shell out to that command and expect it to
produce the Groth16 points:

- **stdin**: a single line of JSON `{"recipient":…, "contentHash":…, "publicSignals":[…]}`
  followed by the raw .eml bytes.
- **stdout**: a JSON object with `pA` (uint256[2]), `pB` (uint256[2][2]), and `pC` (uint256[2]).
  May optionally override `publicSignals`; if present it's used verbatim.
- Non-zero exit, malformed JSON, or missing fields raise `RuntimeError` and
  abort the claim flow — we'd rather stop than ship a proof that will revert.

Example: `FAREWELL_PROVER_CMD="node my-snarkjs-wrapper.js" python farewell_claimer.py …`

## Integration with a real zk-email Circuit

When the Circom circuit ships:

1. **Input (.eml file)**: Full email with headers and MIME body
2. **Circuit Logic**:
   - Extract DKIM-Signature header
   - Verify DKIM signature against sender's public key
   - Extract and normalize TO field (recipient email)
   - Hash recipient email with Poseidon
   - Extract email body
   - Verify Farewell-Hash marker matches content hash
3. **Output (Public Signals)**:
   - publicSignals[0]: Poseidon hash of recipient email (replacing the keccak placeholder — site must migrate in lockstep)
   - publicSignals[1]: SHA3-256 of DKIM public key (replacing the placeholder map)
   - publicSignals[2]: Content hash from Farewell-Hash marker (unchanged)
4. **Proof Generation**: Groth16 proof (pA, pB, pC) proving knowledge of the witness

## Data Flow Through System

```
┌──────────────┐
│ Farewell UI  │ Sends encrypted message → stores emailHashes
│ (Web App)    │ and payloadContentHash on-chain
└───────┬──────┘
        │ [1] Claim package JSON
        ↓
┌──────────────────────────────────────────┐
│ farewell-claimer (Python CLI)            │
│ [2] Send email to recipient              │
│     (attaches claim package JSON)        │
│ [3] Save .eml file                       │
│ [4] Generate proof structure             │
└───────┬──────────────────────────────────┘
        │ [5] DeliveryProofJson + .eml
        ↓
┌──────────────┐
│ Farewell UI  │ [6] Upload proof JSON
│ (Web App)    │ [7] Call _verifyZkEmailProof() on-chain
│              │ [8] Bitmap updated for recipient
└───────┬──────┘
        │ After all recipients proven
        ↓
┌──────────────────────────────────────────┐
│ Smart Contract (Farewell.sol)            │
│ [9] claimReward() transfers ETH          │
└──────────────────────────────────────────┘
```

## Security Properties

**Proven:**
- Email was signed by a DKIM-verified server (no forgery possible)
- Recipient email matches on-chain commitment (no address spoofing)
- Message content matches stored hash (no tampering possible)
- Claimer performed actual delivery (attestation of delivery)

**Not Proven:**
- Recipient actually read or understood the message
- No coercion or fraud in message creation
- No key material compromise during transit

## Related Documentation

- [Claimer User Guide](./claimer-guide.md) — Step-by-step workflow
- [farewell-core Protocol](https://github.com/farewell-world/farewell-core) — Smart contract implementation
- [zk.email Documentation](https://docs.zk.email/) — Circuit design and verification
