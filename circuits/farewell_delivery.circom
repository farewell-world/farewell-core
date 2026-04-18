pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "@zk-email/circuits/email-verifier.circom";
include "@zk-email/circuits/helpers/reveal-substring.circom";
include "@zk-email/circuits/utils/bytes.circom";
include "@zk-email/circuits/utils/hash.circom";

// FarewellDelivery
// =================
// Proves that a DKIM-signed email was sent to a specific recipient, and
// commits to a specific payload content hash.
//
// Public outputs (what the Farewell contract reads as publicSignals):
//   [0] recipientHash = PoseidonModular(PackBytes(recipientEmail))
//       — must match m.recipientEmailHashes[recipientIndex] on-chain.
//   [1] dkimKeyHash   = EmailVerifier.pubkeyHash
//       — Poseidon(k/2)(pubkey chunks) as produced natively by zk-email.
//       — must be in trustedDkimKeys[bytes32(0)][…] on-chain (seeded by
//         scripts/fetch-dkim-keys.ts + scripts/wire-zkemail.ts).
//   [2] contentHash   = pass-through of a private input.
//       — must match m.payloadContentHash on-chain.
//       — v1 security note: the circuit does NOT assert the content hash
//         appears in the body. The body is still DKIM-signed so a claimer
//         cannot forge a body, but they can reuse any DKIM-signed email
//         they received from the recipient and attach it to a reward
//         claim. V2 will bind the hash to the body via an in-circuit
//         ASCII-hex-decode at a known Farewell-Hash marker position.
//
// Parameters:
//   maxHeadersLength    — header bytes (must be multiple of 64 for SHA
//                         block alignment). 1024 fits all mainstream
//                         provider headers for our simple emails.
//   maxBodyLength       — body bytes (after DKIM precomputed SHA prefix).
//                         1024 covers our short Farewell-Hash-bearing
//                         bodies.
//   maxRecipientBytes   — 256 matches @zk-email's EMAIL_ADDR_MAX_BYTES.
//   n, k                — RSA chunking: 121-bit chunks × 17 chunks =
//                         2057 bits capacity, enough for 2048-bit RSA
//                         (Gmail, Outlook, Yahoo, iCloud all use 2048).
template FarewellDelivery(maxHeadersLength, maxBodyLength, maxRecipientBytes, n, k) {
    // ---- EmailVerifier inputs (mirror of @zk-email/circuits) ----
    signal input emailHeader[maxHeadersLength];
    signal input emailHeaderLength;
    signal input pubkey[k];
    signal input signature[k];
    signal input emailBody[maxBodyLength];
    signal input emailBodyLength;
    signal input bodyHashIndex;
    signal input precomputedSHA[32];

    // ---- Farewell-specific private inputs ----
    // Index in the canonicalized header where the recipient email bytes
    // (the value of the "To:" header, stripped of "Name <...>" formatting
    // and normalized to lowercase) start, and the length of those bytes.
    signal input recipientEmailStart;
    signal input recipientEmailLength;
    // The 32-byte payload content hash the contract stored at message-
    // create time (m.payloadContentHash). Passed verbatim to publicSignals[2].
    signal input contentHashIn;

    // ---- Public outputs ----
    signal output recipientHash;
    signal output dkimKeyHash;
    signal output contentHash;

    // 1. DKIM signature verification (RSA-SHA256 over canonicalized header,
    //    body hash check against bh= in header).
    component ev = EmailVerifier(
        maxHeadersLength,
        maxBodyLength,
        n,
        k,
        /* ignoreBodyHashCheck */ 0,
        /* enableHeaderMasking */ 0,
        /* enableBodyMasking   */ 0,
        /* removeSoftLineBreaks*/ 0
    );
    ev.emailHeader      <== emailHeader;
    ev.emailHeaderLength <== emailHeaderLength;
    ev.pubkey           <== pubkey;
    ev.signature        <== signature;
    ev.emailBody        <== emailBody;
    ev.emailBodyLength  <== emailBodyLength;
    ev.bodyHashIndex    <== bodyHashIndex;
    ev.precomputedSHA   <== precomputedSHA;

    dkimKeyHash <== ev.pubkeyHash;

    // 2. Extract the recipient bytes from the signed header. RevealSubstring
    //    enforces the substring is present exactly once at the claimed
    //    position within the header — i.e. this IS the To: value, not some
    //    attacker-chosen range.
    component recipientReveal = RevealSubstring(
        maxHeadersLength,
        maxRecipientBytes,
        /* shouldCheckUniqueness */ 1
    );
    recipientReveal.in                 <== emailHeader;
    recipientReveal.substringStartIndex <== recipientEmailStart;
    recipientReveal.substringLength    <== recipientEmailLength;

    // 3. Pack the extracted bytes into BN254 field elements (31 bytes each)
    //    and Poseidon-hash via PoseidonModular, which chunks into groups of
    //    16 inputs internally and folds with Poseidon(2). This is the same
    //    commitment scheme the claimer and site compute in userland.
    component packer = PackBytes(maxRecipientBytes);
    for (var i = 0; i < maxRecipientBytes; i++) {
        packer.in[i] <== recipientReveal.substring[i];
    }
    var packedLen = computeIntChunkLength(maxRecipientBytes);
    component hasher = PoseidonModular(packedLen);
    for (var i = 0; i < packedLen; i++) {
        hasher.in[i] <== packer.out[i];
    }
    recipientHash <== hasher.out;

    // 4. The content hash flows straight through. See v1 security note at
    //    the top of this file.
    contentHash <== contentHashIn;
}

// maxHeadersLength, maxBodyLength, maxRecipientBytes, n, k
component main = FarewellDelivery(1024, 1024, 256, 121, 17);
