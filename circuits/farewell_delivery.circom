pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "@zk-email/circuits/email-verifier.circom";
include "@zk-email/circuits/helpers/reveal-substring.circom";
include "@zk-email/circuits/utils/bytes.circom";
include "@zk-email/circuits/utils/hash.circom";
include "./hex-decode.circom";

// FarewellDelivery (v2)
// ======================
// Proves that a DKIM-signed email was sent to a specific recipient, with
// the payload content hash embedded in the signed email body.
//
// Public outputs (what the Farewell contract reads as publicSignals):
//   [0] recipientHash = PoseidonModular(PackBytes(recipientEmail))
//       — must match m.recipientEmailHashes[recipientIndex] on-chain.
//   [1] dkimKeyHash   = EmailVerifier.pubkeyHash
//       — Poseidon(k/2)(pubkey chunks) as produced natively by zk-email.
//       — must be in trustedDkimKeys[bytes32(0)][…] on-chain (seeded by
//         scripts/fetch-dkim-keys.ts + scripts/wire-zkemail.ts).
//   [2] contentHash   = decoded from "Farewell-Hash: 0x<64 hex>" in body.
//       — must match m.payloadContentHash on-chain.
//       — the circuit extracts the marker from the DKIM-signed body,
//         ASCII-hex-decodes 64 lowercase chars into a 256-bit value,
//         and constrains it to equal the private contentHashIn input.
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
//   markerLen           — byte length of the "Farewell-Hash: 0x" prefix
//                         (17 bytes). Followed by 64 hex chars = 81 total.
template FarewellDelivery(maxHeadersLength, maxBodyLength, maxRecipientBytes, n, k, markerLen) {
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
    signal input recipientEmailStart;
    signal input recipientEmailLength;
    // The 32-byte payload content hash the contract stored at message-
    // create time (m.payloadContentHash).
    signal input contentHashIn;
    // Byte offset in emailBody where "Farewell-Hash: 0x" begins.
    signal input contentHashMarkerStart;

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

    // 4. Bind the content hash to the DKIM-signed email body.
    //    The body must contain the marker "Farewell-Hash: 0x" (17 bytes)
    //    followed by 64 lowercase hex characters [0-9a-f].

    // 4a. Extract markerLen + 64 bytes from body at the claimed position.
    var totalExtract = markerLen + 64;
    component hashReveal = RevealSubstring(
        maxBodyLength,
        totalExtract,
        /* shouldCheckUniqueness */ 0
    );
    hashReveal.in                  <== emailBody;
    hashReveal.substringStartIndex <== contentHashMarkerStart;
    hashReveal.substringLength     <== totalExtract;

    // 4b. Verify the marker prefix matches "Farewell-Hash: 0x" exactly.
    //     ASCII: F=70 a=97 r=114 e=101 w=119 e=101 l=108 l=108
    //            -=45 H=72 a=97 s=115 h=104 :=58 SP=32 0=48 x=120
    var marker[17] = [70, 97, 114, 101, 119, 101, 108, 108, 45, 72, 97, 115, 104, 58, 32, 48, 120];
    for (var i = 0; i < markerLen; i++) {
        hashReveal.substring[i] === marker[i];
    }

    // 4c. Hex-decode the 64 chars after the marker into a field element.
    component hexDecode = AsciiHexToField(64);
    for (var i = 0; i < 64; i++) {
        hexDecode.chars[i] <== hashReveal.substring[markerLen + i];
    }

    // 4d. Constrain: decoded hash from email body must equal the claimed
    //     content hash (which the contract checks against payloadContentHash).
    hexDecode.value === contentHashIn;
    contentHash <== contentHashIn;
}

// maxHeadersLength, maxBodyLength, maxRecipientBytes, n, k, markerLen
component main = FarewellDelivery(1024, 1024, 256, 121, 17, 17);
