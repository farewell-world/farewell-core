pragma circom 2.1.6;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

// Converts one ASCII hex character [0-9a-f] to its 4-bit numeric value.
// Rejects uppercase and non-hex characters via constraints.
template HexCharToNibble() {
    signal input c;
    signal output nibble;

    // Prover hint: is this a lowercase letter (a-f)?
    signal isLetter;
    isLetter <-- (c >= 97) ? 1 : 0;
    isLetter * (1 - isLetter) === 0;

    // digits: nibble = c - 48; letters: nibble = c - 87
    nibble <== c - 48 - 39 * isLetter;

    // nibble must fit in 4 bits → range [0, 15]
    component bits = Num2Bits(4);
    bits.in <== nibble;

    // digits must give nibble < 10; letters must give nibble >= 10
    component lt = LessThan(4);
    lt.in[0] <== nibble;
    lt.in[1] <== 10;
    lt.out === 1 - isLetter;
}

// Decodes nHexChars ASCII hex characters [0-9a-f] into a single field
// element (big-endian: chars[0] is the most significant nibble).
template AsciiHexToField(nHexChars) {
    signal input chars[nHexChars];
    signal output value;

    component nibbles[nHexChars];
    for (var i = 0; i < nHexChars; i++) {
        nibbles[i] = HexCharToNibble();
        nibbles[i].c <== chars[i];
    }

    // Horner accumulation: value = n[0]*16^(N-1) + n[1]*16^(N-2) + ... + n[N-1]
    signal acc[nHexChars + 1];
    acc[0] <== 0;
    for (var i = 0; i < nHexChars; i++) {
        acc[i + 1] <== acc[i] * 16 + nibbles[i].nibble;
    }
    value <== acc[nHexChars];
}
