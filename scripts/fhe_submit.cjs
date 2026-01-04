// fhe_submit.cjs
const { readFile } = require("node:fs/promises");
const { randomBytes, webcrypto } = require("node:crypto");
const { createInstance, SepoliaConfig } = require("@zama-fhe/relayer-sdk/node");
const { ethers } = require("ethers");

// ---- CLI args ----
function parseArgs(argv) {
  const out = {};
  for (let i = 2; i < argv.length; i++) {
    const k = argv[i];
    const v = argv[i + 1];
    if (!v || v.startsWith("--")) {
      out[k.replace(/^--/, "")] = true; // boolean flag
    } else {
      out[k.replace(/^--/, "")] = v;
      i++;
    }
  }
  return out;
}

const args = parseArgs(process.argv);
const {
  contract,
  recipient,           // string (email or other UTF-8)
  skshare,             // 0x + 32 hex chars (128-bit)
  s,                   // 0x + 32 hex chars (random 128-bit)
  file,                // path to file to encrypt
  "public-message": publicMessage = ""
} = args;

const RPC_URL = process.env.RPC_URL;
const PRIVATE_KEY = process.env.PRIVATE_KEY;

if (!RPC_URL || !PRIVATE_KEY) {
  console.error("Set env: RPC_URL and PRIVATE_KEY");
  process.exit(1);
}
if (!contract) {
  console.error("--contract is required");
  process.exit(1);
}
if (!recipient) {
  console.error("--recipient is required");
  process.exit(1);
}
function isHex128(x) { return /^0x[0-9a-fA-F]{32}$/.test(x); }
if (!isHex128(skshare)) {
  console.error("--skshare must be 0x + 32 hex chars (128-bit)");
  process.exit(1);
}
if (!isHex128(s)) {
  console.error("--s must be 0x + 32 hex chars (128-bit)");
  process.exit(1);
}
if (!file) {
  console.error("--file is required");
  process.exit(1);
}

// ---- helpers ----
const toBigInt = (hex) => BigInt(hex);
const mask128 = (1n << 128n) - 1n;
const u8 = (arr) => new Uint8Array(arr);

// pack UTF-8 string into big-endian 32-byte limbs for euint256[]
function packUtf8To256Limbs(str) {
  const bytes = new TextEncoder().encode(str);
  const limbs = [];
  for (let i = 0; i < bytes.length; i += 32) {
    const chunk = bytes.subarray(i, i + 32);
    let v = 0n;
    for (let j = 0; j < chunk.length; j++) v = (v << 8n) + BigInt(chunk[j]);
    limbs.push(v);
  }
  return { limbs, byteLen: bytes.length };
}

// AES-GCM with 16-byte key (128-bit)
async function aesGcmEncryptHex(plaintextBytes, key16) {
  const iv = randomBytes(12); // 96-bit IV
  const cryptoKey = await webcrypto.subtle.importKey(
    "raw",
    key16,
    { name: "AES-GCM", length: 128 },
    false,
    ["encrypt"]
  );
  const ct = await webcrypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    cryptoKey,
    plaintextBytes
  );
  // Pack as 0x(IV||CT) hex
  const buf = Buffer.concat([Buffer.from(iv), Buffer.from(new Uint8Array(ct))]);
  return "0x" + buf.toString("hex");
}

function bigintXor128(a, b) {
  return (a ^ b) & mask128;
}
function bigintToBytes16(bi) {
  const out = new Uint8Array(16);
  for (let i = 15; i >= 0; i--) {
    out[i] = Number(bi & 0xffn);
    bi >>= 8n;
  }
  return out;
}

// ---- main flow ----
(async () => {
  const provider = new ethers.JsonRpcProvider(RPC_URL);
  const wallet = new ethers.Wallet(PRIVATE_KEY, provider);
  console.log("Using wallet:", await wallet.getAddress());

  // 1) Load file
  const plaintext = await readFile(file);
  // 2) Compute sk = S XOR skShare (both 128-bit)
  const sBI = toBigInt(s);
  const shareBI = toBigInt(skshare);
  const skBI = bigintXor128(sBI, shareBI);
  const key16 = bigintToBytes16(skBI);

  // 3) AES-GCM encrypt the file
  const payloadHex = await aesGcmEncryptHex(plaintext, key16);

  // 4) Prepare FHE encrypted inputs (recipient limbs + S)
  const instance = await createInstance(SepoliaConfig); // tweak if not Sepolia
  const userAddr = await wallet.getAddress();

  // Using the "contract-first" batch input builder (multi-values, 1 proof)
  const input = instance.createEncryptedInput(contract, userAddr);
  const { limbs, byteLen } = packUtf8To256Limbs(recipient);
  for (const limb of limbs) input.add256(limb);
  input.add128(sBI); // S is the value we store (the other share)
  const enc = await input.encrypt();
  const limbHandles = enc.handles.slice(0, limbs.length);
  const encSkShareHandle = enc.handles[limbs.length]; // corresponds to S
  const inputProof = enc.inputProof; // bytes

  // 5) Call addMessage(...)
  //    function addMessage(
  //      externalEuint256[] calldata limbs,
  //      uint32 emailByteLen,
  //      externalEuint128 encSkShare,
  //      bytes calldata payload,
  //      bytes calldata inputProof,
  //      string calldata publicMessage
  //    ) external returns (uint256 index)
  const abi = [
    "function addMessage(bytes32[] limbs,uint32 emailByteLen,bytes32 encSkShare,bytes payload,bytes inputProof,string publicMessage) returns (uint256)"
  ];
  const contractInst = new ethers.Contract(contract, abi, wallet);

  const tx = await contractInst.addMessage(
    limbHandles,
    byteLen,
    encSkShareHandle,
    payloadHex,
    inputProof,
    publicMessage
  );
  const receipt = await tx.wait();

  // Emit a single JSON line so the bash script can jq it.
  console.log(JSON.stringify({
    txHash: tx.hash,
    blockNumber: receipt?.blockNumber ?? null,
    gasUsed: receipt?.gasUsed?.toString() ?? null,
    file
  }));
})().catch((err) => {
  // Print a short error (bash will show which file failed)
  const msg = (err && err.message) ? err.message : String(err);
  console.error(msg);
  process.exit(1);
});
