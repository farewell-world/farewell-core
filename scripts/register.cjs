// register.cjs
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
  checkin,             // 
  grace,               //  
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
if (!checkin) {
  console.error("--checkin is required");
  process.exit(1);
}
if (!grace) {
  console.error("--grace is required");
  process.exit(1);
}

// ---- main flow ----
(async () => {
  const provider = new ethers.JsonRpcProvider(RPC_URL);
  const wallet = new ethers.Wallet(PRIVATE_KEY, provider);
  console.log("Using wallet:", await wallet.getAddress());

  // 4) Prepare FHE encrypted inputs (recipient limbs + S)
  const instance = await createInstance(SepoliaConfig); // tweak if not Sepolia
  const userAddr = await wallet.getAddress();

  // 5) Call register(uint64 checkInPeriod, uint64 gracePeriod) external
  const abi = [
    "function register(uint64 checkInPeriod,uint64 gracePeriod)"
  ];
  const contractInst = new ethers.Contract(contract, abi, wallet);

  const tx = await contractInst.register(checkin, grace);
  const receipt = await tx.wait();

  // Emit a single JSON line so the bash script can jq it.
  console.log(JSON.stringify({
    txHash: tx.hash,
    blockNumber: receipt?.blockNumber ?? null,
    gasUsed: receipt?.gasUsed?.toString() ?? null,
  }));
})().catch((err) => {
  // Print a short error (bash will show which file failed)
  const msg = (err && err.message) ? err.message : String(err);
  console.error(msg);
  process.exit(1);
});
