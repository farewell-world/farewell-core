const hre = require("hardhat");

const ABI = [
  "function addMessage(string recipient, bytes payload, string publicMessage)"
];

async function main() {
  const CONTRACT   = process.env.CONTRACT;
  const RECIPIENT  = process.env.RECIPIENT;
  const PAYLOAD    = process.env.PAYLOAD;     // 0x...
  const PUBLIC_MSG = process.env.PUBLIC_MSG || "";

  if (!CONTRACT || !RECIPIENT || !PAYLOAD) {
    throw new Error("Missing CONTRACT/RECIPIENT/PAYLOAD envs");
  }

  const { ethers } = hre;

  let signer;
  if (process.env.PRIVATE_KEY) {
    signer = new ethers.Wallet(process.env.PRIVATE_KEY, ethers.provider);
  } else {
    [signer] = await ethers.getSigners();
  }
  console.log("Using signer:", await signer.getAddress());

  const contract = new ethers.Contract(CONTRACT, ABI, signer);
  const tx = await contract.messageCount(signer.getAddress());
  const rc = await tx.wait();
  console.log(JSON.stringify({
    hash: tx.hash,
    blockNumber: rc.blockNumber,
    gasUsed: rc.gasUsed?.toString?.()
  }, null, 2));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
