import { ethers } from "hardhat";
import fs from "node:fs";
import path from "node:path";

const FAREWELL_ADDRESS = process.env.FAREWELL_ADDRESS || "0xe59562a989Cc656ec4400902D59cf34A72041c22";
const REGISTRY_PATH = path.join(__dirname, "dkim-registry.json");

interface RegistryEntry {
  domain: string;
  selector: string;
  status: string;
  pubkeyHashDecimal: string;
  pubkeyHashHex: string;
}

async function main() {
  const [owner] = await ethers.getSigners();
  console.log(`Owner: ${owner.address}`);

  // FarewellExtension ABI exposes setZkEmailVerifier/setTrustedDkimKey;
  // the proxy at FAREWELL_ADDRESS delegates to FarewellExtension.
  const farewell = await ethers.getContractAt("FarewellExtension", FAREWELL_ADDRESS, owner);

  // 1. Set verifier if specified
  const verifierAddress = process.env.VERIFIER_ADDRESS;
  if (verifierAddress) {
    const currentVerifier = await farewell.zkEmailVerifier();
    if (currentVerifier.toLowerCase() === verifierAddress.toLowerCase()) {
      console.log(`Verifier already set to ${verifierAddress}`);
    } else {
      console.log(`Setting zkEmailVerifier to ${verifierAddress} ...`);
      const tx = await farewell.setZkEmailVerifier(verifierAddress);
      await tx.wait();
      console.log(`  ✓ tx: ${tx.hash}`);
    }
  }

  // 2. Seed DKIM keys from registry
  if (!fs.existsSync(REGISTRY_PATH)) {
    console.log("No dkim-registry.json found, skipping DKIM seeding.");
    return;
  }

  const registry: RegistryEntry[] = JSON.parse(fs.readFileSync(REGISTRY_PATH, "utf-8"));
  const globalDomain = ethers.zeroPadValue("0x", 32);

  let seeded = 0;
  let skipped = 0;

  for (const entry of registry) {
    const hashBigInt = BigInt(entry.pubkeyHashDecimal);

    const isTrusted = await farewell.trustedDkimKeys(globalDomain, hashBigInt);
    if (isTrusted) {
      console.log(`  skip: ${entry.domain}/${entry.selector} (already trusted)`);
      skipped++;
      continue;
    }

    console.log(`  seeding: ${entry.domain}/${entry.selector} → ${entry.pubkeyHashHex}`);
    const tx = await farewell.setTrustedDkimKey(globalDomain, hashBigInt, true);
    await tx.wait();
    console.log(`    ✓ tx: ${tx.hash}`);
    seeded++;
  }

  console.log(`\nDone: ${seeded} seeded, ${skipped} already trusted.`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
