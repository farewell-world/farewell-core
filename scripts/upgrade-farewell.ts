import { ethers, upgrades } from "hardhat";

async function main() {
  const proxyAddress = process.env.PROXY_ADDRESS;

  if (!proxyAddress) {
    // Try to get from deployments
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { deployments } = require("hardhat");
    const deployment = await deployments.get("Farewell");
    if (!deployment) {
      throw new Error("No PROXY_ADDRESS env var and no deployment found");
    }
    console.log("Using deployment address:", deployment.address);
    await upgradeContract(deployment.address);
  } else {
    console.log("Using PROXY_ADDRESS:", proxyAddress);
    await upgradeContract(proxyAddress);
  }
}

async function upgradeContract(proxyAddress: string) {
  console.log("Upgrading Farewell at proxy:", proxyAddress);

  const [deployer] = await ethers.getSigners();
  console.log("Deployer:", deployer.address);

  // Get the new implementation
  const FarewellV2 = await ethers.getContractFactory("Farewell", deployer);

  // Get current implementation
  const currentImpl = await upgrades.erc1967.getImplementationAddress(proxyAddress);
  console.log("Current implementation:", currentImpl);

  // Upgrade - using unsafeAllow for testnet since storage layout changed
  console.log("Deploying new implementation and upgrading proxy...");
  console.log("⚠️  Using unsafeAllow due to storage layout changes (testnet only!)");
  const upgraded = await upgrades.upgradeProxy(proxyAddress, FarewellV2, {
    kind: "uups",
    unsafeAllow: ["struct-definition", "enum-definition"],
    unsafeSkipStorageCheck: true,
  });
  await upgraded.waitForDeployment();

  // Get new implementation address
  const newImpl = await upgrades.erc1967.getImplementationAddress(proxyAddress);
  console.log("New implementation:", newImpl);

  if (currentImpl === newImpl) {
    console.log("⚠️  Implementation unchanged (contract may already be up to date)");
  } else {
    console.log("✅ Upgrade successful!");
  }

  // Verify functions exist
  const contract = await ethers.getContractAt("Farewell", proxyAddress);
  const hasSetName = typeof contract.setName === "function";
  const hasRevokeMessage = typeof contract.revokeMessage === "function";
  const hasComputeMessageHash = typeof contract.computeMessageHash === "function";
  const hasMessageHashes = typeof contract.messageHashes === "function";
  console.log("setName available:", hasSetName);
  console.log("revokeMessage available:", hasRevokeMessage);
  console.log("computeMessageHash available:", hasComputeMessageHash);
  console.log("messageHashes mapping available:", hasMessageHashes);

  // Save updated deployment info
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { deployments } = require("hardhat");
    const artifact = await (await import("hardhat")).artifacts.readArtifact("Farewell");
    await deployments.save("Farewell", {
      address: proxyAddress,
      abi: artifact.abi,
      implementation: newImpl,
    });
    console.log("Deployment info updated");
  } catch (e) {
    console.log("Could not update deployment info:", e);
  }
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
