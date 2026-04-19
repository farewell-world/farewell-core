import { DeployFunction } from "hardhat-deploy/types";
import { HardhatRuntimeEnvironment } from "hardhat/types";

/**
 * Deploy FarewellTestMode — Sepolia / Hardhat ONLY.
 *
 * This deployment script is skipped on mainnet (chainId 1).
 * The contract constructor also hard-reverts on non-test chains as a second guard.
 */
const func: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
  const { ethers, deployments, getNamedAccounts } = hre;
  const { deployer } = await getNamedAccounts();
  const { chainId } = await ethers.provider.getNetwork();

  const chain = Number(chainId);
  if (chain !== 11155111 && chain !== 31337) {
    console.log(`Skipping FarewellTestMode deployment on chain ${chain} (only Sepolia/Hardhat)`);
    return;
  }

  const signer = await ethers.getSigner(deployer);
  console.log("Deployer:", deployer);

  // Reuse existing FarewellExtension if already deployed, otherwise deploy fresh
  let extensionAddress: string;
  try {
    const existing = await deployments.get("FarewellExtension");
    extensionAddress = existing.address;
    console.log("Reusing FarewellExtension at:", extensionAddress);
  } catch {
    const ExtFactory = await ethers.getContractFactory("FarewellExtension", signer);
    const ext = await ExtFactory.deploy(deployer);
    await ext.waitForDeployment();
    extensionAddress = await ext.getAddress();
    console.log("Deployed FarewellExtension at:", extensionAddress);

    await deployments.save("FarewellExtension", {
      address: extensionAddress,
      abi: (await hre.artifacts.readArtifact("FarewellExtension")).abi,
    });
  }

  const TestModeFactory = await ethers.getContractFactory("FarewellTestMode", signer);
  console.log("Deploying FarewellTestMode with owner:", deployer, "extension:", extensionAddress);
  const testMode = await TestModeFactory.deploy(deployer, extensionAddress);
  await testMode.waitForDeployment();
  const address = await testMode.getAddress();
  console.log("FarewellTestMode deployed to:", address);

  await deployments.save("FarewellTestMode", {
    address,
    abi: (await hre.artifacts.readArtifact("FarewellTestMode")).abi,
  });

  console.log("FarewellTestMode deployment saved. Done.");
};

export default func;
func.id = "deploy_FarewellTestMode";
func.tags = ["FarewellTestMode"];
