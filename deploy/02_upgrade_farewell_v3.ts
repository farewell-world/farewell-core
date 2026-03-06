import { DeployFunction } from "hardhat-deploy/types";
import { HardhatRuntimeEnvironment } from "hardhat/types";

const func: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { ethers, upgrades, deployments, getNamedAccounts } = hre as any;
  const { deployer } = await getNamedAccounts();

  const signer = await ethers.getSigner(deployer);
  const existing = await deployments.get("Farewell");
  const proxyAddr = existing.address;

  console.log("Upgrading Farewell proxy at:", proxyAddr);

  const FarewellV3 = await ethers.getContractFactory("Farewell", signer);
  const upgraded = await upgrades.upgradeProxy(proxyAddr, FarewellV3, {
    kind: "uups",
  });
  await upgraded.waitForDeployment();

  const newImplAddr = await upgrades.erc1967.getImplementationAddress(proxyAddr);
  console.log("New implementation:", newImplAddr);

  // Update hardhat-deploy artifact
  await deployments.save("Farewell", {
    address: proxyAddr,
    abi: (await hre.artifacts.readArtifact("Farewell")).abi,
    implementation: newImplAddr,
  });

  console.log("Upgrade complete.");
};

export default func;
func.id = "upgrade_Farewell_v3";
func.tags = ["FarewellUpgradeV3"];
