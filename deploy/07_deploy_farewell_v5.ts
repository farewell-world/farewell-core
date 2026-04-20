import { DeployFunction } from "hardhat-deploy/types";
import { HardhatRuntimeEnvironment } from "hardhat/types";

const func: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
  const { ethers, deployments, getNamedAccounts } = hre;
  const { deployer } = await getNamedAccounts();

  const signer = await ethers.getSigner(deployer);
  console.log("Deployer:", deployer);
  console.log("Balance:", ethers.formatEther(await ethers.provider.getBalance(deployer)), "ETH");

  // Step 1: Deploy FarewellExtension (council, voting, rewards, ZK proofs, discoverability, admin)
  const FarewellExtension = await ethers.getContractFactory("FarewellExtension", signer);
  console.log("Deploying FarewellExtension with owner:", deployer);
  const extension = await FarewellExtension.deploy(deployer);
  await extension.waitForDeployment();
  const extensionAddress = await extension.getAddress();
  console.log("FarewellExtension deployed to:", extensionAddress);

  // Step 2: Deploy Farewell core with extension address
  const Farewell = await ethers.getContractFactory("Farewell", signer);
  console.log("Deploying Farewell (non-proxy) with owner:", deployer, "extension:", extensionAddress);
  const farewell = await Farewell.deploy(deployer, extensionAddress);
  await farewell.waitForDeployment();

  const address = await farewell.getAddress();
  console.log("Farewell deployed to:", address);

  // Save to hardhat-deploy so deployments.get("Farewell") works
  await deployments.save("Farewell", {
    address,
    abi: (await hre.artifacts.readArtifact("Farewell")).abi,
  });

  await deployments.save("FarewellExtension", {
    address: extensionAddress,
    abi: (await hre.artifacts.readArtifact("FarewellExtension")).abi,
  });

  console.log("Deployment saved. Done.");
};

export default func;
func.id = "deploy_Farewell_v5_encrypted_name";
func.tags = ["FarewellV5"];
