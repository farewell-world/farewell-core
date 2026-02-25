import { DeployFunction } from "hardhat-deploy/types";
import { HardhatRuntimeEnvironment } from "hardhat/types";

const func: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { ethers, upgrades, deployments, getNamedAccounts } = hre as any;
  const { deployer } = await getNamedAccounts();

  const signer = await ethers.getSigner(deployer);
  const Farewell = await ethers.getContractFactory("Farewell", signer);

  const proxy = await upgrades.deployProxy(Farewell, [], {
    kind: "uups",
    initializer: "initialize",
  });
  await proxy.waitForDeployment();

  const proxyAddr = await proxy.getAddress();
  const implAddr = await upgrades.erc1967.getImplementationAddress(proxyAddr);

  console.log("Farewell (proxy):", proxyAddr);
  console.log("Implementation   :", implAddr);

  // (Optional) Save to hardhat-deploy so deployments.get("Farewell") works
  await deployments.save("Farewell", {
    address: proxyAddr,
    abi: (await hre.artifacts.readArtifact("Farewell")).abi,
    implementation: implAddr,
  });
};

export default func;
func.id = "deploy_Farewell";
func.tags = ["Farewell"];
