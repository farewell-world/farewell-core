import { DeployFunction } from "hardhat-deploy/types";
import { HardhatRuntimeEnvironment } from "hardhat/types";

const func: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
  const { ethers, deployments, getNamedAccounts } = hre;
  const { deployer } = await getNamedAccounts();

  const signer = await ethers.getSigner(deployer);
  console.log("Deployer:", deployer);
  console.log("Balance:", ethers.formatEther(await ethers.provider.getBalance(deployer)), "ETH");

  // Deploy MockUSDT (6 decimals, like real USDT)
  const MockERC20 = await ethers.getContractFactory("MockERC20", signer);

  console.log("Deploying MockUSDT...");
  const mockUSDT = await MockERC20.deploy("Mock USDT", "USDT", 6);
  await mockUSDT.waitForDeployment();
  const usdtAddress = await mockUSDT.getAddress();
  console.log("MockUSDT deployed to:", usdtAddress);

  // Mint 1,000,000 USDT to deployer for testing
  const mintAmount = ethers.parseUnits("1000000", 6);
  const mintTx = await mockUSDT.mint(deployer, mintAmount);
  await mintTx.wait();
  console.log("Minted 1,000,000 USDT to deployer");

  // Save deployment
  await deployments.save("MockUSDT", {
    address: usdtAddress,
    abi: (await hre.artifacts.readArtifact("MockERC20")).abi,
  });

  console.log("MockUSDT deployment saved. Done.");
};

export default func;
func.id = "deploy_MockERC20";
func.tags = ["MockERC20"];
