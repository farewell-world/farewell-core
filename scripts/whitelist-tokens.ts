import { ethers } from "hardhat";

async function main() {
  const farewellAddress = "0xe59562a989Cc656ec4400902D59cf34A72041c22";
  const USDC_ADDRESS = "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238";

  // Read MockUSDT address from deployment
  const { deployments } = require("hardhat");
  const mockUSDT = await deployments.get("MockUSDT");
  const USDT_ADDRESS = mockUSDT.address;

  const [signer] = await ethers.getSigners();
  console.log("Signer:", await signer.getAddress());

  const abi = ["function setAllowedRewardToken(address token, bool allowed) external"];
  const contract = new ethers.Contract(farewellAddress, abi, signer);

  console.log(`Whitelisting MockUSDT (${USDT_ADDRESS})...`);
  const tx1 = await contract.setAllowedRewardToken(USDT_ADDRESS, true);
  await tx1.wait();
  console.log("MockUSDT whitelisted.");

  console.log(`Whitelisting USDC (${USDC_ADDRESS})...`);
  const tx2 = await contract.setAllowedRewardToken(USDC_ADDRESS, true);
  await tx2.wait();
  console.log("USDC whitelisted.");

  console.log("Done! Both tokens whitelisted on Farewell contract.");
}

main().catch(console.error);
