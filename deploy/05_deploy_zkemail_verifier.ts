import { DeployFunction } from "hardhat-deploy/types";
import { HardhatRuntimeEnvironment } from "hardhat/types";

const func: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
  const { deployments, getNamedAccounts } = hre;
  const { deploy } = deployments;
  const { deployer } = await getNamedAccounts();

  const result = await deploy("FarewellGroth16Verifier", {
    from: deployer,
    log: true,
  });

  console.log(`FarewellGroth16Verifier deployed at ${result.address}`);
};

func.tags = ["zkemail-verifier"];
export default func;
