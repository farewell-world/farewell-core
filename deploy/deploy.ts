import { DeployFunction } from "hardhat-deploy/types";
import { HardhatRuntimeEnvironment } from "hardhat/types";

const func: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
  const { deployer } = await hre.getNamedAccounts();
  const { deploy } = hre.deployments;

  const deployedFarewell = await deploy("Farewell", {
    from: deployer,
    log: true,
  });

  console.log(`Farewell contract: `, deployedFarewell.address);
};
export default func;
func.id = "deploy_Farewell"; // id required to prevent reexecution
func.tags = ["Farewell"];
