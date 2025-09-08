// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {FHE} from "@fhevm/solidity/lib/FHE.sol";
import {ZamaConfig} from "@fhevm/solidity/config/ZamaConfig.sol";

abstract contract SepoliaConfigUpgradeable is Initializable {
    function __SepoliaConfigUpgradeable_init() internal onlyInitializing {
        FHE.setCoprocessor(ZamaConfig.getSepoliaConfig());
        FHE.setDecryptionOracle(ZamaConfig.getSepoliaOracleAddress());
    }
}
