// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {FHE} from "@fhevm/solidity/lib/FHE.sol";
import {ZamaConfig} from "@fhevm/solidity/config/ZamaConfig.sol";

/// @title SepoliaConfigUpgradeable
/// @notice Upgradeable equivalent of SepoliaConfig that wires FHEVM config in an initializer
abstract contract SepoliaConfigUpgradeable is Initializable {
    /// @dev Call this from your contract's initialize() (or reinitializer) instead of using a constructor
    function __SepoliaConfig_init() internal onlyInitializing {
        // With the new ZamaConfig, the DecryptionOracle is included in CoprocessorConfig
        FHE.setCoprocessor(ZamaConfig.getSepoliaConfig());
    }

    /// @notice Expose the protocol id (useful for clients/frontends)
    function protocolId() public pure returns (uint256) {
        return ZamaConfig.getSepoliaProtocolId();
    }

    // Storage gap for future-proofing upgradeability
    uint256[50] private __gap;
}
