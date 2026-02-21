// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity 0.8.27;

contract MockGroth16Verifier {
    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[] calldata
    ) external pure returns (bool) {
        return true;
    }
}
