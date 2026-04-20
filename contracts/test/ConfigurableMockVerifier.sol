// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity 0.8.27;

/// @title ConfigurableMockVerifier
/// @notice Mock Groth16 verifier with a toggleable result for testing valid and invalid proofs.
contract ConfigurableMockVerifier {
    bool public result = true;

    function setResult(bool _result) external {
        result = _result;
    }

    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[] calldata
    ) external view returns (bool) {
        return result;
    }
}
