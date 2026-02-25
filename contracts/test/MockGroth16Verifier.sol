// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity 0.8.27;

/// @title MockGroth16Verifier
/// @author Farewell Protocol
/// @notice Mock verifier that always returns true, used for testing.
contract MockGroth16Verifier {
    /// @notice Always returns true regardless of proof inputs.
    /// @param pA Proof element A.
    /// @param pB Proof element B.
    /// @param pC Proof element C.
    /// @param pubSignals Public signals array.
    /// @return True unconditionally.
    function verifyProof(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[] calldata pubSignals
    ) external pure returns (bool) {
        // Silence unused variable warnings
        pA;
        pB;
        pC;
        pubSignals;
        return true;
    }
}
