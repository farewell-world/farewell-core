// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity 0.8.27;

import {Farewell} from "../Farewell.sol";
import {FarewellStorage} from "../FarewellStorage.sol";

/// @title FarewellTestMode - Test-only contract for setting up arbitrary user states
/// @author Farewell Protocol
/// @notice SEPOLIA / HARDHAT ONLY. Extends Farewell with onlyOwner functions to directly
///         manipulate user storage, enabling E2E tests with users in any lifecycle state.
///         The constructor hard-reverts on mainnet (chainId 1) and any chain that is not
///         Sepolia (11155111) or Hardhat (31337).
/// @dev No new storage variables — preserves the FarewellStorage layout exactly.
contract FarewellTestMode is Farewell {
    error TestModeChainNotAllowed();

    constructor(
        address initialOwner,
        address _extension
    ) Farewell(initialOwner, _extension) {
        // SAFETY: hard guard against mainnet and unknown chains
        if (block.chainid != 11155111 && block.chainid != 31337)
            revert TestModeChainNotAllowed();
    }

    /// @notice Register a user with a backdated lastCheckIn to place them in any lifecycle state.
    /// @param userAddr The address to register
    /// @param checkInPeriod Check-in period in seconds (min 1 day)
    /// @param gracePeriod Grace period in seconds (min 1 day)
    /// @param backdateSeconds How far back to set lastCheckIn from current block.timestamp.
    ///        0 = alive (just registered). checkInPeriod + gracePeriod/2 = in grace.
    ///        checkInPeriod + gracePeriod + buffer = past grace (eligible for markDeceased).
    function setupTestUser(
        address userAddr,
        uint64 checkInPeriod,
        uint64 gracePeriod,
        uint256 backdateSeconds
    ) external onlyOwner {
        User storage u = users[userAddr];
        bool isNew = (u.lastCheckIn == 0);

        u.checkInPeriod = checkInPeriod;
        u.gracePeriod = gracePeriod;
        u.encryptedVoting = false;
        u.deceased = false;
        u.finalAlive = false;

        uint64 ts = uint64(block.timestamp);
        if (backdateSeconds >= block.timestamp) {
            u.lastCheckIn = 1;
            u.registeredOn = 1;
        } else {
            u.lastCheckIn = ts - uint64(backdateSeconds);
            u.registeredOn = ts - uint64(backdateSeconds);
        }

        if (isNew) ++totalUsers;
        emit UserRegistered(userAddr, checkInPeriod, gracePeriod, u.registeredOn);
    }

    /// @notice Add council members for a user, bypassing the grace-period freeze.
    /// @param userAddr The user to add council members to (must be registered)
    /// @param members Array of council member addresses
    function setupTestCouncil(
        address userAddr,
        address[] calldata members
    ) external onlyOwner onlyRegistered(userAddr) {
        for (uint256 i = 0; i < members.length; ) {
            address m = members[i];
            councils[userAddr].push(
                CouncilMember({member: m, joinedAt: uint64(block.timestamp)})
            );
            councilMembers[userAddr][m] = true;
            memberToUsers[m].push(userAddr);
            emit CouncilMemberAdded(userAddr, m);
            unchecked { ++i; }
        }
    }

    /// @notice Force-mark a user as deceased without time checks.
    /// @param userAddr The user to mark deceased
    /// @param notifierAddr The address recorded as the notifier
    function forceMarkDeceased(
        address userAddr,
        address notifierAddr
    ) external onlyOwner onlyRegistered(userAddr) {
        User storage u = users[userAddr];
        u.deceased = true;
        u.notifier = Notifier({
            notificationTime: uint64(block.timestamp),
            notifierAddress: notifierAddr
        });
        emit Deceased(userAddr, uint64(block.timestamp), notifierAddr);
    }

    /// @notice Force a user into FinalAlive state (council-voted alive) without voting.
    /// @param userAddr The user to set as FinalAlive
    function forceSetFinalAlive(
        address userAddr
    ) external onlyOwner onlyRegistered(userAddr) {
        User storage u = users[userAddr];
        u.finalAlive = true;
        u.lastCheckIn = uint64(block.timestamp);
        emit StatusDecided(userAddr, true);
        emit Ping(userAddr, u.lastCheckIn);
    }
}
