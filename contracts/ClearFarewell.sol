// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity 0.8.27;

/// @title ClearFarewell POC (email-recipient version)
/// @author Farewell
/// @notice Minimal on-chain PoC for posthumous message release via timeout.
/// - Recipients are EMAILS (string), not wallet addresses.
/// - Anyone can call `claim` after timeout; we emit an event with (email, data).
/// - On-chain data is public. Treat `data` as ciphertext in real use.
contract ClearFarewell {
    struct UserConfig {
        uint64 checkInPeriod; // seconds
        uint64 gracePeriod; // seconds
        uint64 lastCheckIn; // timestamp
        bool deceased; // set after timeout
    }

    struct Message {
        string recipientEmail; // human-friendly identifier
        bytes32 recipientEmailHash; // keccak256(bytes(recipientEmail)) for indexed lookups
        bool delivered;
        bytes data; // store ciphertext or plaintext (PoC)
    }

    // --- Custom errors ---
    error AlreadyRegistered();
    error NotRegistered();
    error UserDeceased();
    error NotDeliverable();
    error AlreadyDelivered();
    error BadEmail();
    error BadSize();
    error NotTimedOut();
    error InvalidIndex();

    /// @notice Per-user configuration and liveness state.
    mapping(address user => UserConfig config) public users;
    mapping(address user => Message[] messages) private _messages;

    /// @notice Emitted when a user registers.
    /// @param user The registered address.
    /// @param checkInPeriod Seconds between required pings.
    /// @param gracePeriod Seconds of grace after missed ping.
    event UserRegistered(address indexed user, uint64 indexed checkInPeriod, uint64 indexed gracePeriod);

    /// @notice Emitted when a user pings to confirm liveness.
    /// @param user The address that pinged.
    /// @param when Timestamp of the ping.
    event Ping(address indexed user, uint64 indexed when);

    /// @notice Emitted when a user is marked deceased.
    /// @param user The address marked deceased.
    /// @param when Timestamp of the deceased marking.
    event Deceased(address indexed user, uint64 indexed when);

    /// @notice Emitted when a message is added. Indexed by email hash for efficient filtering.
    /// @param user The sender address.
    /// @param index Index of the new message.
    /// @param recipientEmailHash keccak256 hash of the recipient email.
    /// @param recipientEmail Plaintext recipient email (not indexed).
    event MessageAdded(
        address indexed user,
        uint256 indexed index,
        bytes32 indexed recipientEmailHash,
        string recipientEmail
    );

    /// @notice Emitted when a message is claimed after death.
    /// @param user The sender address.
    /// @param index Index of the claimed message.
    /// @param recipientEmailHash keccak256 hash of the recipient email.
    /// @param recipientEmail Plaintext recipient email.
    /// @param data The message payload.
    event MessageClaimed(
        address indexed user,
        uint256 indexed index,
        bytes32 indexed recipientEmailHash,
        string recipientEmail,
        bytes data
    );

    // --- User lifecycle ---
    uint64 internal constant DEFAULT_CHECKIN = 30 days;
    uint64 internal constant DEFAULT_GRACE = 7 days;

    /// @notice Register with default check-in and grace periods.
    function registerDefault() external {
        uint64 checkInPeriod = DEFAULT_CHECKIN;
        uint64 gracePeriod = DEFAULT_GRACE;
        UserConfig storage u = users[msg.sender];
        if (u.lastCheckIn != 0) revert AlreadyRegistered();
        u.checkInPeriod = checkInPeriod;
        u.gracePeriod = gracePeriod;
        u.lastCheckIn = uint64(block.timestamp);
        u.deceased = false;
        emit UserRegistered(msg.sender, checkInPeriod, gracePeriod);
        emit Ping(msg.sender, u.lastCheckIn);
    }

    /// @notice Register with custom check-in and grace periods.
    /// @param checkInPeriod Seconds between required pings.
    /// @param gracePeriod Seconds of grace after a missed ping.
    function register(uint64 checkInPeriod, uint64 gracePeriod) external {
        // require(checkInPeriod >= 1 days, "period too short");
        // require(gracePeriod >= 1 days, "grace too short");
        UserConfig storage u = users[msg.sender];
        if (u.lastCheckIn != 0) revert AlreadyRegistered();
        u.checkInPeriod = checkInPeriod;
        u.gracePeriod = gracePeriod;
        u.lastCheckIn = uint64(block.timestamp);
        u.deceased = false;
        emit UserRegistered(msg.sender, checkInPeriod, gracePeriod);
        emit Ping(msg.sender, u.lastCheckIn);
    }

    /// @notice Ping to reset the check-in timer and prove liveness.
    function ping() external {
        UserConfig storage u = users[msg.sender];
        if (u.checkInPeriod == 0) revert NotRegistered();
        if (u.deceased) revert UserDeceased();
        u.lastCheckIn = uint64(block.timestamp);
        emit Ping(msg.sender, u.lastCheckIn);
    }

    /// @notice Mark a user as deceased after their timeout has elapsed.
    /// @param user The address to mark as deceased.
    function markDeceased(address user) external {
        UserConfig storage u = users[user];
        if (u.checkInPeriod == 0) revert NotRegistered();
        if (u.deceased) revert UserDeceased();
        // timeout condition: now > lastCheckIn + checkInPeriod + grace
        uint256 deadline = uint256(u.lastCheckIn) + uint256(u.checkInPeriod) + uint256(u.gracePeriod);
        if (!(block.timestamp > deadline)) revert NotTimedOut();
        u.deceased = true;
        emit Deceased(user, uint64(block.timestamp));
    }

    // --- Messages ---

    /// @notice Add a message for a recipient to be released after death.
    /// @param recipientEmail Email address of the intended recipient.
    /// @param data Message payload (treat as ciphertext in real use).
    /// @return index Index of the newly added message.
    function addMessage(string calldata recipientEmail, bytes calldata data) external returns (uint256 index) {
        if (users[msg.sender].checkInPeriod == 0) revert NotRegistered();
        if (!(bytes(recipientEmail).length > 3)) revert BadEmail();
        if (data.length == 0 || data.length > 2000) revert BadSize(); // keep small for PoC gas

        bytes32 emailHash = keccak256(bytes(recipientEmail));
        _messages[msg.sender].push(
            Message({recipientEmail: recipientEmail, recipientEmailHash: emailHash, delivered: false, data: data})
        );
        index = _messages[msg.sender].length - 1;
        emit MessageAdded(msg.sender, index, emailHash, recipientEmail);
    }

    /// @notice Return the number of messages stored for a user.
    /// @param user The address to query.
    /// @return The message count.
    function messageCount(address user) external view returns (uint256) {
        return _messages[user].length;
    }

    /// @notice Return metadata for a specific message.
    /// @param user The owner address.
    /// @param index The message index.
    /// @return recipientEmail Plaintext recipient email.
    /// @return recipientEmailHash keccak256 hash of the recipient email.
    /// @return delivered Whether the message has been claimed.
    function getMessageMeta(
        address user,
        uint256 index
    ) external view returns (string memory recipientEmail, bytes32 recipientEmailHash, bool delivered) {
        if (!(_messages[user].length > index)) revert InvalidIndex();
        Message storage m = _messages[user][index];
        return (m.recipientEmail, m.recipientEmailHash, m.delivered);
    }

    /// @notice Anyone may trigger delivery after user is deceased.
    /// @dev Emits data+email; mark delivered to prevent duplicates.
    /// @param user The deceased user's address.
    /// @param index The message index to claim.
    function claim(address user, uint256 index) external {
        UserConfig storage u = users[user];
        if (!u.deceased) revert NotDeliverable();
        Message storage m = _messages[user][index];
        if (m.delivered) revert AlreadyDelivered();
        m.delivered = true;
        emit MessageClaimed(user, index, m.recipientEmailHash, m.recipientEmail, m.data);
    }

    /// @notice Return the caller's own address (convenience helper).
    /// @return The address of the caller.
    function getMyAddress() external view returns (address) {
        return msg.sender;
    }
}
