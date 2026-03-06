# Discoverability

## Overview

Claimers need to find deceased users on-chain to deliver their messages. Without an enumerable list, there is no way to
discover user addresses from the contract alone — only individual lookups by known address exist. Events
(`Deceased`, `UserRegistered`) work off-chain but require indexers or archive nodes.

The discoverability feature provides an **opt-in** on-chain list of registered users. Claimers can enumerate this list,
check each user's status, and call `markDeceased()` + `claim()` when timeouts are detected.

Users are **not** discoverable by default. They must explicitly opt in by calling `setDiscoverable(true)`.

## How It Works

1. A registered user calls `setDiscoverable(true)` to add themselves to the on-chain list
2. Their address becomes publicly enumerable via `getDiscoverableUsers()`
3. They can call `setDiscoverable(false)` at any time to remove themselves
4. Removal uses swap-and-pop for gas efficiency (array order is not preserved)

## User Guide

### Opting In

```typescript
import { ethers } from "ethers";

const contract = new ethers.Contract(FAREWELL_ADDRESS, FAREWELL_ABI, signer);

// Opt into discoverability (must be registered first)
const tx = await contract.setDiscoverable(true);
await tx.wait();
```

### Opting Out

```typescript
const tx = await contract.setDiscoverable(false);
await tx.wait();
```

## Claimer Guide

Full workflow for a claimer to discover and process deceased users:

```typescript
import { ethers } from "ethers";

const contract = new ethers.Contract(FAREWELL_ADDRESS, FAREWELL_ABI, provider);

// Step 1: Get total count for pagination
const total = await contract.getDiscoverableCount();

// Step 2: Paginate through all discoverable users
const PAGE_SIZE = 100;
for (let offset = 0; offset < total; offset += PAGE_SIZE) {
  const users = await contract.getDiscoverableUsers(offset, PAGE_SIZE);

  for (const userAddr of users) {
    // Step 3: Check each user's state
    const [status, graceSecondsLeft] = await contract.getUserState(userAddr);

    // UserStatus.Deceased = 2 (check-in + grace period expired)
    if (status === 2) {
      // Step 4a: Mark deceased (if not already marked)
      try {
        const tx = await contract.connect(signer).markDeceased(userAddr);
        await tx.wait();
      } catch {
        // Already marked deceased by someone else — continue
      }

      // Step 4b: Claim messages
      const messageCount = await contract.messageCount(userAddr);
      for (let i = 0; i < messageCount; i++) {
        try {
          const tx = await contract.connect(signer).claim(userAddr, i);
          await tx.wait();
        } catch {
          // Already claimed or revoked — skip
        }
      }
    }
  }
}
```

## API Reference

### setDiscoverable(bool)

Toggle discoverability for the calling user.

- **Reverts** with `NotRegistered()` if caller is not registered
- **Reverts** with `AlreadyDiscoverable()` if opting in when already in list
- **Reverts** with `NotDiscoverable()` if opting out when not in list
- **Emits** `DiscoverabilityChanged(address indexed user, bool discoverable)`

### getDiscoverableUsers(uint256 offset, uint256 limit)

Returns a paginated slice of discoverable user addresses.

- Returns empty array if `offset >= total`
- Clamps to array bounds (never reverts)

### getDiscoverableCount()

Returns the total number of discoverable users.

### DiscoverabilityChanged Event

```solidity
event DiscoverabilityChanged(address indexed user, bool discoverable);
```

Emitted when a user opts in or out of discoverability.

## Privacy Considerations

Opting into discoverability **reveals**:

- Your wallet address is a Farewell user
- Your liveness status (anyone can call `getUserState()` on your address)
- Your check-in and grace period configuration

Opting in does **not** reveal:

- Message contents (encrypted with AES-128-GCM)
- Recipient email addresses (encrypted with FHE)
- Key shares (encrypted with FHE)
- Number or content of messages

Users should understand that discoverability is a trade-off: it makes message delivery more likely (claimers can find
you) but exposes your address as a Farewell user on a public blockchain.
