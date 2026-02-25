import { FhevmType } from "@fhevm/hardhat-plugin";
import { Farewell, Farewell__factory } from "../types";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";
import { expect } from "chai";
import { ethers, fhevm } from "hardhat";
import { upgrades } from "hardhat";

type Signers = {
  owner: HardhatEthersSigner;
  alice: HardhatEthersSigner;
  bob: HardhatEthersSigner;
};

async function deployFixture() {
  const FarewellFactory = await ethers.getContractFactory("Farewell");
  // Deploy UUPS proxy and run initialize()
  const proxy = await upgrades.deployProxy(FarewellFactory, [], {
    kind: "uups",
    initializer: "initialize",
  });
  await proxy.waitForDeployment();

  const FarewellContract = proxy as unknown as Farewell;
  const FarewellContractAddress = await FarewellContract.getAddress();
  return { FarewellContract, FarewellContractAddress };
}

// --- helpers ---
const toBytes = (s: string) => ethers.toUtf8Bytes(s);

// utf8 → 32B-chunks (right-padded with zeros), returned as BigInt words
// Pads to MAX_EMAIL_BYTE_LEN (224 bytes = 7 limbs) to prevent length leakage
const MAX_EMAIL_BYTE_LEN = 224;

function chunk32ToU256Words(u8: Uint8Array, padToMax: boolean = true): bigint[] {
  // Pad to MAX_EMAIL_BYTE_LEN if requested (for emails)
  let padded: Uint8Array;
  if (padToMax && u8.length <= MAX_EMAIL_BYTE_LEN) {
    padded = new Uint8Array(MAX_EMAIL_BYTE_LEN);
    padded.set(u8, 0);
  } else {
    padded = u8;
  }

  const words: bigint[] = [];
  for (let i = 0; i < padded.length; i += 32) {
    const slice = padded.subarray(i, i + 32);
    const chunk = new Uint8Array(32);
    chunk.set(slice);
    words.push(BigInt("0x" + Buffer.from(chunk).toString("hex")));
  }
  return words;
}

function u256ToBytes32(u: bigint): Uint8Array {
  const hex = u.toString(16).padStart(64, "0");
  return Uint8Array.from(Buffer.from(hex, "hex"));
}

function concatAndTrim(chunks: Uint8Array[], byteLen: number): Uint8Array {
  const out = new Uint8Array(chunks.length * 32);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += 32;
  }
  return out.slice(0, byteLen);
}

function utf8Decode(u8: Uint8Array): string {
  return new TextDecoder().decode(u8);
}

// --- arrange ---
const email1 = "test@gmail.com";
const payload1 = "hello";
const emailBytes1 = toBytes(email1);
const payloadBytes1 = toBytes(payload1);
const emailWords1 = chunk32ToU256Words(emailBytes1);
const skShare: bigint = 42n;

const email2 = "test2@gmail.com";
const payload2 = "hello2";
const emailBytes2 = toBytes(email2);
const payloadBytes2 = toBytes(payload2);
const emailWords2 = chunk32ToU256Words(emailBytes2);

describe("Farewell", function () {
  let signers: Signers;
  let FarewellContract: Farewell;
  let FarewellContractAddress: string;

  before(async function () {
    // Initializes signers
    const ethSigners: HardhatEthersSigner[] = await ethers.getSigners();
    signers = { owner: ethSigners[0], alice: ethSigners[1], bob: ethSigners[2] };
  });

  beforeEach(async () => {
    ({ FarewellContract, FarewellContractAddress } = await deployFixture());
  });

  it("should work", async function () {
    console.log(`address of user owner is ${signers.owner.address}`);
    console.log(`address of user alice is ${signers.alice.address}`);
    console.log(`address of user bob is ${signers.bob.address}`);
  });

  it("user should be able to add a message after registration", async function () {
    let isRegistered = await FarewellContract.connect(signers.owner).isRegistered(signers.owner.address);
    expect(isRegistered).to.eq(false);

    // Register
    let tx = await FarewellContract.connect(signers.owner)["register()"]();
    await tx.wait();

    isRegistered = await FarewellContract.connect(signers.owner).isRegistered(signers.owner.address);
    expect(isRegistered).to.eq(true);

    // We are going to use the same share for all messages
    // Add a message
    {
      const enc = fhevm.createEncryptedInput(FarewellContractAddress, signers.owner.address);
      // 1) add all email limbs as uint256
      for (const w of emailWords1) enc.add256(w);
      // 2) add the skShare as uint128
      enc.add128(skShare);
      const encrypted = await enc.encrypt();

      const nLimbs = emailWords1.length;
      const limbsHandles = encrypted.handles.slice(0, nLimbs); // externalEuint256[]
      const skShareHandle = encrypted.handles[nLimbs]; // externalEuint128
      tx = await FarewellContract.connect(signers.owner)["addMessage(bytes32[],uint32,bytes32,bytes,bytes)"](
        limbsHandles,
        emailBytes1.length, // emailByteLen
        skShareHandle, // encSkShare (externalEuint128)
        payloadBytes1, // public payload
        encrypted.inputProof,
      );
      await tx.wait();

      const n = await FarewellContract.messageCount(signers.owner.address);
      expect(n).to.eq(1);
    }
    {
      // Add another  message
      const enc = fhevm.createEncryptedInput(FarewellContractAddress, signers.owner.address);
      // 1) add all email limbs as uint256
      for (const w of emailWords2) enc.add256(w);
      // 2) add the skShare as uint128
      enc.add128(skShare);
      const encrypted = await enc.encrypt();

      const nLimbs = emailWords2.length;
      const limbsHandles = encrypted.handles.slice(0, nLimbs); // externalEuint256[]
      const skShareHandle = encrypted.handles[nLimbs]; // externalEuint128

      tx = await FarewellContract.connect(signers.owner)["addMessage(bytes32[],uint32,bytes32,bytes,bytes)"](
        limbsHandles,
        emailBytes2.length, // emailByteLen
        skShareHandle, // encSkShare (externalEuint128)
        payloadBytes2, // public payload
        encrypted.inputProof,
      );
      await tx.wait();

      const n = await FarewellContract.messageCount(signers.owner.address);
      expect(n).to.eq(2);
    }
  });

  it("anyone should be able to claim a message of a dead user but only after the exclusivity period", async function () {
    // Register
    const checkInPeriod = 86400; // 1 day in seconds
    const gracePeriod = 86400; // 1 day in seconds
    let tx = await FarewellContract.connect(signers.owner)["register(uint64,uint64)"](checkInPeriod, gracePeriod);
    await tx.wait();

    // We are going to use the same share for all messages
    // Add a message
    {
      const enc = fhevm.createEncryptedInput(FarewellContractAddress, signers.owner.address);
      // 1) add all email limbs as uint256
      for (const w of emailWords1) enc.add256(w);
      // 2) add the skShare as uint128
      enc.add128(skShare);
      const encrypted = await enc.encrypt();

      const nLimbs = emailWords1.length;
      const limbsHandles = encrypted.handles.slice(0, nLimbs); // externalEuint256[]
      const skShareHandle = encrypted.handles[nLimbs]; // externalEuint128

      tx = await FarewellContract.connect(signers.owner)["addMessage(bytes32[],uint32,bytes32,bytes,bytes)"](
        limbsHandles,
        emailBytes1.length, // emailByteLen
        skShareHandle, // encSkShare (externalEuint128)
        payloadBytes1, // public payload
        encrypted.inputProof,
      );
      await tx.wait();

      const n = await FarewellContract.messageCount(signers.owner.address);
      expect(n).to.eq(1);
    }
    {
      // Add another  message
      const enc = fhevm.createEncryptedInput(FarewellContractAddress, signers.owner.address);
      // 1) add all email limbs as uint256
      for (const w of emailWords2) enc.add256(w);
      // 2) add the skShare as uint128
      enc.add128(skShare);
      const encrypted = await enc.encrypt();

      const nLimbs = emailWords2.length;
      const limbsHandles = encrypted.handles.slice(0, nLimbs); // externalEuint256[]
      const skShareHandle = encrypted.handles[nLimbs]; // externalEuint128

      tx = await FarewellContract.connect(signers.owner)["addMessage(bytes32[],uint32,bytes32,bytes,bytes)"](
        limbsHandles,
        emailBytes1.length, // emailByteLen
        skShareHandle, // encSkShare (externalEuint128)
        payloadBytes1, // public payload
        encrypted.inputProof,
      );
      await tx.wait();

      const n = await FarewellContract.messageCount(signers.owner.address);
      expect(n).to.eq(2);
    }

    // Advance time so owner is considered deceased by timeout
    let timeShift = checkInPeriod + gracePeriod + 1;
    await ethers.provider.send("evm_increaseTime", [timeShift]);
    await ethers.provider.send("evm_mine", []); // mine a block to apply the time

    // Cannot claim before marking deceased
    await expect(FarewellContract.connect(signers.alice).claim(signers.owner.address, 0)).to.be.revertedWithCustomError(
      FarewellContract,
      "NotDeliverable",
    );

    // Alice marks owner as deceased (Alice becomes the notifier)
    tx = await FarewellContract.connect(signers.alice).markDeceased(signers.owner.address);
    await tx.wait();

    // Within the first 24h after notification:
    // - Non-notifier (owner) cannot claim
    await expect(FarewellContract.connect(signers.bob).claim(signers.owner.address, 0)).to.be.revertedWithCustomError(
      FarewellContract,
      "StillExclusiveForNotifier",
    );

    // - Notifier (alice) can claim
    tx = await FarewellContract.connect(signers.alice).claim(signers.owner.address, 0);
    await tx.wait();

    const encryptedClaimedMessage = await FarewellContract.connect(signers.alice).retrieve(signers.owner.address, 0);
    const claimedSkShare = await fhevm.userDecryptEuint(
      FhevmType.euint128,
      encryptedClaimedMessage.skShare,
      FarewellContractAddress,
      signers.alice,
    );
    expect(claimedSkShare).to.eq(skShare);

    // - after 24h exclusivity expires and others can claim
    timeShift = 24 * 60 * 60 + 1;
    await ethers.provider.send("evm_increaseTime", [timeShift]);
    await ethers.provider.send("evm_mine", []); // mine a block to apply the time

    tx = await FarewellContract.connect(signers.bob).claim(signers.owner.address, 1);
    await tx.wait();

    const encryptedClaimedMessageAfter = await FarewellContract.connect(signers.bob).retrieve(signers.owner.address, 1);
    const claimedSkShareAfter = await fhevm.userDecryptEuint(
      FhevmType.euint128,
      encryptedClaimedMessageAfter.skShare,
      FarewellContractAddress,
      signers.bob,
    );
    expect(claimedSkShareAfter).to.eq(skShare);

    // - reconstructs the recipient e-mail
    const limbWords: bigint[] = [];
    for (const limb of encryptedClaimedMessage.encodedRecipientEmail) {
      limbWords.push(await fhevm.userDecryptEuint(FhevmType.euint256, limb, FarewellContractAddress, signers.alice));
    }
    const chunks = limbWords.map(u256ToBytes32);

    // - stitch + trim + utf8
    const emailBytes = concatAndTrim(chunks, Number(encryptedClaimedMessage.emailByteLen));
    const recoveredEmail = utf8Decode(emailBytes);

    expect(recoveredEmail).to.equal(email1);
    expect(ethers.toUtf8String(encryptedClaimedMessage.payload)).to.equal(payload1);
  });

  describe("setName", function () {
    it("should allow a registered user to set and update their name", async function () {
      // Register without name
      let tx = await FarewellContract.connect(signers.owner)["register()"]();
      await tx.wait();

      // Name should be empty initially
      let name = await FarewellContract.getUserName(signers.owner.address);
      expect(name).to.eq("");

      // Set name
      tx = await FarewellContract.connect(signers.owner).setName("Alice");
      await tx.wait();

      name = await FarewellContract.getUserName(signers.owner.address);
      expect(name).to.eq("Alice");

      // Update name
      tx = await FarewellContract.connect(signers.owner).setName("Bob");
      await tx.wait();

      name = await FarewellContract.getUserName(signers.owner.address);
      expect(name).to.eq("Bob");
    });

    it("should allow registration with name", async function () {
      // Register with name
      const tx = await FarewellContract.connect(signers.owner)["register(string,uint64,uint64)"](
        "Charlie",
        86400n, // 1 day check-in
        86400n, // 1 day grace (minimum)
      );
      await tx.wait();

      const name = await FarewellContract.getUserName(signers.owner.address);
      expect(name).to.eq("Charlie");
    });

    it("should revert if user is not registered", async function () {
      await expect(FarewellContract.connect(signers.owner).setName("Test")).to.be.revertedWithCustomError(
        FarewellContract,
        "NotRegistered",
      );
    });
  });

  describe("revokeMessage", function () {
    it("should allow owner to remove their own unclaimed message", async function () {
      // Register
      let tx = await FarewellContract.connect(signers.owner)["register()"]();
      await tx.wait();

      // Add a message
      const enc = fhevm.createEncryptedInput(FarewellContractAddress, signers.owner.address);
      for (const w of emailWords1) enc.add256(w);
      enc.add128(skShare);
      const encrypted = await enc.encrypt();

      const nLimbs = emailWords1.length;
      const limbsHandles = encrypted.handles.slice(0, nLimbs);
      const skShareHandle = encrypted.handles[nLimbs];

      tx = await FarewellContract.connect(signers.owner)["addMessage(bytes32[],uint32,bytes32,bytes,bytes)"](
        limbsHandles,
        emailBytes1.length,
        skShareHandle,
        payloadBytes1,
        encrypted.inputProof,
      );
      await tx.wait();

      let n = await FarewellContract.messageCount(signers.owner.address);
      expect(n).to.eq(1);

      // Revoke the message
      tx = await FarewellContract.connect(signers.owner).revokeMessage(0);
      await tx.wait();

      // Message count should still be 1 (message is marked as revoked, not removed)
      n = await FarewellContract.messageCount(signers.owner.address);
      expect(n).to.eq(1);

      // Trying to retrieve should fail
      await expect(
        FarewellContract.connect(signers.owner).retrieve(signers.owner.address, 0),
      ).to.be.revertedWithCustomError(FarewellContract, "MessageWasRevoked");
    });

    it("should not allow removing an already deleted message", async function () {
      // Register
      let tx = await FarewellContract.connect(signers.owner)["register()"]();
      await tx.wait();

      // Add a message
      const enc = fhevm.createEncryptedInput(FarewellContractAddress, signers.owner.address);
      for (const w of emailWords1) enc.add256(w);
      enc.add128(skShare);
      const encrypted = await enc.encrypt();

      const nLimbs = emailWords1.length;
      const limbsHandles = encrypted.handles.slice(0, nLimbs);
      const skShareHandle = encrypted.handles[nLimbs];

      tx = await FarewellContract.connect(signers.owner)["addMessage(bytes32[],uint32,bytes32,bytes,bytes)"](
        limbsHandles,
        emailBytes1.length,
        skShareHandle,
        payloadBytes1,
        encrypted.inputProof,
      );
      await tx.wait();

      // Revoke the message
      tx = await FarewellContract.connect(signers.owner).revokeMessage(0);
      await tx.wait();

      // Try to revoke again
      await expect(FarewellContract.connect(signers.owner).revokeMessage(0)).to.be.revertedWithCustomError(
        FarewellContract,
        "AlreadyRevoked",
      );
    });

    it("should not allow removing a claimed message", async function () {
      // Register with short periods
      const checkInPeriod = 86400; // 1 day
      const gracePeriod = 86400; // 1 day
      let tx = await FarewellContract.connect(signers.owner)["register(uint64,uint64)"](checkInPeriod, gracePeriod);
      await tx.wait();

      // Add a message
      const enc = fhevm.createEncryptedInput(FarewellContractAddress, signers.owner.address);
      for (const w of emailWords1) enc.add256(w);
      enc.add128(skShare);
      const encrypted = await enc.encrypt();

      const nLimbs = emailWords1.length;
      const limbsHandles = encrypted.handles.slice(0, nLimbs);
      const skShareHandle = encrypted.handles[nLimbs];

      tx = await FarewellContract.connect(signers.owner)["addMessage(bytes32[],uint32,bytes32,bytes,bytes)"](
        limbsHandles,
        emailBytes1.length,
        skShareHandle,
        payloadBytes1,
        encrypted.inputProof,
      );
      await tx.wait();

      // Advance time and mark deceased
      await ethers.provider.send("evm_increaseTime", [checkInPeriod + gracePeriod + 1]);
      await ethers.provider.send("evm_mine", []);

      tx = await FarewellContract.connect(signers.alice).markDeceased(signers.owner.address);
      await tx.wait();

      // Claim the message
      tx = await FarewellContract.connect(signers.alice).claim(signers.owner.address, 0);
      await tx.wait();

      // Try to revoke the claimed message (should fail - user is deceased)
      await expect(FarewellContract.connect(signers.owner).revokeMessage(0)).to.be.revertedWithCustomError(
        FarewellContract,
        "UserDeceased",
      );
    });

    it("should not allow non-owner to remove message", async function () {
      // Register
      let tx = await FarewellContract.connect(signers.owner)["register()"]();
      await tx.wait();

      // Add a message
      const enc = fhevm.createEncryptedInput(FarewellContractAddress, signers.owner.address);
      for (const w of emailWords1) enc.add256(w);
      enc.add128(skShare);
      const encrypted = await enc.encrypt();

      const nLimbs = emailWords1.length;
      const limbsHandles = encrypted.handles.slice(0, nLimbs);
      const skShareHandle = encrypted.handles[nLimbs];

      tx = await FarewellContract.connect(signers.owner)["addMessage(bytes32[],uint32,bytes32,bytes,bytes)"](
        limbsHandles,
        emailBytes1.length,
        skShareHandle,
        payloadBytes1,
        encrypted.inputProof,
      );
      await tx.wait();

      // Alice tries to revoke owner's message
      await expect(FarewellContract.connect(signers.alice).revokeMessage(0)).to.be.revertedWithCustomError(
        FarewellContract,
        "NotRegistered",
      );
    });

    it("should preserve message indices after deletion", async function () {
      // Register
      let tx = await FarewellContract.connect(signers.owner)["register()"]();
      await tx.wait();

      // Add message 0
      {
        const enc = fhevm.createEncryptedInput(FarewellContractAddress, signers.owner.address);
        for (const w of emailWords1) enc.add256(w);
        enc.add128(skShare);
        const encrypted = await enc.encrypt();
        const nLimbs = emailWords1.length;
        tx = await FarewellContract.connect(signers.owner)["addMessage(bytes32[],uint32,bytes32,bytes,bytes)"](
          encrypted.handles.slice(0, nLimbs),
          emailBytes1.length,
          encrypted.handles[nLimbs],
          payloadBytes1,
          encrypted.inputProof,
        );
        await tx.wait();
      }

      // Add message 1
      {
        const enc = fhevm.createEncryptedInput(FarewellContractAddress, signers.owner.address);
        for (const w of emailWords2) enc.add256(w);
        enc.add128(skShare);
        const encrypted = await enc.encrypt();
        const nLimbs = emailWords2.length;
        tx = await FarewellContract.connect(signers.owner)["addMessage(bytes32[],uint32,bytes32,bytes,bytes)"](
          encrypted.handles.slice(0, nLimbs),
          emailBytes2.length,
          encrypted.handles[nLimbs],
          payloadBytes2,
          encrypted.inputProof,
        );
        await tx.wait();
      }

      // Add message 2
      {
        const enc = fhevm.createEncryptedInput(FarewellContractAddress, signers.owner.address);
        for (const w of emailWords1) enc.add256(w);
        enc.add128(skShare);
        const encrypted = await enc.encrypt();
        const nLimbs = emailWords1.length;
        tx = await FarewellContract.connect(signers.owner)["addMessage(bytes32[],uint32,bytes32,bytes,bytes)"](
          encrypted.handles.slice(0, nLimbs),
          emailBytes1.length,
          encrypted.handles[nLimbs],
          payloadBytes1,
          encrypted.inputProof,
        );
        await tx.wait();
      }

      let n = await FarewellContract.messageCount(signers.owner.address);
      expect(n).to.eq(3);

      // Revoke message 1 (middle one)
      tx = await FarewellContract.connect(signers.owner).revokeMessage(1);
      await tx.wait();

      // Message count should still be 3
      n = await FarewellContract.messageCount(signers.owner.address);
      expect(n).to.eq(3);

      // Message 0 should still be accessible
      const msg0 = await FarewellContract.connect(signers.owner).retrieve(signers.owner.address, 0);
      expect(ethers.toUtf8String(msg0.payload)).to.equal(payload1);

      // Message 1 should be revoked
      await expect(
        FarewellContract.connect(signers.owner).retrieve(signers.owner.address, 1),
      ).to.be.revertedWithCustomError(FarewellContract, "MessageWasRevoked");

      // Message 2 should still be accessible
      const msg2 = await FarewellContract.connect(signers.owner).retrieve(signers.owner.address, 2);
      expect(ethers.toUtf8String(msg2.payload)).to.equal(payload1);
    });
  });

  describe("Security validations", function () {
    it("should reject registration with checkInPeriod < 1 day", async function () {
      const shortPeriod = 12 * 60 * 60; // 12 hours
      await expect(
        FarewellContract.connect(signers.owner)["register(uint64,uint64)"](shortPeriod, 7 * 24 * 60 * 60),
      ).to.be.revertedWithCustomError(FarewellContract, "CheckInPeriodTooShort");
    });

    it("should reject registration with gracePeriod < 1 day", async function () {
      const shortGrace = 12 * 60 * 60; // 12 hours
      await expect(
        FarewellContract.connect(signers.owner)["register(uint64,uint64)"](30 * 24 * 60 * 60, shortGrace),
      ).to.be.revertedWithCustomError(FarewellContract, "GracePeriodTooShort");
    });

    it("should reject name longer than 100 characters", async function () {
      const longName = "a".repeat(101);
      await expect(FarewellContract.connect(signers.owner)["register(string)"](longName)).to.be.revertedWithCustomError(
        FarewellContract,
        "NameTooLong",
      );
    });

    it("should reject claim with invalid index (out of bounds)", async function () {
      // Register and mark deceased
      const checkInPeriod = 86400; // 1 day
      const gracePeriod = 86400; // 1 day
      let tx = await FarewellContract.connect(signers.owner)["register(uint64,uint64)"](checkInPeriod, gracePeriod);
      await tx.wait();

      // Add a message
      const enc = fhevm.createEncryptedInput(FarewellContractAddress, signers.owner.address);
      for (const w of emailWords1) enc.add256(w);
      enc.add128(skShare);
      const encrypted = await enc.encrypt();

      const nLimbs = emailWords1.length;
      const limbsHandles = encrypted.handles.slice(0, nLimbs);
      const skShareHandle = encrypted.handles[nLimbs];

      tx = await FarewellContract.connect(signers.owner)["addMessage(bytes32[],uint32,bytes32,bytes,bytes)"](
        limbsHandles,
        emailBytes1.length,
        skShareHandle,
        payloadBytes1,
        encrypted.inputProof,
      );
      await tx.wait();

      // Advance time and mark deceased
      await ethers.provider.send("evm_increaseTime", [checkInPeriod + gracePeriod + 1]);
      await ethers.provider.send("evm_mine", []);

      tx = await FarewellContract.connect(signers.alice).markDeceased(signers.owner.address);
      await tx.wait();

      // Try to claim with invalid index
      await expect(
        FarewellContract.connect(signers.alice).claim(signers.owner.address, 999),
      ).to.be.revertedWithCustomError(FarewellContract, "InvalidIndex");
    });

    it("should enforce email padding to 224 bytes (7 limbs)", async function () {
      let tx = await FarewellContract.connect(signers.owner)["register()"]();
      await tx.wait();

      // Create encrypted input with correct padding (7 limbs for 224 bytes)
      const enc = fhevm.createEncryptedInput(FarewellContractAddress, signers.owner.address);
      for (const w of emailWords1) enc.add256(w);
      enc.add128(skShare);
      const encrypted = await enc.encrypt();

      const nLimbs = emailWords1.length;
      expect(nLimbs).to.eq(7); // Should be 7 limbs for 224 bytes

      const limbsHandles = encrypted.handles.slice(0, nLimbs);
      const skShareHandle = encrypted.handles[nLimbs];

      // This should work with padded email
      tx = await FarewellContract.connect(signers.owner)["addMessage(bytes32[],uint32,bytes32,bytes,bytes)"](
        limbsHandles,
        emailBytes1.length, // original length
        skShareHandle,
        payloadBytes1,
        encrypted.inputProof,
      );
      await tx.wait();

      // Try with wrong number of limbs (should fail)
      const wrongLimbs = limbsHandles.slice(0, 4); // Only 4 limbs instead of 7
      await expect(
        FarewellContract.connect(signers.owner)["addMessage(bytes32[],uint32,bytes32,bytes,bytes)"](
          wrongLimbs,
          emailBytes1.length,
          skShareHandle,
          payloadBytes1,
          encrypted.inputProof,
        ),
      ).to.be.revertedWithCustomError(FarewellContract, "LimbsMismatch");
    });

    it("should reject email longer than 224 bytes", async function () {
      const tx = await FarewellContract.connect(signers.owner)["register()"]();
      await tx.wait();

      // Use valid encryption (7 limbs) but pass emailByteLen > MAX_EMAIL_BYTE_LEN
      const enc = fhevm.createEncryptedInput(FarewellContractAddress, signers.owner.address);
      for (const w of emailWords1) enc.add256(w);
      enc.add128(skShare);
      const encrypted = await enc.encrypt();

      const nLimbs = emailWords1.length;
      const limbsHandles = encrypted.handles.slice(0, nLimbs);
      const skShareHandle = encrypted.handles[nLimbs];

      // Should fail because emailByteLen (225) > MAX_EMAIL_BYTE_LEN (224)
      await expect(
        FarewellContract.connect(signers.owner)["addMessage(bytes32[],uint32,bytes32,bytes,bytes)"](
          limbsHandles,
          225,
          skShareHandle,
          payloadBytes1,
          encrypted.inputProof,
        ),
      ).to.be.revertedWithCustomError(FarewellContract, "EmailTooLong");
    });
  });

  describe("Council System", function () {
    it("should allow adding council member without stake", async function () {
      let tx = await FarewellContract.connect(signers.owner)["register()"]();
      await tx.wait();

      tx = await FarewellContract.connect(signers.owner).addCouncilMember(signers.alice.address);
      await tx.wait();

      const [members] = await FarewellContract.getCouncilMembers(signers.owner.address);
      expect(members.length).to.eq(1);
      expect(members[0]).to.eq(signers.alice.address);
    });

    it("should reject adding more than 20 council members", async function () {
      let tx = await FarewellContract.connect(signers.owner)["register()"]();
      await tx.wait();

      // Add 20 members (the maximum) - use signers + random wallets
      const allSigners = await ethers.getSigners();
      const availableSigners = allSigners.length - 1; // exclude owner at index 0
      for (let i = 1; i <= availableSigners && i <= 20; i++) {
        tx = await FarewellContract.connect(signers.owner).addCouncilMember(allSigners[i].address);
        await tx.wait();
      }
      // Fill remaining slots with random wallet addresses
      for (let i = availableSigners + 1; i <= 20; i++) {
        const randomWallet = ethers.Wallet.createRandom();
        tx = await FarewellContract.connect(signers.owner).addCouncilMember(randomWallet.address);
        await tx.wait();
      }

      const [members] = await FarewellContract.getCouncilMembers(signers.owner.address);
      expect(members.length).to.eq(20);

      // 21st member should be rejected
      const extraWallet = ethers.Wallet.createRandom();
      await expect(
        FarewellContract.connect(signers.owner).addCouncilMember(extraWallet.address),
      ).to.be.revertedWithCustomError(FarewellContract, "CouncilFull");
    });

    it("should allow removing council member", async function () {
      let tx = await FarewellContract.connect(signers.owner)["register()"]();
      await tx.wait();

      // Add member
      tx = await FarewellContract.connect(signers.owner).addCouncilMember(signers.alice.address);
      await tx.wait();

      // Remove member
      tx = await FarewellContract.connect(signers.owner).removeCouncilMember(signers.alice.address);
      await tx.wait();

      const [members] = await FarewellContract.getCouncilMembers(signers.owner.address);
      expect(members.length).to.eq(0);
    });

    it("should track reverse index for council members", async function () {
      let tx = await FarewellContract.connect(signers.owner)["register()"]();
      await tx.wait();

      tx = await FarewellContract.connect(signers.alice)["register()"]();
      await tx.wait();

      // Add bob as council member for both owner and alice
      tx = await FarewellContract.connect(signers.owner).addCouncilMember(signers.bob.address);
      await tx.wait();

      tx = await FarewellContract.connect(signers.alice).addCouncilMember(signers.bob.address);
      await tx.wait();

      // Check reverse index
      const usersForBob = await FarewellContract.getUsersForCouncilMember(signers.bob.address);
      expect(usersForBob.length).to.eq(2);
      expect(usersForBob).to.include(signers.owner.address);
      expect(usersForBob).to.include(signers.alice.address);
    });

    it("should return correct user state", async function () {
      const checkInPeriod = 86400; // 1 day
      const gracePeriod = 86400; // 1 day
      const tx = await FarewellContract.connect(signers.owner)["register(uint64,uint64)"](checkInPeriod, gracePeriod);
      await tx.wait();

      // Initially should be Alive (status 0)
      let [status, graceSecondsLeft] = await FarewellContract.getUserState(signers.owner.address);
      expect(status).to.eq(0); // Alive

      // Advance to grace period
      await ethers.provider.send("evm_increaseTime", [checkInPeriod + 1]);
      await ethers.provider.send("evm_mine", []);

      [status, graceSecondsLeft] = await FarewellContract.getUserState(signers.owner.address);
      expect(status).to.eq(1); // Grace
      expect(graceSecondsLeft).to.be.gt(0);

      // Advance past grace period
      await ethers.provider.send("evm_increaseTime", [gracePeriod + 1]);
      await ethers.provider.send("evm_mine", []);

      [status, graceSecondsLeft] = await FarewellContract.getUserState(signers.owner.address);
      expect(status).to.eq(2); // Deceased (past grace, not yet marked)
    });

    it("should allow council to vote during grace period", async function () {
      const checkInPeriod = 86400; // 1 day
      const gracePeriod = 86400; // 1 day
      let tx = await FarewellContract.connect(signers.owner)["register(uint64,uint64)"](checkInPeriod, gracePeriod);
      await tx.wait();

      // Add council member
      tx = await FarewellContract.connect(signers.owner).addCouncilMember(signers.alice.address);
      await tx.wait();

      // Advance to grace period
      await ethers.provider.send("evm_increaseTime", [checkInPeriod + 1]);
      await ethers.provider.send("evm_mine", []);

      // Alice votes that owner is alive
      tx = await FarewellContract.connect(signers.alice).voteOnStatus(signers.owner.address, true);
      await tx.wait();

      // Check vote was recorded
      const [hasVoted, votedAlive] = await FarewellContract.getGraceVote(signers.owner.address, signers.alice.address);
      expect(hasVoted).to.eq(true);
      expect(votedAlive).to.eq(true);
    });

    it("should reject voting outside grace period", async function () {
      const checkInPeriod = 86400; // 1 day
      const gracePeriod = 86400; // 1 day
      let tx = await FarewellContract.connect(signers.owner)["register(uint64,uint64)"](checkInPeriod, gracePeriod);
      await tx.wait();

      // Add council member
      tx = await FarewellContract.connect(signers.owner).addCouncilMember(signers.alice.address);
      await tx.wait();

      // Try to vote before grace period (should fail)
      await expect(
        FarewellContract.connect(signers.alice).voteOnStatus(signers.owner.address, true),
      ).to.be.revertedWithCustomError(FarewellContract, "NotInGracePeriod");
    });

    it("should mark user as alive with majority vote and prevent future deceased status", async function () {
      const checkInPeriod = 86400; // 1 day
      const gracePeriod = 86400; // 1 day
      let tx = await FarewellContract.connect(signers.owner)["register(uint64,uint64)"](checkInPeriod, gracePeriod);
      await tx.wait();

      // Add 3 council members
      const allSigners = await ethers.getSigners();
      for (let i = 1; i <= 3; i++) {
        tx = await FarewellContract.connect(signers.owner).addCouncilMember(allSigners[i].address);
        await tx.wait();
      }

      // Advance to grace period
      await ethers.provider.send("evm_increaseTime", [checkInPeriod + 1]);
      await ethers.provider.send("evm_mine", []);

      // Majority (2 out of 3) vote alive
      tx = await FarewellContract.connect(allSigners[1]).voteOnStatus(signers.owner.address, true);
      await tx.wait();
      tx = await FarewellContract.connect(allSigners[2]).voteOnStatus(signers.owner.address, true);
      await tx.wait();

      // Check user is now FinalAlive (status 3)
      const [status] = await FarewellContract.getUserState(signers.owner.address);
      expect(status).to.eq(3); // FinalAlive

      // Advance past grace period and try to mark deceased (should fail)
      await ethers.provider.send("evm_increaseTime", [gracePeriod + 1]);
      await ethers.provider.send("evm_mine", []);

      await expect(
        FarewellContract.connect(signers.alice).markDeceased(signers.owner.address),
      ).to.be.revertedWithCustomError(FarewellContract, "UserVotedAlive");
    });

    it("should mark user as deceased with majority dead vote", async function () {
      const checkInPeriod = 86400; // 1 day
      const gracePeriod = 86400; // 1 day
      let tx = await FarewellContract.connect(signers.owner)["register(uint64,uint64)"](checkInPeriod, gracePeriod);
      await tx.wait();

      // Add 3 council members
      const allSigners = await ethers.getSigners();
      for (let i = 1; i <= 3; i++) {
        tx = await FarewellContract.connect(signers.owner).addCouncilMember(allSigners[i].address);
        await tx.wait();
      }

      // Advance to grace period
      await ethers.provider.send("evm_increaseTime", [checkInPeriod + 1]);
      await ethers.provider.send("evm_mine", []);

      // Majority (2 out of 3) vote dead
      tx = await FarewellContract.connect(allSigners[1]).voteOnStatus(signers.owner.address, false);
      await tx.wait();
      tx = await FarewellContract.connect(allSigners[2]).voteOnStatus(signers.owner.address, false);
      await tx.wait();

      // Check user is now Deceased (status 2)
      const [status] = await FarewellContract.getUserState(signers.owner.address);
      expect(status).to.eq(2); // Deceased

      // Verify deceased status
      const isDeceased = await FarewellContract.getDeceasedStatus(signers.owner.address);
      expect(isDeceased).to.eq(true);
    });

    it("should prevent voting after decision is made", async function () {
      const checkInPeriod = 86400; // 1 day
      const gracePeriod = 86400; // 1 day
      let tx = await FarewellContract.connect(signers.owner)["register(uint64,uint64)"](checkInPeriod, gracePeriod);
      await tx.wait();

      // Add 3 council members
      const allSigners = await ethers.getSigners();
      for (let i = 1; i <= 3; i++) {
        tx = await FarewellContract.connect(signers.owner).addCouncilMember(allSigners[i].address);
        await tx.wait();
      }

      // Advance to grace period
      await ethers.provider.send("evm_increaseTime", [checkInPeriod + 1]);
      await ethers.provider.send("evm_mine", []);

      // Majority vote alive
      tx = await FarewellContract.connect(allSigners[1]).voteOnStatus(signers.owner.address, true);
      await tx.wait();
      tx = await FarewellContract.connect(allSigners[2]).voteOnStatus(signers.owner.address, true);
      await tx.wait();

      // Third member tries to vote (should fail - already decided)
      await expect(
        FarewellContract.connect(allSigners[3]).voteOnStatus(signers.owner.address, false),
      ).to.be.revertedWithCustomError(FarewellContract, "VoteAlreadyDecided");
    });

    it("should prevent claiming revoked messages", async function () {
      const checkInPeriod = 86400; // 1 day
      const gracePeriod = 86400; // 1 day
      let tx = await FarewellContract.connect(signers.owner)["register(uint64,uint64)"](checkInPeriod, gracePeriod);
      await tx.wait();

      // Add and revoke message
      const enc = fhevm.createEncryptedInput(FarewellContractAddress, signers.owner.address);
      for (const w of emailWords1) enc.add256(w);
      enc.add128(skShare);
      const encrypted = await enc.encrypt();
      const nLimbs = emailWords1.length;

      tx = await FarewellContract.connect(signers.owner)["addMessage(bytes32[],uint32,bytes32,bytes,bytes)"](
        encrypted.handles.slice(0, nLimbs),
        emailBytes1.length,
        encrypted.handles[nLimbs],
        payloadBytes1,
        encrypted.inputProof,
      );
      await tx.wait();

      tx = await FarewellContract.connect(signers.owner).revokeMessage(0);
      await tx.wait();

      // Advance time past checkIn + grace and mark deceased
      await ethers.provider.send("evm_increaseTime", [checkInPeriod + gracePeriod + 1]);
      await ethers.provider.send("evm_mine", []);
      tx = await FarewellContract.connect(signers.alice).markDeceased(signers.owner.address);
      await tx.wait();

      // Try to claim revoked message (should fail)
      await expect(
        FarewellContract.connect(signers.alice).claim(signers.owner.address, 0),
      ).to.be.revertedWithCustomError(FarewellContract, "MessageWasRevoked");
    });
  });

  describe("Message Editing", function () {
    it("should allow editing message before deceased", async function () {
      let tx = await FarewellContract.connect(signers.owner)["register()"]();
      await tx.wait();

      // Add message
      const enc = fhevm.createEncryptedInput(FarewellContractAddress, signers.owner.address);
      for (const w of emailWords1) enc.add256(w);
      enc.add128(skShare);
      const encrypted = await enc.encrypt();
      const nLimbs = emailWords1.length;

      tx = await FarewellContract.connect(signers.owner)["addMessage(bytes32[],uint32,bytes32,bytes,bytes)"](
        encrypted.handles.slice(0, nLimbs),
        emailBytes1.length,
        encrypted.handles[nLimbs],
        payloadBytes1,
        encrypted.inputProof,
      );
      await tx.wait();

      // Edit message
      const newPayload = toBytes("updated payload");
      const enc2 = fhevm.createEncryptedInput(FarewellContractAddress, signers.owner.address);
      for (const w of emailWords2) enc2.add256(w);
      enc2.add128(skShare);
      const encrypted2 = await enc2.encrypt();

      tx = await FarewellContract.connect(signers.owner).editMessage(
        0,
        encrypted2.handles.slice(0, nLimbs),
        emailBytes2.length,
        encrypted2.handles[nLimbs],
        newPayload,
        encrypted2.inputProof,
        "Updated message",
      );
      await tx.wait();

      // Verify message was updated
      const msg = await FarewellContract.connect(signers.owner).retrieve(signers.owner.address, 0);
      expect(ethers.toUtf8String(msg.payload)).to.equal("updated payload");
      expect(msg.publicMessage).to.equal("Updated message");
    });

    it("should not allow editing message after deceased", async function () {
      const checkInPeriod = 86400; // 1 day
      const gracePeriod = 86400; // 1 day
      let tx = await FarewellContract.connect(signers.owner)["register(uint64,uint64)"](checkInPeriod, gracePeriod);
      await tx.wait();

      // Add message
      const enc = fhevm.createEncryptedInput(FarewellContractAddress, signers.owner.address);
      for (const w of emailWords1) enc.add256(w);
      enc.add128(skShare);
      const encrypted = await enc.encrypt();
      const nLimbs = emailWords1.length;

      tx = await FarewellContract.connect(signers.owner)["addMessage(bytes32[],uint32,bytes32,bytes,bytes)"](
        encrypted.handles.slice(0, nLimbs),
        emailBytes1.length,
        encrypted.handles[nLimbs],
        payloadBytes1,
        encrypted.inputProof,
      );
      await tx.wait();

      // Mark deceased
      await ethers.provider.send("evm_increaseTime", [checkInPeriod + gracePeriod + 1]);
      await ethers.provider.send("evm_mine", []);
      tx = await FarewellContract.connect(signers.alice).markDeceased(signers.owner.address);
      await tx.wait();

      // Try to edit (should fail)
      const enc2 = fhevm.createEncryptedInput(FarewellContractAddress, signers.owner.address);
      for (const w of emailWords2) enc2.add256(w);
      enc2.add128(skShare);
      const encrypted2 = await enc2.encrypt();

      await expect(
        FarewellContract.connect(signers.owner).editMessage(
          0,
          encrypted2.handles.slice(0, nLimbs),
          emailBytes2.length,
          encrypted2.handles[nLimbs],
          payloadBytes2,
          encrypted2.inputProof,
          "",
        ),
      ).to.be.revertedWithCustomError(FarewellContract, "UserDeceased");
    });

    it("should not allow editing claimed message", async function () {
      const checkInPeriod = 86400; // 1 day
      const gracePeriod = 86400; // 1 day
      let tx = await FarewellContract.connect(signers.owner)["register(uint64,uint64)"](checkInPeriod, gracePeriod);
      await tx.wait();

      // Add message, mark deceased, and claim
      const enc = fhevm.createEncryptedInput(FarewellContractAddress, signers.owner.address);
      for (const w of emailWords1) enc.add256(w);
      enc.add128(skShare);
      const encrypted = await enc.encrypt();
      const nLimbs = emailWords1.length;

      tx = await FarewellContract.connect(signers.owner)["addMessage(bytes32[],uint32,bytes32,bytes,bytes)"](
        encrypted.handles.slice(0, nLimbs),
        emailBytes1.length,
        encrypted.handles[nLimbs],
        payloadBytes1,
        encrypted.inputProof,
      );
      await tx.wait();

      await ethers.provider.send("evm_increaseTime", [checkInPeriod + gracePeriod + 1]);
      await ethers.provider.send("evm_mine", []);
      tx = await FarewellContract.connect(signers.alice).markDeceased(signers.owner.address);
      await tx.wait();
      tx = await FarewellContract.connect(signers.alice).claim(signers.owner.address, 0);
      await tx.wait();

      // Try to edit (should fail)
      const enc2 = fhevm.createEncryptedInput(FarewellContractAddress, signers.owner.address);
      for (const w of emailWords2) enc2.add256(w);
      enc2.add128(skShare);
      const encrypted2 = await enc2.encrypt();

      await expect(
        FarewellContract.connect(signers.owner).editMessage(
          0,
          encrypted2.handles.slice(0, nLimbs),
          emailBytes2.length,
          encrypted2.handles[nLimbs],
          payloadBytes2,
          encrypted2.inputProof,
          "",
        ),
      ).to.be.revertedWithCustomError(FarewellContract, "UserDeceased");
    });
  });

  describe("Deposits and Rewards", function () {
    it("should allow user to deposit ETH", async function () {
      let tx = await FarewellContract.connect(signers.owner)["register()"]();
      await tx.wait();

      const depositAmount = ethers.parseEther("1.0");
      tx = await FarewellContract.connect(signers.owner).deposit({ value: depositAmount });
      await tx.wait();

      const deposit = await FarewellContract.getDeposit(signers.owner.address);
      expect(deposit).to.eq(depositAmount);
    });

    it("should calculate reward correctly", async function () {
      let tx = await FarewellContract.connect(signers.owner)["register()"]();
      await tx.wait();

      // Deposit
      const depositAmount = ethers.parseEther("1.0");
      tx = await FarewellContract.connect(signers.owner).deposit({ value: depositAmount });
      await tx.wait();

      // Add message
      const enc = fhevm.createEncryptedInput(FarewellContractAddress, signers.owner.address);
      for (const w of emailWords1) enc.add256(w);
      enc.add128(skShare);
      const encrypted = await enc.encrypt();
      const nLimbs = emailWords1.length;

      tx = await FarewellContract.connect(signers.owner)["addMessage(bytes32[],uint32,bytes32,bytes,bytes)"](
        encrypted.handles.slice(0, nLimbs),
        emailBytes1.length,
        encrypted.handles[nLimbs],
        payloadBytes1,
        encrypted.inputProof,
      );
      await tx.wait();

      // Calculate reward
      const reward = await FarewellContract.calculateReward(signers.owner.address, 0);
      // Base reward is 0.01 ETH, payload is small so should be close to base
      expect(reward).to.be.gte(ethers.parseEther("0.01"));
    });

    it("should allow claiming reward via proveDelivery + claimReward", async function () {
      const checkInPeriod = 86400; // 1 day
      const gracePeriod = 86400; // 1 day
      let tx = await FarewellContract.connect(signers.owner)["register(uint64,uint64)"](checkInPeriod, gracePeriod);
      await tx.wait();

      // Deploy mock verifier and configure
      const MockVerifierFactory = await ethers.getContractFactory("MockGroth16Verifier");
      const mockVerifier = await MockVerifierFactory.deploy();
      await mockVerifier.waitForDeployment();
      const mockVerifierAddr = await mockVerifier.getAddress();
      tx = await FarewellContract.connect(signers.owner).setZkEmailVerifier(mockVerifierAddr);
      await tx.wait();

      // Set trusted DKIM key
      const pubkeyHash = 12345n;
      tx = await FarewellContract.connect(signers.owner).setTrustedDkimKey(ethers.ZeroHash, pubkeyHash, true);
      await tx.wait();

      // Add message with reward using addMessageWithReward
      const enc = fhevm.createEncryptedInput(FarewellContractAddress, signers.owner.address);
      for (const w of emailWords1) enc.add256(w);
      enc.add128(skShare);
      const encrypted = await enc.encrypt();
      const nLimbs = emailWords1.length;

      const recipientEmailHash = ethers.keccak256(ethers.toUtf8Bytes("test@gmail.com"));
      const payloadContentHash = ethers.keccak256(payloadBytes1);
      const rewardAmount = ethers.parseEther("0.1");

      tx = await FarewellContract.connect(signers.owner).addMessageWithReward(
        encrypted.handles.slice(0, nLimbs),
        emailBytes1.length,
        encrypted.handles[nLimbs],
        payloadBytes1,
        encrypted.inputProof,
        "",
        [recipientEmailHash],
        payloadContentHash,
        { value: rewardAmount },
      );
      await tx.wait();

      // Mark deceased and claim
      await ethers.provider.send("evm_increaseTime", [checkInPeriod + gracePeriod + 1]);
      await ethers.provider.send("evm_mine", []);
      tx = await FarewellContract.connect(signers.alice).markDeceased(signers.owner.address);
      await tx.wait();
      tx = await FarewellContract.connect(signers.alice).claim(signers.owner.address, 0);
      await tx.wait();

      // Prove delivery with matching public signals
      const zkProof = {
        pA: [0n, 0n] as [bigint, bigint],
        pB: [
          [0n, 0n],
          [0n, 0n],
        ] as [[bigint, bigint], [bigint, bigint]],
        pC: [0n, 0n] as [bigint, bigint],
        publicSignals: [BigInt(recipientEmailHash), pubkeyHash, BigInt(payloadContentHash)],
      };
      tx = await FarewellContract.connect(signers.alice).proveDelivery(signers.owner.address, 0, 0, zkProof);
      await tx.wait();

      // Claim reward (2-arg version)
      const balanceBefore = await ethers.provider.getBalance(signers.alice.address);
      tx = await FarewellContract.connect(signers.alice).claimReward(signers.owner.address, 0);
      const receipt = await tx.wait();
      const gasUsed = receipt!.gasUsed * receipt!.gasPrice;
      const balanceAfter = await ethers.provider.getBalance(signers.alice.address);

      // Check reward was transferred (accounting for gas)
      expect(balanceAfter + gasUsed - balanceBefore).to.eq(rewardAmount);
    });

    it("should prevent double claiming of reward", async function () {
      const checkInPeriod = 86400; // 1 day
      const gracePeriod = 86400; // 1 day
      let tx = await FarewellContract.connect(signers.owner)["register(uint64,uint64)"](checkInPeriod, gracePeriod);
      await tx.wait();

      // Deploy mock verifier and configure
      const MockVerifierFactory = await ethers.getContractFactory("MockGroth16Verifier");
      const mockVerifier = await MockVerifierFactory.deploy();
      await mockVerifier.waitForDeployment();
      tx = await FarewellContract.connect(signers.owner).setZkEmailVerifier(await mockVerifier.getAddress());
      await tx.wait();
      const pubkeyHash = 12345n;
      tx = await FarewellContract.connect(signers.owner).setTrustedDkimKey(ethers.ZeroHash, pubkeyHash, true);
      await tx.wait();

      // Add message with reward
      const enc = fhevm.createEncryptedInput(FarewellContractAddress, signers.owner.address);
      for (const w of emailWords1) enc.add256(w);
      enc.add128(skShare);
      const encrypted = await enc.encrypt();
      const nLimbs = emailWords1.length;

      const recipientEmailHash = ethers.keccak256(ethers.toUtf8Bytes("test@gmail.com"));
      const payloadContentHash = ethers.keccak256(payloadBytes1);

      tx = await FarewellContract.connect(signers.owner).addMessageWithReward(
        encrypted.handles.slice(0, nLimbs),
        emailBytes1.length,
        encrypted.handles[nLimbs],
        payloadBytes1,
        encrypted.inputProof,
        "",
        [recipientEmailHash],
        payloadContentHash,
        { value: ethers.parseEther("0.1") },
      );
      await tx.wait();

      await ethers.provider.send("evm_increaseTime", [checkInPeriod + gracePeriod + 1]);
      await ethers.provider.send("evm_mine", []);
      tx = await FarewellContract.connect(signers.alice).markDeceased(signers.owner.address);
      await tx.wait();
      tx = await FarewellContract.connect(signers.alice).claim(signers.owner.address, 0);
      await tx.wait();

      // Prove delivery
      const zkProof = {
        pA: [0n, 0n] as [bigint, bigint],
        pB: [
          [0n, 0n],
          [0n, 0n],
        ] as [[bigint, bigint], [bigint, bigint]],
        pC: [0n, 0n] as [bigint, bigint],
        publicSignals: [BigInt(recipientEmailHash), pubkeyHash, BigInt(payloadContentHash)],
      };
      tx = await FarewellContract.connect(signers.alice).proveDelivery(signers.owner.address, 0, 0, zkProof);
      await tx.wait();

      // Claim reward first time
      tx = await FarewellContract.connect(signers.alice).claimReward(signers.owner.address, 0);
      await tx.wait();

      // Try to claim again (should fail - reward already zeroed out)
      await expect(
        FarewellContract.connect(signers.alice).claimReward(signers.owner.address, 0),
      ).to.be.revertedWithCustomError(FarewellContract, "NoReward");
    });
  });

  describe("Integration Tests", function () {
    it("should complete full flow: register → add message with reward → mark deceased → claim → proveDelivery → claimReward", async function () {
      const checkInPeriod = 86400; // 1 day
      const gracePeriod = 86400; // 1 day

      // Register
      let tx = await FarewellContract.connect(signers.owner)["register(string,uint64,uint64)"](
        "Test User",
        checkInPeriod,
        gracePeriod,
      );
      await tx.wait();

      // Deploy mock verifier and configure
      const MockVerifierFactory = await ethers.getContractFactory("MockGroth16Verifier");
      const mockVerifier = await MockVerifierFactory.deploy();
      await mockVerifier.waitForDeployment();
      tx = await FarewellContract.connect(signers.owner).setZkEmailVerifier(await mockVerifier.getAddress());
      await tx.wait();
      const pubkeyHash = 12345n;
      tx = await FarewellContract.connect(signers.owner).setTrustedDkimKey(ethers.ZeroHash, pubkeyHash, true);
      await tx.wait();

      // Add message with reward
      const enc = fhevm.createEncryptedInput(FarewellContractAddress, signers.owner.address);
      for (const w of emailWords1) enc.add256(w);
      enc.add128(skShare);
      const encrypted = await enc.encrypt();
      const nLimbs = emailWords1.length;

      const recipientEmailHash = ethers.keccak256(ethers.toUtf8Bytes("test@gmail.com"));
      const payloadContentHash = ethers.keccak256(payloadBytes1);
      const rewardAmount = ethers.parseEther("0.5");

      tx = await FarewellContract.connect(signers.owner).addMessageWithReward(
        encrypted.handles.slice(0, nLimbs),
        emailBytes1.length,
        encrypted.handles[nLimbs],
        payloadBytes1,
        encrypted.inputProof,
        "Test message",
        [recipientEmailHash],
        payloadContentHash,
        { value: rewardAmount },
      );
      await tx.wait();

      // Advance time and mark deceased
      await ethers.provider.send("evm_increaseTime", [checkInPeriod + gracePeriod + 1]);
      await ethers.provider.send("evm_mine", []);
      tx = await FarewellContract.connect(signers.alice).markDeceased(signers.owner.address);
      await tx.wait();

      // Claim message
      tx = await FarewellContract.connect(signers.alice).claim(signers.owner.address, 0);
      await tx.wait();

      // Prove delivery
      const zkProof = {
        pA: [0n, 0n] as [bigint, bigint],
        pB: [
          [0n, 0n],
          [0n, 0n],
        ] as [[bigint, bigint], [bigint, bigint]],
        pC: [0n, 0n] as [bigint, bigint],
        publicSignals: [BigInt(recipientEmailHash), pubkeyHash, BigInt(payloadContentHash)],
      };
      tx = await FarewellContract.connect(signers.alice).proveDelivery(signers.owner.address, 0, 0, zkProof);
      await tx.wait();

      // Claim reward
      const balanceBefore = await ethers.provider.getBalance(signers.alice.address);
      tx = await FarewellContract.connect(signers.alice).claimReward(signers.owner.address, 0);
      const receipt = await tx.wait();
      const gasUsed = receipt!.gasUsed * receipt!.gasPrice;
      const balanceAfter = await ethers.provider.getBalance(signers.alice.address);

      // Verify reward was received
      expect(balanceAfter + gasUsed - balanceBefore).to.eq(rewardAmount);
    });

    it("should complete council voting flow: add members → enter grace → vote alive → user saved", async function () {
      const checkInPeriod = 86400; // 1 day
      const gracePeriod = 86400; // 1 day

      // Register
      let tx = await FarewellContract.connect(signers.owner)["register(uint64,uint64)"](checkInPeriod, gracePeriod);
      await tx.wait();

      const initialCheckIn = await FarewellContract.getLastCheckIn(signers.owner.address);

      // Add 3 council members
      const allSigners = await ethers.getSigners();
      for (let i = 1; i <= 3; i++) {
        tx = await FarewellContract.connect(signers.owner).addCouncilMember(allSigners[i].address);
        await tx.wait();
      }

      // Advance time to grace period
      await ethers.provider.send("evm_increaseTime", [checkInPeriod + 1]);
      await ethers.provider.send("evm_mine", []);

      // Majority vote alive (2 out of 3)
      tx = await FarewellContract.connect(allSigners[1]).voteOnStatus(signers.owner.address, true);
      await tx.wait();
      tx = await FarewellContract.connect(allSigners[2]).voteOnStatus(signers.owner.address, true);
      await tx.wait();

      // Verify user was saved (lastCheckIn updated)
      const newCheckIn = await FarewellContract.getLastCheckIn(signers.owner.address);
      expect(newCheckIn).to.be.gt(initialCheckIn);

      // Verify user is FinalAlive and cannot be marked deceased
      const [status] = await FarewellContract.getUserState(signers.owner.address);
      expect(status).to.eq(3); // FinalAlive
    });

    it("should complete message lifecycle: add → edit → revoke → cannot claim", async function () {
      // Register with custom short periods
      const checkInPeriod = 86400; // 1 day
      const gracePeriod = 86400; // 1 day
      let tx = await FarewellContract.connect(signers.owner)["register(uint64,uint64)"](checkInPeriod, gracePeriod);
      await tx.wait();

      // Add message
      const enc = fhevm.createEncryptedInput(FarewellContractAddress, signers.owner.address);
      for (const w of emailWords1) enc.add256(w);
      enc.add128(skShare);
      const encrypted = await enc.encrypt();
      const nLimbs = emailWords1.length;

      tx = await FarewellContract.connect(signers.owner)["addMessage(bytes32[],uint32,bytes32,bytes,bytes,string)"](
        encrypted.handles.slice(0, nLimbs),
        emailBytes1.length,
        encrypted.handles[nLimbs],
        payloadBytes1,
        encrypted.inputProof,
        "Original message",
      );
      await tx.wait();

      // Edit message
      const newPayload = toBytes("edited payload");
      const enc2 = fhevm.createEncryptedInput(FarewellContractAddress, signers.owner.address);
      for (const w of emailWords2) enc2.add256(w);
      enc2.add128(skShare);
      const encrypted2 = await enc2.encrypt();

      tx = await FarewellContract.connect(signers.owner).editMessage(
        0,
        encrypted2.handles.slice(0, nLimbs),
        emailBytes2.length,
        encrypted2.handles[nLimbs],
        newPayload,
        encrypted2.inputProof,
        "Edited message",
      );
      await tx.wait();

      // Verify edit
      const msg = await FarewellContract.connect(signers.owner).retrieve(signers.owner.address, 0);
      expect(ethers.toUtf8String(msg.payload)).to.equal("edited payload");
      expect(msg.publicMessage).to.equal("Edited message");

      // Revoke message
      tx = await FarewellContract.connect(signers.owner).revokeMessage(0);
      await tx.wait();

      // Mark deceased (advance past checkIn + grace)
      await ethers.provider.send("evm_increaseTime", [checkInPeriod + gracePeriod + 1]);
      await ethers.provider.send("evm_mine", []);
      tx = await FarewellContract.connect(signers.alice).markDeceased(signers.owner.address);
      await tx.wait();

      // Cannot claim revoked message
      await expect(
        FarewellContract.connect(signers.alice).claim(signers.owner.address, 0),
      ).to.be.revertedWithCustomError(FarewellContract, "MessageWasRevoked");
    });
  });

  describe("Security Fixes", function () {
    it("C-2: should revert proveDelivery when no verifier is set", async function () {
      const checkInPeriod = 86400;
      const gracePeriod = 86400;
      let tx = await FarewellContract.connect(signers.owner)["register(uint64,uint64)"](checkInPeriod, gracePeriod);
      await tx.wait();

      // Add message with reward (no verifier configured)
      const enc = fhevm.createEncryptedInput(FarewellContractAddress, signers.owner.address);
      for (const w of emailWords1) enc.add256(w);
      enc.add128(skShare);
      const encrypted = await enc.encrypt();
      const nLimbs = emailWords1.length;

      const recipientEmailHash = ethers.keccak256(ethers.toUtf8Bytes("test@gmail.com"));
      const payloadContentHash = ethers.keccak256(payloadBytes1);

      // Set trusted DKIM key (needed for proof validation steps before verifier check)
      tx = await FarewellContract.connect(signers.owner).setTrustedDkimKey(ethers.ZeroHash, 12345n, true);
      await tx.wait();

      tx = await FarewellContract.connect(signers.owner).addMessageWithReward(
        encrypted.handles.slice(0, nLimbs),
        emailBytes1.length,
        encrypted.handles[nLimbs],
        payloadBytes1,
        encrypted.inputProof,
        "",
        [recipientEmailHash],
        payloadContentHash,
        { value: ethers.parseEther("0.1") },
      );
      await tx.wait();

      // Mark deceased and claim
      await ethers.provider.send("evm_increaseTime", [checkInPeriod + gracePeriod + 1]);
      await ethers.provider.send("evm_mine", []);
      tx = await FarewellContract.connect(signers.alice).markDeceased(signers.owner.address);
      await tx.wait();
      tx = await FarewellContract.connect(signers.alice).claim(signers.owner.address, 0);
      await tx.wait();

      // Try to prove delivery without verifier set - should revert
      const zkProof = {
        pA: [0n, 0n] as [bigint, bigint],
        pB: [
          [0n, 0n],
          [0n, 0n],
        ] as [[bigint, bigint], [bigint, bigint]],
        pC: [0n, 0n] as [bigint, bigint],
        publicSignals: [BigInt(recipientEmailHash), 12345n, BigInt(payloadContentHash)],
      };
      await expect(
        FarewellContract.connect(signers.alice).proveDelivery(signers.owner.address, 0, 0, zkProof),
      ).to.be.revertedWithCustomError(FarewellContract, "VerifierNotConfigured");
    });

    it("H-1: should prevent re-claiming an already claimed message", async function () {
      const checkInPeriod = 86400;
      const gracePeriod = 86400;
      let tx = await FarewellContract.connect(signers.owner)["register(uint64,uint64)"](checkInPeriod, gracePeriod);
      await tx.wait();

      // Add message
      const enc = fhevm.createEncryptedInput(FarewellContractAddress, signers.owner.address);
      for (const w of emailWords1) enc.add256(w);
      enc.add128(skShare);
      const encrypted = await enc.encrypt();
      const nLimbs = emailWords1.length;

      tx = await FarewellContract.connect(signers.owner)["addMessage(bytes32[],uint32,bytes32,bytes,bytes)"](
        encrypted.handles.slice(0, nLimbs),
        emailBytes1.length,
        encrypted.handles[nLimbs],
        payloadBytes1,
        encrypted.inputProof,
      );
      await tx.wait();

      // Mark deceased
      await ethers.provider.send("evm_increaseTime", [checkInPeriod + gracePeriod + 1]);
      await ethers.provider.send("evm_mine", []);
      tx = await FarewellContract.connect(signers.alice).markDeceased(signers.owner.address);
      await tx.wait();

      // Alice claims message 0
      tx = await FarewellContract.connect(signers.alice).claim(signers.owner.address, 0);
      await tx.wait();

      // Wait for exclusivity to expire
      await ethers.provider.send("evm_increaseTime", [24 * 60 * 60 + 1]);
      await ethers.provider.send("evm_mine", []);

      // Bob tries to claim the same message (should fail)
      await expect(FarewellContract.connect(signers.bob).claim(signers.owner.address, 0)).to.be.revertedWithCustomError(
        FarewellContract,
        "AlreadyClaimed",
      );
    });

    it("H-2: should allow finalAlive user to re-enter liveness cycle via ping", async function () {
      const checkInPeriod = 86400;
      const gracePeriod = 86400;
      let tx = await FarewellContract.connect(signers.owner)["register(uint64,uint64)"](checkInPeriod, gracePeriod);
      await tx.wait();

      // Add 3 council members
      const allSigners = await ethers.getSigners();
      for (let i = 1; i <= 3; i++) {
        tx = await FarewellContract.connect(signers.owner).addCouncilMember(allSigners[i].address);
        await tx.wait();
      }

      // Advance to grace period
      await ethers.provider.send("evm_increaseTime", [checkInPeriod + 1]);
      await ethers.provider.send("evm_mine", []);

      // Majority vote alive
      tx = await FarewellContract.connect(allSigners[1]).voteOnStatus(signers.owner.address, true);
      await tx.wait();
      tx = await FarewellContract.connect(allSigners[2]).voteOnStatus(signers.owner.address, true);
      await tx.wait();

      // User is now FinalAlive
      let [status] = await FarewellContract.getUserState(signers.owner.address);
      expect(status).to.eq(3); // FinalAlive

      // User pings - should clear finalAlive and re-enter normal cycle
      tx = await FarewellContract.connect(signers.owner).ping();
      await tx.wait();

      // Status should now be Alive (not FinalAlive)
      [status] = await FarewellContract.getUserState(signers.owner.address);
      expect(status).to.eq(0); // Alive

      // Advance past checkIn + grace again - now markDeceased should work
      await ethers.provider.send("evm_increaseTime", [checkInPeriod + gracePeriod + 1]);
      await ethers.provider.send("evm_mine", []);

      tx = await FarewellContract.connect(signers.alice).markDeceased(signers.owner.address);
      await tx.wait();

      [status] = await FarewellContract.getUserState(signers.owner.address);
      expect(status).to.eq(2); // Deceased
    });

    it("H-4: should prevent re-registration during grace period", async function () {
      const checkInPeriod = 86400;
      const gracePeriod = 86400;
      const tx = await FarewellContract.connect(signers.owner)["register(string,uint64,uint64)"](
        "Original",
        checkInPeriod,
        gracePeriod,
      );
      await tx.wait();

      // Advance past check-in period into grace
      await ethers.provider.send("evm_increaseTime", [checkInPeriod + 1]);
      await ethers.provider.send("evm_mine", []);

      // Try to re-register (should fail - check-in period expired)
      await expect(
        FarewellContract.connect(signers.owner)["register(string,uint64,uint64)"](
          "Updated",
          checkInPeriod,
          gracePeriod,
        ),
      ).to.be.revertedWithCustomError(FarewellContract, "CheckInExpired");
    });

    it("H-4: should update name on re-registration", async function () {
      const checkInPeriod = 86400;
      const gracePeriod = 86400;
      let tx = await FarewellContract.connect(signers.owner)["register(string,uint64,uint64)"](
        "Original",
        checkInPeriod,
        gracePeriod,
      );
      await tx.wait();

      let name = await FarewellContract.getUserName(signers.owner.address);
      expect(name).to.eq("Original");

      // Re-register within check-in period (should update name)
      tx = await FarewellContract.connect(signers.owner)["register(string,uint64,uint64)"](
        "Updated",
        checkInPeriod,
        gracePeriod,
      );
      await tx.wait();

      name = await FarewellContract.getUserName(signers.owner.address);
      expect(name).to.eq("Updated");
    });

    it("M-1: should invalidate old message hash when editing", async function () {
      let tx = await FarewellContract.connect(signers.owner)["register()"]();
      await tx.wait();

      // Add message
      const enc = fhevm.createEncryptedInput(FarewellContractAddress, signers.owner.address);
      for (const w of emailWords1) enc.add256(w);
      enc.add128(skShare);
      const encrypted = await enc.encrypt();
      const nLimbs = emailWords1.length;

      tx = await FarewellContract.connect(signers.owner)["addMessage(bytes32[],uint32,bytes32,bytes,bytes)"](
        encrypted.handles.slice(0, nLimbs),
        emailBytes1.length,
        encrypted.handles[nLimbs],
        payloadBytes1,
        encrypted.inputProof,
      );
      await tx.wait();

      // Get original hash
      const msg = await FarewellContract.connect(signers.owner).retrieve(signers.owner.address, 0);
      const originalHash = msg.hash;
      expect(await FarewellContract.messageHashes(originalHash)).to.eq(true);

      // Edit message
      const enc2 = fhevm.createEncryptedInput(FarewellContractAddress, signers.owner.address);
      for (const w of emailWords2) enc2.add256(w);
      enc2.add128(skShare);
      const encrypted2 = await enc2.encrypt();

      tx = await FarewellContract.connect(signers.owner).editMessage(
        0,
        encrypted2.handles.slice(0, nLimbs),
        emailBytes2.length,
        encrypted2.handles[nLimbs],
        toBytes("new payload"),
        encrypted2.inputProof,
        "new public msg",
      );
      await tx.wait();

      // Old hash should be invalidated
      expect(await FarewellContract.messageHashes(originalHash)).to.eq(false);

      // New hash should be set
      const editedMsg = await FarewellContract.connect(signers.owner).retrieve(signers.owner.address, 0);
      expect(await FarewellContract.messageHashes(editedMsg.hash)).to.eq(true);
      expect(editedMsg.hash).to.not.eq(originalHash);
    });

    it("M-2: should allow clearing public message via edit", async function () {
      let tx = await FarewellContract.connect(signers.owner)["register()"]();
      await tx.wait();

      // Add message with public message
      const enc = fhevm.createEncryptedInput(FarewellContractAddress, signers.owner.address);
      for (const w of emailWords1) enc.add256(w);
      enc.add128(skShare);
      const encrypted = await enc.encrypt();
      const nLimbs = emailWords1.length;

      tx = await FarewellContract.connect(signers.owner)["addMessage(bytes32[],uint32,bytes32,bytes,bytes,string)"](
        encrypted.handles.slice(0, nLimbs),
        emailBytes1.length,
        encrypted.handles[nLimbs],
        payloadBytes1,
        encrypted.inputProof,
        "Hello world",
      );
      await tx.wait();

      let msg = await FarewellContract.connect(signers.owner).retrieve(signers.owner.address, 0);
      expect(msg.publicMessage).to.eq("Hello world");

      // Edit with empty public message - should clear it
      const enc2 = fhevm.createEncryptedInput(FarewellContractAddress, signers.owner.address);
      for (const w of emailWords1) enc2.add256(w);
      enc2.add128(skShare);
      const encrypted2 = await enc2.encrypt();

      tx = await FarewellContract.connect(signers.owner).editMessage(
        0,
        encrypted2.handles.slice(0, nLimbs),
        emailBytes1.length,
        encrypted2.handles[nLimbs],
        payloadBytes1,
        encrypted2.inputProof,
        "",
      );
      await tx.wait();

      msg = await FarewellContract.connect(signers.owner).retrieve(signers.owner.address, 0);
      expect(msg.publicMessage).to.eq("");
    });

    it("M-5: should clear stale vote when removing council member during active vote", async function () {
      const checkInPeriod = 86400;
      const gracePeriod = 86400;
      let tx = await FarewellContract.connect(signers.owner)["register(uint64,uint64)"](checkInPeriod, gracePeriod);
      await tx.wait();

      // Add 3 council members
      const allSigners = await ethers.getSigners();
      for (let i = 1; i <= 3; i++) {
        tx = await FarewellContract.connect(signers.owner).addCouncilMember(allSigners[i].address);
        await tx.wait();
      }

      // Advance to grace period
      await ethers.provider.send("evm_increaseTime", [checkInPeriod + 1]);
      await ethers.provider.send("evm_mine", []);

      // Member 1 votes alive
      tx = await FarewellContract.connect(allSigners[1]).voteOnStatus(signers.owner.address, true);
      await tx.wait();

      let [aliveVotes] = await FarewellContract.getGraceVoteStatus(signers.owner.address);
      expect(aliveVotes).to.eq(1);

      // Owner removes member 1 (who voted alive) - ping first to re-enter alive status
      // Actually owner can't ping because they're in grace. They need to remove member directly.
      tx = await FarewellContract.connect(signers.owner).removeCouncilMember(allSigners[1].address);
      await tx.wait();

      // Vote count should be decremented
      [aliveVotes] = await FarewellContract.getGraceVoteStatus(signers.owner.address);
      expect(aliveVotes).to.eq(0);
    });

    it("M-6: should refund reward ETH when revoking a reward-bearing message", async function () {
      let tx = await FarewellContract.connect(signers.owner)["register()"]();
      await tx.wait();

      // Add message with reward
      const enc = fhevm.createEncryptedInput(FarewellContractAddress, signers.owner.address);
      for (const w of emailWords1) enc.add256(w);
      enc.add128(skShare);
      const encrypted = await enc.encrypt();
      const nLimbs = emailWords1.length;

      const recipientEmailHash = ethers.keccak256(ethers.toUtf8Bytes("test@gmail.com"));
      const payloadContentHash = ethers.keccak256(payloadBytes1);
      const rewardAmount = ethers.parseEther("0.5");

      tx = await FarewellContract.connect(signers.owner).addMessageWithReward(
        encrypted.handles.slice(0, nLimbs),
        emailBytes1.length,
        encrypted.handles[nLimbs],
        payloadBytes1,
        encrypted.inputProof,
        "",
        [recipientEmailHash],
        payloadContentHash,
        { value: rewardAmount },
      );
      await tx.wait();

      // Check locked rewards
      const lockedBefore = await FarewellContract.lockedRewards(signers.owner.address);
      expect(lockedBefore).to.eq(rewardAmount);

      // Revoke message - should refund reward
      const balanceBefore = await ethers.provider.getBalance(signers.owner.address);
      tx = await FarewellContract.connect(signers.owner).revokeMessage(0);
      const receipt = await tx.wait();
      const gasUsed = receipt!.gasUsed * BigInt(receipt!.gasPrice);
      const balanceAfter = await ethers.provider.getBalance(signers.owner.address);

      // Check that reward was refunded (minus gas)
      expect(balanceAfter + gasUsed - balanceBefore).to.eq(rewardAmount);

      // Locked rewards should be zero
      const lockedAfter = await FarewellContract.lockedRewards(signers.owner.address);
      expect(lockedAfter).to.eq(0);
    });

    it("I-4: should reject addMessageWithReward with zero reward", async function () {
      const tx = await FarewellContract.connect(signers.owner)["register()"]();
      await tx.wait();

      const enc = fhevm.createEncryptedInput(FarewellContractAddress, signers.owner.address);
      for (const w of emailWords1) enc.add256(w);
      enc.add128(skShare);
      const encrypted = await enc.encrypt();
      const nLimbs = emailWords1.length;

      const recipientEmailHash = ethers.keccak256(ethers.toUtf8Bytes("test@gmail.com"));
      const payloadContentHash = ethers.keccak256(payloadBytes1);

      await expect(
        FarewellContract.connect(signers.owner).addMessageWithReward(
          encrypted.handles.slice(0, nLimbs),
          emailBytes1.length,
          encrypted.handles[nLimbs],
          payloadBytes1,
          encrypted.inputProof,
          "",
          [recipientEmailHash],
          payloadContentHash,
          { value: 0 },
        ),
      ).to.be.revertedWithCustomError(FarewellContract, "MustIncludeReward");
    });
  });
});
