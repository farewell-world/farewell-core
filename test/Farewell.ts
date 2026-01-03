import { FhevmType } from "@fhevm/hardhat-plugin";
import { Farewell, Farewell__factory } from "../types";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";
import { expect } from "chai";
import { toUtf8Bytes } from "ethers";
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
// Pads to MAX_EMAIL_BYTE_LEN (256 bytes) to prevent length leakage
const MAX_EMAIL_BYTE_LEN = 256;

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
    let tx = await FarewellContract.connect(signers.owner).register();
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
      tx = await FarewellContract.connect(signers.owner).addMessage(
        limbsHandles,
        emailBytes1.length, // emailByteLen
        skShareHandle, // encSkShare (externalEuint128)
        payloadBytes1, // public payload
        encrypted.inputProof
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

      tx = await FarewellContract.connect(signers.owner).addMessage(
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
    const checkInPeriod = 1;
    const gracePeriod = 1;
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

      tx = await FarewellContract.connect(signers.owner).addMessage(
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

      tx = await FarewellContract.connect(signers.owner).addMessage(
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
    await expect(FarewellContract.connect(signers.alice).claim(signers.owner.address, 0)).to.be.revertedWith(
      "not deliverable",
    );

    // Alice marks owner as deceased (Alice becomes the notifier)
    tx = await FarewellContract.connect(signers.alice).markDeceased(signers.owner.address);
    await tx.wait();

    // Within the first 24h after notification:
    // - Non-notifier (owner) cannot claim
    await expect(FarewellContract.connect(signers.bob).claim(signers.owner.address, 0)).to.be.revertedWith(
      "still exclusive for the notifier",
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

    tx = await FarewellContract.connect(signers.bob).claim(signers.owner.address, 0);
    await tx.wait();

    const encryptedClaimedMessageAfter = await FarewellContract.connect(signers.bob).retrieve(signers.owner.address, 0);
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
      let tx = await FarewellContract.connect(signers.owner).register();
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
        3600n   // 1 hour grace
      );
      await tx.wait();

      const name = await FarewellContract.getUserName(signers.owner.address);
      expect(name).to.eq("Charlie");
    });

    it("should revert if user is not registered", async function () {
      await expect(
        FarewellContract.connect(signers.owner).setName("Test")
      ).to.be.revertedWith("not registered");
    });
  });

  describe("removeMessage", function () {
    it("should allow owner to remove their own unclaimed message", async function () {
      // Register
      let tx = await FarewellContract.connect(signers.owner).register();
      await tx.wait();

      // Add a message
      const enc = fhevm.createEncryptedInput(FarewellContractAddress, signers.owner.address);
      for (const w of emailWords1) enc.add256(w);
      enc.add128(skShare);
      const encrypted = await enc.encrypt();

      const nLimbs = emailWords1.length;
      const limbsHandles = encrypted.handles.slice(0, nLimbs);
      const skShareHandle = encrypted.handles[nLimbs];

      tx = await FarewellContract.connect(signers.owner).addMessage(
        limbsHandles,
        emailBytes1.length,
        skShareHandle,
        payloadBytes1,
        encrypted.inputProof
      );
      await tx.wait();

      let n = await FarewellContract.messageCount(signers.owner.address);
      expect(n).to.eq(1);

      // Remove the message
      tx = await FarewellContract.connect(signers.owner).removeMessage(0);
      await tx.wait();

      // Message count should still be 1 (message is marked as deleted, not removed)
      n = await FarewellContract.messageCount(signers.owner.address);
      expect(n).to.eq(1);

      // Trying to retrieve should fail
      await expect(
        FarewellContract.connect(signers.owner).retrieve(signers.owner.address, 0)
      ).to.be.revertedWith("message was deleted");
    });

    it("should not allow removing an already deleted message", async function () {
      // Register
      let tx = await FarewellContract.connect(signers.owner).register();
      await tx.wait();

      // Add a message
      const enc = fhevm.createEncryptedInput(FarewellContractAddress, signers.owner.address);
      for (const w of emailWords1) enc.add256(w);
      enc.add128(skShare);
      const encrypted = await enc.encrypt();

      const nLimbs = emailWords1.length;
      const limbsHandles = encrypted.handles.slice(0, nLimbs);
      const skShareHandle = encrypted.handles[nLimbs];

      tx = await FarewellContract.connect(signers.owner).addMessage(
        limbsHandles,
        emailBytes1.length,
        skShareHandle,
        payloadBytes1,
        encrypted.inputProof
      );
      await tx.wait();

      // Remove the message
      tx = await FarewellContract.connect(signers.owner).removeMessage(0);
      await tx.wait();

      // Try to remove again
      await expect(
        FarewellContract.connect(signers.owner).removeMessage(0)
      ).to.be.revertedWith("already deleted");
    });

    it("should not allow removing a claimed message", async function () {
      // Register with short periods
      const checkInPeriod = 1;
      const gracePeriod = 1;
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

      tx = await FarewellContract.connect(signers.owner).addMessage(
        limbsHandles,
        emailBytes1.length,
        skShareHandle,
        payloadBytes1,
        encrypted.inputProof
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

      // Try to remove the claimed message (should fail)
      await expect(
        FarewellContract.connect(signers.owner).removeMessage(0)
      ).to.be.revertedWith("cannot delete claimed message");
    });

    it("should not allow non-owner to remove message", async function () {
      // Register
      let tx = await FarewellContract.connect(signers.owner).register();
      await tx.wait();

      // Add a message
      const enc = fhevm.createEncryptedInput(FarewellContractAddress, signers.owner.address);
      for (const w of emailWords1) enc.add256(w);
      enc.add128(skShare);
      const encrypted = await enc.encrypt();

      const nLimbs = emailWords1.length;
      const limbsHandles = encrypted.handles.slice(0, nLimbs);
      const skShareHandle = encrypted.handles[nLimbs];

      tx = await FarewellContract.connect(signers.owner).addMessage(
        limbsHandles,
        emailBytes1.length,
        skShareHandle,
        payloadBytes1,
        encrypted.inputProof
      );
      await tx.wait();

      // Alice tries to remove owner's message
      await expect(
        FarewellContract.connect(signers.alice).removeMessage(0)
      ).to.be.revertedWith("not registered");
    });

    it("should preserve message indices after deletion", async function () {
      // Register
      let tx = await FarewellContract.connect(signers.owner).register();
      await tx.wait();

      // Add message 0
      {
        const enc = fhevm.createEncryptedInput(FarewellContractAddress, signers.owner.address);
        for (const w of emailWords1) enc.add256(w);
        enc.add128(skShare);
        const encrypted = await enc.encrypt();
        const nLimbs = emailWords1.length;
        tx = await FarewellContract.connect(signers.owner).addMessage(
          encrypted.handles.slice(0, nLimbs),
          emailBytes1.length,
          encrypted.handles[nLimbs],
          payloadBytes1,
          encrypted.inputProof
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
        tx = await FarewellContract.connect(signers.owner).addMessage(
          encrypted.handles.slice(0, nLimbs),
          emailBytes2.length,
          encrypted.handles[nLimbs],
          payloadBytes2,
          encrypted.inputProof
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
        tx = await FarewellContract.connect(signers.owner).addMessage(
          encrypted.handles.slice(0, nLimbs),
          emailBytes1.length,
          encrypted.handles[nLimbs],
          payloadBytes1,
          encrypted.inputProof
        );
        await tx.wait();
      }

      let n = await FarewellContract.messageCount(signers.owner.address);
      expect(n).to.eq(3);

      // Remove message 1 (middle one)
      tx = await FarewellContract.connect(signers.owner).removeMessage(1);
      await tx.wait();

      // Message count should still be 3
      n = await FarewellContract.messageCount(signers.owner.address);
      expect(n).to.eq(3);

      // Message 0 should still be accessible
      const msg0 = await FarewellContract.connect(signers.owner).retrieve(signers.owner.address, 0);
      expect(ethers.toUtf8String(msg0.payload)).to.equal(payload1);

      // Message 1 should be deleted
      await expect(
        FarewellContract.connect(signers.owner).retrieve(signers.owner.address, 1)
      ).to.be.revertedWith("message was deleted");

      // Message 2 should still be accessible
      const msg2 = await FarewellContract.connect(signers.owner).retrieve(signers.owner.address, 2);
      expect(ethers.toUtf8String(msg2.payload)).to.equal(payload1);
    });
  });

  describe("Security validations", function () {
    it("should reject registration with checkInPeriod < 1 day", async function () {
      const shortPeriod = 12 * 60 * 60; // 12 hours
      await expect(
        FarewellContract.connect(signers.owner)["register(uint64,uint64)"](shortPeriod, 7 * 24 * 60 * 60)
      ).to.be.revertedWith("checkInPeriod too short");
    });

    it("should reject registration with gracePeriod < 1 day", async function () {
      const shortGrace = 12 * 60 * 60; // 12 hours
      await expect(
        FarewellContract.connect(signers.owner)["register(uint64,uint64)"](30 * 24 * 60 * 60, shortGrace)
      ).to.be.revertedWith("gracePeriod too short");
    });

    it("should reject name longer than 100 characters", async function () {
      const longName = "a".repeat(101);
      await expect(
        FarewellContract.connect(signers.owner).register(longName)
      ).to.be.revertedWith("name too long");
    });

    it("should reject claim with invalid index (out of bounds)", async function () {
      // Register and mark deceased
      const checkInPeriod = 1;
      const gracePeriod = 1;
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

      tx = await FarewellContract.connect(signers.owner).addMessage(
        limbsHandles,
        emailBytes1.length,
        skShareHandle,
        payloadBytes1,
        encrypted.inputProof
      );
      await tx.wait();

      // Advance time and mark deceased
      await ethers.provider.send("evm_increaseTime", [checkInPeriod + gracePeriod + 1]);
      await ethers.provider.send("evm_mine", []);

      tx = await FarewellContract.connect(signers.alice).markDeceased(signers.owner.address);
      await tx.wait();

      // Try to claim with invalid index
      await expect(
        FarewellContract.connect(signers.alice).claim(signers.owner.address, 999)
      ).to.be.revertedWith("invalid index");
    });

    it("should enforce email padding to 256 bytes (8 limbs)", async function () {
      let tx = await FarewellContract.connect(signers.owner).register();
      await tx.wait();

      // Create encrypted input with correct padding (8 limbs)
      const enc = fhevm.createEncryptedInput(FarewellContractAddress, signers.owner.address);
      for (const w of emailWords1) enc.add256(w);
      enc.add128(skShare);
      const encrypted = await enc.encrypt();

      const nLimbs = emailWords1.length;
      expect(nLimbs).to.eq(8); // Should be 8 limbs for 256 bytes

      const limbsHandles = encrypted.handles.slice(0, nLimbs);
      const skShareHandle = encrypted.handles[nLimbs];

      // This should work with padded email
      tx = await FarewellContract.connect(signers.owner).addMessage(
        limbsHandles,
        emailBytes1.length, // original length
        skShareHandle,
        payloadBytes1,
        encrypted.inputProof
      );
      await tx.wait();

      // Try with wrong number of limbs (should fail)
      const wrongLimbs = limbsHandles.slice(0, 4); // Only 4 limbs instead of 8
      await expect(
        FarewellContract.connect(signers.owner).addMessage(
          wrongLimbs,
          emailBytes1.length,
          skShareHandle,
          payloadBytes1,
          encrypted.inputProof
        )
      ).to.be.revertedWith("limbs must match padded length");
    });

    it("should reject email longer than 256 bytes", async function () {
      let tx = await FarewellContract.connect(signers.owner).register();
      await tx.wait();

      // Create a long email (> 256 bytes)
      const longEmail = "a".repeat(257) + "@example.com";
      const longEmailBytes = toBytes(longEmail);
      const longEmailWords = chunk32ToU256Words(longEmailBytes);

      const enc = fhevm.createEncryptedInput(FarewellContractAddress, signers.owner.address);
      for (const w of longEmailWords) enc.add256(w);
      enc.add128(skShare);
      const encrypted = await enc.encrypt();

      const nLimbs = longEmailWords.length;
      const limbsHandles = encrypted.handles.slice(0, nLimbs);
      const skShareHandle = encrypted.handles[nLimbs];

      // Should fail because emailByteLen > MAX_EMAIL_BYTE_LEN
      await expect(
        FarewellContract.connect(signers.owner).addMessage(
          limbsHandles,
          longEmailBytes.length,
          skShareHandle,
          payloadBytes1,
          encrypted.inputProof
        )
      ).to.be.revertedWith("email too long");
    });
  });
});
