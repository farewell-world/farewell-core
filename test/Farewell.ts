import { FhevmType } from "@fhevm/hardhat-plugin";
import { Farewell, Farewell__factory } from "../types";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";
import { expect } from "chai";
import { toUtf8Bytes } from "ethers";
import { ethers, fhevm } from "hardhat";

type Signers = {
  owner: HardhatEthersSigner;
  alice: HardhatEthersSigner;
  bob: HardhatEthersSigner;
};

async function deployFixture() {
  const factory = (await ethers.getContractFactory("Farewell")) as Farewell__factory;
  const FarewellContract = (await factory.deploy()) as Farewell;
  const FarewellContractAddress = await FarewellContract.getAddress();

  return { FarewellContract, FarewellContractAddress };
}

// --- helpers ---
const toBytes = (s: string) => ethers.toUtf8Bytes(s);

// utf8 → 32B-chunks (right-padded with zeros), returned as BigInt words
function chunk32ToU256Words(u8: Uint8Array): bigint[] {
  const words: bigint[] = [];
  for (let i = 0; i < u8.length; i += 32) {
    const slice = u8.slice(i, i + 32);
    const padded = new Uint8Array(32);
    padded.set(slice);
    words.push(BigInt("0x" + Buffer.from(padded).toString("hex")));
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
    // Register
    let tx = await FarewellContract.connect(signers.owner).registerDefault();
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
    let tx = await FarewellContract.connect(signers.owner).register(checkInPeriod, gracePeriod);
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
});
