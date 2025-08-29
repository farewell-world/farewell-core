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

describe("Farewell", function () {
  let signers: Signers;
  let FarewellContract: Farewell;
  let FarewellContractAddress: string;

  before(async function () {
    // Initializes signers
    const ethSigners: HardhatEthersSigner[] = await ethers.getSigners();
    signers = { owner: ethSigners[0], alice: ethSigners[1], bob: ethSigners[2]};
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
    const skShare: bigint = BigInt(42);
    const encryptedSkShare = await fhevm
      .createEncryptedInput(FarewellContractAddress, signers.owner.address)
      .add128(skShare)
      .encrypt();

    let tx = await FarewellContract.connect(signers.owner).registerDefault(
      encryptedSkShare.handles[0],
      encryptedSkShare.inputProof,
    );
    await tx.wait();

    tx = await FarewellContract.connect(signers.owner).addMessage(toUtf8Bytes("test@gmail.com"), toUtf8Bytes("hello"));
    await tx.wait();
    let n = await FarewellContract.messageCount(signers.owner.address);
    expect(n).to.eq(1);
    tx = await FarewellContract.connect(signers.owner).addMessage(
      toUtf8Bytes("test2@gmail.com"),
      toUtf8Bytes("hello2"),
    );
    await tx.wait();
    n = await FarewellContract.messageCount(signers.owner.address);
    expect(n).to.eq(2);
  });

  it("alice's message count should now be affected by others'", async function () {
    const OwnerskShare: bigint = BigInt(42);
    const encryptedOwnerSkShare = await fhevm
      .createEncryptedInput(FarewellContractAddress, signers.owner.address)
      .add128(OwnerskShare)
      .encrypt();

    let tx = await FarewellContract.connect(signers.owner).registerDefault(
      encryptedOwnerSkShare.handles[0],
      encryptedOwnerSkShare.inputProof,
    );
    await tx.wait();
    tx = await FarewellContract.connect(signers.owner).addMessage(toUtf8Bytes("test@gmail.com"), toUtf8Bytes("hello"));
    await tx.wait();
    let n = await FarewellContract.messageCount(signers.owner.address);
    expect(n).to.eq(1);

    const AliceskShare: bigint = BigInt(42);
    const encryptedAliceSkShare = await fhevm
      .createEncryptedInput(FarewellContractAddress, signers.alice.address)
      .add128(AliceskShare)
      .encrypt();

    tx = await FarewellContract.connect(signers.alice).registerDefault(
      encryptedAliceSkShare.handles[0],
      encryptedAliceSkShare.inputProof,
    );
    await tx.wait();
    n = await FarewellContract.messageCount(signers.alice.address);
    expect(n).to.eq(0);
  });

  it("anyone should be able to claim a message of a dead user but only after the exclusivity period", async function () {
    const skShare = BigInt(42);
    const encryptedSkShare = await fhevm
      .createEncryptedInput(FarewellContractAddress, signers.owner.address)
      .add128(skShare)
      .encrypt();

    let tx = await FarewellContract.connect(signers.owner).register(
      1,
      1,
      encryptedSkShare.handles[0],
      encryptedSkShare.inputProof,
    );
    await tx.wait();
    tx = await FarewellContract.connect(signers.owner).addMessage(toUtf8Bytes("test@gmail.com"), toUtf8Bytes("hello"));
    await tx.wait();
    let n = await FarewellContract.messageCount(signers.owner.address);
    expect(n).to.eq(1);
    tx = await FarewellContract.connect(signers.owner).addMessage(
      toUtf8Bytes("test2@gmail.com"),
      toUtf8Bytes("hello2"),
    );
    await tx.wait();
    n = await FarewellContract.messageCount(signers.owner.address);
    expect(n).to.eq(2);

  // Advance time so owner is considered deceased by timeout
    await ethers.provider.send("evm_increaseTime", [3]);

    // Cannot claim before marking deceased
    await expect(FarewellContract.connect(signers.alice).claim(signers.owner.address, 0)).to.be.reverted;

  // Alice marks owner as deceased (Alice becomes the notifier)
  tx = await FarewellContract.connect(signers.alice).markDeceased(signers.owner.address);
  await tx.wait();

    // Within the first 24h after notification:
  // - Non-notifier (owner) cannot claim
  await expect(
    FarewellContract.connect(signers.bob).claim(signers.owner.address, 0)).to.be.reverted;

  // - Notifier (alice) can claim
  const encryptedClaimedMessage = await FarewellContract.connect(signers.alice).claim(signers.owner.address, 0);
  const claimedMessage = await fhevm.userDecryptEuint(
    FhevmType.euint128,
    encryptedClaimedMessage,
    FarewellContractAddress,
    signers.alice,
  );
  expect(claimedMessage).to.eq(skShare);

  // - after 24h exclusivity expires and others can claim
  await ethers.provider.send("evm_increaseTime", [24 * 60 * 60 + 1]);
  await ethers.provider.send("evm_mine", []); // mine a block to apply the time

  const encryptedClaimedMessageAfter = await FarewellContract.connect(signers.bob).claim(signers.owner.address, 0);
  const claimedMessageAfter = await fhevm.userDecryptEuint(
    FhevmType.euint128,
    encryptedClaimedMessageAfter,
    FarewellContractAddress,
    signers.bob,
  );
  expect(claimedMessageAfter).to.eq(skShare);
  });
});
