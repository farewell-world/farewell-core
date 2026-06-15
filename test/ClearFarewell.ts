import { ClearFarewell, ClearFarewell__factory } from "../types";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";
import { expect } from "chai";
import { toUtf8Bytes } from "ethers";
import { ethers } from "hardhat";

type Signers = {
  owner: HardhatEthersSigner;
  alice: HardhatEthersSigner;
};

async function deployFixture() {
  const factory = (await ethers.getContractFactory("ClearFarewell")) as ClearFarewell__factory;
  const clearFarewellContract = (await factory.deploy()) as ClearFarewell;
  const clearFarewellContractAddress = await clearFarewellContract.getAddress();

  return { clearFarewellContract, clearFarewellContractAddress };
}

describe("ClearFarewell", function () {
  let signers: Signers;
  let clearFarewellContract: ClearFarewell;
  let clearFarewellContractAddress: ClearFarewell;

  before(async function () {
    // Initializes signers
    const ethSigners: HardhatEthersSigner[] = await ethers.getSigners();
    signers = { owner: ethSigners[0], alice: ethSigners[1] };
  });

  beforeEach(async () => {
    ({ clearFarewellContract, clearFarewellContractAddress } = await deployFixture());
  });

  it("user should be able to add a message after registration", async function () {
    let tx = await clearFarewellContract.connect(signers.owner).registerDefault();
    await tx.wait();
    tx = await clearFarewellContract.connect(signers.owner).addMessage("test@gmail.com", toUtf8Bytes("hello"));
    await tx.wait();
    let n = await clearFarewellContract.messageCount(signers.owner.address);
    expect(n).to.eq(1);
    tx = await clearFarewellContract.connect(signers.owner).addMessage("test2@gmail.com", toUtf8Bytes("hello2"));
    await tx.wait();
    n = await clearFarewellContract.messageCount(signers.owner.address);
    expect(n).to.eq(2);
  });

  it("alice's message count should now be affected by others'", async function () {
    let tx = await clearFarewellContract.connect(signers.owner).registerDefault();
    await tx.wait();
    tx = await clearFarewellContract.connect(signers.owner).addMessage("test@gmail.com", toUtf8Bytes("hello"));
    await tx.wait();
    let n = await clearFarewellContract.messageCount(signers.owner.address);
    expect(n).to.eq(1);

    tx = await clearFarewellContract.connect(signers.alice).registerDefault();
    await tx.wait();
    n = await clearFarewellContract.messageCount(signers.alice.address);
    expect(n).to.eq(0);
  });

  it("one should not be able to register twice", async function () {
    const tx = await clearFarewellContract.connect(signers.owner).register(1, 1);
    await tx.wait();
    await expect(clearFarewellContract.connect(signers.owner).registerDefault()).to.be.reverted;
  });

  it("one cannot mark a user as dead if within grace period", async function () {
    const tx = await clearFarewellContract.connect(signers.owner).registerDefault();
    await tx.wait();
    await expect(clearFarewellContract.connect(signers.alice).markDeceased(signers.owner.address)).to.be.reverted;
  });

  it("one should be able to mark a user as dead after the grace period", async function () {
    // Set checkInPeriod and gracePeriod to 2 seconds
    const tx = await clearFarewellContract.connect(signers.owner).register(1, 1);
    await tx.wait();
    await ethers.provider.send("evm_increaseTime", [5]);
    await expect(clearFarewellContract.connect(signers.alice).markDeceased(signers.owner.address)).to.not.reverted;
  });

  it("ping must advance the last check in time", async function () {
    // Set checkInPeriod and gracePeriod to 5 seconds
    let tx = await clearFarewellContract.connect(signers.owner).register(5, 2);
    await tx.wait();
    await ethers.provider.send("evm_increaseTime", [3]);
    tx = await clearFarewellContract.connect(signers.owner).ping();
    await tx.wait();
    await ethers.provider.send("evm_increaseTime", [2]);
    await expect(clearFarewellContract.connect(signers.alice).markDeceased(signers.owner.address)).to.be.reverted;
    await ethers.provider.send("evm_increaseTime", [6]);
    await expect(clearFarewellContract.connect(signers.alice).markDeceased(signers.owner.address)).to.not.reverted;
  });
});
