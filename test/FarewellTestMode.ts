import {
  Farewell__factory,
  FarewellExtension,
  FarewellExtension__factory,
  FarewellTestMode,
  FarewellTestMode__factory,
} from "../types";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";
import { expect } from "chai";
import { ethers } from "hardhat";

// Combined type: FarewellTestMode (core + test helpers) + FarewellExtension
type FarewellFull = FarewellTestMode & FarewellExtension;

const ONE_DAY = 86400;
const CHECK_IN = 30 * ONE_DAY; // 30 days
const GRACE = 7 * ONE_DAY; // 7 days

async function deployFixture() {
  const [owner] = await ethers.getSigners();

  const ExtFactory = await ethers.getContractFactory("FarewellExtension");
  const ext = await ExtFactory.deploy(owner.address);
  await ext.waitForDeployment();
  const extensionAddress = await ext.getAddress();

  const TestModeFactory = await ethers.getContractFactory("FarewellTestMode");
  const core = await TestModeFactory.deploy(owner.address, extensionAddress);
  await core.waitForDeployment();
  const contractAddress = await core.getAddress();

  // Merge ABIs: TestMode (includes Farewell core + test helpers) + Extension
  const combinedAbi = [
    ...FarewellTestMode__factory.abi,
    ...FarewellExtension__factory.abi.filter(
      (extItem) =>
        extItem.type !== "constructor" &&
        !FarewellTestMode__factory.abi.some(
          (coreItem) =>
            "name" in coreItem && "name" in extItem && coreItem.name === extItem.name,
        ),
    ),
  ];

  const contract = new ethers.Contract(
    contractAddress,
    combinedAbi,
    owner,
  ) as unknown as FarewellFull;

  return { contract, contractAddress };
}

describe("FarewellTestMode", function () {
  let contract: FarewellFull;
  let contractAddress: string;
  let signers: HardhatEthersSigner[];

  // Signer roles
  let owner: HardhatEthersSigner;
  let alice: HardhatEthersSigner; // past grace, not marked
  let bob: HardhatEthersSigner; // in grace, savable
  let charlie: HardhatEthersSigner; // in grace, killable
  let dave: HardhatEthersSigner; // already deceased
  let elias: HardhatEthersSigner; // alive
  let fiona: HardhatEthersSigner; // in grace, no council
  let council1: HardhatEthersSigner;
  let council2: HardhatEthersSigner;
  let council3: HardhatEthersSigner;

  before(async function () {
    signers = await ethers.getSigners();
    [owner, alice, bob, charlie, dave, elias, fiona, council1, council2, council3] = signers;
  });

  beforeEach(async function () {
    ({ contract, contractAddress } = await deployFixture());

    // --- Set up all 6 test users ---

    // Alice: past grace (backdated checkIn + grace + 1 day)
    let tx = await contract.setupTestUser(
      alice.address, "Alice", CHECK_IN, GRACE, CHECK_IN + GRACE + ONE_DAY,
    );
    await tx.wait();

    // Bob: in grace (backdated checkIn + half grace)
    tx = await contract.setupTestUser(
      bob.address, "Bob", CHECK_IN, GRACE, CHECK_IN + Math.floor(GRACE / 2),
    );
    await tx.wait();
    tx = await contract.setupTestCouncil(
      bob.address, [council1.address, council2.address, council3.address],
    );
    await tx.wait();

    // Charlie: in grace (same timing as Bob), with council
    tx = await contract.setupTestUser(
      charlie.address, "Charlie", CHECK_IN, GRACE, CHECK_IN + Math.floor(GRACE / 2),
    );
    await tx.wait();
    tx = await contract.setupTestCouncil(
      charlie.address, [council1.address, council2.address, council3.address],
    );
    await tx.wait();

    // Dave: alive then force deceased
    tx = await contract.setupTestUser(dave.address, "Dave", CHECK_IN, GRACE, 0);
    await tx.wait();
    tx = await contract.forceMarkDeceased(dave.address, owner.address);
    await tx.wait();

    // Elias: alive
    tx = await contract.setupTestUser(elias.address, "Elias", CHECK_IN, GRACE, 0);
    await tx.wait();

    // Fiona: in grace, no council
    tx = await contract.setupTestUser(
      fiona.address, "Fiona", CHECK_IN, GRACE, CHECK_IN + Math.floor(GRACE / 2),
    );
    await tx.wait();
  });

  // --- Setup function tests ---

  describe("Setup Functions", function () {
    it("setupTestUser registers a user with correct state", async function () {
      expect(await contract.isRegistered(alice.address)).to.eq(true);
      expect(await contract.getUserName(alice.address)).to.eq("Alice");
    });

    it("setupTestUser rejects non-owner", async function () {
      await expect(
        contract.connect(alice).setupTestUser(
          ethers.Wallet.createRandom().address, "Rando", CHECK_IN, GRACE, 0,
        ),
      ).to.be.revertedWithCustomError(contract, "OwnableUnauthorizedAccount");
    });

    it("setupTestCouncil rejects non-owner", async function () {
      await expect(
        contract.connect(alice).setupTestCouncil(bob.address, [council1.address]),
      ).to.be.revertedWithCustomError(contract, "OwnableUnauthorizedAccount");
    });

    it("forceMarkDeceased rejects non-owner", async function () {
      await expect(
        contract.connect(alice).forceMarkDeceased(elias.address, alice.address),
      ).to.be.revertedWithCustomError(contract, "OwnableUnauthorizedAccount");
    });

    it("forceSetFinalAlive rejects non-owner", async function () {
      await expect(
        contract.connect(alice).forceSetFinalAlive(elias.address),
      ).to.be.revertedWithCustomError(contract, "OwnableUnauthorizedAccount");
    });

    it("setupTestCouncil adds members correctly", async function () {
      const [members] = await contract.getCouncilMembers(bob.address);
      expect(members.length).to.eq(3);
      expect(members).to.include(council1.address);
      expect(members).to.include(council2.address);
      expect(members).to.include(council3.address);
    });

    it("forceMarkDeceased sets deceased flag", async function () {
      expect(await contract.getDeceasedStatus(dave.address)).to.eq(true);
    });

    it("forceSetFinalAlive sets finalAlive flag", async function () {
      // Set up a fresh user and force FinalAlive
      const tx = await contract.setupTestUser(
        owner.address, "Owner", CHECK_IN, GRACE, 0,
      );
      await tx.wait();
      const tx2 = await contract.forceSetFinalAlive(owner.address);
      await tx2.wait();

      const [status] = await contract.getUserState(owner.address);
      expect(status).to.eq(3); // FinalAlive
    });

    it("totalUsers counter is correct", async function () {
      const total = await contract.getNumberOfRegisteredUsers();
      expect(total).to.eq(6); // Alice, Bob, Charlie, Dave, Elias, Fiona
    });
  });

  // --- Alice: past grace, not yet marked deceased ---

  describe("Alice - Past Grace, Not Yet Marked", function () {
    it("getUserState returns Deceased (past grace timeout)", async function () {
      const [status] = await contract.getUserState(alice.address);
      expect(status).to.eq(2); // Deceased (past grace but not formally marked)
    });

    it("anyone can call markDeceased on Alice", async function () {
      const tx = await contract.connect(council1).markDeceased(alice.address);
      await tx.wait();

      expect(await contract.getDeceasedStatus(alice.address)).to.eq(true);
    });

    it("Alice can still ping (deceased flag not set) which resets her to Alive", async function () {
      // ping() only checks the deceased flag, not time — Alice is past grace
      // but not formally marked, so she can escape by pinging
      const tx = await contract.connect(alice).ping();
      await tx.wait();

      const [status] = await contract.getUserState(alice.address);
      expect(status).to.eq(0); // Alive
    });

    it("after markDeceased, Alice cannot ping", async function () {
      let tx = await contract.connect(council1).markDeceased(alice.address);
      await tx.wait();

      await expect(
        contract.connect(alice).ping(),
      ).to.be.revertedWithCustomError(contract, "UserDeceased");
    });
  });

  // --- Bob: in grace, council saves him ---

  describe("Bob - In Grace, Council Votes Alive", function () {
    it("getUserState returns Grace", async function () {
      const [status, graceSecondsLeft] = await contract.getUserState(bob.address);
      expect(status).to.eq(1); // Grace
      expect(graceSecondsLeft).to.be.gt(0);
    });

    it("markDeceased reverts (still in grace)", async function () {
      await expect(
        contract.connect(owner).markDeceased(bob.address),
      ).to.be.revertedWithCustomError(contract, "NotTimedOut");
    });

    it("council majority (2/3) votes alive → FinalAlive", async function () {
      let tx = await contract.connect(council1).voteOnStatus(bob.address, true);
      await tx.wait();
      tx = await contract.connect(council2).voteOnStatus(bob.address, true);
      await tx.wait();

      const [status] = await contract.getUserState(bob.address);
      expect(status).to.eq(3); // FinalAlive
    });

    it("after FinalAlive, markDeceased reverts", async function () {
      let tx = await contract.connect(council1).voteOnStatus(bob.address, true);
      await tx.wait();
      tx = await contract.connect(council2).voteOnStatus(bob.address, true);
      await tx.wait();

      // Advance time past grace
      await ethers.provider.send("evm_increaseTime", [GRACE]);
      await ethers.provider.send("evm_mine", []);

      await expect(
        contract.connect(owner).markDeceased(bob.address),
      ).to.be.revertedWithCustomError(contract, "UserVotedAlive");
    });

    it("after FinalAlive, Bob can ping to reset", async function () {
      let tx = await contract.connect(council1).voteOnStatus(bob.address, true);
      await tx.wait();
      tx = await contract.connect(council2).voteOnStatus(bob.address, true);
      await tx.wait();

      // Bob pings — clears finalAlive, resets lastCheckIn
      tx = await contract.connect(bob).ping();
      await tx.wait();

      const [status] = await contract.getUserState(bob.address);
      expect(status).to.eq(0); // Alive
    });

    it("non-council member cannot vote", async function () {
      await expect(
        contract.connect(fiona).voteOnStatus(bob.address, true),
      ).to.be.revertedWithCustomError(contract, "NotCouncilMember");
    });
  });

  // --- Charlie: in grace, council votes dead ---

  describe("Charlie - In Grace, Council Votes Dead", function () {
    it("getUserState returns Grace", async function () {
      const [status] = await contract.getUserState(charlie.address);
      expect(status).to.eq(1); // Grace
    });

    it("council majority (2/3) votes dead → Deceased", async function () {
      let tx = await contract.connect(council1).voteOnStatus(charlie.address, false);
      await tx.wait();
      tx = await contract.connect(council2).voteOnStatus(charlie.address, false);
      await tx.wait();

      const [status] = await contract.getUserState(charlie.address);
      expect(status).to.eq(2); // Deceased
    });

    it("after dead vote, deceased flag is set", async function () {
      let tx = await contract.connect(council1).voteOnStatus(charlie.address, false);
      await tx.wait();
      tx = await contract.connect(council2).voteOnStatus(charlie.address, false);
      await tx.wait();

      expect(await contract.getDeceasedStatus(charlie.address)).to.eq(true);
    });

    it("Charlie cannot ping after council kills him", async function () {
      let tx = await contract.connect(council1).voteOnStatus(charlie.address, false);
      await tx.wait();
      tx = await contract.connect(council2).voteOnStatus(charlie.address, false);
      await tx.wait();

      await expect(
        contract.connect(charlie).ping(),
      ).to.be.revertedWithCustomError(contract, "UserDeceased");
    });

    it("third vote after decision reverts", async function () {
      let tx = await contract.connect(council1).voteOnStatus(charlie.address, false);
      await tx.wait();
      tx = await contract.connect(council2).voteOnStatus(charlie.address, false);
      await tx.wait();

      // Dead vote sets deceased=true, so the next vote hits UserDeceased before VoteAlreadyDecided
      await expect(
        contract.connect(council3).voteOnStatus(charlie.address, true),
      ).to.be.revertedWithCustomError(contract, "UserDeceased");
    });
  });

  // --- Dave: already deceased ---

  describe("Dave - Already Deceased", function () {
    it("getUserState returns Deceased", async function () {
      const [status] = await contract.getUserState(dave.address);
      expect(status).to.eq(2); // Deceased
    });

    it("ping reverts with UserDeceased", async function () {
      await expect(
        contract.connect(dave).ping(),
      ).to.be.revertedWithCustomError(contract, "UserDeceased");
    });

    it("register reverts with UserDeceased", async function () {
      await expect(
        contract.connect(dave)["register()"](),
      ).to.be.revertedWithCustomError(contract, "UserDeceased");
    });

    it("setName reverts with UserDeceased", async function () {
      await expect(
        contract.connect(dave).setName("New Name"),
      ).to.be.revertedWithCustomError(contract, "UserDeceased");
    });
  });

  // --- Elias: alive ---

  describe("Elias - Alive and Well", function () {
    it("getUserState returns Alive", async function () {
      const [status] = await contract.getUserState(elias.address);
      expect(status).to.eq(0); // Alive
    });

    it("can ping successfully", async function () {
      const tx = await contract.connect(elias).ping();
      await tx.wait();

      const [status] = await contract.getUserState(elias.address);
      expect(status).to.eq(0); // Still alive
    });

    it("markDeceased reverts with NotTimedOut", async function () {
      await expect(
        contract.connect(owner).markDeceased(elias.address),
      ).to.be.revertedWithCustomError(contract, "NotTimedOut");
    });

    it("can update name", async function () {
      const tx = await contract.connect(elias).setName("Elias Updated");
      await tx.wait();

      expect(await contract.getUserName(elias.address)).to.eq("Elias Updated");
    });

    it("can update check-in period", async function () {
      const tx = await contract.connect(elias).setCheckInPeriod(60 * ONE_DAY);
      await tx.wait();

      const [status] = await contract.getUserState(elias.address);
      expect(status).to.eq(0); // Still alive
    });
  });

  // --- Fiona: in grace, no council ---

  describe("Fiona - In Grace, No Council", function () {
    it("getUserState returns Grace with graceSecondsLeft > 0", async function () {
      const [status, graceSecondsLeft] = await contract.getUserState(fiona.address);
      expect(status).to.eq(1); // Grace
      expect(graceSecondsLeft).to.be.gt(0);
    });

    it("markDeceased reverts (still in grace)", async function () {
      await expect(
        contract.connect(owner).markDeceased(fiona.address),
      ).to.be.revertedWithCustomError(contract, "NotTimedOut");
    });

    it("Fiona can ping to reset (escape grace)", async function () {
      const tx = await contract.connect(fiona).ping();
      await tx.wait();

      const [status] = await contract.getUserState(fiona.address);
      expect(status).to.eq(0); // Alive after ping
    });

    it("after grace expires, markDeceased succeeds", async function () {
      // Advance time past remaining grace
      await ethers.provider.send("evm_increaseTime", [GRACE]);
      await ethers.provider.send("evm_mine", []);

      const tx = await contract.connect(owner).markDeceased(fiona.address);
      await tx.wait();

      expect(await contract.getDeceasedStatus(fiona.address)).to.eq(true);
    });
  });

  // --- Cross-scenario interactions ---

  describe("Cross-Scenario Checks", function () {
    it("all 6 users are registered", async function () {
      for (const s of [alice, bob, charlie, dave, elias, fiona]) {
        expect(await contract.isRegistered(s.address)).to.eq(true);
      }
    });

    it("council member reverse lookup works for Bob and Charlie", async function () {
      const usersForCouncil1 = await contract.getUsersForCouncilMember(council1.address);
      expect(usersForCouncil1.length).to.eq(2);
      expect(usersForCouncil1).to.include(bob.address);
      expect(usersForCouncil1).to.include(charlie.address);
    });

    it("Bob and Charlie have independent vote states", async function () {
      // Vote alive on Bob
      let tx = await contract.connect(council1).voteOnStatus(bob.address, true);
      await tx.wait();

      // Vote dead on Charlie
      tx = await contract.connect(council1).voteOnStatus(charlie.address, false);
      await tx.wait();

      // Bob's vote: 1 alive, 0 dead
      const [bobAlive, bobDead] = await contract.getGraceVoteStatus(bob.address);
      expect(bobAlive).to.eq(1);
      expect(bobDead).to.eq(0);

      // Charlie's vote: 0 alive, 1 dead
      const [charlieAlive, charlieDead] = await contract.getGraceVoteStatus(charlie.address);
      expect(charlieAlive).to.eq(0);
      expect(charlieDead).to.eq(1);
    });
  });
});
