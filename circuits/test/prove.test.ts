import { expect } from "chai";
import { buildInput, N } from "../scripts/prove.js";
import { H, buildTree } from "./helpers.js";

describe("buildInput (parametric prover)", () => {
  it("binds each commitment to Poseidon(amount,payee,salt) and roots the whitelist", async () => {
    const batch = {
      payments: [
        { amount: 50n, payee: 11n },
        { amount: 75n, payee: 22n },
      ],
      whitelist: [11n, 22n, 33n],
      dailyLimit: 1000n,
      perTaskLimit: 300n,
      periodId: 2n,
      periodSpent: 125n, // 50 + 75 — what the treasury recorded for the period
    };
    const input = await buildInput(batch);

    // commitments bind to the real openings (with the CSPRNG salt the builder drew)
    expect(input.commitments[0]).to.equal((await H([50n, 11n, BigInt(input.salt[0])])).toString());
    expect(input.commitments[1]).to.equal((await H([75n, 22n, BigInt(input.salt[1])])).toString());

    // public policy carried through, and the root is a real tree over the whitelist
    expect(input.dailyLimit).to.equal("1000");
    expect(input.perTaskLimit).to.equal("300");
    expect(input.periodId).to.equal("2");
    const tree = await buildTree([11n, 22n, 33n], 8);
    expect(input.whitelistRoot).to.equal(tree.root.toString());

    // padded to the circuit's fixed batch, pad slots carry amount 0
    expect(input.amount).to.have.length(N);
    expect(input.amount[2]).to.equal("0");
    expect(input.salt.every((s) => BigInt(s) >= 1n << 128n)).to.equal(true);
  });

  it("refuses a batch that does not account for the period's on-chain spend", async () => {
    const batch = {
      payments: [{ amount: 50n, payee: 11n }],
      whitelist: [11n, 22n, 33n],
      dailyLimit: 1000n,
      perTaskLimit: 300n,
      periodId: 2n,
      periodSpent: 125n, // the chain saw 125; this batch only accounts for 50
    };
    let err: Error | undefined;
    try {
      await buildInput(batch);
    } catch (e) {
      err = e as Error;
    }
    expect(err?.message).to.match(/does not match the period's on-chain spend/);
  });

  it("refuses an empty whitelist", async () => {
    const batch = {
      payments: [],
      whitelist: [],
      dailyLimit: 1000n,
      perTaskLimit: 300n,
      periodId: 2n,
      periodSpent: 0n,
    };
    let err: Error | undefined;
    try {
      await buildInput(batch);
    } catch (e) {
      err = e as Error;
    }
    expect(err?.message).to.match(/whitelist cannot be empty/);
  });

  it("refuses a batch with more than N payments", async () => {
    const payments = Array.from({ length: N + 1 }, () => ({ amount: 1n, payee: 11n }));
    const batch = {
      payments,
      whitelist: [11n, 22n],
      dailyLimit: 1000n,
      perTaskLimit: 300n,
      periodId: 2n,
      periodSpent: BigInt(N + 1),
    };
    let err: Error | undefined;
    try {
      await buildInput(batch);
    } catch (e) {
      err = e as Error;
    }
    expect(err?.message).to.match(/exceeds the circuit batch capacity N=16/);
  });

  it("refuses a payment whose payee is not in the whitelist", async () => {
    const batch = {
      payments: [
        { amount: 50n, payee: 11n },
        { amount: 75n, payee: 99n },
      ],
      whitelist: [11n, 22n, 33n],
      dailyLimit: 1000n,
      perTaskLimit: 300n,
      periodId: 2n,
      periodSpent: 125n,
    };
    let err: Error | undefined;
    try {
      await buildInput(batch);
    } catch (e) {
      err = e as Error;
    }
    expect(err?.message).to.match(/payee 99 at payment 1 is not in the whitelist/);
  });

  it("refuses a whitelist exceeding the Merkle tree capacity (1 << levels)", async () => {
    const oversized = Array.from({ length: 257 }, (_, i) => BigInt(i + 1));
    let err: Error | undefined;
    try {
      await buildTree(oversized, 8);
    } catch (e) {
      err = e as Error;
    }
    expect(err?.message).to.match(/whitelist has 257 members, which exceeds the tree capacity 256/);
  });

  it("refuses invalid tree levels and out-of-bounds pathFor indices", async () => {
    let levelErr: Error | undefined;
    try {
      await buildTree([11n], 0);
    } catch (e) {
      levelErr = e as Error;
    }
    expect(levelErr?.message).to.match(/levels must be an integer in 1\.\.30/);

    const tree = await buildTree([11n, 22n], 2);
    expect(() => tree.pathFor(-1)).to.throw(/leaf index -1 out of bounds/);
    expect(() => tree.pathFor(4)).to.throw(/leaf index 4 out of bounds/);
  });
});
