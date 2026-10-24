// Off-chain Poseidon over BN254 (matches circomlib's in-circuit Poseidon).
import { buildPoseidon } from "circomlibjs";

let _p: any;
export async function poseidon() {
  return (_p ??= await buildPoseidon());
}

/** Poseidon hash returning the result as a bigint field element. */
export async function H(inputs: (bigint | number)[]): Promise<bigint> {
  const p = await poseidon();
  return BigInt(p.F.toString(p(inputs.map((x) => BigInt(x)))));
}

/** Whitelist leaf = Poseidon(payeeField), matching the circuit. */
export async function leaf(payeeField: bigint): Promise<bigint> {
  return H([payeeField]);
}

export type Tree = {
  root: bigint;
  pathFor: (index: number) => { pathElements: bigint[]; pathIndices: number[] };
};

/**
 * Fixed-depth Poseidon Merkle tree over the whitelist, matching the circuit:
 * leaf = Poseidon(payee), node = Poseidon(left, right), pathIndices[l] = (index >> l) & 1.
 */
export async function buildTree(payees: bigint[], levels = 8): Promise<Tree> {
  if (!Number.isInteger(levels) || levels < 1 || levels > 30) {
    throw new Error(`levels must be an integer in 1..30, got ${levels}`);
  }
  const capacity = 1 << levels;
  if (payees.length > capacity) {
    throw new Error(
      `whitelist has ${payees.length} members, which exceeds the tree capacity ${capacity} for levels=${levels}`,
    );
  }

  const layer: bigint[] = [];
  for (const p of payees) layer.push(await leaf(p));
  const zeroLeaf = await H([0n]);
  while (layer.length < capacity) layer.push(zeroLeaf);

  const layers: bigint[][] = [layer];
  for (let l = 0; l < levels; l++) {
    const cur = layers[l];
    const next: bigint[] = [];
    for (let i = 0; i < cur.length; i += 2) next.push(await H([cur[i], cur[i + 1]]));
    layers.push(next);
  }
  const root = layers[levels][0];

  const pathFor = (index: number) => {
    if (!Number.isInteger(index) || index < 0 || index >= capacity) {
      throw new Error(`leaf index ${index} out of bounds for tree capacity ${capacity}`);
    }
    const pathElements: bigint[] = [];
    const pathIndices: number[] = [];
    let j = index;
    for (let l = 0; l < levels; l++) {
      pathElements.push(layers[l][j ^ 1]);
      pathIndices.push(j & 1);
      j >>= 1;
    }
    return { pathElements, pathIndices };
  };
  return { root, pathFor };
}
