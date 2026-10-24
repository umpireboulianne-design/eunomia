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
 *
 * Empty leaf slots are padded with literal `0n` (not `Poseidon(0)`), which no `Poseidon(x)`
 * can produce — otherwise `payee = 0` would pass membership in every tree with fewer than
 * `2^levels` members. Treasuries whose `whitelist_root` was computed with `H(0)` padding must
 * republish their `whitelist_root` (`set_whitelist_root` / `prove-and-submit.ts --publish-root`).
 */
export async function buildTree(payees: bigint[], levels = 8): Promise<Tree> {
  const layer: bigint[] = [];
  for (const p of payees) layer.push(await leaf(p));
  while (layer.length < 1 << levels) layer.push(0n);


  const layers: bigint[][] = [layer];
  for (let l = 0; l < levels; l++) {
    const cur = layers[l];
    const next: bigint[] = [];
    for (let i = 0; i < cur.length; i += 2) next.push(await H([cur[i], cur[i + 1]]));
    layers.push(next);
  }
  const root = layers[levels][0];

  const pathFor = (index: number) => {
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
