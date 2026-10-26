// The payer's out-entry vector commitment: `commitment.rs` (`VectorKind::OutEntry`, `leaf_digest`
// :171-185, `bind_root` :221-225, `Opening::reconstruct` :654-666) over the stateless BMT in
// storage/src/bmt/mod.rs (`finalize` :113-115, `Tree::new` :254-288, single-item proofs :320-334
// and `root_from_multi_inclusion` :680-800).
//
//   leaf_i   = SHA256("_COMMONWARE_CLEARING_OUT_ENTRY_LEAF" || u32 n || u32 i || u64 len || entry_i)
//   node     = SHA256(u32 i || leaf_i) at level 0, SHA256(left || right) above; an unpaired last
//              node is paired with itself
//   bmt_root = SHA256(u32 n || tree_root), with tree_root = SHA256("") when n = 0
//   root     = SHA256("_COMMONWARE_CLEARING_OUT_ENTRY_ROOT" || u32 n || bmt_root)

import { sha256 } from '@noble/hashes/sha2.js'
import { MAX_VECTOR_LENGTH, type Opening, type OutEntry, compare, concat, encodeOutEntry, u32, u64, utf8 } from './codec.js'

const LEAF_DOMAIN = utf8('_COMMONWARE_CLEARING_OUT_ENTRY_LEAF')
const ROOT_DOMAIN = utf8('_COMMONWARE_CLEARING_OUT_ENTRY_ROOT')

function leafDigest(length: number, position: number, encoded: Uint8Array): Uint8Array {
  return sha256(concat(LEAF_DOMAIN, u32(length), u32(position), u64(BigInt(encoded.length)), encoded))
}

function bindRoot(length: number, treeRoot: Uint8Array): Uint8Array {
  const bmtRoot = sha256(concat(u32(length), treeRoot))
  return sha256(concat(ROOT_DOMAIN, u32(length), bmtRoot))
}

/** `commitment::empty_root(VectorKind::OutEntry)`: the predecessor of a payer with no prior vector. */
export function emptyRoot(): Uint8Array {
  return bindRoot(0, sha256(new Uint8Array()))
}

/**
 * Reconstructs the vector root that `opening` authenticates for `entry`, or returns undefined
 * when the path is malformed (missing or extra siblings, position outside the tree).
 */
export function reconstruct(opening: Opening, entry: OutEntry): Uint8Array | undefined {
  const { leafCount, siblings } = opening
  let position = opening.position
  if (leafCount > MAX_VECTOR_LENGTH || position >= leafCount) return undefined
  let node = sha256(concat(u32(position), leafDigest(leafCount, position, encodeOutEntry(entry))))
  let width = leafCount
  let next = 0
  while (width > 1) {
    const isRight = position % 2 === 1
    // The last node of an odd-width level is paired with itself and consumes no sibling.
    const sibling = isRight || position + 1 < width ? siblings[next++] : node
    if (sibling === undefined) return undefined
    node = sha256(isRight ? concat(sibling, node) : concat(node, sibling))
    position = Math.floor(position / 2)
    width = Math.ceil(width / 2)
  }
  if (next !== siblings.length) return undefined
  return bindRoot(leafCount, node)
}

/** A built out-entry vector: its root and an opening for every position. */
export type Tree = {
  root: Uint8Array
  opening(position: number): Opening
}

/** Builds the commitment over entries that are already strictly sorted by recipient bytes. */
export function build(entries: readonly OutEntry[]): Tree {
  const length = entries.length
  if (length > MAX_VECTOR_LENGTH) throw new RangeError('vector is too long')
  for (let i = 1; i < length; i++)
    if (compare(entries[i - 1]!.recipient, entries[i]!.recipient) >= 0) throw new Error('entries are not strictly recipient-sorted')
  if (length === 0) return { root: emptyRoot(), opening: () => { throw new RangeError('empty vector has no openings') } }

  const levels: Uint8Array[][] = [
    entries.map((entry, i) => sha256(concat(u32(i), leafDigest(length, i, encodeOutEntry(entry))))),
  ]
  while (levels.at(-1)!.length > 1) {
    const level = levels.at(-1)!
    const parents: Uint8Array[] = []
    for (let i = 0; i < level.length; i += 2) parents.push(sha256(concat(level[i]!, level[i + 1] ?? level[i]!)))
    levels.push(parents)
  }
  return {
    root: bindRoot(length, levels.at(-1)![0]!),
    opening(position) {
      if (!Number.isInteger(position) || position < 0 || position >= length) throw new RangeError('position out of range')
      const siblings: Uint8Array[] = []
      let index = position
      for (const level of levels.slice(0, -1)) {
        const sibling = index % 2 === 1 ? index - 1 : index + 1
        if (sibling < level.length) siblings.push(level[sibling]!)
        index = Math.floor(index / 2)
      }
      return { position, leafCount: length, siblings }
    },
  }
}
