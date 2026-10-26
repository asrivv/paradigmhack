// Ed25519 as `commonware-cryptography-curve25519` (cryptography/curve25519/src/signing.rs) applies it:
//
// - Signatures follow ZIP215: A and R may be non-canonical encodings of curve points, s must be
//   canonical (s < L), and the equation is cofactored, [8](sB - R - kA) = 0, with k hashed over
//   the exact R, A and message bytes (signing.rs:350-383).
// - Every clearing account is a `StrictVerifyingKey`: a canonical, non-identity point in the
//   prime-order subgroup, checked when the key is decoded (signing.rs:457-470).
// - Signed messages are framed as `union_unique(namespace, message)` (signing.rs:391-394).

import { ed25519 } from '@noble/curves/ed25519.js'
import { unionUnique } from './codec.js'

export function isStrictKey(key: Uint8Array): boolean {
  if (key.length !== 32) return false
  try {
    const point = ed25519.Point.fromBytes(key, true)
    const canonical = point.toBytes()
    for (let i = 0; i < 32; i++) if (canonical[i] !== key[i]) return false
    return !point.is0() && point.isTorsionFree()
  } catch {
    return false
  }
}

/** ZIP215 verification of an unframed message. */
export function verifyRaw(signature: Uint8Array, message: Uint8Array, key: Uint8Array): boolean {
  if (signature.length !== 64 || key.length !== 32) return false
  try {
    return ed25519.verify(signature, message, key, { zip215: true })
  } catch {
    return false
  }
}

export function verify(namespace: Uint8Array, message: Uint8Array, signature: Uint8Array, key: Uint8Array): boolean {
  return verifyRaw(signature, unionUnique(namespace, message), key)
}

export function sign(namespace: Uint8Array, message: Uint8Array, secretKey: Uint8Array): Uint8Array {
  return ed25519.sign(unionUnique(namespace, message), secretKey)
}

export function publicKey(secretKey: Uint8Array): Uint8Array {
  return ed25519.getPublicKey(secretKey)
}
