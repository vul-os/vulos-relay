import { describe, it, expect } from 'vitest'
import { blake3 } from '@noble/hashes/blake3.js'
import {
  hashBytes,
  manifestRoot,
  chunkProof,
  encodeChunkProof,
  decodeChunkProof,
  verifyChunkProof,
  isChunkProofValid,
  verifyChunkResponse,
  parseAddr,
  encodeAddr,
  ChunkProofError,
} from '../chunkProof.js'

// chunkProof.test.js — the browser half of the § 5.3 verified-partial-fetch
// contract.
//
// Two things are under test and they are different in kind:
//
//  1. INTEROP — that this verifier computes byte-for-byte the same tree as the
//     Go node. Asserted against the fixed vector pinned in
//     tunnel/pubcache/proof_test.go, not against this file's own output, because
//     an implementation checked only against itself is checked against nothing.
//  2. ADVERSARIAL BEHAVIOUR — that every way of lying about a chunk is
//     REJECTED. A proof checker tested only on valid proofs is not tested at
//     all, and this one runs in a browser against an untrusted gateway, so most
//     of what follows is an attack.

const toHex = (b) => Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join('')
const utf8 = (s) => new TextEncoder().encode(s)

// ── the interop vector, copied verbatim from tunnel/pubcache/proof_test.go ────
//
// A 5-chunk blob over the payloads "a".."e", one byte each. Five leaves is the
// smallest tree that promotes an odd node at TWO levels, so it pins the
// promotion rule and not just the happy path — note chunk 4's proof carries a
// single sibling where chunks 0-3 carry three.
//
// If either implementation drifts by one byte, one of the two suites fails.
// Regenerate BOTH copies together if the construction ever changes on purpose.

const INTEROP_ROOT_B64 = 'HqmS4uJD2JJOZjmeF-YZikRhImZOgGvZHe6IwCOpRyT_'

const INTEROP_PROOF_HEX = [
  '8200835820609ad16ca3186fc12dd32ce1d49ed57dd879c802246de385a20f7dbee2f894395820c97979256dd9f06e0dc6be9fabf2baef2acd2118939563d18bfa79661dc36dce58201365330142a154c52d28959cc1db9166d7b10c2591a9acc25d959ec7e1b8d242',
  '8201835820208e131bd1411e9d8c1d8417b9e9f370e2118a32b37535c77357c6d152348ac75820c97979256dd9f06e0dc6be9fabf2baef2acd2118939563d18bfa79661dc36dce58201365330142a154c52d28959cc1db9166d7b10c2591a9acc25d959ec7e1b8d242',
  '82028358208cc8a6db6f14fc57eacea4131385777a244b1f6feaeae1fed47ee8ef6e0982cf5820abd36c78c5c484698bf962a24adc9293467661696e0897a500df261d2b1664f258201365330142a154c52d28959cc1db9166d7b10c2591a9acc25d959ec7e1b8d242',
  '820383582093ce26dbcfb499cfd2b7ddfda025f4377f02bf62416d7f4799ea467720edaddd5820abd36c78c5c484698bf962a24adc9293467661696e0897a500df261d2b1664f258201365330142a154c52d28959cc1db9166d7b10c2591a9acc25d959ec7e1b8d242',
  '82048158205fa8b1b087f0c5dec0dc650c299f1779e735fd3b317e85793bbedac488a5183f',
]

const VECTOR_DATA = ['a', 'b', 'c', 'd', 'e'].map(utf8)
const VECTOR_N = VECTOR_DATA.length
const vectorChunks = () => VECTOR_DATA.map(hashBytes)

const fromHex = (h) => Uint8Array.from(h.match(/../g).map((x) => parseInt(x, 16)))

// ── the primitive ────────────────────────────────────────────────────────────

describe('BLAKE3 (cross-language known-answer)', () => {
  // Asserted identically in tunnel/pubcache/interop_test.go. This localises a
  // divergence to the hash function, so a @noble/hashes bump that changed
  // BLAKE3's output says so plainly instead of looking like a Merkle bug.
  it('matches the Go zeebo/blake3 output byte-for-byte', () => {
    expect(toHex(blake3(utf8('')))).toBe('af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262')
    expect(toHex(blake3(utf8('abc')))).toBe('6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85')
    expect(toHex(blake3(utf8('DMTAP-PUB-v0/manifest')))).toBe(
      '2cb5f9a18d18cee51f625aa0f285da550f033606024ec0f7df46e682fa8149f5',
    )
  })
})

// ── interop ──────────────────────────────────────────────────────────────────

describe('chunk-tree interop vector (cross-language)', () => {
  it('computes the Go node root byte-for-byte', () => {
    expect(encodeAddr(manifestRoot(vectorChunks()))).toBe(INTEROP_ROOT_B64)
  })

  it('computes every audit path byte-for-byte', () => {
    const chunks = vectorChunks()
    for (let i = 0; i < VECTOR_N; i++) {
      expect(toHex(encodeChunkProof(i, chunkProof(chunks, i)))).toBe(INTEROP_PROOF_HEX[i])
    }
  })

  it('verifies every chunk against the pinned Go proof bodies', () => {
    // The load-bearing direction: bytes produced by the GO encoder, decoded and
    // folded by the JS verifier, against the trusted root.
    for (let i = 0; i < VECTOR_N; i++) {
      const { index, path } = decodeChunkProof(fromHex(INTEROP_PROOF_HEX[i]))
      expect(index).toBe(i)
      expect(() =>
        verifyChunkProof({ root: INTEROP_ROOT_B64, nChunks: VECTOR_N, index: i, chunk: VECTOR_DATA[i], path }),
      ).not.toThrow()
    }
  })

  it('pins the odd-node promotion shape: chunk 4 carries a shorter path', () => {
    const chunks = vectorChunks()
    expect([0, 1, 2, 3, 4].map((i) => chunkProof(chunks, i).length)).toEqual([3, 3, 3, 3, 1])
  })

  it('round-trips the pinned bodies through decode → encode unchanged', () => {
    for (const hex of INTEROP_PROOF_HEX) {
      const { index, path } = decodeChunkProof(fromHex(hex))
      expect(toHex(encodeChunkProof(index, path))).toBe(hex)
    }
  })
})

// ── tree shape across every size ─────────────────────────────────────────────

describe('tree shape', () => {
  const data = (n) => Array.from({ length: n }, (_, i) => utf8(`chunk-${i}`))

  it('proves every chunk of every tree size up to 64', () => {
    // Walks every index of every shape in the range where promotion patterns
    // repeat. If any single chunk of any single shape failed, verified seek
    // would be silently unreliable exactly where the feature is meant to be used.
    for (let n = 1; n <= 64; n++) {
      const d = data(n)
      const chunks = d.map(hashBytes)
      const root = manifestRoot(chunks)
      for (let i = 0; i < n; i++) {
        const path = chunkProof(chunks, i)
        expect(isChunkProofValid({ root, nChunks: n, index: i, chunk: d[i], path })).toBe(true)
      }
    }
  })

  it('produces a logarithmic path — the entire point of the endpoint', () => {
    const n = 4096
    const chunks = data(n).map(hashBytes)
    expect(chunkProof(chunks, 1234).length).toBe(12) // log2(4096), not 4096
  })
})

// ── adversarial: the verifier must reject every lie ──────────────────────────

describe('adversarial — a lying gateway', () => {
  const chunks = () => vectorChunks()
  const root = INTEROP_ROOT_B64
  const good = (i) => ({ root, nChunks: VECTOR_N, index: i, chunk: VECTOR_DATA[i], path: chunkProof(chunks(), i) })

  it('rejects a wrong index (valid proof, wrong leaf)', () => {
    // The proof for chunk 0 presented as chunk 1. Both are real proofs of the
    // same tree; only the pairing order and level differ, so this is the attack
    // a naive verifier passes.
    const path = chunkProof(chunks(), 0)
    expect(isChunkProofValid({ root, nChunks: VECTOR_N, index: 1, chunk: VECTOR_DATA[0], path })).toBe(false)
    expect(isChunkProofValid({ root, nChunks: VECTOR_N, index: 1, chunk: VECTOR_DATA[1], path })).toBe(false)
  })

  it('rejects tampered chunk bytes, including a single flipped bit', () => {
    for (let i = 0; i < VECTOR_N; i++) {
      const tampered = Uint8Array.from(VECTOR_DATA[i])
      tampered[0] ^= 0x01
      expect(isChunkProofValid({ ...good(i), chunk: tampered })).toBe(false)
    }
    // Appending is a tamper too — the leaf is over the chunk's address, so any
    // length change changes h_i.
    expect(isChunkProofValid({ ...good(0), chunk: utf8('a!') })).toBe(false)
    expect(isChunkProofValid({ ...good(0), chunk: new Uint8Array(0) })).toBe(false)
  })

  it('rejects EACH path element corrupted independently', () => {
    // Corrupting only one sibling at a time proves every element is actually
    // consumed and folded, not merely counted.
    for (let i = 0; i < VECTOR_N; i++) {
      const base = chunkProof(chunks(), i)
      for (let e = 0; e < base.length; e++) {
        const path = base.map((h) => Uint8Array.from(h))
        path[e][0] ^= 0x01
        expect(isChunkProofValid({ root, nChunks: VECTOR_N, index: i, chunk: VECTOR_DATA[i], path })).toBe(false)
      }
    }
  })

  it('rejects a reordered path', () => {
    // Bottom-up order is part of the construction; a permuted path folds to a
    // different node even though every element is authentic.
    const path = chunkProof(chunks(), 0)
    expect(path.length).toBe(3)
    expect(isChunkProofValid({ root, nChunks: VECTOR_N, index: 0, chunk: VECTOR_DATA[0], path: [path[1], path[0], path[2]] })).toBe(false)
    expect(isChunkProofValid({ root, nChunks: VECTOR_N, index: 0, chunk: VECTOR_DATA[0], path: [...path].reverse() })).toBe(false)
  })

  it('rejects a truncated path', () => {
    const path = chunkProof(chunks(), 0)
    for (let k = 0; k < path.length; k++) {
      expect(isChunkProofValid({ root, nChunks: VECTOR_N, index: 0, chunk: VECTOR_DATA[0], path: path.slice(0, k) })).toBe(false)
    }
  })

  it('rejects an over-long path — a server may not pad a proof', () => {
    // Trailing unconsumed material is refused explicitly rather than ignored;
    // ignoring it would let a server attach unverified bytes to a valid proof.
    const path = chunkProof(chunks(), 0)
    expect(isChunkProofValid({ root, nChunks: VECTOR_N, index: 0, chunk: VECTOR_DATA[0], path: [...path, new Uint8Array(32)] })).toBe(false)
    // Chunk 4 is the promoted node with a 1-element path; padding it to 3 is the
    // natural "my verifier ignores promotion" forgery.
    const p4 = chunkProof(chunks(), 4)
    expect(p4.length).toBe(1)
    expect(isChunkProofValid({ root, nChunks: VECTOR_N, index: 4, chunk: VECTOR_DATA[4], path: [...p4, new Uint8Array(32), new Uint8Array(32)] })).toBe(false)
  })

  it('rejects a wrong root', () => {
    const otherRoot = manifestRoot(['x', 'y', 'z'].map(utf8).map(hashBytes))
    expect(isChunkProofValid({ ...good(0), root: otherRoot })).toBe(false)
    // A root differing in exactly one bit must fail too.
    const near = parseAddr(root)
    near[near.length - 1] ^= 0x01
    expect(isChunkProofValid({ ...good(0), root: near })).toBe(false)
  })

  it('treats nChunks as STRUCTURAL METADATA, not a second authenticator', () => {
    // This pins an honest limitation rather than a guarantee, and the Go suite
    // asserts the identical numbers (TestNChunksIsStructuralNotAuthenticating).
    //
    // nChunks tells the verifier the tree's WIDTH — at which levels the
    // promotion rule skips a path element. It is NOT independently
    // authenticated, and several widths can imply the same consumption pattern:
    // for chunk 0 of the 5-leaf vector, n=5,6,7,8 all consume the same three
    // elements in the same order and therefore fold to the same root.
    //
    // That is not a forgery vector — the fold still has to hit the TRUSTED root,
    // so a wrong nChunks cannot smuggle a bad chunk past a correct root. It is
    // the reason the API documents that nChunks must come from the manifest
    // header the caller already trusts, and never from the proof response.
    const accepted = (i) => {
      const out = []
      for (let n = 1; n <= 40; n++) if (isChunkProofValid({ ...good(i), nChunks: n })) out.push(n)
      return out
    }
    expect(accepted(0)).toEqual([5, 6, 7, 8])
    // Chunk 4 is the promoted odd node, so its 1-element path pins the width
    // exactly — promotion is what makes the tree size observable at all.
    expect(accepted(4)).toEqual([5])

    // Widths that imply a different consumption pattern still fail closed.
    for (const n of [1, 2, 3, 4, 9, 100]) {
      expect(isChunkProofValid({ ...good(0), nChunks: n })).toBe(false)
    }
  })

  it('rejects out-of-range and non-integer indices', () => {
    for (const index of [-1, VECTOR_N, VECTOR_N + 1, 1.5, NaN]) {
      expect(isChunkProofValid({ ...good(0), index })).toBe(false)
    }
    expect(isChunkProofValid({ ...good(0), nChunks: 0 })).toBe(false)
    expect(isChunkProofValid({ ...good(0), nChunks: -1 })).toBe(false)
  })

  it('rejects a path whose elements are the wrong width', () => {
    expect(isChunkProofValid({ ...good(0), path: [new Uint8Array(31), new Uint8Array(32), new Uint8Array(32)] })).toBe(false)
    expect(isChunkProofValid({ ...good(0), path: [new Uint8Array(33), new Uint8Array(32), new Uint8Array(32)] })).toBe(false)
    expect(isChunkProofValid({ ...good(0), path: 'not-an-array' })).toBe(false)
  })

  it('throws ChunkProofError with a diagnostic code, never a bare Error', () => {
    // Callers must be able to tell a refusal from a crash.
    let err
    try {
      verifyChunkProof({ ...good(0), chunk: utf8('tampered') })
    } catch (e) {
      err = e
    }
    expect(err).toBeInstanceOf(ChunkProofError)
    expect(err.code).toBe('PROOF_INVALID')
  })
})

// ── adversarial: the wire decoder ────────────────────────────────────────────

describe('adversarial — the § 5.3 proof body decoder', () => {
  const validBody = () => fromHex(INTEROP_PROOF_HEX[0])

  it('rejects trailing bytes', () => {
    const b = validBody()
    expect(() => decodeChunkProof(Uint8Array.from([...b, 0x00]))).toThrow(ChunkProofError)
  })

  it('rejects truncation at every length', () => {
    const b = validBody()
    for (let k = 0; k < b.length; k++) {
      expect(() => decodeChunkProof(b.slice(0, k))).toThrow(ChunkProofError)
    }
  })

  it('rejects a non-minimal integer encoding', () => {
    // index 0 encoded as 0x18 0x00 (one-byte head) rather than 0x00. Two byte
    // strings that mean one proof is exactly what a strict decoder forbids.
    const b = validBody()
    const bad = Uint8Array.from([b[0], 0x18, 0x00, ...b.slice(2)])
    expect(() => decodeChunkProof(bad)).toThrow(ChunkProofError)
  })

  it('rejects an indefinite-length array', () => {
    expect(() => decodeChunkProof(Uint8Array.from([0x9f, 0x00, 0xff]))).toThrow(ChunkProofError)
  })

  it('rejects a body that is not a 2-element array', () => {
    expect(() => decodeChunkProof(Uint8Array.from([0x83, 0x00, 0x80, 0x00]))).toThrow(ChunkProofError)
    expect(() => decodeChunkProof(Uint8Array.from([0xa0]))).toThrow(ChunkProofError) // a map
    expect(() => decodeChunkProof(new Uint8Array(0))).toThrow(ChunkProofError)
  })

  it('rejects a path element that is not a 32-byte string', () => {
    // array(2)[ 0, array(1)[ bytes(31) ] ]
    const bad = Uint8Array.from([0x82, 0x00, 0x81, 0x58, 0x1f, ...new Uint8Array(31)])
    expect(() => decodeChunkProof(bad)).toThrow(ChunkProofError)
  })

  it('rejects a path longer than the 40-level bound', () => {
    // Claims 1000 elements without supplying them — refused on the declared
    // count, before any allocation proportional to it.
    const bad = Uint8Array.from([0x82, 0x00, 0x99, 0x03, 0xe8])
    expect(() => decodeChunkProof(bad)).toThrow(ChunkProofError)
  })
})

// ── the one-call browser path ────────────────────────────────────────────────

describe('verifyChunkResponse', () => {
  it('returns the chunk when the served proof body verifies', () => {
    const out = verifyChunkResponse({
      root: INTEROP_ROOT_B64,
      nChunks: VECTOR_N,
      index: 2,
      chunk: VECTOR_DATA[2],
      proof: fromHex(INTEROP_PROOF_HEX[2]),
    })
    expect(Array.from(out)).toEqual(Array.from(VECTOR_DATA[2]))
  })

  it('rejects a valid proof for a DIFFERENT chunk than the one requested', () => {
    // The subtle one: the server answers a seek for chunk 3 with a perfectly
    // valid proof of chunk 1. Everything folds; it is simply not the chunk that
    // was asked for. A player that trusted the proof alone would render the
    // wrong bytes at the wrong offset.
    expect(() =>
      verifyChunkResponse({
        root: INTEROP_ROOT_B64,
        nChunks: VECTOR_N,
        index: 3,
        chunk: VECTOR_DATA[1],
        proof: fromHex(INTEROP_PROOF_HEX[1]),
      }),
    ).toThrow(ChunkProofError)
  })

  it('rejects a tampered chunk served with an authentic proof', () => {
    expect(() =>
      verifyChunkResponse({
        root: INTEROP_ROOT_B64,
        nChunks: VECTOR_N,
        index: 0,
        chunk: utf8('A'),
        proof: fromHex(INTEROP_PROOF_HEX[0]),
      }),
    ).toThrow(ChunkProofError)
  })
})

// ── addressing ───────────────────────────────────────────────────────────────

describe('addressing', () => {
  it('addresses a chunk as 0x1e ‖ BLAKE3-256(bytes)', () => {
    const a = hashBytes(utf8('a'))
    expect(a.length).toBe(33)
    expect(a[0]).toBe(0x1e)
    expect(toHex(a.slice(1))).toBe(toHex(blake3(utf8('a'))))
  })

  it('round-trips an address through base64url', () => {
    const a = hashBytes(utf8('hello'))
    expect(Array.from(parseAddr(encodeAddr(a)))).toEqual(Array.from(a))
  })

  it('rejects non-canonical, wrong-length, and wrong-prefix addresses', () => {
    const a = hashBytes(utf8('a'))
    expect(() => parseAddr(encodeAddr(a) + '=')).toThrow(ChunkProofError) // padded
    expect(() => parseAddr(encodeAddr(a.slice(0, 20)))).toThrow(ChunkProofError) // short
    const wrongPrefix = Uint8Array.from(a)
    wrongPrefix[0] = 0x1f
    expect(() => parseAddr(encodeAddr(wrongPrefix))).toThrow(ChunkProofError)
    expect(() => parseAddr('!!!not-base64!!!')).toThrow(ChunkProofError)
    expect(() => parseAddr('')).toThrow(ChunkProofError)
  })

  it('rejects an empty chunk list', () => {
    expect(() => manifestRoot([])).toThrow(ChunkProofError)
    expect(() => chunkProof([], 0)).toThrow(ChunkProofError)
  })
})
