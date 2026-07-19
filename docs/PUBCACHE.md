# The Cache / Pin role — serving public, self-verifying objects

Cache/pin is the **content-serving substrate role**: a node may **cache and
re-serve public, content-addressed objects** — announces, manifests, chunks — so
readers can fetch them from somewhere nearby instead of from wherever they were
first published.

`vulos-relayd` is a **reference implementation** (`tunnel/pubcache`), but this
document is the *role*, not the product. It is one of the DMTAP substrate's
[infrastructure roles](https://github.com/vul-os/dmtap) (`substrate/ROLES.md` § 6),
over the DMTAP-PUB public-object profile (§ 22.5.1, `substrate/FEEDS.md` § 5).
**Any node may serve it**; a Vulos-operated PoP is simply a well-run instance,
with no privileged position, no registry to join, and nothing a client must
trust it for.

> **The whole security argument in one line: a cache cannot forge, only fail to
> serve.** Every object on this surface is authenticated by the address it is
> fetched by, so a reader verifies the bytes itself and a lying holder is caught
> by arithmetic rather than by reputation. This node additionally **refuses to
> store anything that does not match its content address**, so a poisoned
> upstream cannot become a poisoned cache.

---

## 1. Off by default, on purpose

This is the **one role a relay serves that is NOT content-blind.** The tunnel
moves bytes it cannot read; the mailbox holds ciphertext it cannot open; the
rendezvous node stores opaque blobs keyed by a public key. A public-object cache
serves **plaintext the operator can read**, which changes the operator's
moderation and liability posture — so DMTAP § 22.6.1 makes it **explicit
operator opt-in** (the `pub-1` capability), never automatic, and `vulos-relayd`
ships it **disabled**.

Enable it deliberately:

```bash
vulos-relayd -domain relay.example.com \
  -pubcache \
  -pubcache-upstreams https://gw1.example.org,https://gw2.example.org
```

A holder applies **its own serve policy** and may decline any object for any
reason (§ 22.6.2). There is **no protocol-level takedown**: nothing can compel a
holder to serve, and no holder can force another to drop. Availability is the
emergent sum of independent holder choices.

---

## 2. The surface

Mounted on the relay's **apex host** under `-pubcache-prefix` (default
`/.well-known/dmtap-pub`). A request to a tunnel subdomain is never captured —
a box at `<name>.<domain>` keeps its own well-known paths, because a box may
serve this very role itself.

| Endpoint | Object | Cached? |
|---|---|---|
| `GET {p}/announce/{id}` | `PubAnnounce` | yes — immutable, verified |
| `GET {p}/manifest/{id}` | `PubManifest` | yes — immutable, verified |
| `GET {p}/chunk/{h}` | raw plaintext chunk | yes — immutable, verified |
| `GET {p}/manifest/{id}/proof?chunk=i` | chunk-tree range proof | yes — immutable, **optional** (§ 5) |
| `GET {p}/feed/{pub}/head` | `FeedHead` | **never** — mutable passthrough |
| `GET {p}/feed/{pub}/range?from=&to=` | `[FeedEntry]` | **never** — mutable passthrough |
| `GET {p}/healthz` | liveness + cache counters | n/a |

`{id}` and `{h}` are the **unpadded base64url** of a full content address
(`prefix ‖ digest`, § 18.1.5); `{pub}` is the base64url publisher identity key.
Reads are **anonymous** — no authentication for public reads — and the role has
**no write surface at all**: a cache is filled by reads passing through it, never
by anyone pushing objects into it.

Cached responses carry `Cache-Control: public, immutable, max-age=…` and a
**strong `ETag` equal to the content address**, so any ordinary HTTP cache or CDN
may front this surface without understanding DMTAP (§ 22.5.1). Feed reads carry
`no-cache, must-revalidate`.

Anything this holder will not serve — missing, oversize, unverifiable, or
policy-declined — is a **404** (`ERR_PUB_NOT_SERVED`, `0x090C`). The correct
client response is to **rotate to another holder**. The failure modes are
deliberately indistinguishable from outside: a cache's refusal is never a
statement about whether an object exists.

---

## 3. Verification — the mandatory gate

Nothing enters the store without passing verification, and the rule differs per
object because the addressing does:

| Object | Address rule | Failure |
|---|---|---|
| `PubAnnounce` | `0x1e ‖ BLAKE3-256(det_cbor(obj))` (§ 18.9.4 anchor, § 22.3.3 step 2) | `0x0905` |
| chunk | `0x1e ‖ BLAKE3-256(plaintext)` (§ 22.2.2) | `0x090A` |
| `PubManifest` | `0x1e ‖ MTH(chunk hashes)` — the DS-tagged RFC 6962 tree of § 22.2.2 | `0x0909` |

A manifest is checked three independent ways: the **key-5 trap** (a
`PubManifest` carrying a key field is a leaked *sealed* manifest or a
malformation — `ERR_PUB_MANIFEST_KEY_PRESENT`, `0x0902`), the **recomputed
Merkle root**, and **agreement with its own `id` field**. Because the DS tag
`"DMTAP-PUB-v0/manifest"` is folded into every leaf and node, a public root and a
sealed root over the same chunk-hash list are different values: the two address
spaces are **type-incompatible**, so a sealed manifest mis-served as a public one
fails closed (`0x0903`) instead of being "tried both ways" (§ 22.2.3).

A failed verification is **logged, refused, and not retained** — the next request
re-tries upstream rather than being served a stored lie.

**Feed heads are not cached.** A `FeedHead` is mutable and authenticated by an
Ed25519 signature chaining through a `DeviceCert`, which hashing alone cannot
check. § 22.5.1 permits either verifying signatures or not caching it; this
implementation takes the second path and proxies feed reads without storing
them, behind its own `-pubcache-serve-feeds` opt-in. **An object this node cannot
verify is an object it does not hold.**

Verification remains the **client's** job regardless. A fetcher MUST check
signatures and content addresses on every response (§ 22.3.3, § 22.4). This
node's gate protects *the cache*; it is not a licence for a reader to trust it.

---

## 4. Bounded, and not an amplifier

An internet-facing cache is an abuse surface unless every axis is capped. All of
these are operator-chosen numbers, not functions of what the internet asks for:

- **Upstreams are config-only.** The `-pubcache-upstreams` list is the *only* set
  of hosts this role will ever contact. No header, query parameter, or path
  segment can name one — a client supplies a content **address**, and this node
  decides where to look. Base URLs are validated at startup (http/https, no
  credentials, no query, host required) and **redirects are not followed**, which
  is the one way an allowlist could otherwise be talked out of itself. The role is
  therefore **SSRF-free by shape, not by filtering**.
- **Bounded fan-out.** A global in-flight semaphore, **sequential** (never
  parallel) upstream attempts, and **single-flight coalescing** so a thundering
  herd for one cold object is one upstream fetch.
- **Size caps.** Per-object (`-pubcache-max-object-bytes`, default 16 MiB) and
  total (`-pubcache-max-bytes`, default 256 MiB, LRU-evicted). An oversize object
  is refused rather than allowed to evict the cache on its way through.
- **Rate limits.** Reads are anonymous by protocol requirement, so limits key on
  **source address** plus an **aggregate** bucket; the limiter's key table is
  itself capped, fail-closed.
- **Bounded feed reads.** The `{pub}` component must decode to a canonical 32-byte
  key, and a range's span is capped — an unbounded or inverted range is refused,
  never clamped.

---

## 5. Chunk-tree range proofs — verified partial fetch (optional)

**`FEEDS.md § 5.3`. OPTIONAL, and off unless `-pubcache-serve-proofs` is set.**

Ordinarily a fetcher verifies a chunk by holding the **whole** `PubManifest`: it
has every `h_i`, so it can check any chunk byte-for-byte. That is fine for small
blobs and wasteful for large media — verifying one 1 MiB chunk in the middle of a
multi-gigabyte video means first pulling a chunk-hash list with thousands of
entries. The § 22.2.2 tree already commits to every leaf, so an **O(log n)
inclusion proof** is enough:

```
GET {p}/manifest/{id}/proof?chunk=i   →   [ i, [ sibling_hashes… ] ]   application/cbor
```

A client fetches `chunk/{h_i}`, fetches its path, folds the siblings with the
same DS-tagged `leaf`/`node` functions, and checks the result against the
`PubManifest.id` it **already trusts from the signed announce**. That is verified
seek, and verified resume: the machinery under segmented (HLS/DASH) playback and
under large-file download that survives an interrupted connection.

**This adds no trust.** It allocates no new object, no new signing preimage, and
no new § 21 error code — it serves a proof the tree already commits to. A lying
holder cannot forge a path to a root it does not control (BLAKE3 collision
resistance), so the endpoint is a convenience, never a trust root, exactly like
every other § 22 read. The endpoint is **advertised by presence**: a holder that
does not offer it answers `404` and the client falls back to whole-manifest
verification, so enabling it is purely additive and disabling it breaks nothing.

A proof is only ever built over a chunk list that has **already passed the
verification gate** (§ 3). The manifest is resolved through the ordinary verified
read path, so this node cannot emit a path over a list it has not proved.

### Encoding

The body is a canonically-encoded CBOR array `[chunk_index, [siblings…]]`,
deterministic per § 18.1.2 (minimal heads, definite lengths, no tags). The
response is immutable and content-addressed by `(id, i)`, so it carries the same
long `Cache-Control` as the other content-addressed reads and an `ETag` of
`"{id}.{i}"`.

Siblings are **bare 32-byte tree nodes**, not 33-byte content addresses. § 5.3
does not state this explicitly, so it is worth being precise: under § 3.2 the
`leaf`/`node` functions output raw BLAKE3-256, and the `0x1e` multihash prefix is
applied only where a digest becomes an *address* — at the leaves' **inputs**
(`h_i`) and at the root when it becomes `PubManifest.id`. Interior nodes are
never addresses, so they travel bare.

Path elements are ordered **bottom-up**, and a level at which the node is the
promoted odd one contributes **no element** — see the note on tree shape below.

### Verifying — the client's job, as always

```go
// root and nChunks come from what the client ALREADY TRUSTS — the signed
// announce and the manifest header it commits to — never from the same
// response that carried the proof.
idx, path, err := pubcache.DecodeChunkProof(body)
err = pubcache.VerifyChunkProof(root, nChunks, idx, chunkBytes, path)
```

`VerifyChunkProof` returns `nil` **only** if the chunk is proven; wrong index,
tampered bytes, a tampered/reordered/truncated/over-long path, and a wrong root
are all errors, and the chunk must then be discarded (rotate to another holder).
`ChunkProof(chunks, i)` is the generating side, for anyone serving the endpoint.

**`nChunks` is necessarily out-of-band.** § 5.3's response carries the index and
the path but **not the tree size**, and RFC 6962 audit-path verification needs
the size to know where odd-node promotion happens. A client therefore takes it
from the manifest header it already trusts (`⌈size ÷ chunk_sz⌉`) — two small
fields, not the chunk list, so the O(log n) saving stands. Note that `nChunks` is
**structural metadata, not a second authenticator**: two counts that imply the
same fold shape for a given index accept the same proof, and correctly so — the
**root** is what authenticates.

### Verifying in the browser

Server-side verification alone leaves the feature half-built. If only a Go node
can check a path, then a **web** client — the one that most needs partial fetch —
still has to trust whichever gateway handed it the bytes, which is the exact
trust the content-addressed design exists to remove. So the JS client ships the
same verifier:

```js
import {
  verifyChunkResponse, decodeChunkProof, verifyChunkProof, hashBytes, manifestRoot,
} from '@vulos/relay-client/chunkProof'

// The one-call path: bytes and proof body exactly as served, root and nChunks
// from what you already trust.
const bytes = verifyChunkResponse({
  root,          // 33-byte address or base64url, from the SIGNED announce
  nChunks,       // ⌈size ÷ chunk_sz⌉, from the trusted manifest header
  index: i,      // the chunk you asked for
  chunk,         // Uint8Array as served
  proof,         // § 5.3 CBOR body as served
})               // → returns the chunk, or throws ChunkProofError
```

It is exported as its **own subpath** (like `./rendezvous`), so an app that never
verifies a chunk does not pull in BLAKE3. `decodeChunkProof` / `verifyChunkProof`
are available separately for callers that already have the path in hand, and
`isChunkProofValid` is the boolean form. BLAKE3 comes from
[`@noble/hashes`](https://github.com/paulmillr/noble-hashes) — audited, and
already a dependency of the rendezvous client.

`verifyChunkResponse` also cross-checks the index **inside** the proof against
the one you requested. A gateway answering a seek for chunk 3 with a perfectly
valid proof of chunk 1 would otherwise pass every hash check and hand a player
the wrong bytes at the wrong offset.

**The browser use case, concretely.** A player seeking to 00:47:12 of a
multi-gigabyte video maps the offset to chunk *i*, fetches `/chunk/{h_i}` and
`/chunk-proof/{id}/{i}`, and proves *i* belongs to the root it got from the
signed announce — without downloading a chunk list with thousands of entries, and
without trusting the holder. A download resuming at 60 % verifies each new chunk
as it lands, so a holder that swaps bytes mid-transfer is caught at that chunk
rather than at the end of the file. In both cases the client can rotate to
another holder on failure, which is the whole asymmetry the role rests on: a
holder can fail to serve, but it cannot lie.

The same honesty applies here as above: **`nChunks` is structural metadata, not a
second authenticator.** It comes from the manifest header, it tells the verifier
where odd-node promotion happens, and several counts can imply the same fold for
a given index — for chunk 0 of the interop vector, `n = 5, 6, 7, 8` all verify.
That is not a forgery vector, because the fold must still reproduce the **trusted
root**; it is the reason `nChunks` must come from the trusted header and never
from the response that carried the proof. Both test suites assert those exact
widths, so this is a tested property rather than a caveat in prose.

### Tree shape, and parity with vidmesh

§ 3.2 specifies the tree by the **RFC 6962 split rule** (recurse on the largest
power of two below `n`). The proof path here is generated the other way round —
level by level, pairing left to right and **promoting** a level's unpaired final
node unchanged — which is the rule *vidmesh* uses, and the one that yields a path
and a verifier directly. **These are the same tree**, and because that is exactly
the sort of claim that is true at powers of two and false at `n = 11`, the test
suite asserts the two constructions agree for every `n` up to 300 rather than
leaving it as an assertion in a comment.

Structure is shared with vidmesh; **hashes are not**, and deliberately. vidmesh
hashes `BLAKE3(0x00 ‖ chunk_bytes)` at the leaves with no domain-separation tag;
§ 3.2 hashes `BLAKE3(DS ‖ 0x00 ‖ h_i)` over the chunk's *address* with
`DS = "DMTAP-PUB-v0/manifest" ‖ 0x00`. **The spec governs here** — the DS tag is
what makes a public root and a sealed root over the same chunk list different
values (§ 3.3), which is a property this role depends on. So a vidmesh proof and
a DMTAP-PUB proof have the same *shape* and different *values*; they are not
wire-interchangeable, and § 5.3 never claims they are.

`proof_test.go` pins a 5-chunk interop vector — root and every path, byte for
byte — for anyone implementing the endpoint elsewhere. Five leaves is the
smallest tree that promotes an odd node at two levels.

That vector is also the **cross-language interop lock**. The JS verifier asserts
the *same* constants in `client/src/__tests__/chunkProof.test.js`, so a one-byte
divergence between the Go node and the browser — a different DS tag, a leaf taken
over chunk bytes instead of the chunk address, an interior node that picked up a
multihash prefix, a top-down path, a promotion that re-hashes — fails one of the
two suites. Underneath it, three BLAKE3 known-answer vectors are asserted in both
languages, so a dependency bump that changed the primitive reports itself as a
hash mismatch instead of an inscrutable Merkle bug. This is the same arrangement
the rendezvous role uses for its canonical signing message (`canonical_test.go` ↔
`rendezvous.test.js`). **If you change the construction, regenerate both copies
together.**

---

## 6. Eviction is not deletion; pinning is not implemented

A content address is **a name, not a promise** (§ 5.5.1). When this node evicts or
expires an object it is simply **ceasing to be one of the holders** — it has not
deleted anything, and it makes no claim the object is gone.

**Pinning** (durable retention with a real storage budget) is deliberately *not*
implemented here: `vulos-relayd` holds soft state only. A pin-capable holder is a
compatible, separate implementation of the **same wire protocol** — which is the
point of describing this as a role rather than a service.

---

## 7. Configuration reference

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `-pubcache` | `VULOS_RELAY_PUBCACHE=1` | off | enable the role (serves readable plaintext — opt in deliberately) |
| `-pubcache-prefix` | `VULOS_RELAY_PUBCACHE_PREFIX` | `/.well-known/dmtap-pub` | mount prefix |
| `-pubcache-upstreams` | `VULOS_RELAY_PUBCACHE_UPSTREAMS` | *(none)* | comma-separated gateway base URLs, tried in order |
| `-pubcache-max-object-bytes` | `VULOS_RELAY_PUBCACHE_MAX_OBJECT` | 16 MiB | per-object size cap |
| `-pubcache-max-bytes` | `VULOS_RELAY_PUBCACHE_MAX_BYTES` | 256 MiB | total cache cap (LRU) |
| `-pubcache-ttl` | `VULOS_RELAY_PUBCACHE_TTL` | 1h | per-object cache lifetime |
| `-pubcache-upstream-timeout` | `VULOS_RELAY_PUBCACHE_UPSTREAM_TIMEOUT` | 15s | one upstream read |
| `-pubcache-max-inflight` | `VULOS_RELAY_PUBCACHE_MAX_INFLIGHT` | 16 | concurrent upstream fetches, role-wide |
| `-pubcache-serve-feeds` | `VULOS_RELAY_PUBCACHE_SERVE_FEEDS=1` | off | also proxy the mutable feed reads (never cached) |
| `-pubcache-serve-proofs` | `VULOS_RELAY_PUBCACHE_SERVE_PROOFS=1` | off | also serve the optional chunk-tree range proofs (§ 5) |

With **no upstreams configured** the role is still valid: it is a holder that
holds nothing and answers `404` to everything. That is a legitimate node, not a
misconfiguration — and it is the safest thing an accidental `-pubcache` can do.

---

## 8. Related

- **[docs/RENDEZVOUS.md](RENDEZVOUS.md)** — the sibling reachability role
  (announce / resolve / signal / mailbox + ICE), which *is* content-blind.
- **[docs/SECURITY.md](SECURITY.md)** — what a relay operator can and cannot see.
- DMTAP `substrate/ROLES.md` § 6 (the role), `22-public-objects.md` (the objects
  and their verification), `substrate/FEEDS.md` § 5 (the HTTP profile), § 5.3 (chunk-tree range proofs).
