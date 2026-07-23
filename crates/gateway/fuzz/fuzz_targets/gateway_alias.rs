#![no_main]
use libfuzzer_sys::fuzz_target;
use gateway::forwarded_addr::{decode, encode};

// **Relocated from envoir, and RETARGETED** (`fuzz/fuzz_targets/gateway_alias.rs`, removed by
// envoir commit `620a68c` when the gateway moved to Wakala).
//
// Envoir's original target fuzzed `dmtap::naming::{gateway_alias_local, ik_from_gateway_alias}` —
// a **key-derived** gateway alias that reversibly packs a full 32-byte DMTAP identity key into a
// `dmtap1-<base32>` local-part and decodes it straight back. That function pair lived in
// `envoir-node`'s library crate (`../node/src/naming.rs`), NOT in `envoir-gateway` — it has no
// analogue anywhere in Wakala's `gateway` crate (this crate's own key-derived alias,
// `gateway::authz::key_derived_localpart`, is a one-way **content-address hash** of the key,
// `k` + base32(first 10 bytes of `ContentId::of(key)`); by design it does NOT reversibly decode
// back to the key, so envoir's bijection property simply does not hold for it, and would be a
// false property to assert here). Re-homing this target verbatim would therefore either fuzz code
// that does not exist in this crate, or assert a round-trip guarantee this crate's key-derived
// alias deliberately does not make.
//
// The nearest genuine analogue actually IN this crate — same general shape (an attacker-controlled
// SMTP local-part decoded before any other authentication has happened, §7.10) and the same two
// properties (never-panic decode of arbitrary bytes; encode→decode round-trips) — is the
// **forwarded-address** SRS-style codec, `gateway::forwarded_addr::{encode, decode}` (§7.10.2):
// `local.native_domain@gateway.domain`, reversibly and unambiguously. This target fuzzes that
// instead, replacing the two properties one-for-one with `forwarded_addr`'s equivalents.
//
// Two properties, both checked here:
//  1. `decode(local)` — **never panics**, on any string, and fails closed (returns `None`) on
//     anything that is not a canonical, unambiguous `escape(local).escape(native_domain)` form.
//  2. `encode(local, native_domain)` → `decode` **round-trips** for any pair the encoder accepts:
//     encoding a `(local, native_domain)` pair and decoding the result must always recover the
//     exact same (lowercased) pair — the codec's own canonical-form-idempotence guarantee
//     (`crate::gateway::forwarded_addr` module docs), mirroring the sibling wire-decoder fuzz
//     targets' round-trip contract elsewhere in this workspace.
fuzz_target!(|data: &[u8]| {
    // Property 1: an arbitrary local-part (attacker-controlled SMTP `RCPT TO`/`MAIL FROM` local
    // part) must never panic and must fail closed on anything not a canonical forwarded address.
    let as_str = String::from_utf8_lossy(data).into_owned();
    let _ = decode(&as_str);

    // Property 2: round-trip for arbitrary attacker-controlled (local, native_domain) pairs — split
    // the fuzz bytes at a data-controlled point so both halves vary independently, then run each
    // half through the same lossy UTF-8 decode `encode` itself would apply on the wire.
    if data.is_empty() {
        return;
    }
    let (split_byte, rest) = data.split_at(1);
    let split = (split_byte[0] as usize) % (rest.len() + 1);
    let (local_bytes, domain_bytes) = rest.split_at(split);
    let local = String::from_utf8_lossy(local_bytes).into_owned();
    let native_domain = String::from_utf8_lossy(domain_bytes).into_owned();

    if let Ok(encoded) = encode(&local, &native_domain) {
        match decode(&encoded) {
            Some((l, d)) => {
                assert_eq!(
                    l,
                    local.to_ascii_lowercase(),
                    "forwarded-address round trip must recover the local part"
                );
                assert_eq!(
                    d,
                    native_domain.to_ascii_lowercase(),
                    "forwarded-address round trip must recover the native domain"
                );
            }
            None => panic!(
                "encode({local:?}, {native_domain:?}) produced {encoded:?}, which decode() then \
                 refused — a value this codec's own encoder just emitted must always decode back \
                 (canonical-form idempotence, §7.10.2)"
            ),
        }
    }
});
