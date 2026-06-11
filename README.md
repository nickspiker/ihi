![ihi](ihi.webp)

# ihi

**Identity crypto primitives. The math recognizes what you are.**

In Māori understanding, ihi is the specific quality of mana that is outwardly perceptible — the awe-inspiring presence that stops others, that can be witnessed and verified from outside. You cannot claim it. It flows from nature and lineage. The observer recognizes it.

This crate computes exactly that.

```toml
[dependencies]
ihi = "0.0.44"
```

> **Pre-1.0 stability:** Until `0.1.0`, the algorithms themselves (spaghettify, the handle-proof PoW, the provable-destruction construction) may still see breaking changes. These are very new ideas and the byte-level contract is not yet frozen — every 0.0.x release is permitted to alter test vectors. The determinism guarantees below apply *within* a given version, not across them. Pin exact versions if you publish identities you intend to verify later.

---

## Primitives

### `chaos_amp(input: &[u8; 64]) -> [u8; 48]`

The core mixing primitive. **Bit-exact with PIPE's silicon Verilog** (`/mnt/Octopus/Code/pipe/rtl/chaos_amp_v2.v`) — same algorithm, two implementations (software + FPGA), one byte-level contract. Pure integer arithmetic; zero floating point; zero transitive dependencies that can drift.

16 buckets × 24 bits each (384-bit state). 16 rounds. Each round is two phases: data-dependent op-selection (a 32-op ALU menu picked per bucket from `val[4:0]`) followed by ARX cross-bucket diffusion. Full avalanche over the state in ~5-8 rounds; 16 rounds for margin.

### `spaghettify(input: &[u8]) -> [u8; 32]`

Transparently irreversible chaos amplifier for arbitrary-length input. Wraps `chaos_amp` with BLAKE3-XOF absorption (input → 64 bytes) and a defense-in-depth finalizer (`smear_hash` over `chaos_state || original_input`).

Unlike traditional hash functions whose hardness is conjectured ("we believe SHA-3 is one-way"), spaghettify's hardness is **auditable by inspection**. Counting paths:

```
Op-selection entropy:   5 bits × 16 buckets × 16 rounds   = 1280 bits ≈ 10^385
Shift/rotate entropy:   4 bits × 30% × 256 op-applications ≈  300 bits
Branch entropy (CSWAP): 1 bit  ×  3% × 256 op-applications ≈    8 bits
                                                            ───────────
Total distinct paths thru one chaos_amp:                  ~10^482

Atoms in the observable universe:                            ~10^80
```

How to count: each (bucket, round) cell independently picks one of 32 ops based on `val[4:0]`. With 16 buckets × 16 rounds = 256 cells, op-selection alone enumerates `32^256 = 2^1280 ≈ 10^385` distinct op-sequences. About 30% of those ops add 4 bits of shift/rotate entropy on top, and op 21 (CSWAP) adds 1 bit of branch entropy when it fires (~3% of the time). The combined ~1600 bits ≈ 10^482 is the path-explosion bound an attacker would need to enumerate to invert the chaos layer alone.

To forge an identity then requires **either** inverting the smear_hash finalizer (simultaneously breaking BLAKE3 ⊕ SHA3-256 ⊕ SHA-512) **or** inverting BLAKE3-XOF AND navigating ~10^482 paths thru chaos_amp. The math does not care if you trust it.

Information loss compounds the argument: 11 lossy + 3 extreme-lossy ops in the 32-op menu (44% of the menu) destroy 4-23 bits per application. Over 256 op-applications per call, ~700-2500 cumulative bits are destroyed — collisions are guaranteed to exist by the pigeonhole principle, they just cannot be navigated to.

**See [PROOF.md](PROOF.md)** for the step-by-step walkthru: counting the op-selection paths (10³⁸⁵), adding shift entropy (300 bits), adding branch entropy, the per-op information-loss table, why path explosion and information loss compound rather than substitute, and what the proof does *not* claim. [SPAGHETTIFY.md](SPAGHETTIFY.md) is the engineering deep-dive (state layout, op menu, NUMS provenance, silicon-software unification with PIPE, porting checklist).

### `smear_hash(input: &[u8]) -> [u8; 32]`

Defense-in-depth output hash. XORs BLAKE3 ⊕ SHA3-256 ⊕ SHA-512.

If **any** algorithm survives cryptanalysis, the output remains secure. An attacker must break all three simultaneously.

### `handle_proof(hash: &blake3::Hash) -> blake3::Hash`

Memory-hard sequential proof-of-work for identity registration. Deterministic — same handle always produces the same public ID, enabling decentralized verification without coordination. ~1 second per handle makes bulk squatting expensive.

---

## Design

```
identity = spaghettify(system_secret || developer_pubkey || option)
```

The process doesn't assert its identity. The oracle looks at what the process provably **is** — binary content, signing authority, hardware state — and derives what flows from that nature.

To forge an identity requires either breaking the multi-hash finalizer or navigating ~10^482 paths thru the chaos amplifier. There are ~10^80 atoms in the observable universe. The full counting walkthru lives in [PROOF.md](PROOF.md).

The math does not care if you trust it.

---

## Determinism contract

ihi has **zero non-deterministic transitive dependencies**, by construction. Every byte of every output comes from pure integer arithmetic over fixed-width types. No floating point. No platform-defined behavior. No `#[cfg(target_*)]` branches that change output bytes.

`tests/test_vectors.rs` locks the byte output of every public function on a diverse set of inputs. Any future change to ihi, its dependencies, or rustc that alters output bytes will fail the test immediately and loudly. Cross-implementation ports (C, JS, future hardware) must reproduce these exact bytes.

### Text canonicalization

Handle strings are canonicalized thru two stacked anchors before they ever reach BLAKE3:

1. **NFC normalization**, performed inside vsf 0.4.0+'s `VsfType::x` Huffman encoder. Anchored by Unicode's stability policy: once a codepoint is assigned, its NFC form is guaranteed not to change across Unicode versions.
2. **Huffman encoding over the full 1,112,064-codepoint codespace** (0x000000–0x10FFFF minus the U+D800–U+DFFF surrogate range). Every valid codepoint has a pre-assigned code in the frozen codebook. Yearly Unicode codepoint additions do not change the encoding of any existing character because every slot is already reserved. The codebook file is vendored in the vsf repo and integrity-checked by BLAKE3 at build time.

Together this means `handle_to_proof("café")` and `handle_to_proof("cafe\u{0301}")` produce the same 32-byte proof. Any change to either anchor would invalidate every published identity and trigger a MAJOR version bump per the rules in `Cargo.toml`.

> **History**: ihi ≤ 0.0.43 inherited a vsf ≤ 0.3.x bug where the Huffman encoder did NOT actually perform NFC normalization despite the documentation claiming so. NFD-form handles hashed differently from NFC-form handles for the same logical text. ihi 0.0.44 + vsf 0.4.0 fix this at the source. Identities computed by earlier versions over NFD-form input are bifurcated and must be re-attested.

---

## `no_std`

Fully `no_std`. Suitable for bare-metal kernels, embedded targets, and constrained environments.

---

## License

MIT OR Apache-2.0

**Author:** Nick Spiker
