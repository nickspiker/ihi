# spaghettify + chaos_amp: deep dive

The canonical engineering reference for ihi's chaos mixing primitive — its algorithm, its silicon-software unification, its byte-level contract, and the spec every port must satisfy. For the path-explosion + information-loss security proof walkthru see [PROOF.md](PROOF.md). For the elevator pitch see [README.md](README.md).

---

## 1. What it is

`spaghettify(input: &[u8]) -> [u8; 32]` is a deterministic one-way function whose hardness is **auditable by inspection** rather than conjectured. You can count the paths yourself, count the bits destroyed, and verify the NUMS constants from their BLAKE3 seed strings — no "we believe X is hard" required.

Its inner core, `chaos_amp(input: &[u8; 64]) -> [u8; 48]`, is **bit-exact** with the Verilog at `/mnt/Octopus/Code/pipe/rtl/chaos_amp_v2.v`. Same algorithm, two implementations (software + FPGA), one byte-level contract. Bytes from the software call equal bytes from the silicon call for the same input. That equality is enforced by the test vectors in `tests/test_vectors.rs::chaos_amp_vectors`.

## 2. What it isn't

- **Not a standard cryptographic hash** — it is not collision-resistant in the way SHA-3 is (collisions are guaranteed to exist by pigeonhole; the security argument is that they are intractable to navigate to, not that they don't exist).
- **Not memory-hard** — it is preimage-resistant via path explosion and information loss, not via memory cost. For memory-hardness see `handle_proof` (~24 MB sequential PoW).
- **Not a substitute for AEAD or signatures** — it's a one-way mixing function for identity derivation, not for message authentication or confidentiality.

## 3. Architecture

```
input (arbitrary length)
       │
       ▼
┌─────────────────────────┐
│  BLAKE3 XOF absorb      │   any-length input → 64 fixed bytes
└─────────────────────────┘
       │
       ▼
┌─────────────────────────┐
│  chaos_amp (the core)   │   64 → 48 bytes thru 16 buckets × 16 rounds
│  ── 32-op data-dep ALU  │   bit-exact with chaos_amp_v2.v silicon
│  ── ARX cross-mix       │
└─────────────────────────┘
       │
       ▼
┌─────────────────────────┐
│  smear_hash_parts(      │   BLAKE3 ⊕ SHA3-256 ⊕ SHA-512
│    chaos_state ‖ input  │   defense-in-depth — secure if EITHER
│  )                      │   chaos_amp OR the multi-hash survives
└─────────────────────────┘
       │
       ▼
   32 bytes
```

Three layers, three independent security arguments. An attacker must defeat **at least one of** (BLAKE3 + SHA3-256 + SHA-512 simultaneously) OR (BLAKE3-XOF inversion + chaos_amp path-explosion + information-loss reconstruction). Either layer surviving suffices. See [PROOF.md](PROOF.md) for the formal walkthru.

---

## 4. chaos_amp — the silicon-equivalent core

### 4.1 State layout

16 buckets, 24 bits each, packed into `u32` with the top byte forced to zero by `BUCKET_MASK = 0x00FF_FFFF`. Total state = 384 bits.

The 24 bits per bucket are partitioned conceptually as **16-bit fraction (low) + 8-bit exponent (high)** — this F16E8 naming is inherited from PIPE's silicon convention and does NOT imply any floating-point semantics. The two halves are simply two parallel integer lanes; each op operates on them as `i16/i8` or `u16/u8` per its definition.

### 4.2 Input absorption

```
for i in 0..16:
    chunk      = u32::from_le_bytes(input[i*4 .. i*4+4])
    folded     = chunk ^ ((chunk >> 24) & 0xFF)   // top byte XOR-folds into bottom
    state[i]   = folded & BUCKET_MASK
```

The XOR-fold ensures every one of the 512 input bits affects initial state — without it, the top byte of each 4-byte input chunk would be masked out and discarded entirely.

### 4.3 Round structure

Each round is two phases. The pre-round snapshot makes both phases parallel-safe (every bucket reads from `snap`, writes go to fresh `tmp` / `state` arrays). This is essential for FPGA implementation, where the 16 bucket updates within a phase execute combinationally in one clock.

```
snap = state.clone()

// Phase 1 — data-dependent op selection
for i in 0..16:
    val        = snap[i]
    op_idx     = val[4:0]                          // 5 bits → 32-op menu
    secondary  = snap[(i + 11) & 15]
    tmp[i]     = op_apply(op_idx, val, secondary)
                 ^ ROUND_CONST[round]
                 ^ pos_const(i, round)

// Phase 2 — ARX cross-bucket diffusion
for i in 0..16:
    near       = tmp[(i + 1) & 15]
    far        = tmp[(i + 7) & 15]
    far_rot    = rotate_left_24(far, 5)
    state[i]   = (tmp[i] + near + far_rot) & BUCKET_MASK
```

**Phase 1** contributes the path entropy (which op fires depends on `val[4:0]`, which itself is computed by previous rounds and ultimately by input bits).

**Phase 2** contributes guaranteed cross-bucket diffusion. Every bucket sees changes from positions `{i, i+1, i+7, i+11}` per round. With three coprime offsets `{1, 7, 11}` over 16 positions, full avalanche reaches all 16 buckets within ⌈log₂ 16⌉ ≈ 4 rounds even if Phase 1 contributed nothing. We run 16 rounds for margin.

### 4.4 The 32-op ALU

Each op is binary in `(val, secondary)`. Output is masked to 24 bits. Bit-exact with `chaos_amp_v2.v::op_apply` — `case (op_idx)` arms in 1:1 correspondence.

| idx | name | description | lossy? |
|----:|------|-------------|--------|
|  0 | ADD          | `frac_a + frac_b`, `exp_a + exp_b` (wrapping)         | no |
|  1 | SUB          | wrapping subtract                                      | no |
|  2 | MUL_LO       | wrapping multiply (low half)                           | no |
|  3 | AND          | bitwise AND                                            | YES |
|  4 | OR           | bitwise OR                                             | YES |
|  5 | XOR          | bitwise XOR                                            | no |
|  6 | ANDN         | `a & ~b`                                               | YES |
|  7 | NOT          | `~a ^ b`                                               | no |
|  8 | SHL          | left shift by `secondary[3:0]`                         | YES |
|  9 | SHR          | right shift by `secondary[3:0]`                        | YES |
| 10 | ROL_B        | rotate left by `secondary[3:0]`                        | no |
| 11 | ROR_B        | rotate right by `secondary[3:0]`                       | no |
| 12 | ROL_S        | rotate left by **self's** `val[3:0]` — high path entropy | no |
| 13 | NEG          | two's complement negate, XOR secondary                  | no |
| 14 | ABS          | wrapping absolute value, add secondary                  | YES |
| 15 | BSWAP        | byte-swap fraction                                      | no |
| 16 | MIN          | signed `min(a, b)`                                      | YES |
| 17 | MAX          | signed `max(a, b)`                                      | YES |
| 18 | POPCNT       | low byte ← popcount(val ⊕ sec); top byte XOR-preserved | YES (8b) |
| 19 | SAT_ADD      | saturating add — clamps at MAX / MIN                    | YES |
| 20 | SAT_SUB      | saturating subtract                                     | YES |
| 21 | CSWAP        | branch on `frac_a < frac_b` — two distinct paths        | branch |
| 22 | GFMUL        | GF(2⁸) multiply on low byte, AES polynomial 0x11B       | no (algebraic) |
| 23 | PARITY       | XOR-fold val to 1 bit, paint across all 24 bits         | EXTREME (23b) |
| 24 | BREV         | bit-reverse fraction                                    | no |
| 25 | NREV         | nibble-reverse within bytes                             | no |
| 26 | AVG          | rounded average of (a, b)                               | YES |
| 27 | LFSR_TICK    | Galois LFSR step (taps 0xB400)                          | no |
| 28 | EXPAND_LO    | replicate low byte across word                          | YES (8b) |
| 29 | SQUEEZE      | XOR all bytes → 1 byte, paint across                    | EXTREME (16b) |
| 30 | ZIP          | bit-interleave low bytes of (val, secondary)            | no |
| 31 | PCNT_REPLACE | bytes ← popcounts of val / secondary / exp parts        | EXTREME (16b) |

Twelve ops are non-lossy (bijective at the bit level given fixed secondary). Eleven are lossy (destroy 1-8 bits). Three are extreme-lossy (compress 16-24 bits to ≤8 distinct outputs). Two — ROL_S (op 12) and CSWAP (op 21) — contribute extra path entropy beyond op selection itself.

### 4.5 Round constants — NUMS provenance

`ROUND_CONSTS` are the first 16 little-endian `u32` of:

```
blake3("PIPE chaos amp v2 - Dragonfly")           // u32s 0..8
blake3("PIPE chaos amp v2 - Dragonfly - more")    // u32s 8..16
```

The seed strings are intentionally self-descriptive — anyone re-deriving from BLAKE3 can verify by inspection that no magic numbers were planted. The constants are hardcoded in `chaos_amp.rs` for `no_std` compatibility (BLAKE3 can't run at `const`-time); `tests/test_vectors.rs::chaos_amp_round_consts_match_blake3` re-derives them at runtime on every test run and asserts bit-for-bit equality. If anyone ever renames a seed string or fat-fingers a constant, the test fails immediately.

The "PIPE" prefix reflects that this primitive was first specified for PIPE silicon. ihi now hosts the canonical software side; the seed strings stay verbatim to preserve bit-exactness with deployed PIPE silicon. Renaming the strings would silently change every output byte and break unification.

### 4.6 Position-dependent constants

```
pos_const(i, r) = ((i * 0x9E37_79B9) ^ (r * 0x517C_C1B7)) & 0x00FF_FFFF
```

The golden-ratio multiplier `0x9E37_79B9` and the second-largest-fractional-part constant `0x517C_C1B7` keep neighbouring `(i, r)` pairs distinct without any table lookup. Cheap on silicon (yosys reduces multiply-by-constant to a shift+add chain) and trivial in software.

Without this, every bucket at round `r` would XOR the same `ROUND_CONST[r]` and `pos_const` could converge to a fixed point in degenerate edge cases. The position-dependent mix prevents that.

---

## 5. spaghettify — the arbitrary-input wrapper

Three lines of structural Rust:

```rust
let mut block = [0u8; 64];
blake3::Hasher::new().update(input).finalize_xof().fill(&mut block);
let state = chaos_amp(&block);
smear_hash_parts(&[&state, input])
```

### 5.1 BLAKE3-XOF absorb

Why XOF instead of a fixed-size BLAKE3 digest? XOF mode produces deterministic 64-byte output for any input length without padding ambiguity. Two different inputs cannot share an absorbed 64-byte block unless they collide under BLAKE3-XOF, which reduces to BLAKE3's preimage / collision resistance — a problem the world has thoroughly examined.

### 5.2 smear_hash defense-in-depth

`smear_hash_parts(&[chaos_state, input])` computes BLAKE3 ⊕ SHA3-256 ⊕ SHA-512[..32] over the concatenation `chaos_state ‖ input` and XORs them.

**Key property**: the original input bytes are fed into the multi-hash directly, not just thru chaos_amp. A complete break of chaos_amp (suppose someone publishes a polynomial-time inverter tomorrow) still leaves the attacker facing a 3-way-XOR of three independent cryptographic hashes over `(known chaos_state ‖ unknown input)`. Inverting that requires simultaneously inverting BLAKE3 AND SHA3-256 AND SHA-512 — three constructions chosen for maximum design diversity (Merkle tree of ChaCha-based compression vs Keccak sponge vs Merkle-Damgård ARX).

Output security holds if **any one** of {chaos_amp, BLAKE3, SHA3-256, SHA-512} survives cryptanalysis.

---

## 6. Security argument (summary)

The two-pronged argument:

- **Path explosion**: any attacker attempting preimage attack against chaos_amp must enumerate ~10⁴⁸² distinct execution traces per candidate input. This dominates physical realizability by hundreds of orders of magnitude.
- **Information loss**: even if the attacker pays that cost per candidate, ~110 lossy op-applications per call destroy ~700-2500 cumulative bits, making the inverse mapping ambiguous within each trace.

These two arguments are independent and compound multiplicatively. The defense-in-depth smear_hash finalize layers a third argument on top — even a complete break of chaos_amp leaves the multi-hash standing.

**See [PROOF.md](PROOF.md) for the full walkthru with step-by-step counting.**

---

## 7. Silicon-software unification

chaos_amp exists in two implementations:

- **Software**: `/mnt/Octopus/Code/ihi/src/chaos_amp.rs`
- **Silicon**: `/mnt/Octopus/Code/pipe/rtl/chaos_amp_v2.v` (and the silicon synthesis path thru `top_pipe_silicon.v`)

These are not "similar" or "equivalent in spirit" — they are **bit-exact**. The same 64-byte input produces the same 48-byte (384-bit) output from both implementations, byte-for-byte. The contract is enforced by:

1. **`tests/test_vectors.rs::chaos_amp_vectors`** — locks 4 input/output pairs. Software must produce these. Silicon must produce these. Divergence anywhere is a unification break.
2. **`tests/test_vectors.rs::chaos_amp_round_consts_match_blake3`** — locks the NUMS seed strings. Either implementation must use ROUND_CONSTS derivable from these exact strings.
3. **The 1:1 mapping between Rust `match op_idx` and Verilog `case (op_idx)`** — enforced by inspection at PR review time; any new op or op change must land in both files in the same patch.

### 7.1 What "bit-exact" means concretely

- Endianness: little-endian for input absorption (`u32::from_le_bytes`); little-endian for state-to-bytes serialization. The Verilog handles this with explicit byte-position arithmetic in `S_LOAD` and the output packing.
- Signedness: ops that compare or saturate (16, 17, 19, 20, 21) treat the fraction as `i16`, the exponent as `i8`. The Verilog declares these `reg signed [15:0]` / `reg signed [7:0]` accordingly.
- Wrapping: all arithmetic ops are `wrapping_*` in Rust, which matches Verilog's native modular arithmetic on fixed-width regs.
- Top byte: forced to zero after every update via `BUCKET_MASK`. The Verilog state regs are `[23:0]` so this is automatic; the Rust mask is explicit.

### 7.2 Multi-cycle ops in silicon

Verilog needs multi-cycle FSM paths for ops 2 (MUL_LO — 16-cycle shift-add) and 22 (GFMUL — 8-cycle iterative). The Rust does them combinationally in one expression. The bit-level results are identical; the timing differs (514 silicon clocks per chaos_amp vs nanoseconds in software).

This timing asymmetry is fine — only the byte outputs are part of the unification contract.

---

## 8. Determinism contract

The contract: **same input bytes → same output bytes, on every architecture, today, tomorrow, a billion years from now**.

What guarantees it:

- All arithmetic is integer over fixed-width types (`u8`, `u16`, `u32`, `i8`, `i16` plus `i256::U256` for the smear_hash bookkeeping). No floating point anywhere in chaos_amp or spaghettify or smear_hash.
- All dep crates (`blake3`, `sha2`, `sha3`, `i256`) have wire formats specified at the bit level by their respective standards or by being pure-integer libraries. Output bytes cannot change between patch versions without breaking the standard.
- No `#[cfg(target_*)]` branches that affect output bytes.
- No allocation-order or thread-local state that affects output bytes.

What could break it:

- A minor-version bump of any dep that silently changes output bytes (extremely unlikely for the listed deps, but the Cargo.toml comment block enumerates the historical incident that motivated the lockdown).
- A change to chaos_amp.rs or smear.rs source that alters byte-affecting logic.
- A change to the NUMS seed strings (caught by `chaos_amp_round_consts_match_blake3`).

The test suite `tests/test_vectors.rs` catches any of these — 12 tests cover every public function on diverse inputs, and any byte mismatch fails loudly.

---

## 9. Cross-implementation porting

If you are porting ihi to C, JavaScript, Python, or a new FPGA platform, the canonical conformance check is: produce the exact byte outputs locked in `tests/test_vectors.rs` for every test input.

### 9.1 Required behaviors

Beyond the obvious "implement the spec":

- `u16::wrapping_shl(sh)` where `sh ∈ {0..15}` — pay attention to your language's behavior at `sh = 0` and large `sh`. Rust's `wrapping_shl(16)` does NOT wrap to `wrapping_shl(0)`; it returns 0. Verify your port matches.
- `i16::wrapping_neg()` and `i16::wrapping_abs()` — `i16::MIN.wrapping_neg() == i16::MIN`, similarly for `wrapping_abs`. Some languages panic on overflow; you must use explicit wrapping.
- `u16::reverse_bits()` — bit-reversal within a 16-bit word, NOT byte-reversal. The two are different.
- Signed comparison in op 16 (MIN), 17 (MAX), 21 (CSWAP) — must be signed, not unsigned. Mixing these breaks bit-exactness.
- BLAKE3 XOF: ensure your BLAKE3 implementation supports XOF output mode (not all do). The XOF stream for a given input is bit-stable across BLAKE3 versions by the spec.

### 9.2 Conformance checklist

- [ ] `chaos_amp([0u8; 64])` matches `chaos_amp_vectors` entry 0
- [ ] `chaos_amp([0xFFu8; 64])` matches entry 1
- [ ] `chaos_amp(blake3("alice") ‖ blake3("alice"))` matches entry 2
- [ ] `chaos_amp(blake3("photon") ‖ blake3("photon"))` matches entry 3
- [ ] ROUND_CONSTS re-derived from `blake3("PIPE chaos amp v2 - Dragonfly") ‖ blake3("PIPE chaos amp v2 - Dragonfly - more")` match the hardcoded values
- [ ] `spaghettify(b"")` matches `spaghettify_vectors` entry 0
- [ ] `spaghettify(b"alice")` matches the corresponding entry
- [ ] `smear_hash(b"")` matches `smear_hash_vectors` entry 0
- [ ] `handle_to_proof("alice")` matches `handle_to_proof_vectors` entry "alice" (takes ~1s)
- [ ] All 13 `handle_to_proof` vectors match (full ~13s suite)
- [ ] `handle_to_filename("alice") == "33IWCmI-FK8aFnSbfO955BlQXBllqtv9cRc0UqYX9YU.vsf"`

If any vector mismatches, your port has a determinism bug. Diagnose before shipping.

### 9.3 Common pitfalls

- Endianness on input absorption (LE for the chunk-to-u32 conversion)
- Sign-extension on `(val >> 16) as u8 as i8` — keep the unsigned intermediate before casting to signed
- The XOR-fold of the top byte into the bottom byte during absorption (easy to miss)
- The position constants `0x9E37_79B9` and `0x517C_C1B7` — golden ratio fractions, easy to mistype
- `rotate_left(5)` in Phase 2's `far` term is a 24-bit rotation (`(far << 5) | (far >> 19)` masked), NOT a u32 rotation

---

## 10. Performance

Approximate, not benchmarked rigorously. Order-of-magnitude only:

| operation | software (release, 2025 desktop) | silicon (chaos_amp_v2.v) |
|---|---|---|
| chaos_amp (single 64-byte block) | ~5-20 μs | 514 cycles ≈ 10 μs @ 50 MHz |
| spaghettify (single small input) | ~10-30 μs | n/a |
| smear_hash (single small input) | ~5-15 μs | n/a |
| handle_proof (single call) | **~1 second** (intentional, anti-squat) | n/a |

The handle_proof memory-hard PoW dominates anywhere it appears. spaghettify and chaos_amp are negligible in any pipeline that also touches handle_proof.

---

## 11. Version history

- **v0 (0.0.0 – 0.0.3, yanked + unpublish-requested)**: 53-bucket / 23-op / 11-23-data-dependent-rounds design. Used `spirix` ScalarF4E4 for chaos operations. Each published version pinned a different `spirix` minor version (0.0.8 → 0.0.11), causing a **bifurcated identity namespace**: the same handle resolved to different public IDs depending on which ihi version Cargo happened to resolve. Vectors from v0 are dead; no migration path exists.
- **v1 (0.0.42, current)**: chaos_amp-based design. Bit-exact with PIPE silicon. Zero floating-point dependencies. Zero transitive deps that can drift. Version number jumped from 0.0.3 to 0.0.42 to make the cryptographic discontinuity unmistakable.

The bifurcation incident is the entire reason `chaos_amp` exists as ihi's core mixing primitive. See the Cargo.toml comment block for the full historical note and the rules it imposes.

---

## 12. References

- [README.md](README.md) — elevator pitch + headline numbers
- [PROOF.md](PROOF.md) — path-explosion + information-loss proof walkthru
- [src/chaos_amp.rs](src/chaos_amp.rs) — implementation + module-level technical spec
- [src/spaghettify.rs](src/spaghettify.rs) — wrapper implementation
- [tests/test_vectors.rs](tests/test_vectors.rs) — byte-level conformance contract
- [examples/gen_test_vectors.rs](examples/gen_test_vectors.rs) — regenerate vectors when intentional algorithm changes happen
- [/mnt/Octopus/Code/pipe/rtl/chaos_amp_v2.v](../pipe/rtl/chaos_amp_v2.v) — silicon implementation (the other half of the bit-exact unification)
- [/mnt/Octopus/Code/pipe/PROTOCOL.md](../pipe/PROTOCOL.md) — PIPE protocol context for how chaos_amp is used downstream
