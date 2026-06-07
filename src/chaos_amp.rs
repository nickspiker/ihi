//! Chaos amplifier — the core mixing primitive shared between ihi (software) and PIPE (silicon).
//!
//! Pure integer math, zero floating point, zero transitive deps that can drift. The bit-level contract is defined here in software and mirrored bit-exactly in [`/mnt/Octopus/Code/pipe/rtl/chaos_amp_v2.v`](Verilog). Any change here changes silicon; any change in silicon changes here; the two are one design split across two implementations.
//!
//! # State layout
//!
//! 16 buckets × 24 bits each, packed into a `u32` with the top 8 bits forced to zero. Total state = 384 bits. The 24-bit width is partitioned into a 16-bit "fraction" half (low 16) and an 8-bit "exponent" half (high 8) — this F16E8 naming inherits from PIPE's silicon convention, NOT from any floating-point library. The two halves are simply two parallel integer lanes; the ALU treats them as separate i16/i8 (signed) or u16/u8 (unsigned) per op.
//!
//! Input absorption (64 bytes → 16 × 24-bit buckets): each bucket consumes 4 input bytes interpreted as little-endian u32; the top byte XOR-folds into the bottom byte before truncation to 24 bits, so every one of the 512 input bits affects the initial state.
//!
//! Output extraction: each bucket's low 24 bits → 3 bytes little-endian, total 48 bytes. The wrapper that built this (`spaghettify`) finalizes with [`crate::smear_hash_parts`].
//!
//! # Round structure (16 rounds × 2 phases)
//!
//! Snap-based parallel update — every bucket reads from a pre-round snapshot, so all 16 bucket updates within a phase are independent (required for combinational FPGA implementation):
//!
//! ```text
//! snap = state.clone()
//!
//! // Phase 1 — data-dependent op selection
//! for i in 0..16:
//!     val       = snap[i]
//!     op_idx    = val[4:0]                        // 5 bits → 32-op menu
//!     secondary = snap[(i + 11) & 15]
//!     tmp[i]    = op_apply(op_idx, val, secondary) ^ ROUND_CONST[round] ^ pos_const(i, round)
//!
//! // Phase 2 — ARX cross-bucket diffusion
//! for i in 0..16:
//!     near       = tmp[(i + 1) & 15]
//!     far_rot    = rotate_left(tmp[(i + 7) & 15], 5)
//!     state[i]   = (tmp[i] + near + far_rot) & BUCKET_MASK   // 24-bit wrap
//! ```
//!
//! Phase 1 contributes data-dependent path entropy (which op fires depends on the bucket value itself). Phase 2 contributes guaranteed cross-bucket diffusion — every bucket sees changes from positions {i, i+1, i+7, i+11} per round, so a single-bit input flip reaches all 16 buckets within ~5 rounds. We run 16 rounds for margin.
//!
//! # Op menu (32 ops: 16 arithmetic-style + 16 chaos-specific)
//!
//! Selected by `val[4:0]`. Every op is binary in `(val, secondary)` — required so each bucket update mixes information from a neighbour. Lossy ops destroy bits irrecoverably; "extreme lossy" ops compress 16-24 bits to ≤8 distinct outputs.
//!
//! | idx | name        | description                                     | lossy?         |
//! |-----|-------------|-------------------------------------------------|----------------|
//! | 0   | ADD         | wrapping i16 + i16, i8 + i8                     | no             |
//! | 1   | SUB         | wrapping subtract                                | no             |
//! | 2   | MUL_LO      | wrapping multiply (low half)                     | no             |
//! | 3   | AND         | bitwise AND                                      | YES            |
//! | 4   | OR          | bitwise OR                                       | YES            |
//! | 5   | XOR         | bitwise XOR                                      | no             |
//! | 6   | ANDN        | `a & ~b`                                         | YES            |
//! | 7   | NOT         | `~a ^ b`                                         | no             |
//! | 8   | SHL         | left shift by secondary low 4 bits               | YES            |
//! | 9   | SHR         | right shift by secondary low 4 bits              | YES            |
//! | 10  | ROL_B       | rotate left by secondary low 4                   | no             |
//! | 11  | ROR_B       | rotate right by secondary low 4                  | no             |
//! | 12  | ROL_S       | rotate left by self low 4 (high path entropy)    | no             |
//! | 13  | NEG         | two's complement negate, XOR secondary           | no             |
//! | 14  | ABS         | wrapping absolute value                          | YES            |
//! | 15  | BSWAP       | byte-swap fraction                               | no             |
//! | 16  | MIN         | signed min(a, b)                                 | YES            |
//! | 17  | MAX         | signed max(a, b)                                 | YES            |
//! | 18  | POPCNT      | low byte ← popcount(val^sec); top byte preserved | YES (8b)       |
//! | 19  | SAT_ADD     | saturating add (clamp at MAX/MIN)                | YES            |
//! | 20  | SAT_SUB     | saturating subtract                              | YES            |
//! | 21  | CSWAP       | branch on `frac_a < frac_b` — two distinct paths | branch entropy |
//! | 22  | GFMUL       | GF(2⁸) multiply on low byte (AES polynomial)     | no (algebraic) |
//! | 23  | PARITY      | XOR-fold val to 1 bit, paint across all 24 bits  | EXTREME (23b)  |
//! | 24  | BREV        | bit-reverse fraction                             | no             |
//! | 25  | NREV        | nibble-reverse within bytes                      | no             |
//! | 26  | AVG         | rounded average of (a, b)                        | YES            |
//! | 27  | LFSR_TICK   | Galois LFSR step (taps 0xB400)                   | no             |
//! | 28  | EXPAND_LO   | replicate low byte across word                   | YES (8b)       |
//! | 29  | SQUEEZE     | XOR all bytes → 1 byte, paint across             | EXTREME (16b)  |
//! | 30  | ZIP         | bit-interleave low bytes of (val, secondary)     | no             |
//! | 31  | PCNT_REPLACE| bytes ← popcounts of val/secondary/exp parts     | EXTREME (16b)  |
//!
//! # Path-entropy counting
//!
//! - **Op selection** dominates: 5 bits × 16 buckets × 16 rounds = **1280 bits ≈ 10³⁸⁵** distinct op-sequences
//! - **Shift/rotate amounts** (in ~10 of 32 ops): 4 extra bits × ~30% incidence × 256 op-applications ≈ **300 bits**
//! - **Branch entropy** (CSWAP): 1 bit × ~3% incidence × 256 op-applications ≈ **8 bits** (small but real)
//! - **Combined**: ~**1600 bits ≈ 10⁴⁸²** total paths through one chaos_amp evaluation
//!
//! For comparison: ~10⁸⁰ atoms in the observable universe. Even the op-selection minimum (10³⁸⁵) exceeds that by 10³⁰⁵.
//!
//! # Information loss
//!
//! 11 lossy ops + 3 extreme-lossy ops in the 32-op menu = ~44% chance per op-application of irreversible bit destruction. Over 256 op-applications per chaos_amp call, ~110 lossy applications expected, each destroying 4-23 bits = **~700-2500 cumulative bits destroyed** (a bound — many re-destroy already-destroyed bits). The function is preimage-resistant by construction; collisions exist by the pigeonhole principle but are infeasible to navigate to.
//!
//! # Round constants — NUMS provenance
//!
//! `ROUND_CONSTS` are the first 16 little-endian u32 of `blake3("PIPE chaos amp v2 - Dragonfly") || blake3("PIPE chaos amp v2 - Dragonfly - more")`. The seed strings are intentionally self-descriptive — anyone re-deriving from BLAKE3 can verify by inspection that no magic numbers were planted. The constants are stored hardcoded for `no_std` compatibility (BLAKE3 itself can't run at `const` time); `tests/test_vectors.rs::chaos_amp_round_consts_match_blake3` verifies the hardcoded values match their BLAKE3 derivation on every test run.
//!
//! The "PIPE" prefix in the seed strings reflects that PIPE silicon was where this primitive was first specified. ihi now hosts the canonical software side; the seed strings stay verbatim to preserve bit-exactness with existing PIPE silicon. Renaming the strings would silently change every output byte.

const BUCKETS: usize = 16;
const ROUNDS: usize = 16;

/// 384-bit chaos state — 16 × 24-bit buckets, top 8 bits of each u32 are zero by invariant.
pub type ChaosState = [u32; BUCKETS];

/// Mask for 24 valid bits per bucket: 16-bit fraction (low) + 8-bit exponent (high). Top byte of each u32 is forced 0 after every update.
const BUCKET_MASK: u32 = 0x00FF_FFFF;

/// Round constants — first 8 u32 LE from `blake3("PIPE chaos amp v2 - Dragonfly")`, next 8 from `blake3("PIPE chaos amp v2 - Dragonfly - more")`. Verified by `chaos_amp_round_consts_match_blake3` in tests/test_vectors.rs.
const ROUND_CONSTS: [u32; ROUNDS] = [
    0x6344f5d9, 0x9a9b6f24, 0xac41a271, 0xc373c1f2, 0x261b7279, 0x6f4d3ec7, 0x23f83617, 0x1816c525,
    0x1fa89706, 0xb8278130, 0x12c98cb4, 0x755dd5a8, 0x5b4b9635, 0x3f76d80f, 0x033b166b, 0xcd721263,
];

/// Position-dependent constant — `(i * 0x9E37_79B9) ^ (round_idx * 0x517C_C1B7)` masked to 24 bits. The golden-ratio multiplier keeps neighbouring (i, round) pairs distinct without table lookups. Cheap on silicon (yosys reduces multiply-by-constant to a shift+add chain).
#[inline]
fn pos_const(i: usize, round_idx: usize) -> u32 {
    ((i as u32).wrapping_mul(0x9E37_79B9) ^ (round_idx as u32).wrapping_mul(0x517C_C1B7))
        & BUCKET_MASK
}

/// AES-irreducible-polynomial GF(2^8) multiply — backs op 22 (GFMUL). 8 conditional XORs on FPGA fabric; same loop in software.
#[inline]
fn gf_mul(a: u8, b: u8) -> u8 {
    let mut p: u8 = 0;
    let mut a = a;
    let mut b = b;
    for _ in 0..8 {
        if (b & 1) != 0 {
            p ^= a;
        }
        let hi = (a & 0x80) != 0;
        a <<= 1;
        if hi {
            a ^= 0x1B;
        }
        b >>= 1;
    }
    p
}

/// 32-op ALU. Every op is binary in `(val, secondary)`; output is masked to 24 bits. Bit-exact with [`chaos_amp_v2.v::op_apply`] — the case/match arms are in 1:1 correspondence with the Verilog `case (op_idx)`. Any change here demands the matching change in silicon (and vice versa).
#[inline]
fn op_apply(op_idx: u8, val: u32, secondary: u32) -> u32 {
    let frac_a = val as i16;
    let frac_b = secondary as i16;
    let ufa = frac_a as u16;
    let ufb = frac_b as u16;
    let exp_a = ((val >> 16) as u8) as i8;
    let exp_b = ((secondary >> 16) as u8) as i8;
    let uea = exp_a as u8;
    let ueb = exp_b as u8;
    let sh = (secondary as u32) & 15;
    let sh_self = (val as u32) & 15;

    let (new_frac, new_exp): (i16, i8) = match op_idx & 0x1F {
        0 => (frac_a.wrapping_add(frac_b), exp_a.wrapping_add(exp_b)),
        1 => (frac_a.wrapping_sub(frac_b), exp_a.wrapping_sub(exp_b)),
        2 => (frac_a.wrapping_mul(frac_b), exp_a.wrapping_mul(exp_b)),
        3 => (frac_a & frac_b, exp_a & exp_b),
        4 => (frac_a | frac_b, exp_a | exp_b),
        5 => (frac_a ^ frac_b, exp_a ^ exp_b),
        6 => ((ufa & !ufb) as i16, (uea & !ueb) as i8),
        7 => ((!ufa) as i16 ^ frac_b, (!uea) as i8 ^ exp_b),
        8 => (ufa.wrapping_shl(sh) as i16 ^ frac_b, exp_a ^ exp_b),
        9 => (ufa.wrapping_shr(sh) as i16 ^ frac_b, exp_a ^ exp_b),
        10 => (ufa.rotate_left(sh) as i16 ^ frac_b, exp_a ^ exp_b),
        11 => (ufa.rotate_right(sh) as i16 ^ frac_b, exp_a ^ exp_b),
        12 => (ufa.rotate_left(sh_self) as i16 ^ frac_b, exp_a ^ exp_b),
        13 => (frac_a.wrapping_neg() ^ frac_b, exp_a.wrapping_neg() ^ exp_b),
        14 => (
            frac_a.wrapping_abs().wrapping_add(frac_b),
            exp_a.wrapping_abs().wrapping_add(exp_b),
        ),
        15 => ((ufa.swap_bytes() as i16) ^ frac_b, exp_a ^ exp_b),

        16 => (frac_a.min(frac_b), exp_a.min(exp_b)),
        17 => (frac_a.max(frac_b), exp_a.max(exp_b)),
        18 => {
            let xor = ufa ^ ufb;
            let pc = xor.count_ones() as u8;
            let preserved = ((ufa >> 8) ^ (ufb >> 8)) as u8;
            (
                (((preserved as u16) << 8) | (pc as u16)) as i16,
                (uea ^ ueb) as i8,
            )
        }
        19 => (frac_a.saturating_add(frac_b), exp_a.saturating_add(exp_b)),
        20 => (frac_a.saturating_sub(frac_b), exp_a.saturating_sub(exp_b)),
        21 => {
            if frac_a < frac_b {
                (ufb.rotate_left(8) as i16 ^ frac_a, exp_b ^ exp_a)
            } else {
                (frac_a ^ frac_b, exp_a ^ exp_b)
            }
        }
        22 => {
            let lo = gf_mul(ufa as u8, ufb as u8);
            (
                (((ufa & 0xFF00) | lo as u16) as i16) ^ frac_b,
                (uea ^ ueb) as i8,
            )
        }
        23 => {
            let p = (ufa.count_ones() as u32 + uea.count_ones()) & 1;
            let p_paint16: u16 = if p == 1 { 0xFFFF } else { 0x0000 };
            let p_paint8: u8 = if p == 1 { 0xFF } else { 0x00 };
            ((p_paint16 ^ ufb) as i16, (p_paint8 ^ ueb) as i8)
        }
        24 => (ufa.reverse_bits() as i16 ^ frac_b, exp_a ^ exp_b),
        25 => {
            let lo = ((ufa & 0x000F) << 4) | ((ufa & 0x00F0) >> 4);
            let hi = ((ufa & 0x0F00) << 4) | ((ufa & 0xF000) >> 4);
            (((lo | hi) as i16) ^ frac_b, exp_a ^ exp_b)
        }
        26 => {
            let avg_frac = (((frac_a as i32) + (frac_b as i32) + 1) >> 1) as i16;
            let avg_exp = (((exp_a as i16) + (exp_b as i16) + 1) >> 1) as i8;
            (avg_frac, avg_exp)
        }
        27 => {
            let lsb = ufa & 1;
            let stepped = (ufa >> 1) ^ (if lsb == 1 { 0xB400u16 } else { 0u16 });
            (stepped as i16 ^ frac_b, exp_a ^ exp_b)
        }
        28 => {
            let lo = (ufa & 0xFF) as u8;
            let exp = (((lo as u16) << 8) | (lo as u16)) as i16;
            (exp ^ frac_b, exp_a ^ exp_b)
        }
        29 => {
            let x = ufa ^ ufb;
            let s = ((x & 0xFF) as u8) ^ ((x >> 8) as u8) ^ uea ^ ueb;
            ((((s as u16) << 8) | (s as u16)) as i16, s as i8)
        }
        30 => {
            let alo = (ufa & 0xFF) as u8;
            let blo = (ufb & 0xFF) as u8;
            let mut z: u16 = 0;
            for i in 0..8u32 {
                z |= (((alo >> i) & 1) as u16) << (2 * i);
                z |= (((blo >> i) & 1) as u16) << (2 * i + 1);
            }
            (z as i16, exp_a ^ exp_b)
        }
        31 => {
            let pa = ufa.count_ones() as u8;
            let pb = ufb.count_ones() as u8;
            let pe = ((uea as u16) + (ueb as u16)).count_ones() as u8;
            ((((pb as u16) << 8) | pa as u16) as i16, pe as i8)
        }
        _ => unreachable!(),
    };

    ((new_frac as u16) as u32) | (((new_exp as u8) as u32) << 16)
}

/// One round: data-dependent op-select (Phase 1) followed by ARX cross-bucket diffusion (Phase 2). See module-level docs for the snap-based parallel update rationale.
#[inline]
fn round(state: &mut ChaosState, round_idx: usize) {
    let snap = *state;
    let rc = ROUND_CONSTS[round_idx];

    let mut tmp = [0u32; BUCKETS];
    for i in 0..BUCKETS {
        let val = snap[i];
        let op_idx = (val & 0x1F) as u8;
        let secondary = snap[(i + 11) & (BUCKETS - 1)];
        let result = op_apply(op_idx, val, secondary);
        tmp[i] = (result ^ rc ^ pos_const(i, round_idx)) & BUCKET_MASK;
    }

    for i in 0..BUCKETS {
        let near = tmp[(i + 1) & (BUCKETS - 1)];
        let far = tmp[(i + 7) & (BUCKETS - 1)];
        let far_rot = ((far << 5) | (far >> (24 - 5))) & BUCKET_MASK;
        let mixed = tmp[i].wrapping_add(near).wrapping_add(far_rot);
        state[i] = mixed & BUCKET_MASK;
    }
}

/// Absorb a 64-byte block into the 16-bucket state. Each bucket consumes 4 input bytes interpreted as little-endian u32; the top byte XOR-folds into the bottom byte before truncation to 24 bits, so every one of the 512 input bits affects initial state. Bit-exact with `chaos_amp_v2.v::S_LOAD`.
fn absorb_input(input: &[u8; 64]) -> ChaosState {
    let mut state = [0u32; BUCKETS];
    for i in 0..BUCKETS {
        let chunk = u32::from_le_bytes([
            input[i * 4],
            input[i * 4 + 1],
            input[i * 4 + 2],
            input[i * 4 + 3],
        ]);
        let folded = chunk ^ ((chunk >> 24) & 0xFF);
        state[i] = folded & BUCKET_MASK;
    }
    state
}

/// Serialize the 16-bucket state to 48 raw bytes (3 bytes per bucket, little-endian). The top byte of each u32 is always zero by `BUCKET_MASK` invariant.
fn state_to_bytes(state: &ChaosState) -> [u8; 48] {
    let mut out = [0u8; 48];
    for i in 0..BUCKETS {
        out[i * 3] = state[i] as u8;
        out[i * 3 + 1] = (state[i] >> 8) as u8;
        out[i * 3 + 2] = (state[i] >> 16) as u8;
    }
    out
}

/// Run the full chaos amplifier over a 64-byte input and return 48 bytes of mixed state.
///
/// This is the canonical mixing primitive — bit-exact with [`/mnt/Octopus/Code/pipe/rtl/chaos_amp_v2.v`](PIPE silicon). For arbitrary-length input, see [`crate::spaghettify`] which wraps this with BLAKE3-XOF absorption and a defense-in-depth output finalizer.
///
/// # Determinism
///
/// Pure integer math. Zero floating-point. No transitive dependency that could drift between versions. Same 64 input bytes → same 48 output bytes, today, tomorrow, on every architecture, forever.
pub fn chaos_amp(input: &[u8; 64]) -> [u8; 48] {
    let mut state = absorb_input(input);
    for r in 0..ROUNDS {
        round(&mut state, r);
    }
    state_to_bytes(&state)
}

/// Verify the hardcoded ROUND_CONSTS match their BLAKE3 derivation. Exposed for use by `tests/test_vectors.rs::chaos_amp_round_consts_match_blake3`.
#[doc(hidden)]
pub fn _round_consts_for_test() -> [u32; ROUNDS] {
    ROUND_CONSTS
}
