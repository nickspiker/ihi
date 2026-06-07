use crate::chaos_amp::chaos_amp;
use crate::smear::smear_hash_parts;

/// Spaghettify — arbitrary-length input → 32-byte mixed output.
///
/// Thin wrapper over [`chaos_amp`] that absorbs arbitrary input length and finalizes with defense-in-depth multi-hash mixing. The mixing core ([`chaos_amp`]) is bit-exact with PIPE's silicon Verilog ([`/mnt/Octopus/Code/pipe/rtl/chaos_amp_v2.v`]); the wrapper structure is pure software.
///
/// # Pipeline
///
/// 1. **BLAKE3 XOF absorb**: `blake3_xof(input)` → 64 bytes. Any input length compresses deterministically to the 64-byte block `chaos_amp` consumes. BLAKE3's extendable-output mode is bit-stable across versions and platforms.
/// 2. **chaos_amp**: 64 bytes → 48 bytes through 16 buckets × 16 rounds of the 32-op data-dependent ALU. See [`crate::chaos_amp`] for the path-entropy argument (~10^482 paths) and the lossy-op information-destruction bound.
/// 3. **Defense-in-depth finalize**: `smear_hash(chaos_state || original_input)` → 32 bytes. XORs BLAKE3 ⊕ SHA3-256 ⊕ SHA-512; the original input bytes are re-mixed in so the output remains cryptographically strong even if the chaos layer has unknown weaknesses. Output is secure if ANY one of {chaos_amp, BLAKE3, SHA3-256, SHA-512} survives cryptanalysis.
///
/// # Irreversibility
///
/// Given output O, finding input I such that `spaghettify(I) = O` requires either:
///
/// - Inverting `smear_hash` over (chaos_state || input) — must simultaneously invert BLAKE3, SHA3-256, AND SHA-512, OR
/// - Inverting BLAKE3-XOF AND navigating ~10^482 op-selection paths through `chaos_amp`
///
/// For comparison: ~10^80 atoms in the observable universe. The function is preimage-resistant by construction; collisions exist by the pigeonhole principle (the lossy ops destroy ~700-2500 cumulative bits per call) but cannot be navigated to.
///
/// # Determinism
///
/// Zero floating point. Zero transitive deps that introduce platform-dependent behavior. Same input bytes → same output bytes, on every architecture, forever. This is the entire reason ihi exists.
pub fn spaghettify(input: &[u8]) -> [u8; 32] {
    // Phase 1: BLAKE3 XOF absorbs arbitrary-length input into a fixed 64-byte block. XOF mode is bit-stable across BLAKE3 versions and gives deterministic 64-byte output for any input length.
    let mut block = [0u8; 64];
    let mut hasher = blake3::Hasher::new();
    hasher.update(input);
    hasher.finalize_xof().fill(&mut block);

    // Phase 2: Run the canonical chaos mixing primitive — bit-exact with PIPE silicon.
    let chaos_state = chaos_amp(&block);

    // Phase 3: Defense-in-depth finalize. smear_hash over (chaos_state || input) means the output is secure if EITHER the chaos layer OR the multi-hash layer survives attack — the original input bytes flow into the multi-hash directly, so a complete break of chaos_amp still leaves a 3-way-XOR of cryptographic hashes.
    smear_hash_parts(&[&chaos_state, input])
}
