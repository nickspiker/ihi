use sha2::{Digest as Sha2Digest, Sha512};
use sha3::{Digest as Sha3Digest, Sha3_256};

/// Multi-algorithm hash smear for defense-in-depth.
///
/// XORs outputs from three fundamentally different hash constructions:
/// - BLAKE3: Merkle tree of ChaCha-based compression (modern, fast)
/// - SHA3-256: Keccak sponge construction (NIST standard, permutation-based)
/// - SHA-512: Merkle-Damgård with ARX rounds (battle-tested, truncated to 32 bytes)
///
/// If ANY algorithm survives cryptanalysis, the output remains secure. An attacker must break ALL THREE simultaneously to compromise the result.
///
/// Not memory-hard — that's not the goal. The input is already high-entropy from the avalanche mixing; this adds hash algorithm diversity.
pub fn smear_hash(data: &[u8]) -> [u8; 32] {
    smear_hash_parts(&[data])
}

/// Smear hash over multiple slices fed sequentially — no allocation needed. Identical output to `smear_hash(&[a, b, ...].concat())`.
pub fn smear_hash_parts(parts: &[&[u8]]) -> [u8; 32] {
    // BLAKE3 - Merkle tree of ChaCha-based compression
    let mut b3 = blake3::Hasher::new();
    for p in parts { b3.update(p); }
    let blake3_out = *b3.finalize().as_bytes();

    // SHA3-256 - Keccak sponge (completely different construction)
    let mut sha3 = Sha3_256::new();
    for p in parts { Sha3Digest::update(&mut sha3, p); }
    let sha3_out: [u8; 32] = sha3.finalize().into();

    // SHA-512 truncated to 32 bytes - Merkle-Damgård ARX
    let mut sha512 = Sha512::new();
    for p in parts { Sha2Digest::update(&mut sha512, p); }
    let sha512_full: [u8; 64] = sha512.finalize().into();
    let mut sha512_out = [0u8; 32];
    sha512_out.copy_from_slice(&sha512_full[..32]);

    // XOR all three - output is secure if ANY one survives
    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = blake3_out[i] ^ sha3_out[i] ^ sha512_out[i];
    }
    result
}
