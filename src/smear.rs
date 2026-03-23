use sha2::{Digest, Sha512};
use sha3::Sha3_256;

/// Multi-algorithm hash smear for defense-in-depth.
///
/// XORs outputs from three fundamentally different hash constructions:
/// - BLAKE3: Merkle tree of ChaCha-based compression (modern, fast)
/// - SHA3-256: Keccak sponge construction (NIST standard, permutation-based)
/// - SHA-512: Merkle-Damgård with ARX rounds (battle-tested, truncated to 32 bytes)
///
/// If ANY algorithm survives cryptanalysis, the output remains secure.
/// An attacker must break ALL THREE simultaneously to compromise the result.
///
/// Not memory-hard - that's not the goal. The input is already high-entropy
/// from the avalanche mixing. This adds hash algorithm diversity.
pub fn smear_hash(data: &[u8]) -> [u8; 32] {
    // BLAKE3 - Merkle tree of ChaCha-based compression
    let blake3_out = *blake3::hash(data).as_bytes();

    // SHA3-256 - Keccak sponge (completely different construction)
    let mut sha3 = Sha3_256::new();
    sha3.update(data);
    let sha3_out: [u8; 32] = sha3.finalize().into();

    // SHA-512 truncated to 32 bytes - Merkle-Damgård ARX
    let mut sha512 = Sha512::new();
    sha512.update(data);
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
