use alloc::vec::Vec;
use i256::U256;

const SIZE: usize = 24_873_856; // 24MB - fits in L3 cache, prevents bulk parallelization
const CHUNK_SIZE: usize = 32; // BLAKE3 output size
const ROUNDS: usize = 17; // Tuned for ~1s on 2025 hardware

/// Proves computational work for handle registration.
///
/// Computes a deterministic proof-of-work for a given handle hash using memory-hard sequential processing. The same handle always produces the same public ID, enabling decentralized verification without coordination.
///
/// # Design Goals
///
/// - **Anti-squatting**: ~1 second per handle makes bulk registration expensive
/// - **Rate limiting**: Sequential rounds prevent parallelization across handles
/// - **ASIC resistance**: Data-dependent reads and variable memory usage resist hardware optimization
/// - **Deterministic**: Same handle → same ID (no salt, no randomization)
/// - **Verifiable**: Anyone can recompute to verify claimed handle ownership
///
/// # Algorithm
///
/// Each of 17 rounds consists of:
///
/// 0. **Variable fill determination**: Hash determines buffer fill (25-75% of 24MB)
/// 1. **Sequential hash chain**: Each chunk depends on previous chunk (non-seekable)
/// 2. **Data-dependent reads**: Random reads from earlier chunks (cache-hostile)
/// 3. **State advancement**: Round output becomes input to next round
///
/// # Security Properties
///
/// - **Memory-hard**: 24MB scratch buffer makes bulk parallelization expensive
/// - **Time-hard**: 17 sequential rounds, each feeding into the next
/// - **Unpredictable work**: Variable fill (25-75%) prevents precomputation attacks
/// - **Cache-hostile**: Data-dependent reads prevent efficient caching/ASICs
/// - **Forward secrecy**: Breaking round N doesn't reveal earlier rounds
///
/// # Performance
///
/// Tuned for approximately one second on 2025 desktop CPUs. Hardware improvements will reduce wall time but maintain economic cost (electricity, opportunity cost of CPU time).
///
/// # Arguments
///
/// * `hash` - BLAKE3 hash of the plaintext handle
///
/// # Returns
///
/// Final BLAKE3 hash after 17 rounds - this becomes the public ID (32 bytes)
///
/// # Examples
///
/// ```rust,no_run
/// use ihi::handle_to_proof; let public_id = handle_to_proof("fractal decoder");
/// ```
///
/// For callers that need to manage the BLAKE3 pre-hash themselves, this lower-level entry point accepts the hash directly. The canonical pipeline for a plaintext handle is [`handle_to_proof`].
pub fn handle_proof(hash: &blake3::Hash) -> blake3::Hash {
    // Allocate scratch buffer without initialization (for performance)
    let mut scratch = Vec::with_capacity(SIZE);
    // SAFETY: Buffer is completely filled by Phase 1 and Phase 2 before the final hash. Phase 1 fills [0..fill_size], Phase 2 fills [fill_size..SIZE]. SIZE is exactly divisible by CHUNK_SIZE (24_873_856 / 32 = 777_308).
    unsafe {
        scratch.set_len(SIZE);
    }

    let mut round_hash = *hash;

    for round in 0..ROUNDS {
        // Mix round number into hash to prevent cross-round collisions
        let hash_num =
            U256::from_be_bytes(*round_hash.as_bytes()).wrapping_add(U256::from(round as u128));

        // Phase 0: Determine fill size (25-75% of buffer), aligned to CHUNK_SIZE Alignment ensures Phase 1 fills exactly up to where Phase 2 starts (no gaps)
        let min_fill = SIZE / 4;
        let max_fill = SIZE * 3 / 4;
        let fill_range = max_fill - min_fill;
        let fill_size_raw =
            min_fill + ((hash_num % U256::from(fill_range as u128)).as_u128() as usize);
        let fill_size = (fill_size_raw / CHUNK_SIZE) * CHUNK_SIZE; // Align down to 32-byte boundary

        // Phase 1: Sequential hash chain (memory-hard, non-seekable) Each chunk must be computed in order - no parallelization or seeking possible
        scratch[..CHUNK_SIZE].copy_from_slice(round_hash.as_bytes());

        for i in 1..(fill_size / CHUNK_SIZE) {
            let prev_start = (i - 1) * CHUNK_SIZE;
            let curr_start = i * CHUNK_SIZE;

            // Hash previous chunk
            let prev_hash = blake3::hash(&scratch[prev_start..prev_start + CHUNK_SIZE]);

            // Mix with round hash and position to ensure uniqueness
            let hash_num_out = U256::from_be_bytes(*prev_hash.as_bytes())
                .wrapping_add(hash_num)
                .wrapping_add(U256::from(i as u128));

            scratch[curr_start..curr_start + CHUNK_SIZE]
                .copy_from_slice(&hash_num_out.to_be_bytes());
        }

        // Phase 2: Data-dependent random reads (cache-hostile, ASIC-resistant) Read location depends on previous hash value - unpredictable memory access pattern
        let mut curr_start = fill_size;

        while curr_start + CHUNK_SIZE <= SIZE {
            // Previous chunk determines where we read from
            let prev_hash_num = U256::from_be_bytes(
                scratch[curr_start - CHUNK_SIZE..curr_start]
                    .try_into()
                    .unwrap(),
            );

            // Random read from earlier in buffer
            let read_idx =
                (prev_hash_num % U256::from((curr_start - CHUNK_SIZE) as u128)).as_u128() as usize;

            // Hash the randomly-selected chunk
            let prev_hash = blake3::hash(&scratch[read_idx..read_idx + CHUNK_SIZE]);

            // Mix with round hash and position
            let new_val = U256::from_be_bytes(*prev_hash.as_bytes())
                .wrapping_add(hash_num)
                .wrapping_add(U256::from(curr_start as u128));

            scratch[curr_start..curr_start + CHUNK_SIZE].copy_from_slice(&new_val.to_be_bytes());
            curr_start += CHUNK_SIZE;
        }

        // Advance to next round: output of this round becomes input to next Forces sequential processing of all 17 rounds
        round_hash = blake3::hash(&scratch);
    }

    // Final hash is the public ID - deterministic, verifiable, expensive to compute
    round_hash
}

/// Canonical handle hash — `BLAKE3(VsfType::x(handle).flatten())`. The exposed intermediate state on the way to [`handle_to_proof`], usable as a deterministic 32-byte derivation seed wherever a handle string needs to map to fixed bytes.
///
/// Pipeline position: this is the FIRST half of [`handle_to_proof`]'s computation. The second half is the memory-hard PoW. Calling this directly gives consumers the cheap pre-hash (no PoW; sub-microsecond) for use cases that don't need the anti-squatting cost — e.g. local-only contact-table keys, avatar Ed25519 keypair seeds, message-encryption sub-key derivation.
///
/// The handle string is wrapped in `VsfType::x` and flattened to its canonical binary representation before hashing. This ensures deterministic Unicode handling — the same logical text always produces the same bytes regardless of normalization form, preventing café/café-class identity splits.
pub fn handle_to_hash(handle: &str) -> blake3::Hash {
    use alloc::string::ToString;
    use vsf::types::VsfType;
    let vsf_bytes = VsfType::x(handle.to_string()).flatten();
    blake3::hash(&vsf_bytes)
}

/// Compute the deterministic public ID for a plaintext handle string.
///
/// Pipeline: [`handle_to_hash`] → [`handle_proof`]. The handle is wrapped in `VsfType::x` and flattened to canonical binary form before BLAKE3 hashing, ensuring deterministic Unicode handling. The resulting hash is then fed through the memory-hard PoW.
///
/// Returns the 32-byte proof. Use [`proof_to_filename`] to convert to a base64url filename for capsule storage.
///
/// This is the canonical entry point — every component in the stack (photon, vsf::handle, toka, fgtw) should call this rather than rolling its own pre-hash step.
pub fn handle_to_proof(handle: &str) -> blake3::Hash {
    handle_proof(&handle_to_hash(handle))
}

/// Encode a handle proof as a base64url filename with `.vsf` extension.
///
/// Uses the RFC 4648 base64url alphabet (A-Z, a-z, 0-9, `-`, `_`) for filesystem and URL safety; no padding (the proof is exactly 32 bytes → 43 base64url chars, no ambiguity). Suffixed with `.vsf` so the filename is self-describing as a VSF capsule.
pub fn proof_to_filename(proof: &blake3::Hash) -> alloc::string::String {
    use alloc::string::String;
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let bytes = proof.as_bytes();
    let mut encoded = String::with_capacity(47); // 43 base64url chars + ".vsf"
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let chunk = (bytes[i] as u32) << 16 | (bytes[i + 1] as u32) << 8 | (bytes[i + 2] as u32);
        encoded.push(ALPHABET[(chunk >> 18) as usize & 0x3F] as char);
        encoded.push(ALPHABET[(chunk >> 12) as usize & 0x3F] as char);
        encoded.push(ALPHABET[(chunk >> 6) as usize & 0x3F] as char);
        encoded.push(ALPHABET[chunk as usize & 0x3F] as char);
        i += 3;
    }
    if i < bytes.len() {
        let rem = bytes.len() - i;
        let mut chunk = (bytes[i] as u32) << 16;
        if rem == 2 {
            chunk |= (bytes[i + 1] as u32) << 8;
        }
        encoded.push(ALPHABET[(chunk >> 18) as usize & 0x3F] as char);
        encoded.push(ALPHABET[(chunk >> 12) as usize & 0x3F] as char);
        if rem == 2 {
            encoded.push(ALPHABET[(chunk >> 6) as usize & 0x3F] as char);
        }
    }
    encoded.push_str(".vsf");
    encoded
}

/// Convenience shortcut: handle string → base64url `.vsf` filename. Equivalent to `proof_to_filename(&handle_to_proof(handle))`. Runs the ~1s memory-hard proof; reuse the [`blake3::Hash`] from [`handle_to_proof`] across multiple filename derivations rather than calling this in a loop.
pub fn handle_to_filename(handle: &str) -> alloc::string::String {
    proof_to_filename(&handle_to_proof(handle))
}
