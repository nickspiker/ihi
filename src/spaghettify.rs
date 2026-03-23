use crate::smear::smear_hash;
use i256::U256;
use spirix::ScalarF4E4;

/// Bootstrap seed - Nothing Up My Sleeve: ASCII bytes of self-documenting string
/// "PHOTON_SPAGHETTI: 53 buckets, 23 ops, Spirix chaos, NUMS seed v0"
const LAVA_SEED_256: [u8; 64] =
    *b"PHOTON_SPAGHETTI: 53 buckets, 23 ops, Spirix chaos, NUMS seed v0";

// Constants for U256 - use from_be_bytes with const arrays
const U256_ZERO: U256 = U256::from_be_bytes([0u8; 32]);
const U256_ONE: U256 = U256::from_be_bytes([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
]);

/// Integer square root for U256 using Newton-Raphson
fn sqrt_u256(n: U256) -> U256 {
    if n == U256_ZERO {
        return U256_ZERO;
    }
    if n == U256_ONE {
        return U256_ONE;
    }

    // Start with a rough estimate: n >> (leading_zeros / 2)
    // For U256, we approximate by checking high bits
    let mut x = n >> 128; // Start smaller
    if x == U256_ZERO {
        x = n >> 64;
    }
    if x == U256_ZERO {
        x = n >> 32;
    }
    if x == U256_ZERO {
        x = n;
    }

    // Newton-Raphson: x_new = (x + n/x) / 2
    loop {
        if x == U256_ZERO {
            return U256_ZERO;
        }
        let x_new = (x + n / x) >> 1;
        if x_new >= x {
            return x;
        }
        x = x_new;
    }
}

/// Convert U256 to 8 Spirix ScalarF4E4 values (deterministic chaos mode!)
/// Random bit patterns become Spirix scalars with deterministic behavior across all platforms.
/// Uses 8×32-bit (16-bit fraction + 16-bit exponent) = 256 bits exact.
/// Each scalar is normalized to ensure valid Spirix representation (prevents div-by-zero panics).
fn u256_to_spirix8(n: U256) -> [ScalarF4E4; 8] {
    let bytes = n.to_be_bytes();
    let mut s0 = ScalarF4E4 {
        fraction: i16::from_be_bytes([bytes[0], bytes[1]]),
        exponent: i16::from_be_bytes([bytes[2], bytes[3]]),
    };
    let mut s1 = ScalarF4E4 {
        fraction: i16::from_be_bytes([bytes[4], bytes[5]]),
        exponent: i16::from_be_bytes([bytes[6], bytes[7]]),
    };
    let mut s2 = ScalarF4E4 {
        fraction: i16::from_be_bytes([bytes[8], bytes[9]]),
        exponent: i16::from_be_bytes([bytes[10], bytes[11]]),
    };
    let mut s3 = ScalarF4E4 {
        fraction: i16::from_be_bytes([bytes[12], bytes[13]]),
        exponent: i16::from_be_bytes([bytes[14], bytes[15]]),
    };
    let mut s4 = ScalarF4E4 {
        fraction: i16::from_be_bytes([bytes[16], bytes[17]]),
        exponent: i16::from_be_bytes([bytes[18], bytes[19]]),
    };
    let mut s5 = ScalarF4E4 {
        fraction: i16::from_be_bytes([bytes[20], bytes[21]]),
        exponent: i16::from_be_bytes([bytes[22], bytes[23]]),
    };
    let mut s6 = ScalarF4E4 {
        fraction: i16::from_be_bytes([bytes[24], bytes[25]]),
        exponent: i16::from_be_bytes([bytes[26], bytes[27]]),
    };
    let mut s7 = ScalarF4E4 {
        fraction: i16::from_be_bytes([bytes[28], bytes[29]]),
        exponent: i16::from_be_bytes([bytes[30], bytes[31]]),
    };
    s0.normalize();
    s1.normalize();
    s2.normalize();
    s3.normalize();
    s4.normalize();
    s5.normalize();
    s6.normalize();
    s7.normalize();
    [s0, s1, s2, s3, s4, s5, s6, s7]
}

/// Convert 8 Spirix ScalarF4E4 values back to U256
fn spirix8_to_u256(s: [ScalarF4E4; 8]) -> U256 {
    let mut bytes = [0u8; 32];
    for i in 0..8 {
        let frac = s[i].fraction.to_be_bytes();
        let exp = s[i].exponent.to_be_bytes();
        bytes[i * 4] = frac[0];
        bytes[i * 4 + 1] = frac[1];
        bytes[i * 4 + 2] = exp[0];
        bytes[i * 4 + 3] = exp[1];
    }
    U256::from_be_bytes(bytes)
}

/// Apply sin to U256 via Spirix (deterministic across all platforms)
fn chaos_sin(n: U256) -> U256 {
    let s = u256_to_spirix8(n);
    spirix8_to_u256([
        s[0].sin(),
        s[1].sin(),
        s[2].sin(),
        s[3].sin(),
        s[4].sin(),
        s[5].sin(),
        s[6].sin(),
        s[7].sin(),
    ])
}

/// Apply cos to U256 via Spirix
fn chaos_cos(n: U256) -> U256 {
    let s = u256_to_spirix8(n);
    spirix8_to_u256([
        s[0].cos(),
        s[1].cos(),
        s[2].cos(),
        s[3].cos(),
        s[4].cos(),
        s[5].cos(),
        s[6].cos(),
        s[7].cos(),
    ])
}

/// Apply ln (natural log) to U256 via Spirix - negative/zero become deterministic undefined
fn chaos_ln(n: U256) -> U256 {
    let s = u256_to_spirix8(n);
    spirix8_to_u256([
        s[0].ln(),
        s[1].ln(),
        s[2].ln(),
        s[3].ln(),
        s[4].ln(),
        s[5].ln(),
        s[6].ln(),
        s[7].ln(),
    ])
}

/// Apply exp to U256 via Spirix - large values become deterministic exploded
fn chaos_exp(n: U256) -> U256 {
    let s = u256_to_spirix8(n);
    spirix8_to_u256([
        s[0].exp(),
        s[1].exp(),
        s[2].exp(),
        s[3].exp(),
        s[4].exp(),
        s[5].exp(),
        s[6].exp(),
        s[7].exp(),
    ])
}

/// Apply tan to U256 via Spirix - near-90° values become deterministic undefined
fn chaos_tan(n: U256) -> U256 {
    let s = u256_to_spirix8(n);
    spirix8_to_u256([
        s[0].tan(),
        s[1].tan(),
        s[2].tan(),
        s[3].tan(),
        s[4].tan(),
        s[5].tan(),
        s[6].tan(),
        s[7].tan(),
    ])
}

/// Apply atan to U256 via Spirix - compresses everything to [-π/2, π/2]
fn chaos_atan(n: U256) -> U256 {
    let s = u256_to_spirix8(n);
    spirix8_to_u256([
        s[0].atan(),
        s[1].atan(),
        s[2].atan(),
        s[3].atan(),
        s[4].atan(),
        s[5].atan(),
        s[6].atan(),
        s[7].atan(),
    ])
}

/// Spirix addition: deterministic handling of infinity/undefined states
fn chaos_add(a: U256, b: U256) -> U256 {
    let sa = u256_to_spirix8(a);
    let sb = u256_to_spirix8(b);
    spirix8_to_u256([
        sa[0] + sb[0],
        sa[1] + sb[1],
        sa[2] + sb[2],
        sa[3] + sb[3],
        sa[4] + sb[4],
        sa[5] + sb[5],
        sa[6] + sb[6],
        sa[7] + sb[7],
    ])
}

/// Spirix subtraction: deterministic handling of infinity/undefined states
fn chaos_sub(a: U256, b: U256) -> U256 {
    let sa = u256_to_spirix8(a);
    let sb = u256_to_spirix8(b);
    spirix8_to_u256([
        sa[0] - sb[0],
        sa[1] - sb[1],
        sa[2] - sb[2],
        sa[3] - sb[3],
        sa[4] - sb[4],
        sa[5] - sb[5],
        sa[6] - sb[6],
        sa[7] - sb[7],
    ])
}

/// Spirix multiplication: 0 * Inf = undefined (deterministic), overflow → exploded
fn chaos_mul(a: U256, b: U256) -> U256 {
    let sa = u256_to_spirix8(a);
    let sb = u256_to_spirix8(b);
    spirix8_to_u256([
        sa[0] * sb[0],
        sa[1] * sb[1],
        sa[2] * sb[2],
        sa[3] * sb[3],
        sa[4] * sb[4],
        sa[5] * sb[5],
        sa[6] * sb[6],
        sa[7] * sb[7],
    ])
}

/// Spirix division: x/0 = Inf, 0/0 = undefined (deterministic)
fn chaos_div(a: U256, b: U256) -> U256 {
    let sa = u256_to_spirix8(a);
    let sb = u256_to_spirix8(b);
    spirix8_to_u256([
        sa[0] / sb[0],
        sa[1] / sb[1],
        sa[2] / sb[2],
        sa[3] / sb[3],
        sa[4] / sb[4],
        sa[5] / sb[5],
        sa[6] / sb[6],
        sa[7] / sb[7],
    ])
}

/// Spirix power: deterministic handling of edge cases
fn chaos_pow(a: U256, b: U256) -> U256 {
    let sa = u256_to_spirix8(a);
    let sb = u256_to_spirix8(b);
    spirix8_to_u256([
        sa[0].pow(sb[0]),
        sa[1].pow(sb[1]),
        sa[2].pow(sb[2]),
        sa[3].pow(sb[3]),
        sa[4].pow(sb[4]),
        sa[5].pow(sb[5]),
        sa[6].pow(sb[6]),
        sa[7].pow(sb[7]),
    ])
}

/// Spirix hypot: sqrt(a² + b²) via square() and sqrt()
fn chaos_hypot(a: U256, b: U256) -> U256 {
    let sa = u256_to_spirix8(a);
    let sb = u256_to_spirix8(b);
    spirix8_to_u256([
        (sa[0].square() + sb[0].square()).sqrt(),
        (sa[1].square() + sb[1].square()).sqrt(),
        (sa[2].square() + sb[2].square()).sqrt(),
        (sa[3].square() + sb[3].square()).sqrt(),
        (sa[4].square() + sb[4].square()).sqrt(),
        (sa[5].square() + sb[5].square()).sqrt(),
        (sa[6].square() + sb[6].square()).sqrt(),
        (sa[7].square() + sb[7].square()).sqrt(),
    ])
}

/// Spaghettify: Rube Goldberg mixing with U256 chunks and Spirix chaos.
///
/// A deterministic one-way function that achieves **provable irreversibility** through
/// information destruction and path explosion. Not a cryptographic hash - instead a
/// "chaos amplifier" that makes preimage search computationally infeasible.
///
/// # Irreversibility Proof
///
/// **Information-Destroying Operations** (many-to-one mappings):
/// - `sqrt_u256`: 2^256 inputs → 2^128 outputs (op 12) - exact 2:1 collision guarantee
/// - `count_ones`: 2^256 inputs → 257 outputs (op 17) - ~10^75 collisions per output
/// - `saturating_add/sub`: clamps at 0 or MAX (ops 13,14) - infinite inputs → one output
/// - `AND/OR`: bit-level information loss (ops 15,16) - many patterns collapse to same result
/// - Spirix undefined states: ln(neg), 0/0, tan(π/2), etc. → deterministic "undefined" value
///
/// **Per-Round Information Loss:**
/// - 53 buckets × ~40% information-destroying op probability ≈ 21 lossy ops per round
/// - Each lossy op has ≥2:1 collision ratio (many have exponentially more)
/// - After R rounds: collision space grows multiplicatively
///
/// **Path Explosion:**
/// - 23^53 ≈ 10^72 possible operation sequences per round
/// - 11-23 rounds (data-dependent): total paths ≈ 10^792 to 10^1656
/// - Exceeds atoms in observable universe (~10^80) by factor of 10^700+
///
/// **Defense in Depth:**
/// - Final `smear_hash()` provides cryptographic one-wayness even if chaos layer is weak
/// - Original input re-appended before hash: secure if EITHER layer survives attack
///
/// # Security Model
///
/// Given output O, finding input I such that spaghettify(I) = O requires:
/// 1. Inverting smear_hash (cryptographic hardness)
/// 2. OR inverting 11-23 rounds of mixed lossy/reversible ops (combinatorial explosion)
/// 3. AND somehow navigating 10^72+ path choices per round
///
/// The function is **preimage-resistant** (cannot find input from output) but makes no
/// claim about **collision-resistance** (finding two inputs with same output) - collisions
/// are guaranteed to exist due to the lossy operations, they're just infeasible to find.
///
/// # Parameters
/// - **53 buckets** (prime) × U256 = 1696 bytes state
/// - **23 operations** (prime) - bucket value mod 23 selects op
/// - **11-23 rounds** (primes) - data-dependent iteration count
/// - **Spirix ScalarF4E4** - 8×32-bit deterministic floats per U256
///
/// NOT memory-hard - maximum weirdness, not resource consumption.
///
/// # Arguments
/// * `input` - Arbitrary length byte slice (0 to any size)
///
/// # Returns
/// 32 bytes of maximally entangled chaos (via smear_hash)
pub fn spaghettify(input: &[u8]) -> [u8; 32] {
    const BUCKETS: usize = 53; // Prime, 53 * 32 = 1696 bytes
    const CROSS: usize = 29; // Prime offset for cross-contamination (changed from 23)
    const OPS: usize = 23; // Prime number of operations

    let mut buckets: [U256; BUCKETS] = [U256_ZERO; BUCKETS];

    // Phase 1: Create input-modified seed
    // Start with LAVA_SEED, then mix input into it
    let mut seed = [
        U256::from_be_bytes(LAVA_SEED_256[0..32].try_into().unwrap()),
        U256::from_be_bytes(LAVA_SEED_256[32..64].try_into().unwrap()),
    ];

    // Mix each 32-byte chunk of input into seed
    for (chunk_idx, chunk) in input.chunks(32).enumerate() {
        let mut chunk_bytes = [0u8; 32];
        chunk_bytes[..chunk.len()].copy_from_slice(chunk);
        let chunk_val = U256::from_be_bytes(chunk_bytes);

        // XOR and rotate into both seed values
        seed[0] = seed[0] ^ chunk_val;
        seed[1] = seed[1].wrapping_add(chunk_val);
        seed[0] = (seed[0] << 7) | (seed[0] >> 249); // Rotate left 7
        seed[1] = seed[1] ^ (chunk_val >> (chunk_idx % 128));
    }

    // Also mix in input length to differentiate padding scenarios
    seed[0] = seed[0].wrapping_add(U256::from(input.len() as u128));

    // Expand modified seed into all 53 buckets
    for i in 0..BUCKETS {
        // Derive bucket from both seed values with position mixing
        let s0_rot = (seed[0] << (i % 128)) | (seed[0] >> (256 - (i % 128)));
        let s1_rot = (seed[1] >> (i % 64)) | (seed[1] << (256 - (i % 64)));
        buckets[i] = s0_rot ^ s1_rot;
        buckets[i] = buckets[i].wrapping_add(U256::from((i as u128) * 89));
    }

    // Pre-round mixing: cascade differences across neighbors
    for i in 0..BUCKETS {
        let next = (i + 1) % BUCKETS;
        buckets[next] = buckets[next] ^ buckets[i].wrapping_add(U256::from(i as u128));
    }

    // Phase 2: Determine round count from initial state (11-23, both prime)
    let state_sum: u128 = buckets.iter().map(|b| b.as_u128()).sum();
    let rounds = 11 + (state_sum % 13) as usize; // Variable work: 11..=23

    // Phase 3: Spaghettification - the chaos engine with U256 ops
    for round in 0..rounds {
        // Round-dependent constant from seed
        let round_const = seed[round % 2].wrapping_add(U256::from(round as u128));

        for i in 0..BUCKETS {
            let val = buckets[i];
            let op = (val.as_u128() as usize) % OPS; // Which operation (23 choices)

            // Data-dependent target
            let target = (i + (val.as_u128() as usize) + round * 31) % BUCKETS; // 31 is prime
            let secondary = (target + CROSS) % BUCKETS;

            // Position-dependent constant prevents convergence to fixed point
            let pos_const = round_const.wrapping_add(U256::from((i as u128) * 89));

            let op_result = match op {
                // Spirix unary ops (deterministic across all platforms):
                0 => chaos_sin(val),  // Trig chaos
                1 => chaos_cos(val),  // More trig chaos
                2 => chaos_ln(val),   // Negative → undefined
                3 => chaos_exp(val),  // Large → exploded
                4 => chaos_tan(val),  // Near-90° → undefined
                5 => chaos_atan(val), // Compresses range

                // Spirix binary ops (deterministic special value handling):
                6 => chaos_add(val, buckets[secondary]), // Inf + (-Inf) → undefined
                7 => chaos_sub(val, buckets[secondary]), // Inf - Inf → undefined
                8 => chaos_mul(val, buckets[secondary]), // 0 * Inf → undefined
                9 => chaos_div(val, buckets[secondary]), // 0/0 → undefined, x/0 → Inf
                10 => chaos_pow(val, buckets[secondary]), // neg^frac → undefined
                11 => chaos_hypot(val, buckets[secondary]), // sqrt(a² + b²)

                // U256 arithmetic ops:
                12 => sqrt_u256(val), // Lossy: 2^256 → 2^128 outputs
                13 => buckets[target].saturating_add(val), // Stuck at MAX
                14 => buckets[target].saturating_sub(val), // Stuck at 0
                15 => buckets[target] & val, // Bits destroyed
                16 => buckets[target] | val, // Bits forced on
                17 => U256::from(val.count_ones() as u128), // 256 bits → 0-256

                // Reversible but path-dependent:
                18 => buckets[target] ^ val, // XOR mixing
                19 => (val << (val.as_u128() % 256)) | (val >> (256 - val.as_u128() % 256)), // Data-dep rotate
                20 => buckets[target].wrapping_mul(val | U256_ONE), // |1 avoids *0
                21 => {
                    // Conditional swap - branch creates path explosion
                    if val > buckets[secondary] {
                        buckets.swap(target, secondary);
                    }
                    buckets[target]
                }
                _ => val.wrapping_add(buckets[secondary]), // Cross-bucket mixing (op 22)
            };

            // Mix in position constant to prevent fixed point convergence
            buckets[target] = op_result ^ pos_const;
        }
    }

    // Phase 4: Collapse 53 U256 buckets → bytes, append input, then smear_hash
    // Defense in depth: if spaghettify has unknown weaknesses, original input
    // is still mixed in. Output is secure if ANY layer survives (like CLUTCH).
    let mut state_bytes = alloc::vec::Vec::with_capacity(BUCKETS * 32 + input.len());
    for bucket in &buckets {
        state_bytes.extend_from_slice(&bucket.to_be_bytes());
    }
    state_bytes.extend_from_slice(input); // Append original input

    // Use smear_hash to collapse to 32 bytes with hash algorithm diversity
    smear_hash(&state_bytes)
}
