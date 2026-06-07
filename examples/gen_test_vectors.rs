//! Test-vector generator. Run with:
//!
//!     cargo run --release --example gen_test_vectors
//!
//! Prints (input → output) pairs for every public function in ihi, in a format ready to paste into `tests/test_vectors.rs`. Run once to capture the canonical byte values, paste them into the test file, then the assertions LOCK those values forever — any future change to ihi or its dependencies that alters output bytes will fail the test immediately.

use blake3;
use ihi::{
    chaos_amp, handle_proof, handle_to_filename, handle_to_proof, proof_to_filename, smear_hash,
    smear_hash_parts, spaghettify,
};

/// Inputs covering: empty, single-char, typical short, ASCII-with-space, numeric, mixed-case, longer, UTF-8 multi-byte (2-byte accented, 3-byte CJK, 4-byte emoji), repeating bytes (collision check), and bytes that look like the old VSF type markers (`a`, `l`, `x`) to confirm the new path doesn't accidentally re-introduce VSF-byte dependence.
const HANDLES: &[&str] = &[
    "",
    "a",
    "alice",
    "fractal decoder",
    "12345",
    "Photon-Messenger",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",       // 32 'a's, exercises chunk boundary
    "lemming",                                  // starts with 'l' (old VSF ASCII marker)
    "xenon",                                    // starts with 'x' (UTF-8 VSF marker)
    "atrium",                                   // starts with 'a' (new ASCII VSF marker)
    "café",                                     // UTF-8 2-byte accented
    "中文",                                     // UTF-8 3-byte CJK
    "🚀",                                       // UTF-8 4-byte emoji
];

/// Byte-oriented inputs for `smear_hash` / `smear_hash_parts` / `spaghettify` — covers empty, single byte at both extremes, zero-padded, all-ones, alternating, and a 32-byte BLAKE3-style hash to exercise mixed-bit inputs.
const BYTE_INPUTS: &[&[u8]] = &[
    &[],
    &[0x00],
    &[0xFF],
    &[0x00; 32],
    &[0xFF; 32],
    &[0xAA, 0x55, 0xAA, 0x55],
    b"alice",
    b"the quick brown fox jumps over the lazy dog",
];

fn print_hex(bytes: &[u8]) {
    print!("[");
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            print!(", ");
        }
        print!("0x{:02x}", b);
    }
    print!("]");
}

fn main() {
    println!("// ───────────────── handle_to_proof ─────────────────");
    for h in HANDLES {
        let p = handle_to_proof(h);
        print!("    ({:?}, ", h);
        print_hex(p.as_bytes());
        println!("),");
    }

    println!();
    println!("// ───────────────── handle_to_filename ──────────────");
    for h in HANDLES {
        let f = handle_to_filename(h);
        println!("    ({:?}, {:?}),", h, f);
    }

    println!();
    println!("// ───────────────── handle_proof (raw hash input) ───");
    let hash_inputs: &[&[u8]] = &[b"", b"alice", b"\x00".as_ref(), b"\xff".as_ref()];
    for input in hash_inputs {
        let h = blake3::hash(input);
        let p = handle_proof(&h);
        print!("    (\"blake3({:?})\", ", input);
        print_hex(p.as_bytes());
        println!("),");
    }

    println!();
    println!("// ───────────────── proof_to_filename ──────────────");
    let proofs: &[[u8; 32]] = &[[0u8; 32], [0xFF; 32], *blake3::hash(b"alice").as_bytes()];
    for p in proofs {
        let f = proof_to_filename(&blake3::Hash::from(*p));
        print!("    (");
        print_hex(p);
        println!(", {:?}),", f);
    }

    println!();
    println!("// ───────────────── smear_hash ────────────────────");
    for input in BYTE_INPUTS {
        let h = smear_hash(input);
        print!("    (");
        print_hex(input);
        print!(", ");
        print_hex(&h);
        println!("),");
    }

    println!();
    println!("// ───────────────── smear_hash_parts ──────────────");
    let parts_inputs: &[&[&[u8]]] = &[
        &[],
        &[b""],
        &[b"alice"],
        &[b"alice", b"bob"],
        &[b"alice", b"bob", b"carol"],
        &[&[0x00; 16], &[0xFF; 16]],
    ];
    for parts in parts_inputs {
        let h = smear_hash_parts(parts);
        print!("    ({:?}, ", parts);
        print_hex(&h);
        println!("),");
    }

    println!();
    println!("// ───────────────── spaghettify ───────────────────");
    for input in BYTE_INPUTS {
        let h = spaghettify(input);
        print!("    (");
        print_hex(input);
        print!(", ");
        print_hex(&h);
        println!("),");
    }

    println!();
    println!("// ───────────────── chaos_amp (64-byte block) ──────");
    // Locks the bit-exact silicon-equivalent output of the core mixing primitive. Inputs: all-zero (catches missing input absorption), all-one (catches missing input absorption inverse), and two blake3-derived patterns (catches typical-input regressions and avalanche-relevant cases).
    let chaos_inputs: [[u8; 64]; 4] = [
        [0u8; 64],
        [0xFFu8; 64],
        {
            let h = blake3::hash(b"alice");
            let mut b = [0u8; 64];
            b[..32].copy_from_slice(h.as_bytes());
            b[32..].copy_from_slice(h.as_bytes());
            b
        },
        {
            let h = blake3::hash(b"photon");
            let mut b = [0u8; 64];
            b[..32].copy_from_slice(h.as_bytes());
            b[32..].copy_from_slice(h.as_bytes());
            b
        },
    ];
    let labels = [
        "[0u8; 64]",
        "[0xFFu8; 64]",
        "blake3(\"alice\") repeated to 64 bytes",
        "blake3(\"photon\") repeated to 64 bytes",
    ];
    for (i, input) in chaos_inputs.iter().enumerate() {
        let out = chaos_amp(input);
        print!("    (\"{}\", ", labels[i]);
        print_hex(&out);
        println!("),");
    }
}
