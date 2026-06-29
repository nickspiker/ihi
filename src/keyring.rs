//! Keyring — the constant-size device-set commitment for one identity.
//!
//! A single identity (handle) binds many devices (the fleet). The PUBLIC credential for that identity is a
//! **single 32-byte Merkle root** over the fleet's per-device leaves — **identical in size whether the fleet
//! has one device or a billion**, so an observer learns nothing about the device count. The per-device leaf
//! list stays private to the fleet; a device proves membership with a fixed-size inclusion proof against the
//! published root, revealing only "a member," never the count.
//!
//! This module is the ONE source of truth for leaf derivation + root + inclusion-proof, shared by the client
//! (photon, builds the tree) and the registry/worker (fgtw, verifies proofs). It is `no_std` and depends only
//! on `blake3` + [`crate::spaghettify`] — both already core to `ihi` — so it is available without the `handle`
//! feature (fgtw builds `ihi` with `default-features = false`).
//!
//! ## Why a sparse tree
//!
//! The tree has a fixed depth ([`KEYRING_DEPTH`]) so the root and every inclusion proof are constant size
//! regardless of how many real devices exist. A full `1 << DEPTH` tree is never materialized: empty subtrees
//! collapse to precomputed per-level "zero" hashes, so the root costs `O(real_leaves · DEPTH)`, not
//! `O(2^DEPTH)`. The fixed depth also means the proof LENGTH never hints at the fleet size.

use crate::spaghettify::spaghettify;

/// Fixed tree depth. `1 << 30` leaf slots caps a fleet at ~1.07 billion devices — the user's "1 device or 1
/// billion, same-size key" bound — while keeping the root at 32 bytes and every inclusion proof at exactly
/// [`KEYRING_DEPTH`] sibling nodes. Raising it changes the wire format (a new `kr_ver`); it is not a runtime
/// knob.
pub const KEYRING_DEPTH: usize = 30;

/// One sibling node carried in an inclusion proof.
pub type Node = [u8; 32];

/// A complete inclusion proof: one sibling per level, leaf-to-root. Fixed length ⇒ constant size ⇒ reveals
/// nothing about the fleet size.
pub type InclusionProof = [Node; KEYRING_DEPTH];

/// Leaf kind tags, mixed into the leaf preimage so leaves of different purposes living in the SAME tree can
/// never be substituted for one another (a device-membership leaf must not validate as an avatar-write leaf).
/// One byte, picked so the values are not 0/contiguous-by-accident; they are an explicit menu, not a count.
pub mod kind {
    /// A device's membership in the fleet.
    pub const DEVICE: u8 = b'd';
    /// A device's authority to write the identity's avatar.
    pub const AVATAR: u8 = b'a';
    /// A device's authority to write a stored blob.
    pub const BLOB: u8 = b'b';
}

/// Domain-separation prefixes so a leaf hash can never collide with an interior-node hash (a second-preimage
/// guard: without distinct prefixes an attacker could present an interior node as a leaf). One byte each.
const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;

/// Derive a fleet leaf: `spaghettify(kind ‖ device_secret ‖ identity_seed)`.
///
/// SECRET-based (patent-literal) so the leaf id is unguessable — it cannot be recomputed by anyone lacking
/// the device secret, which by construction never leaves the device. `spaghettify` is the provably-lossy OWF,
/// so distinct identities' leaves are mutually unlinkable (cross-handle linking impossible). `identity_seed`
/// is the caller's `handle_to_hash(handle)` (passed in so this module needs no `handle` feature).
pub fn leaf(kind: u8, device_secret: &[u8; 32], identity_seed: &[u8; 32]) -> [u8; 32] {
    let mut preimage = [0u8; 1 + 32 + 32];
    preimage[0] = kind;
    preimage[1..33].copy_from_slice(device_secret);
    preimage[33..65].copy_from_slice(identity_seed);
    spaghettify(&preimage)
}

/// Hash a leaf value into its tree position (distinct from interior nodes via [`LEAF_PREFIX`]).
fn hash_leaf(leaf_value: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&[LEAF_PREFIX]);
    h.update(leaf_value);
    *h.finalize().as_bytes()
}

/// Hash two child nodes into their parent (distinct from leaves via [`NODE_PREFIX`]). Left then right — order
/// matters and is fixed by the bit of the index at that level.
fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&[NODE_PREFIX]);
    h.update(left);
    h.update(right);
    *h.finalize().as_bytes()
}

/// The "zero" hash for an empty subtree at each level: level 0 is an empty leaf slot, level `i+1` is two
/// empty level-`i` subtrees. Returned as an array `[level 0 .. level DEPTH]` so an absent sibling at any
/// level is a cheap lookup instead of recursion. Computed once per call (cheap: DEPTH hashes).
fn zero_hashes() -> [[u8; 32]; KEYRING_DEPTH + 1] {
    let mut z = [[0u8; 32]; KEYRING_DEPTH + 1];
    // Level 0 = the hash of an absent leaf. A fixed sentinel (all-zero leaf value) the real leaves never
    // collide with, since a real leaf is a spaghettify output (preimage-resistant) and is then LEAF_PREFIX-
    // hashed, whereas this is the LEAF_PREFIX-hash of the zero value — a specific, fixed point.
    z[0] = hash_leaf(&[0u8; 32]);
    let mut level = 1;
    while level <= KEYRING_DEPTH {
        let child = z[level - 1];
        z[level] = hash_node(&child, &child);
        level += 1;
    }
    z
}

/// Compute the Merkle root over a fleet's leaf values. Leaves occupy positions `0..leaves.len()` (insertion
/// order); the remaining `(1 << DEPTH) - leaves.len()` positions are empty and collapse to the per-level zero
/// hashes, so the cost is `O(leaves.len() · DEPTH)`, not `O(2^DEPTH)`. The output is 32 bytes for ANY fleet
/// size — the constant-size-regardless-of-N property.
///
/// `leaves.len()` must be `<= 1 << DEPTH`; a fleet that large is not a real scenario (it is the ~1.07B cap),
/// and the caller controls its own fleet, so this is an internal invariant, not external input — callers that
/// could exceed it are buggy and should be fixed, not guarded.
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    let zeros = zero_hashes();
    if leaves.is_empty() {
        return zeros[KEYRING_DEPTH];
    }
    // Build the current level as the hashed leaves; fold upward, supplying zero-hashes for absent siblings.
    // `level_nodes` holds the occupied prefix of the current level; everything past it is `zeros[level]`.
    // We fold in place using a small heap-free approach: hash pairs, carrying a possible odd tail paired with
    // the level's zero hash.
    let mut current: alloc::vec::Vec<[u8; 32]> = leaves.iter().map(hash_leaf).collect();
    let mut level = 0;
    while level < KEYRING_DEPTH {
        let zero = zeros[level];
        let mut next: alloc::vec::Vec<[u8; 32]> =
            alloc::vec::Vec::with_capacity((current.len() + 1) / 2);
        let mut i = 0;
        while i < current.len() {
            let left = current[i];
            let right = if i + 1 < current.len() { current[i + 1] } else { zero };
            next.push(hash_node(&left, &right));
            i += 2;
        }
        current = next;
        level += 1;
    }
    current[0]
}

/// Build the inclusion proof for the leaf at `index` in a fleet of `leaf_count` real leaves: the sibling at
/// every level, leaf-to-root. Fixed length [`KEYRING_DEPTH`]. Absent siblings are the per-level zero hash.
pub fn inclusion_proof(leaves: &[[u8; 32]], index: usize) -> InclusionProof {
    let zeros = zero_hashes();
    let mut proof = [[0u8; 32]; KEYRING_DEPTH];
    let mut current: alloc::vec::Vec<[u8; 32]> = leaves.iter().map(hash_leaf).collect();
    let mut idx = index;
    let mut level = 0;
    while level < KEYRING_DEPTH {
        let zero = zeros[level];
        // Sibling is the node across the pair from `idx` at this level.
        let sibling_idx = idx ^ 1;
        proof[level] = if sibling_idx < current.len() { current[sibling_idx] } else { zero };
        // Fold to the next level.
        let mut next: alloc::vec::Vec<[u8; 32]> =
            alloc::vec::Vec::with_capacity((current.len() + 1) / 2);
        let mut i = 0;
        while i < current.len() {
            let left = current[i];
            let right = if i + 1 < current.len() { current[i + 1] } else { zero };
            next.push(hash_node(&left, &right));
            i += 2;
        }
        current = next;
        idx >>= 1;
        level += 1;
    }
    proof
}

/// Verify that `leaf_value` sits at `index` under `root`, given its inclusion `proof`. Folds the leaf up
/// through the proof's siblings (left/right ordered by each index bit) and checks the result equals `root`.
/// Constant work, constant exposure — the verifier learns only that this one leaf is a member, never the
/// fleet size or any other leaf.
pub fn verify_inclusion(
    leaf_value: &[u8; 32],
    index: usize,
    proof: &InclusionProof,
    root: &[u8; 32],
) -> bool {
    let mut acc = hash_leaf(leaf_value);
    let mut idx = index;
    let mut level = 0;
    while level < KEYRING_DEPTH {
        let sibling = &proof[level];
        acc = if idx & 1 == 0 {
            hash_node(&acc, sibling)
        } else {
            hash_node(sibling, &acc)
        };
        idx >>= 1;
        level += 1;
    }
    &acc == root
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::vec::Vec;

    fn fleet(n: usize) -> Vec<[u8; 32]> {
        // Distinct leaves derived like the real path: spaghettify over a per-device secret.
        (0..n)
            .map(|i| {
                let mut secret = [0u8; 32];
                secret[0] = i as u8;
                secret[1] = (i >> 8) as u8;
                leaf(kind::DEVICE, &secret, &[7u8; 32])
            })
            .collect()
    }

    #[test]
    fn root_is_constant_size_regardless_of_fleet() {
        // The whole point: the public credential is the same SIZE for 1 device or 1000 devices.
        let r1 = merkle_root(&fleet(1));
        let r1000 = merkle_root(&fleet(1000));
        assert_eq!(r1.len(), 32);
        assert_eq!(r1000.len(), 32);
        // ...and different fleets give different roots (it actually commits to the set).
        assert_ne!(r1, r1000);
    }

    #[test]
    fn every_member_proves_inclusion() {
        let leaves = fleet(37);
        let root = merkle_root(&leaves);
        for (i, lv) in leaves.iter().enumerate() {
            let proof = inclusion_proof(&leaves, i);
            assert_eq!(proof.len(), KEYRING_DEPTH, "proof length is fixed, never hints at N");
            assert!(verify_inclusion(lv, i, &proof, &root), "member {} must verify", i);
        }
    }

    #[test]
    fn non_member_and_wrong_index_fail() {
        let leaves = fleet(8);
        let root = merkle_root(&leaves);
        // A leaf that isn't in the tree must not verify with anyone's proof.
        let outsider = leaf(kind::DEVICE, &[0xFF; 32], &[7u8; 32]);
        let proof0 = inclusion_proof(&leaves, 0);
        assert!(!verify_inclusion(&outsider, 0, &proof0, &root));
        // A real member with the WRONG index must not verify.
        assert!(!verify_inclusion(&leaves[3], 4, &inclusion_proof(&leaves, 3), &root));
    }

    #[test]
    fn revocation_changes_the_root() {
        // Removing a device (dropping its leaf) yields a different root, and the removed device's old proof
        // no longer validates against the new root — the revocation-sticks property.
        let mut leaves = fleet(5);
        let root_before = merkle_root(&leaves);
        let removed_leaf = leaves[2];
        let removed_proof = inclusion_proof(&leaves, 2);
        assert!(verify_inclusion(&removed_leaf, 2, &removed_proof, &root_before));
        leaves.remove(2);
        let root_after = merkle_root(&leaves);
        assert_ne!(root_before, root_after);
        assert!(
            !verify_inclusion(&removed_leaf, 2, &removed_proof, &root_after),
            "a removed device's old proof must fail against the new root"
        );
    }

    #[test]
    fn kind_tag_prevents_cross_use() {
        // The SAME device secret under a different kind tag is a different leaf — a device-membership leaf
        // can't be replayed as an avatar-write leaf.
        let secret = [9u8; 32];
        let seed = [7u8; 32];
        assert_ne!(
            leaf(kind::DEVICE, &secret, &seed),
            leaf(kind::AVATAR, &secret, &seed)
        );
    }

    #[test]
    fn cross_handle_leaves_uncorrelated() {
        // Same device, two identities → unrelated leaves (spaghettify lossiness; no cross-handle linking).
        let secret = [3u8; 32];
        assert_ne!(
            leaf(kind::DEVICE, &secret, &[1u8; 32]),
            leaf(kind::DEVICE, &secret, &[2u8; 32])
        );
    }
}
