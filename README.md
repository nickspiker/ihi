![ihi](ihi.webp)

# ihi

**Identity crypto primitives. The math recognizes what you are.**

In Māori understanding, ihi is the specific quality of mana that is outwardly perceptible — the awe-inspiring presence that stops others, that can be witnessed and verified from outside. You cannot claim it. It flows from nature and lineage. The observer recognizes it.

This crate computes exactly that.

```toml
[dependencies]
ihi = "0.0.0"
```

---

## Primitives

### `spaghettify(input: &[u8]) -> [u8; 32]`

Transparently irreversible chaos amplifier. 53 buckets, 23 operations per bucket per round, 11–23 data-dependent rounds.

Unlike traditional hash functions whose hardness is conjectured ("we believe SHA-3 is one-way"), spaghettify's hardness is **auditable by inspection**:

```
Minimum paths to invert: 23^(53×11) ≈ 10^792
Maximum paths to invert: 23^(53×23) ≈ 10^1656
Atoms in observable universe: ~10^80
```

Count the paths yourself. The operations are listed. The collision ratios are measured. This isn't a claim — it's arithmetic.

Deterministic across all platforms via [Spirix](https://crates.io/crates/spirix) — two's complement floating-point that eliminates IEEE 754 implementation-defined behavior.

### `smear_hash(input: &[u8]) -> [u8; 32]`

Defense-in-depth output hash. XORs BLAKE3 ⊕ SHA3-256 ⊕ SHA-512.

If **any** algorithm survives cryptanalysis, the output remains secure. An attacker must break all three simultaneously.

### `handle_proof(hash: &blake3::Hash) -> blake3::Hash`

Memory-hard sequential proof-of-work for identity registration. Deterministic — same handle always produces the same public ID, enabling decentralized verification without coordination. ~1 second per handle makes bulk squatting expensive.

---

## Design

```
ihi = spaghettify(system_secret || developer_pubkey || option)
```

The process doesn't assert its identity. The oracle looks at what the process provably **is** — binary content, signing authority, hardware state — and derives what flows from that nature.

To forge ihi requires navigating a minimum of 10^792 paths through spaghettify. There are ~10^80 atoms in the observable universe.

The math does not care whether you trust it.

---

## `no_std`

Fully `no_std`. Suitable for bare-metal kernels, embedded targets, and constrained environments.

---

## License

MIT OR Apache-2.0

**Author:** Nick Spiker
