#![no_std]

#[cfg(any(feature = "handle", feature = "keyring"))]
extern crate alloc;

mod chaos_amp;
#[cfg(feature = "handle")]
mod handle;
#[cfg(feature = "keyring")]
pub mod keyring;
mod smear;
mod spaghettify;

pub use chaos_amp::chaos_amp;
#[doc(hidden)]
pub use chaos_amp::_round_consts_for_test;
#[cfg(feature = "handle")]
pub use handle::{handle_proof, handle_to_filename, handle_to_hash, handle_to_proof, proof_to_filename};
pub use smear::{smear_hash, smear_hash_parts};
pub use spaghettify::spaghettify;
