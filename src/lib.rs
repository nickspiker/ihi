#![no_std]

#[cfg(feature = "handle")]
extern crate alloc;

#[cfg(feature = "handle")]
mod handle;
mod smear;
mod spaghettify;

#[cfg(feature = "handle")]
pub use handle::handle_proof;
pub use smear::{smear_hash, smear_hash_parts};
pub use spaghettify::spaghettify;
