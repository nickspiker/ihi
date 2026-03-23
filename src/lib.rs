#![no_std]

extern crate alloc;

mod handle;
mod smear;
mod spaghettify;

pub use handle::handle_proof;
pub use smear::smear_hash;
pub use spaghettify::spaghettify;
