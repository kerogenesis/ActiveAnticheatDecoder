pub mod rc4;
pub mod sha1;

pub use rc4::{crypt, crypt_in_place};
pub use sha1::digest;
