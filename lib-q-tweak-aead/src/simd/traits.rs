//! Stream XOR trait (portable implementation).

use crate::params::{
    KEY_BYTES,
    NONCE_BYTES,
};

pub trait TweakAeadStreamOps {
    fn xor_keystream(key: &[u8; KEY_BYTES], nonce: &[u8; NONCE_BYTES], pt: &[u8], ct: &mut [u8]);
}
