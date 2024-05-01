pub const KEY_SIZE_128: u8 = 1;
pub const KEY_SIZE_192: u8 = 2;
pub const KEY_SIZE_256: u8 = 3;

pub const BLOCK_MODE_CBC: u8 = 1;
pub const BLOCK_MODE_ECB: u8 = 2;

#[derive(Default)]
pub struct Format {
    pub key_size: u8,
    pub block_mode: u8,
}

impl Format {
    pub fn load(bytes: &[u8]) -> Self {
        Self {
            key_size: bytes[0],
            block_mode: bytes[1],
        }
    }
    pub fn dump(&self) -> Vec<u8> {
        vec![self.key_size, self.block_mode]
    }
}
