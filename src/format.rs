pub const KEY_SIZE_256: u8 = 1;
pub const KEY_SIZE_384: u8 = 2;
pub const KEY_SIZE_512: u8 = 3;

pub const BLOCK_MODE_ECB: u8 = 1;
pub const BLOCK_MODE_CBC: u8 = 2;
pub const BLOCK_MODE_OFB: u8 = 3;

#[derive(Default)]
pub struct Format {
    pub key_size: u8,
    pub block_mode: u8,
    pub salt: u128,
}

impl Format {
    pub fn load(bytes: &[u8]) -> Self {
        Self {
            key_size: bytes[6],
            block_mode: bytes[7],
            salt: u128::from_be_bytes(bytes[8..24].try_into().unwrap()),
        }
    }
    pub fn dump(&self) -> Vec<u8> {
        let mut header = b"NWCRY\0".to_vec();
        header.push(self.key_size);
        header.push(self.block_mode);
        header.extend(&self.salt.to_be_bytes());

        header
    }
}
