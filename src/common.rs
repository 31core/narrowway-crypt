pub const BUFF_BLOCKS: usize = 16 * 1024;

pub const BLOCK_SIZE_256: usize = 32;
pub const BLOCK_SIZE_384: usize = 48;
pub const BLOCK_SIZE_512: usize = 64;

pub fn pkcs7padding_pad(block: &mut [u8], data_size: usize, block_size: usize) {
    for byte in block[data_size..].iter_mut() {
        *byte = (block_size - data_size) as u8;
    }
}
