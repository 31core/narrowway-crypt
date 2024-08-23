use narrowway::*;
use std::fs::File;
use std::io::{Read, Result as IOResult, Write};

use crate::common::*;

pub const COUNTER_LEN: usize = 8;

fn ctr_gen_256(nonce: &[u8; BLOCK_SIZE_256 - COUNTER_LEN], counter: u64) -> [u8; BLOCK_SIZE_256] {
    let mut ctr = [0; BLOCK_SIZE_256];

    ctr[0..BLOCK_SIZE_256 - COUNTER_LEN].copy_from_slice(nonce);
    ctr[BLOCK_SIZE_256 - COUNTER_LEN..BLOCK_SIZE_256].copy_from_slice(&counter.to_be_bytes());

    ctr
}

fn ctr_gen_384(nonce: &[u8; BLOCK_SIZE_384 - COUNTER_LEN], counter: u64) -> [u8; BLOCK_SIZE_384] {
    let mut ctr = [0; BLOCK_SIZE_384];

    ctr[0..BLOCK_SIZE_384 - COUNTER_LEN].copy_from_slice(nonce);
    ctr[BLOCK_SIZE_384 - COUNTER_LEN..BLOCK_SIZE_384].copy_from_slice(&counter.to_be_bytes());

    ctr
}

fn ctr_gen_512(nonce: &[u8; BLOCK_SIZE_512 - COUNTER_LEN], counter: u64) -> [u8; BLOCK_SIZE_512] {
    let mut ctr = [0; BLOCK_SIZE_512];

    ctr[0..BLOCK_SIZE_512 - COUNTER_LEN].copy_from_slice(nonce);
    ctr[BLOCK_SIZE_512 - COUNTER_LEN..BLOCK_SIZE_512].copy_from_slice(&counter.to_be_bytes());

    ctr
}

pub fn narrowway256_ctr_encrypt<R, W>(
    src: &mut R,
    dst: &mut W,
    key: [u8; BLOCK_SIZE_256],
    nonce: [u8; BLOCK_SIZE_256 - COUNTER_LEN],
) -> IOResult<()>
where
    R: Read,
    W: Write,
{
    let cipher = Cipher256::new(key);
    let mut counter = 0;

    'main: loop {
        let mut blocks = vec![0; BLOCK_SIZE_256 * BUFF_BLOCKS];
        let buf_size = src.read(&mut blocks)?;

        let mut dst_buf = vec![0; BLOCK_SIZE_256 * BUFF_BLOCKS];
        for i in 0..BUFF_BLOCKS {
            let mut block = [0; BLOCK_SIZE_256];
            let size = std::cmp::min(BLOCK_SIZE_256, buf_size - i * BLOCK_SIZE_256);
            block.copy_from_slice(&blocks[BLOCK_SIZE_256 * i..BLOCK_SIZE_256 * (i + 1)]);

            pkcs7padding_pad(&mut block, size, BLOCK_SIZE_256);
            let key = cipher.encrypt(ctr_gen_256(&nonce, counter));
            for (i, byte) in block.iter_mut().enumerate() {
                *byte ^= key[i];
            }

            if size < BLOCK_SIZE_256 {
                dst.write_all(&dst_buf[..BLOCK_SIZE_256 * i])?;
                dst.write_all(&block)?;
                break 'main;
            } else {
                dst_buf[BLOCK_SIZE_256 * i..BLOCK_SIZE_256 * (i + 1)].copy_from_slice(&block);
            }

            counter += 1;
        }
        dst.write_all(&dst_buf[..buf_size])?;
    }
    Ok(())
}

pub fn narrowway384_ctr_encrypt<R, W>(
    src: &mut R,
    dst: &mut W,
    key: [u8; BLOCK_SIZE_384],
    nonce: [u8; BLOCK_SIZE_384 - COUNTER_LEN],
) -> IOResult<()>
where
    R: Read,
    W: Write,
{
    let cipher = Cipher384::new(key);
    let mut counter = 0;

    'main: loop {
        let mut blocks = vec![0; BLOCK_SIZE_384 * BUFF_BLOCKS];
        let buf_size = src.read(&mut blocks)?;

        let mut dst_buf = vec![0; BLOCK_SIZE_384 * BUFF_BLOCKS];
        for i in 0..BUFF_BLOCKS {
            let mut block = [0; BLOCK_SIZE_384];
            let size = std::cmp::min(BLOCK_SIZE_384, buf_size - i * BLOCK_SIZE_384);
            block.copy_from_slice(&blocks[BLOCK_SIZE_384 * i..BLOCK_SIZE_384 * (i + 1)]);

            pkcs7padding_pad(&mut block, size, BLOCK_SIZE_384);
            let key = cipher.encrypt(ctr_gen_384(&nonce, counter));
            for (i, byte) in block.iter_mut().enumerate() {
                *byte ^= key[i];
            }

            if size < BLOCK_SIZE_384 {
                dst.write_all(&dst_buf[..BLOCK_SIZE_384 * i])?;
                dst.write_all(&block)?;
                break 'main;
            } else {
                dst_buf[BLOCK_SIZE_384 * i..BLOCK_SIZE_384 * (i + 1)].copy_from_slice(&block);
            }

            counter += 1;
        }
        dst.write_all(&dst_buf)?;
    }
    Ok(())
}

pub fn narrowway512_ctr_encrypt<R, W>(
    src: &mut R,
    dst: &mut W,
    key: [u8; BLOCK_SIZE_512],
    nonce: [u8; BLOCK_SIZE_512 - COUNTER_LEN],
) -> IOResult<()>
where
    R: Read,
    W: Write,
{
    let cipher = Cipher512::new(key);
    let mut counter = 0;

    'main: loop {
        let mut blocks = vec![0; BLOCK_SIZE_512 * BUFF_BLOCKS];
        let buf_size = src.read(&mut blocks)?;

        let mut dst_buf = vec![0; BLOCK_SIZE_512 * BUFF_BLOCKS];
        for i in 0..BUFF_BLOCKS {
            let mut block = [0; BLOCK_SIZE_512];
            let size = std::cmp::min(BLOCK_SIZE_512, buf_size - i * BLOCK_SIZE_512);
            block.copy_from_slice(&blocks[BLOCK_SIZE_512 * i..BLOCK_SIZE_512 * (i + 1)]);

            pkcs7padding_pad(&mut block, size, BLOCK_SIZE_512);
            let key = cipher.encrypt(ctr_gen_512(&nonce, counter));
            for (i, byte) in block.iter_mut().enumerate() {
                *byte ^= key[i];
            }

            if size < BLOCK_SIZE_512 {
                dst.write_all(&dst_buf[..BLOCK_SIZE_512 * i])?;
                dst.write_all(&block)?;
                break 'main;
            } else {
                dst_buf[BLOCK_SIZE_512 * i..BLOCK_SIZE_512 * (i + 1)].copy_from_slice(&block);
            }

            counter += 1;
        }
        dst.write_all(&dst_buf)?;
    }
    Ok(())
}

pub fn narrowway256_ctr_decrypt<R>(
    src: &mut R,
    dst: &mut File,
    key: [u8; BLOCK_SIZE_256],
    nonce: [u8; BLOCK_SIZE_256 - COUNTER_LEN],
) -> IOResult<()>
where
    R: Read,
{
    let cipher = Cipher256::new(key);
    let mut counter = 0;

    let mut block = [0; BLOCK_SIZE_256];
    loop {
        let mut blocks = vec![0; BLOCK_SIZE_256 * BUFF_BLOCKS];
        let buf_size = src.read(&mut blocks)?;

        if buf_size == 0 {
            dst.set_len(dst.metadata()?.len() - block[BLOCK_SIZE_256 - 1] as u64)?;
            break;
        }

        let mut dst_buf = vec![0; BLOCK_SIZE_256 * BUFF_BLOCKS];
        for i in 0..buf_size / BLOCK_SIZE_256 {
            block.copy_from_slice(&blocks[BLOCK_SIZE_256 * i..BLOCK_SIZE_256 * (i + 1)]);

            let key = cipher.encrypt(ctr_gen_256(&nonce, counter));
            for (i, byte) in block.iter_mut().enumerate() {
                *byte ^= key[i];
            }
            dst_buf[BLOCK_SIZE_256 * i..BLOCK_SIZE_256 * (i + 1)].copy_from_slice(&block);

            counter += 1;
        }
        dst.write_all(&dst_buf[..buf_size])?;
    }
    Ok(())
}

pub fn narrowway384_ctr_decrypt<R>(
    src: &mut R,
    dst: &mut File,
    key: [u8; BLOCK_SIZE_384],
    nonce: [u8; BLOCK_SIZE_384 - COUNTER_LEN],
) -> IOResult<()>
where
    R: Read,
{
    let cipher = Cipher384::new(key);
    let mut counter = 0;

    let mut block = [0; BLOCK_SIZE_384];
    loop {
        let mut blocks = vec![0; BLOCK_SIZE_384 * BUFF_BLOCKS];
        let buf_size = src.read(&mut blocks)?;

        if buf_size == 0 {
            dst.set_len(dst.metadata()?.len() - block[BLOCK_SIZE_384 - 1] as u64)?;
            break;
        }

        let mut dst_buf = vec![0; BLOCK_SIZE_384 * BUFF_BLOCKS];
        for i in 0..buf_size / BLOCK_SIZE_384 {
            block.copy_from_slice(&blocks[BLOCK_SIZE_384 * i..BLOCK_SIZE_384 * (i + 1)]);

            let key = cipher.encrypt(ctr_gen_384(&nonce, counter));
            for (i, byte) in block.iter_mut().enumerate() {
                *byte ^= key[i];
            }
            dst_buf[BLOCK_SIZE_384 * i..BLOCK_SIZE_384 * (i + 1)].copy_from_slice(&block);

            counter += 1;
        }
        dst.write_all(&dst_buf[..buf_size])?;
    }
    Ok(())
}

pub fn narrowway512_ctr_decrypt<R>(
    src: &mut R,
    dst: &mut File,
    key: [u8; BLOCK_SIZE_512],
    nonce: [u8; BLOCK_SIZE_512 - COUNTER_LEN],
) -> IOResult<()>
where
    R: Read,
{
    let cipher = Cipher512::new(key);
    let mut counter = 0;

    let mut block = [0; BLOCK_SIZE_512];
    loop {
        let mut blocks = vec![0; BLOCK_SIZE_512 * BUFF_BLOCKS];
        let buf_size = src.read(&mut blocks)?;

        if buf_size == 0 {
            dst.set_len(dst.metadata()?.len() - block[BLOCK_SIZE_512 - 1] as u64)?;
            break;
        }

        let mut dst_buf = vec![0; BLOCK_SIZE_512 * BUFF_BLOCKS];
        for i in 0..buf_size / BLOCK_SIZE_512 {
            block.copy_from_slice(&blocks[BLOCK_SIZE_512 * i..BLOCK_SIZE_512 * (i + 1)]);

            let key = cipher.encrypt(ctr_gen_512(&nonce, counter));
            for (i, byte) in block.iter_mut().enumerate() {
                *byte ^= key[i];
            }
            dst_buf[BLOCK_SIZE_512 * i..BLOCK_SIZE_512 * (i + 1)].copy_from_slice(&block);

            counter += 1;
        }
        dst.write_all(&dst_buf[..buf_size])?;
    }
    Ok(())
}
