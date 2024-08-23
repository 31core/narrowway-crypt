use narrowway::*;
use std::fs::File;
use std::io::{Read, Result as IOResult, Write};

use crate::common::*;

pub fn narrowway256_cfb_encrypt<R, W>(
    src: &mut R,
    dst: &mut W,
    key: [u8; BLOCK_SIZE_256],
    mut iv: [u8; BLOCK_SIZE_256],
) -> IOResult<()>
where
    R: Read,
    W: Write,
{
    let cipher = Cipher256::new(key);

    'main: loop {
        let mut blocks = vec![0; BLOCK_SIZE_256 * BUFF_BLOCKS];
        let buf_size = src.read(&mut blocks)?;

        let mut dst_buf = vec![0; BLOCK_SIZE_256 * BUFF_BLOCKS];
        for i in 0..BUFF_BLOCKS {
            let mut block = [0; BLOCK_SIZE_256];
            let size = std::cmp::min(BLOCK_SIZE_256, buf_size - i * BLOCK_SIZE_256);
            block.copy_from_slice(&blocks[BLOCK_SIZE_256 * i..BLOCK_SIZE_256 * (i + 1)]);

            pkcs7padding_pad(&mut block, size, BLOCK_SIZE_256);
            iv = cipher.encrypt(iv);
            for (i, byte) in block.iter_mut().enumerate() {
                *byte ^= iv[i];
            }
            iv = block;

            if size < BLOCK_SIZE_256 {
                dst.write_all(&dst_buf[..BLOCK_SIZE_256 * i])?;
                dst.write_all(&block)?;
                break 'main;
            } else {
                dst_buf[BLOCK_SIZE_256 * i..BLOCK_SIZE_256 * (i + 1)].copy_from_slice(&block);
            }
        }
        dst.write_all(&dst_buf[..buf_size])?;
    }
    Ok(())
}

pub fn narrowway384_cfb_encrypt<R, W>(
    src: &mut R,
    dst: &mut W,
    key: [u8; BLOCK_SIZE_384],
    mut iv: [u8; BLOCK_SIZE_384],
) -> IOResult<()>
where
    R: Read,
    W: Write,
{
    let cipher = Cipher384::new(key);

    'main: loop {
        let mut blocks = vec![0; BLOCK_SIZE_384 * BUFF_BLOCKS];
        let buf_size = src.read(&mut blocks)?;

        let mut dst_buf = vec![0; BLOCK_SIZE_384 * BUFF_BLOCKS];
        for i in 0..BUFF_BLOCKS {
            let mut block = [0; BLOCK_SIZE_384];
            let size = std::cmp::min(BLOCK_SIZE_384, buf_size - i * BLOCK_SIZE_384);
            block.copy_from_slice(&blocks[BLOCK_SIZE_384 * i..BLOCK_SIZE_384 * (i + 1)]);

            pkcs7padding_pad(&mut block, size, BLOCK_SIZE_384);
            iv = cipher.encrypt(iv);
            for (i, byte) in block.iter_mut().enumerate() {
                *byte ^= iv[i];
            }
            iv = block;

            if size < BLOCK_SIZE_384 {
                dst.write_all(&dst_buf[..BLOCK_SIZE_384 * i])?;
                dst.write_all(&block)?;
                break 'main;
            } else {
                dst_buf[BLOCK_SIZE_384 * i..BLOCK_SIZE_384 * (i + 1)].copy_from_slice(&block);
            }
        }
        dst.write_all(&dst_buf)?;
    }
    Ok(())
}

pub fn narrowway512_cfb_encrypt<R, W>(
    src: &mut R,
    dst: &mut W,
    key: [u8; BLOCK_SIZE_512],
    mut iv: [u8; BLOCK_SIZE_512],
) -> IOResult<()>
where
    R: Read,
    W: Write,
{
    let cipher = Cipher512::new(key);

    'main: loop {
        let mut blocks = vec![0; BLOCK_SIZE_512 * BUFF_BLOCKS];
        let buf_size = src.read(&mut blocks)?;

        let mut dst_buf = vec![0; BLOCK_SIZE_512 * BUFF_BLOCKS];
        for i in 0..BUFF_BLOCKS {
            let mut block = [0; BLOCK_SIZE_512];
            let size = std::cmp::min(BLOCK_SIZE_512, buf_size - i * BLOCK_SIZE_512);
            block.copy_from_slice(&blocks[BLOCK_SIZE_512 * i..BLOCK_SIZE_512 * (i + 1)]);

            pkcs7padding_pad(&mut block, size, BLOCK_SIZE_512);
            iv = cipher.encrypt(iv);
            for (i, byte) in block.iter_mut().enumerate() {
                *byte ^= iv[i];
            }
            iv = block;

            if size < BLOCK_SIZE_512 {
                dst.write_all(&dst_buf[..BLOCK_SIZE_512 * i])?;
                dst.write_all(&block)?;
                break 'main;
            } else {
                dst_buf[BLOCK_SIZE_512 * i..BLOCK_SIZE_512 * (i + 1)].copy_from_slice(&block);
            }
        }
        dst.write_all(&dst_buf)?;
    }
    Ok(())
}

pub fn narrowway256_cfb_decrypt<R>(
    src: &mut R,
    dst: &mut File,
    key: [u8; BLOCK_SIZE_256],
    mut iv: [u8; BLOCK_SIZE_256],
) -> IOResult<()>
where
    R: Read,
{
    let cipher = Cipher256::new(key);

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

            let iv_enc = cipher.encrypt(iv);
            iv = block;
            for (i, byte) in block.iter_mut().enumerate() {
                *byte ^= iv_enc[i];
            }

            dst_buf[BLOCK_SIZE_256 * i..BLOCK_SIZE_256 * (i + 1)].copy_from_slice(&block);
        }
        dst.write_all(&dst_buf[..buf_size])?;
    }
    Ok(())
}

pub fn narrowway384_cfb_decrypt<R>(
    src: &mut R,
    dst: &mut File,
    key: [u8; BLOCK_SIZE_384],
    mut iv: [u8; BLOCK_SIZE_384],
) -> IOResult<()>
where
    R: Read,
{
    let cipher = Cipher384::new(key);

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

            let iv_enc = cipher.encrypt(iv);
            iv = block;
            for (i, byte) in block.iter_mut().enumerate() {
                *byte ^= iv_enc[i];
            }

            dst_buf[BLOCK_SIZE_384 * i..BLOCK_SIZE_384 * (i + 1)].copy_from_slice(&block);
        }
        dst.write_all(&dst_buf[..buf_size])?;
    }
    Ok(())
}

pub fn narrowway512_cfb_decrypt<R>(
    src: &mut R,
    dst: &mut File,
    key: [u8; BLOCK_SIZE_512],
    mut iv: [u8; BLOCK_SIZE_512],
) -> IOResult<()>
where
    R: Read,
{
    let cipher = Cipher512::new(key);

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

            let iv_enc = cipher.encrypt(iv);
            iv = block;
            for (i, byte) in block.iter_mut().enumerate() {
                *byte ^= iv_enc[i];
            }

            dst_buf[BLOCK_SIZE_512 * i..BLOCK_SIZE_512 * (i + 1)].copy_from_slice(&block);
        }
        dst.write_all(&dst_buf[..buf_size])?;
    }
    Ok(())
}
