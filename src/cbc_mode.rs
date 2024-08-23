use narrowway::*;
use std::fs::File;
use std::io::{Read, Result as IOResult, Write};

use crate::common::*;

pub fn narrowway256_cbc_encrypt<R, W>(
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
            for (i, byte) in block.iter_mut().enumerate() {
                *byte ^= iv[i];
            }
            let cipher_text = cipher.encrypt(block);

            if size < BLOCK_SIZE_256 {
                dst.write_all(&dst_buf[..BLOCK_SIZE_256 * i])?;
                dst.write_all(&cipher_text)?;
                break 'main;
            } else {
                dst_buf[BLOCK_SIZE_256 * i..BLOCK_SIZE_256 * (i + 1)].copy_from_slice(&cipher_text);

                iv = cipher_text;
            }
        }
        dst.write_all(&dst_buf[..buf_size])?;
    }
    Ok(())
}

pub fn narrowway384_cbc_encrypt<R, W>(
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
            for (i, byte) in block.iter_mut().enumerate() {
                *byte ^= iv[i];
            }
            let cipher_text = cipher.encrypt(block);

            if size < BLOCK_SIZE_384 {
                dst.write_all(&dst_buf[..BLOCK_SIZE_384 * i])?;
                dst.write_all(&cipher_text)?;
                break 'main;
            } else {
                dst_buf[BLOCK_SIZE_384 * i..BLOCK_SIZE_384 * (i + 1)].copy_from_slice(&cipher_text);

                for (i, byte) in cipher_text.iter().enumerate() {
                    iv[i] = *byte;
                }
            }
        }
        dst.write_all(&dst_buf)?;
    }
    Ok(())
}

pub fn narrowway512_cbc_encrypt<R, W>(
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
            for (i, byte) in block.iter_mut().enumerate() {
                *byte ^= iv[i];
            }
            let cipher_text = cipher.encrypt(block);

            if size < BLOCK_SIZE_512 {
                dst.write_all(&dst_buf[..BLOCK_SIZE_512 * i])?;
                dst.write_all(&cipher_text)?;
                break 'main;
            } else {
                dst_buf[BLOCK_SIZE_512 * i..BLOCK_SIZE_512 * (i + 1)].copy_from_slice(&cipher_text);

                for (i, byte) in cipher_text.iter().enumerate() {
                    iv[i] = *byte;
                }
            }
        }
        dst.write_all(&dst_buf)?;
    }
    Ok(())
}

pub fn narrowway256_cbc_decrypt<R>(
    src: &mut R,
    dst: &mut File,
    key: [u8; BLOCK_SIZE_256],
    mut iv: [u8; BLOCK_SIZE_256],
) -> IOResult<()>
where
    R: Read,
{
    let cipher = Cipher256::new(key);

    let mut old_iv = iv;
    let mut block = [0; BLOCK_SIZE_256];
    loop {
        let mut blocks = vec![0; BLOCK_SIZE_256 * BUFF_BLOCKS];
        let buf_size = src.read(&mut blocks)?;

        if buf_size == 0 {
            let mut plain_text = cipher.decrypt(block);
            for (i, byte) in plain_text.iter_mut().enumerate() {
                *byte ^= old_iv[i];
            }
            dst.set_len(dst.metadata()?.len() - plain_text[BLOCK_SIZE_256 - 1] as u64)?;
            break;
        }

        let mut dst_buf = vec![0; BLOCK_SIZE_256 * BUFF_BLOCKS];
        for i in 0..buf_size / BLOCK_SIZE_256 {
            block.copy_from_slice(&blocks[BLOCK_SIZE_256 * i..BLOCK_SIZE_256 * (i + 1)]);
            old_iv = iv;
            iv = block;
            let mut plain_text = cipher.decrypt(block);
            for (i, byte) in plain_text.iter_mut().enumerate() {
                *byte ^= old_iv[i];
            }
            dst_buf[BLOCK_SIZE_256 * i..BLOCK_SIZE_256 * (i + 1)].copy_from_slice(&plain_text);
        }
        dst.write_all(&dst_buf[..buf_size])?;
    }
    Ok(())
}

pub fn narrowway384_cbc_decrypt<R>(
    src: &mut R,
    dst: &mut File,
    key: [u8; BLOCK_SIZE_384],
    mut iv: [u8; BLOCK_SIZE_384],
) -> IOResult<()>
where
    R: Read,
{
    let cipher = Cipher384::new(key);

    let mut old_iv = iv;
    let mut block = [0; BLOCK_SIZE_384];
    loop {
        let mut blocks = vec![0; BLOCK_SIZE_384 * BUFF_BLOCKS];
        let buf_size = src.read(&mut blocks)?;

        if buf_size == 0 {
            let mut plain_text = cipher.decrypt(block);
            for (i, byte) in plain_text.iter_mut().enumerate() {
                *byte ^= old_iv[i];
            }
            dst.set_len(dst.metadata()?.len() - plain_text[BLOCK_SIZE_384 - 1] as u64)?;
            break;
        }

        let mut dst_buf = vec![0; BLOCK_SIZE_384 * BUFF_BLOCKS];
        for i in 0..buf_size / BLOCK_SIZE_384 {
            block.copy_from_slice(&blocks[BLOCK_SIZE_384 * i..BLOCK_SIZE_384 * (i + 1)]);
            old_iv = iv;
            iv = block;
            let mut plain_text = cipher.decrypt(block);
            for (i, byte) in plain_text.iter_mut().enumerate() {
                *byte ^= old_iv[i];
            }
            dst_buf[BLOCK_SIZE_384 * i..BLOCK_SIZE_384 * (i + 1)].copy_from_slice(&plain_text);
        }
        dst.write_all(&dst_buf[..buf_size])?;
    }
    Ok(())
}

pub fn narrowway512_cbc_decrypt<R>(
    src: &mut R,
    dst: &mut File,
    key: [u8; BLOCK_SIZE_512],
    mut iv: [u8; BLOCK_SIZE_512],
) -> IOResult<()>
where
    R: Read,
{
    let cipher = Cipher512::new(key);

    let mut old_iv = iv;
    let mut block = [0; BLOCK_SIZE_512];
    loop {
        let mut blocks = vec![0; BLOCK_SIZE_512 * BUFF_BLOCKS];
        let buf_size = src.read(&mut blocks)?;

        if buf_size == 0 {
            let mut plain_text = cipher.decrypt(block);
            for (i, byte) in plain_text.iter_mut().enumerate() {
                *byte ^= old_iv[i];
            }
            dst.set_len(dst.metadata()?.len() - plain_text[BLOCK_SIZE_512 - 1] as u64)?;
            break;
        }

        let mut dst_buf = vec![0; BLOCK_SIZE_512 * BUFF_BLOCKS];
        for i in 0..buf_size / BLOCK_SIZE_512 {
            block.copy_from_slice(&blocks[BLOCK_SIZE_512 * i..BLOCK_SIZE_512 * (i + 1)]);
            old_iv = iv;
            iv = block;
            let mut plain_text = cipher.decrypt(block);
            for (i, byte) in plain_text.iter_mut().enumerate() {
                *byte ^= old_iv[i];
            }
            dst_buf[BLOCK_SIZE_512 * i..BLOCK_SIZE_512 * (i + 1)].copy_from_slice(&plain_text);
        }
        dst.write_all(&dst_buf[..buf_size])?;
    }
    Ok(())
}
