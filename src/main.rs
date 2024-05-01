mod format;

use clap::{Parser, Subcommand, ValueEnum};
use narrowway::*;
use std::fs::{File, OpenOptions};
use std::io::{Read, Result as IOResult, Write};

use crate::format::*;

const BUFF_BLOCKS: usize = 16 * 1024;

const BLOCK_SIZE_128: usize = 16;
const BLOCK_SIZE_192: usize = 24;
const BLOCK_SIZE_256: usize = 32;

#[derive(Clone, ValueEnum)]
enum Algorithm {
    #[value(name = "128")]
    Narrowway128,
    #[value(name = "192")]
    Narrowway192,
    #[value(name = "256")]
    Narrowway256,
}

#[derive(Clone, ValueEnum)]
enum BlockMode {
    Ecb,
    Cbc,
}

#[derive(Parser)]
#[command(
    author = "31core",
    version = "0.1.0",
    about = "NarrowWay encryption/decryption utility"
)]
struct Args {
    #[command(subcommand)]
    command: Command,
    #[arg(short, long, default_value = "256")]
    algorithm: Algorithm,
    #[arg(short, long, default_value = "cbc")]
    block_mode: BlockMode,
    /// Keep source file
    #[arg(short, long)]
    keep: bool,
    /// Secret key
    #[arg(short = 'K', long)]
    key: Option<String>,
    /// Secret key file
    #[arg(short = 'f', long)]
    key_file: Option<String>,
    /// Source file to encrypt or decrypt
    input: String,
    /// Output file to encrypt or decrypt
    output: Option<String>,
}

#[derive(Subcommand)]
enum Command {
    /// Encrypt a file
    Encrypt,
    /// Decrypt a file
    Decrypt,
}

fn narrowway128_ecb_encrypt<R, W>(
    src: &mut R,
    dst: &mut W,
    key: [u8; BLOCK_SIZE_128],
) -> IOResult<()>
where
    R: Read,
    W: Write,
{
    let cipher = Cipher128::new(key);

    'main: loop {
        let mut blocks = vec![0; BLOCK_SIZE_128 * BUFF_BLOCKS];
        let buf_size = src.read(&mut blocks)?;

        if buf_size == 0 {
            let zero_block = [0; BLOCK_SIZE_128];
            let cipher_text = cipher.encrypt(zero_block);
            dst.write_all(&cipher_text)?;
            break;
        }

        let mut dst_buf = vec![0; BLOCK_SIZE_128 * BUFF_BLOCKS];
        for i in 0..BUFF_BLOCKS {
            let mut block = [0; BLOCK_SIZE_128];
            let size = std::cmp::min(BLOCK_SIZE_128, buf_size - i * BLOCK_SIZE_128);
            block.copy_from_slice(&blocks[BLOCK_SIZE_128 * i..BLOCK_SIZE_128 * (i + 1)]);

            if size < BLOCK_SIZE_128 {
                for byte in block[size..].iter_mut() {
                    *byte = size as u8;
                }
                let cipher_text = cipher.encrypt(block);
                dst.write_all(&dst_buf[..BLOCK_SIZE_128 * i])?;
                dst.write_all(&cipher_text)?;
                break 'main;
            } else {
                let cipher_text = cipher.encrypt(block);
                dst_buf[BLOCK_SIZE_128 * i..BLOCK_SIZE_128 * (i + 1)].copy_from_slice(&cipher_text);
            }
        }
        dst.write_all(&dst_buf)?;
    }
    Ok(())
}

fn narrowway192_ecb_encrypt<R, W>(
    src: &mut R,
    dst: &mut W,
    key: [u8; BLOCK_SIZE_192],
) -> IOResult<()>
where
    R: Read,
    W: Write,
{
    let cipher = Cipher192::new(key);

    'main: loop {
        let mut blocks = vec![0; BLOCK_SIZE_192 * BUFF_BLOCKS];
        let buf_size = src.read(&mut blocks)?;

        if buf_size == 0 {
            let zero_block = [0; BLOCK_SIZE_192];
            let cipher_text = cipher.encrypt(zero_block);
            dst.write_all(&cipher_text)?;
            break;
        }

        let mut dst_buf = vec![0; BLOCK_SIZE_192 * BUFF_BLOCKS];
        for i in 0..BUFF_BLOCKS {
            let mut block = [0; BLOCK_SIZE_192];
            let size = std::cmp::min(BLOCK_SIZE_192, buf_size - i * BLOCK_SIZE_192);
            block.copy_from_slice(&blocks[BLOCK_SIZE_192 * i..BLOCK_SIZE_192 * (i + 1)]);

            if size < BLOCK_SIZE_192 {
                for byte in block[size..].iter_mut() {
                    *byte = size as u8;
                }
                let cipher_text = cipher.encrypt(block);
                dst.write_all(&dst_buf[..BLOCK_SIZE_192 * i])?;
                dst.write_all(&cipher_text)?;
                break 'main;
            } else {
                let cipher_text = cipher.encrypt(block);
                dst_buf[BLOCK_SIZE_192 * i..BLOCK_SIZE_192 * (i + 1)].copy_from_slice(&cipher_text);
            }
        }
        dst.write_all(&dst_buf)?;
    }
    Ok(())
}

fn narrowway256_ecb_encrypt<R, W>(
    src: &mut R,
    dst: &mut W,
    key: [u8; BLOCK_SIZE_256],
) -> IOResult<()>
where
    R: Read,
    W: Write,
{
    let cipher = Cipher256::new(key);

    'main: loop {
        let mut blocks = vec![0; BLOCK_SIZE_256 * BUFF_BLOCKS];
        let buf_size = src.read(&mut blocks)?;

        if buf_size == 0 {
            let zero_block = [0; BLOCK_SIZE_256];
            let cipher_text = cipher.encrypt(zero_block);
            dst.write_all(&cipher_text)?;
            break;
        }

        let mut dst_buf = vec![0; BLOCK_SIZE_256 * BUFF_BLOCKS];
        for i in 0..BUFF_BLOCKS {
            let mut block = [0; BLOCK_SIZE_256];
            let size = std::cmp::min(BLOCK_SIZE_256, buf_size - i * BLOCK_SIZE_256);
            block.copy_from_slice(&blocks[BLOCK_SIZE_256 * i..BLOCK_SIZE_256 * (i + 1)]);

            if size < BLOCK_SIZE_256 {
                for byte in block[size..].iter_mut() {
                    *byte = size as u8;
                }
                let cipher_text = cipher.encrypt(block);
                dst.write_all(&dst_buf[..BLOCK_SIZE_256 * i])?;
                dst.write_all(&cipher_text)?;
                break 'main;
            } else {
                let cipher_text = cipher.encrypt(block);
                dst_buf[BLOCK_SIZE_256 * i..BLOCK_SIZE_256 * (i + 1)].copy_from_slice(&cipher_text);
            }
        }
        dst.write_all(&dst_buf)?;
    }
    Ok(())
}

fn narrowway128_ecb_decrypt<R>(
    src: &mut R,
    dst: &mut File,
    key: [u8; BLOCK_SIZE_128],
) -> IOResult<()>
where
    R: Read,
{
    let cipher = Cipher128::new(key);

    let mut block = [0; BLOCK_SIZE_128];
    loop {
        let mut blocks = vec![0; BLOCK_SIZE_128 * BUFF_BLOCKS];
        let buf_size = src.read(&mut blocks)?;

        if buf_size == 0 {
            let plain_text = cipher.decrypt(block);
            dst.set_len(
                dst.metadata()?.len()
                    - (BLOCK_SIZE_128 - plain_text[BLOCK_SIZE_128 - 1] as usize) as u64,
            )?;
            break;
        }

        let mut dst_buf = vec![0; BLOCK_SIZE_128 * BUFF_BLOCKS];
        for i in 0..buf_size / BLOCK_SIZE_128 {
            block.copy_from_slice(&blocks[BLOCK_SIZE_128 * i..BLOCK_SIZE_128 * (i + 1)]);
            let plain_text = cipher.decrypt(block);
            dst_buf[BLOCK_SIZE_128 * i..BLOCK_SIZE_128 * (i + 1)].copy_from_slice(&plain_text);
        }
        dst.write_all(&dst_buf[..buf_size])?;
    }
    Ok(())
}

fn narrowway192_ecb_decrypt<R>(
    src: &mut R,
    dst: &mut File,
    key: [u8; BLOCK_SIZE_192],
) -> IOResult<()>
where
    R: Read,
{
    let cipher = Cipher192::new(key);

    let mut block = [0; BLOCK_SIZE_192];
    loop {
        let mut blocks = vec![0; BLOCK_SIZE_192 * BUFF_BLOCKS];
        let buf_size = src.read(&mut blocks)?;

        if buf_size == 0 {
            let plain_text = cipher.decrypt(block);
            dst.set_len(
                dst.metadata()?.len()
                    - (BLOCK_SIZE_192 - plain_text[BLOCK_SIZE_192 - 1] as usize) as u64,
            )?;
            break;
        }

        let mut dst_buf = vec![0; BLOCK_SIZE_192 * BUFF_BLOCKS];
        for i in 0..buf_size / BLOCK_SIZE_192 {
            block.copy_from_slice(&blocks[BLOCK_SIZE_192 * i..BLOCK_SIZE_192 * (i + 1)]);
            let plain_text = cipher.decrypt(block);
            dst_buf[BLOCK_SIZE_192 * i..BLOCK_SIZE_192 * (i + 1)].copy_from_slice(&plain_text);
        }
        dst.write_all(&dst_buf[..buf_size])?;
    }
    Ok(())
}

fn narrowway256_ecb_decrypt<R>(
    src: &mut R,
    dst: &mut File,
    key: [u8; BLOCK_SIZE_256],
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
            let cipher_text = cipher.decrypt(block);
            dst.set_len(
                dst.metadata()?.len()
                    - (BLOCK_SIZE_256 - cipher_text[BLOCK_SIZE_256 - 1] as usize) as u64,
            )?;
            break;
        }

        let mut dst_buf = vec![0; BLOCK_SIZE_256 * BUFF_BLOCKS];
        for i in 0..buf_size / BLOCK_SIZE_256 {
            block.copy_from_slice(&blocks[BLOCK_SIZE_256 * i..BLOCK_SIZE_256 * (i + 1)]);
            let plain_text = cipher.decrypt(block);
            dst_buf[BLOCK_SIZE_256 * i..BLOCK_SIZE_256 * (i + 1)].copy_from_slice(&plain_text);
        }
        dst.write_all(&dst_buf[..buf_size])?;
    }
    Ok(())
}

fn narrowway128_cbc_encrypt<R, W>(
    src: &mut R,
    dst: &mut W,
    key: [u8; BLOCK_SIZE_128],
    mut iv: [u8; BLOCK_SIZE_128],
) -> IOResult<()>
where
    R: Read,
    W: Write,
{
    let cipher = Cipher128::new(key);

    'main: loop {
        let mut blocks = vec![0; BLOCK_SIZE_128 * BUFF_BLOCKS];
        let buf_size = src.read(&mut blocks)?;

        if buf_size == 0 {
            let cipher_text = cipher.encrypt(iv); // iv = zero_block xor iv
            dst.write_all(&cipher_text)?;
            break;
        }

        let mut dst_buf = vec![0; BLOCK_SIZE_128 * BUFF_BLOCKS];
        for i in 0..BUFF_BLOCKS {
            let mut block = [0; BLOCK_SIZE_128];
            let size = std::cmp::min(BLOCK_SIZE_128, buf_size - i * BLOCK_SIZE_128);
            block.copy_from_slice(&blocks[BLOCK_SIZE_128 * i..BLOCK_SIZE_128 * (i + 1)]);

            if size < BLOCK_SIZE_128 {
                for byte in block[size..].iter_mut() {
                    *byte = size as u8;
                }
                for (i, byte) in block.iter_mut().enumerate() {
                    *byte ^= iv[i];
                }
                let cipher_text = cipher.encrypt(block);
                dst.write_all(&dst_buf[..BLOCK_SIZE_128 * i])?;
                dst.write_all(&cipher_text)?;
                break 'main;
            } else {
                for (i, byte) in block.iter_mut().enumerate() {
                    *byte ^= iv[i];
                }
                let cipher_text = cipher.encrypt(block);
                dst_buf[BLOCK_SIZE_128 * i..BLOCK_SIZE_128 * (i + 1)].copy_from_slice(&cipher_text);

                iv = cipher_text;
            }
        }
        dst.write_all(&dst_buf[..buf_size])?;
    }
    Ok(())
}

fn narrowway192_cbc_encrypt<R, W>(
    src: &mut R,
    dst: &mut W,
    key: [u8; BLOCK_SIZE_192],
    mut iv: [u8; BLOCK_SIZE_192],
) -> IOResult<()>
where
    R: Read,
    W: Write,
{
    let cipher = Cipher192::new(key);

    'main: loop {
        let mut blocks = vec![0; BLOCK_SIZE_192 * BUFF_BLOCKS];
        let buf_size = src.read(&mut blocks)?;

        if buf_size == 0 {
            let cipher_text = cipher.encrypt(iv); // iv = zero_block xor iv
            dst.write_all(&cipher_text)?;
            break;
        }

        let mut dst_buf = vec![0; BLOCK_SIZE_192 * BUFF_BLOCKS];
        for i in 0..BUFF_BLOCKS {
            let mut block = [0; BLOCK_SIZE_192];
            let size = std::cmp::min(BLOCK_SIZE_192, buf_size - i * BLOCK_SIZE_192);
            block.copy_from_slice(&blocks[BLOCK_SIZE_192 * i..BLOCK_SIZE_192 * (i + 1)]);

            if size < BLOCK_SIZE_192 {
                for byte in block[size..].iter_mut() {
                    *byte = size as u8;
                }
                for (i, byte) in block.iter_mut().enumerate() {
                    *byte ^= iv[i];
                }
                let cipher_text = cipher.encrypt(block);
                dst.write_all(&dst_buf[..BLOCK_SIZE_192 * i])?;
                dst.write_all(&cipher_text)?;
                break 'main;
            } else {
                for (i, byte) in block.iter_mut().enumerate() {
                    *byte ^= iv[i];
                }
                let cipher_text = cipher.encrypt(block);
                dst_buf[BLOCK_SIZE_192 * i..BLOCK_SIZE_192 * (i + 1)].copy_from_slice(&cipher_text);

                for (i, byte) in cipher_text.iter().enumerate() {
                    iv[i] = *byte;
                }
            }
        }
        dst.write_all(&dst_buf)?;
    }
    Ok(())
}

fn narrowway256_cbc_encrypt<R, W>(
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

        if buf_size == 0 {
            let cipher_text = cipher.encrypt(iv); // iv = zero_block xor iv
            dst.write_all(&cipher_text)?;
            break;
        }

        let mut dst_buf = vec![0; BLOCK_SIZE_256 * BUFF_BLOCKS];
        for i in 0..BUFF_BLOCKS {
            let mut block = [0; BLOCK_SIZE_256];
            let size = std::cmp::min(BLOCK_SIZE_256, buf_size - i * BLOCK_SIZE_256);
            block.copy_from_slice(&blocks[BLOCK_SIZE_256 * i..BLOCK_SIZE_256 * (i + 1)]);

            if size < BLOCK_SIZE_256 {
                for byte in block[size..].iter_mut() {
                    *byte = size as u8;
                }
                for (i, byte) in block.iter_mut().enumerate() {
                    *byte ^= iv[i];
                }
                let cipher_text = cipher.encrypt(block);
                dst.write_all(&dst_buf[..BLOCK_SIZE_256 * i])?;
                dst.write_all(&cipher_text)?;
                break 'main;
            } else {
                for (i, byte) in block.iter_mut().enumerate() {
                    *byte ^= iv[i];
                }
                let cipher_text = cipher.encrypt(block);
                dst_buf[BLOCK_SIZE_256 * i..BLOCK_SIZE_256 * (i + 1)].copy_from_slice(&cipher_text);

                for (i, byte) in cipher_text.iter().enumerate() {
                    iv[i] = *byte;
                }
            }
        }
        dst.write_all(&dst_buf)?;
    }
    Ok(())
}

fn narrowway128_cbc_decrypt<R>(
    src: &mut R,
    dst: &mut File,
    key: [u8; BLOCK_SIZE_128],
    mut iv: [u8; BLOCK_SIZE_128],
) -> IOResult<()>
where
    R: Read,
{
    let cipher = Cipher128::new(key);

    let mut old_iv = iv;
    let mut block = [0; BLOCK_SIZE_128];
    loop {
        let mut blocks = vec![0; BLOCK_SIZE_128 * BUFF_BLOCKS];
        let buf_size = src.read(&mut blocks)?;

        if buf_size == 0 {
            let mut plain_text = cipher.decrypt(block);
            for (i, byte) in plain_text.iter_mut().enumerate() {
                *byte ^= old_iv[i];
            }
            dst.set_len(
                dst.metadata()?.len()
                    - (BLOCK_SIZE_128 - plain_text[BLOCK_SIZE_128 - 1] as usize) as u64,
            )?;
            break;
        }

        let mut dst_buf = vec![0; BLOCK_SIZE_128 * BUFF_BLOCKS];
        for i in 0..buf_size / BLOCK_SIZE_128 {
            block.copy_from_slice(&blocks[BLOCK_SIZE_128 * i..BLOCK_SIZE_128 * (i + 1)]);
            old_iv = iv;
            iv = block;
            let mut plain_text = cipher.decrypt(block);
            for (i, byte) in plain_text.iter_mut().enumerate() {
                *byte ^= old_iv[i];
            }
            dst_buf[BLOCK_SIZE_128 * i..BLOCK_SIZE_128 * (i + 1)].copy_from_slice(&plain_text);
        }
        dst.write_all(&dst_buf[..buf_size])?;
    }
    Ok(())
}

fn narrowway192_cbc_decrypt<R>(
    src: &mut R,
    dst: &mut File,
    key: [u8; BLOCK_SIZE_192],
    mut iv: [u8; BLOCK_SIZE_192],
) -> IOResult<()>
where
    R: Read,
{
    let cipher = Cipher192::new(key);

    let mut old_iv = iv;
    let mut block = [0; BLOCK_SIZE_192];
    loop {
        let mut blocks = vec![0; BLOCK_SIZE_192 * BUFF_BLOCKS];
        let buf_size = src.read(&mut blocks)?;

        if buf_size == 0 {
            let mut plain_text = cipher.decrypt(block);
            for (i, byte) in plain_text.iter_mut().enumerate() {
                *byte ^= old_iv[i];
            }
            dst.set_len(
                dst.metadata()?.len()
                    - (BLOCK_SIZE_192 - plain_text[BLOCK_SIZE_192 - 1] as usize) as u64,
            )?;
            break;
        }

        let mut dst_buf = vec![0; BLOCK_SIZE_192 * BUFF_BLOCKS];
        for i in 0..buf_size / BLOCK_SIZE_192 {
            block.copy_from_slice(&blocks[BLOCK_SIZE_192 * i..BLOCK_SIZE_192 * (i + 1)]);
            old_iv = iv;
            iv = block;
            let mut plain_text = cipher.decrypt(block);
            for (i, byte) in plain_text.iter_mut().enumerate() {
                *byte ^= old_iv[i];
            }
            dst_buf[BLOCK_SIZE_192 * i..BLOCK_SIZE_192 * (i + 1)].copy_from_slice(&plain_text);
        }
        dst.write_all(&dst_buf[..buf_size])?;
    }
    Ok(())
}

fn narrowway256_cbc_decrypt<R>(
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
            dst.set_len(
                dst.metadata()?.len()
                    - (BLOCK_SIZE_256 - plain_text[BLOCK_SIZE_256 - 1] as usize) as u64,
            )?;
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

fn main() -> IOResult<()> {
    let args = Args::parse();

    let output_name;
    match args.command {
        Command::Encrypt => match args.output {
            Some(ref out) => output_name = out.to_owned(),
            None => output_name = format!("{}.nw", args.input),
        },
        Command::Decrypt => match args.output {
            Some(ref out) => output_name = out.to_owned(),
            None => output_name = args.input[..args.input.len() - 3].to_string(),
        },
    }

    let mut src = OpenOptions::new().read(true).open(&args.input)?;
    let mut dst = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(output_name)?;

    let orig_key;

    if let Some(k) = args.key {
        orig_key = k;
    } else {
        orig_key = std::fs::read_to_string(args.key_file.unwrap())?;
    }

    match args.command {
        Command::Encrypt => match args.algorithm {
            Algorithm::Narrowway128 => match args.block_mode {
                BlockMode::Ecb => {
                    dst.write_all(
                        &Format {
                            key_size: KEY_SIZE_128,
                            block_mode: BLOCK_MODE_ECB,
                        }
                        .dump(),
                    )?;

                    let mut key = [0; BLOCK_SIZE_128];
                    key[..std::cmp::min(orig_key.len(), BLOCK_SIZE_128)].copy_from_slice(
                        &orig_key.as_bytes()[..std::cmp::min(orig_key.len(), BLOCK_SIZE_128)],
                    );
                    narrowway128_ecb_encrypt(&mut src, &mut dst, key)?;
                }
                BlockMode::Cbc => {
                    dst.write_all(
                        &Format {
                            key_size: KEY_SIZE_128,
                            block_mode: BLOCK_MODE_CBC,
                        }
                        .dump(),
                    )?;

                    let mut key = [0; BLOCK_SIZE_128];
                    key[..std::cmp::min(orig_key.len(), BLOCK_SIZE_128)].copy_from_slice(
                        &orig_key.as_bytes()[..std::cmp::min(orig_key.len(), BLOCK_SIZE_128)],
                    );

                    let mut iv = [0; BLOCK_SIZE_128];
                    for byte in &mut iv {
                        *byte = rand::random();
                    }
                    dst.write_all(&iv)?;
                    narrowway128_cbc_encrypt(&mut src, &mut dst, key, iv)?;
                }
            },
            Algorithm::Narrowway192 => match args.block_mode {
                BlockMode::Ecb => {
                    dst.write_all(
                        &Format {
                            key_size: KEY_SIZE_192,
                            block_mode: BLOCK_MODE_ECB,
                        }
                        .dump(),
                    )?;

                    let mut key = [0; BLOCK_SIZE_192];
                    key[..std::cmp::min(orig_key.len(), BLOCK_SIZE_192)].copy_from_slice(
                        &orig_key.as_bytes()[..std::cmp::min(orig_key.len(), BLOCK_SIZE_192)],
                    );
                    narrowway192_ecb_encrypt(&mut src, &mut dst, key)?;
                }
                BlockMode::Cbc => {
                    dst.write_all(
                        &Format {
                            key_size: KEY_SIZE_192,
                            block_mode: BLOCK_MODE_CBC,
                        }
                        .dump(),
                    )?;

                    let mut key = [0; BLOCK_SIZE_192];
                    key[..std::cmp::min(orig_key.len(), BLOCK_SIZE_192)].copy_from_slice(
                        &orig_key.as_bytes()[..std::cmp::min(orig_key.len(), BLOCK_SIZE_192)],
                    );

                    let mut iv = [0; BLOCK_SIZE_192];
                    for byte in &mut iv {
                        *byte = rand::random();
                    }
                    dst.write_all(&iv)?;
                    narrowway192_cbc_encrypt(&mut src, &mut dst, key, iv)?;
                }
            },
            Algorithm::Narrowway256 => match args.block_mode {
                BlockMode::Ecb => {
                    dst.write_all(
                        &Format {
                            key_size: KEY_SIZE_256,
                            block_mode: BLOCK_MODE_ECB,
                        }
                        .dump(),
                    )?;

                    let mut key = [0; BLOCK_SIZE_256];
                    key[..std::cmp::min(orig_key.len(), BLOCK_SIZE_256)].copy_from_slice(
                        &orig_key.as_bytes()[..std::cmp::min(orig_key.len(), BLOCK_SIZE_256)],
                    );
                    narrowway256_ecb_encrypt(&mut src, &mut dst, key)?;
                }
                BlockMode::Cbc => {
                    dst.write_all(
                        &Format {
                            key_size: KEY_SIZE_256,
                            block_mode: BLOCK_MODE_CBC,
                        }
                        .dump(),
                    )?;

                    let mut key = [0; BLOCK_SIZE_256];
                    key[..std::cmp::min(orig_key.len(), BLOCK_SIZE_256)].copy_from_slice(
                        &orig_key.as_bytes()[..std::cmp::min(orig_key.len(), BLOCK_SIZE_256)],
                    );

                    let mut iv = [0; BLOCK_SIZE_256];
                    for byte in &mut iv {
                        *byte = rand::random();
                    }
                    dst.write_all(&iv)?;
                    narrowway256_cbc_encrypt(&mut src, &mut dst, key, iv)?;
                }
            },
        },
        Command::Decrypt => {
            let mut header = [0; 2];
            src.read_exact(&mut header)?;
            let header = Format::load(&header);

            match header.key_size {
                KEY_SIZE_128 => match header.block_mode {
                    BLOCK_MODE_ECB => {
                        let mut key = [0; BLOCK_SIZE_128];
                        key[..std::cmp::min(orig_key.len(), BLOCK_SIZE_128)].copy_from_slice(
                            &orig_key.as_bytes()[..std::cmp::min(orig_key.len(), BLOCK_SIZE_128)],
                        );
                        narrowway128_ecb_decrypt(&mut src, &mut dst, key)?;
                    }
                    BLOCK_MODE_CBC => {
                        let mut key = [0; BLOCK_SIZE_128];
                        key[..std::cmp::min(orig_key.len(), BLOCK_SIZE_128)].copy_from_slice(
                            &orig_key.as_bytes()[..std::cmp::min(orig_key.len(), BLOCK_SIZE_128)],
                        );

                        let mut iv = [0; BLOCK_SIZE_128];
                        src.read_exact(&mut iv)?;
                        narrowway128_cbc_decrypt(&mut src, &mut dst, key, iv)?;
                    }
                    _ => {}
                },
                KEY_SIZE_192 => match header.block_mode {
                    BLOCK_MODE_ECB => {
                        let mut key = [0; BLOCK_SIZE_192];
                        key[..std::cmp::min(orig_key.len(), BLOCK_SIZE_192)].copy_from_slice(
                            &orig_key.as_bytes()[..std::cmp::min(orig_key.len(), BLOCK_SIZE_192)],
                        );
                        narrowway192_ecb_decrypt(&mut src, &mut dst, key)?;
                    }
                    BLOCK_MODE_CBC => {
                        let mut key = [0; BLOCK_SIZE_192];
                        key[..std::cmp::min(orig_key.len(), BLOCK_SIZE_192)].copy_from_slice(
                            &orig_key.as_bytes()[..std::cmp::min(orig_key.len(), BLOCK_SIZE_192)],
                        );

                        let mut iv = [0; BLOCK_SIZE_192];
                        src.read_exact(&mut iv)?;
                        narrowway192_cbc_decrypt(&mut src, &mut dst, key, iv)?;
                    }
                    _ => {}
                },
                KEY_SIZE_256 => match header.block_mode {
                    BLOCK_MODE_ECB => {
                        let mut key = [0; BLOCK_SIZE_256];
                        key[..std::cmp::min(orig_key.len(), BLOCK_SIZE_256)].copy_from_slice(
                            &orig_key.as_bytes()[..std::cmp::min(orig_key.len(), BLOCK_SIZE_256)],
                        );
                        narrowway256_ecb_decrypt(&mut src, &mut dst, key)?;
                    }
                    BLOCK_MODE_CBC => {
                        let mut key = [0; BLOCK_SIZE_256];
                        key[..std::cmp::min(orig_key.len(), BLOCK_SIZE_256)].copy_from_slice(
                            &orig_key.as_bytes()[..std::cmp::min(orig_key.len(), BLOCK_SIZE_256)],
                        );

                        let mut iv = [0; BLOCK_SIZE_256];
                        src.read_exact(&mut iv)?;
                        narrowway256_cbc_decrypt(&mut src, &mut dst, key, iv)?;
                    }
                    _ => {}
                },
                _ => {}
            }
        }
    }

    if !args.keep {
        std::fs::remove_file(&args.input)?;
    }

    Ok(())
}
