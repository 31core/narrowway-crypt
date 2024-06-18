mod format;
mod key;

use clap::{Parser, Subcommand, ValueEnum};
use narrowway::*;
use std::fs::{File, OpenOptions};
use std::io::{Read, Result as IOResult, Write};

use crate::format::*;

const BUFF_BLOCKS: usize = 16 * 1024;

const BLOCK_SIZE_256: usize = 32;
const BLOCK_SIZE_384: usize = 48;
const BLOCK_SIZE_512: usize = 64;

#[derive(Clone, ValueEnum)]
enum Algorithm {
    #[value(name = "256")]
    Narrowway256,
    #[value(name = "384")]
    Narrowway384,
    #[value(name = "512")]
    Narrowway512,
}

#[derive(Clone, ValueEnum)]
enum BlockMode {
    Ecb,
    Cbc,
}

#[derive(Parser)]
#[command(
    author = "31core",
    about = "NarrowWay encryption/decryption utility",
    version
)]
struct Args {
    #[command(subcommand)]
    command: Command,
    #[arg(short, long, default_value = "512")]
    algorithm: Algorithm,
    #[arg(short, long, default_value = "cbc")]
    block_mode: BlockMode,
    /// Keep source file
    #[arg(short, long)]
    keep: bool,
    /// Do not store/read file header
    #[arg(short, long)]
    raw: bool,
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

fn narrowway384_ecb_encrypt<R, W>(
    src: &mut R,
    dst: &mut W,
    key: [u8; BLOCK_SIZE_384],
) -> IOResult<()>
where
    R: Read,
    W: Write,
{
    let cipher = Cipher384::new(key);

    'main: loop {
        let mut blocks = vec![0; BLOCK_SIZE_384 * BUFF_BLOCKS];
        let buf_size = src.read(&mut blocks)?;

        if buf_size == 0 {
            let zero_block = [0; BLOCK_SIZE_384];
            let cipher_text = cipher.encrypt(zero_block);
            dst.write_all(&cipher_text)?;
            break;
        }

        let mut dst_buf = vec![0; BLOCK_SIZE_384 * BUFF_BLOCKS];
        for i in 0..BUFF_BLOCKS {
            let mut block = [0; BLOCK_SIZE_384];
            let size = std::cmp::min(BLOCK_SIZE_384, buf_size - i * BLOCK_SIZE_384);
            block.copy_from_slice(&blocks[BLOCK_SIZE_384 * i..BLOCK_SIZE_384 * (i + 1)]);

            if size < BLOCK_SIZE_384 {
                for byte in block[size..].iter_mut() {
                    *byte = size as u8;
                }
                let cipher_text = cipher.encrypt(block);
                dst.write_all(&dst_buf[..BLOCK_SIZE_384 * i])?;
                dst.write_all(&cipher_text)?;
                break 'main;
            } else {
                let cipher_text = cipher.encrypt(block);
                dst_buf[BLOCK_SIZE_384 * i..BLOCK_SIZE_384 * (i + 1)].copy_from_slice(&cipher_text);
            }
        }
        dst.write_all(&dst_buf)?;
    }
    Ok(())
}

fn narrowway512_ecb_encrypt<R, W>(
    src: &mut R,
    dst: &mut W,
    key: [u8; BLOCK_SIZE_512],
) -> IOResult<()>
where
    R: Read,
    W: Write,
{
    let cipher = Cipher512::new(key);

    'main: loop {
        let mut blocks = vec![0; BLOCK_SIZE_512 * BUFF_BLOCKS];
        let buf_size = src.read(&mut blocks)?;

        if buf_size == 0 {
            let zero_block = [0; BLOCK_SIZE_512];
            let cipher_text = cipher.encrypt(zero_block);
            dst.write_all(&cipher_text)?;
            break;
        }

        let mut dst_buf = vec![0; BLOCK_SIZE_512 * BUFF_BLOCKS];
        for i in 0..BUFF_BLOCKS {
            let mut block = [0; BLOCK_SIZE_512];
            let size = std::cmp::min(BLOCK_SIZE_512, buf_size - i * BLOCK_SIZE_512);
            block.copy_from_slice(&blocks[BLOCK_SIZE_512 * i..BLOCK_SIZE_512 * (i + 1)]);

            if size < BLOCK_SIZE_512 {
                for byte in block[size..].iter_mut() {
                    *byte = size as u8;
                }
                let cipher_text = cipher.encrypt(block);
                dst.write_all(&dst_buf[..BLOCK_SIZE_512 * i])?;
                dst.write_all(&cipher_text)?;
                break 'main;
            } else {
                let cipher_text = cipher.encrypt(block);
                dst_buf[BLOCK_SIZE_512 * i..BLOCK_SIZE_512 * (i + 1)].copy_from_slice(&cipher_text);
            }
        }
        dst.write_all(&dst_buf)?;
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
            let plain_text = cipher.decrypt(block);
            dst.set_len(
                dst.metadata()?.len()
                    - (BLOCK_SIZE_256 - plain_text[BLOCK_SIZE_256 - 1] as usize) as u64,
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

fn narrowway384_ecb_decrypt<R>(
    src: &mut R,
    dst: &mut File,
    key: [u8; BLOCK_SIZE_384],
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
            let plain_text = cipher.decrypt(block);
            dst.set_len(
                dst.metadata()?.len()
                    - (BLOCK_SIZE_384 - plain_text[BLOCK_SIZE_384 - 1] as usize) as u64,
            )?;
            break;
        }

        let mut dst_buf = vec![0; BLOCK_SIZE_384 * BUFF_BLOCKS];
        for i in 0..buf_size / BLOCK_SIZE_384 {
            block.copy_from_slice(&blocks[BLOCK_SIZE_384 * i..BLOCK_SIZE_384 * (i + 1)]);
            let plain_text = cipher.decrypt(block);
            dst_buf[BLOCK_SIZE_384 * i..BLOCK_SIZE_384 * (i + 1)].copy_from_slice(&plain_text);
        }
        dst.write_all(&dst_buf[..buf_size])?;
    }
    Ok(())
}

fn narrowway512_ecb_decrypt<R>(
    src: &mut R,
    dst: &mut File,
    key: [u8; BLOCK_SIZE_512],
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
            let cipher_text = cipher.decrypt(block);
            dst.set_len(
                dst.metadata()?.len()
                    - (BLOCK_SIZE_512 - cipher_text[BLOCK_SIZE_512 - 1] as usize) as u64,
            )?;
            break;
        }

        let mut dst_buf = vec![0; BLOCK_SIZE_512 * BUFF_BLOCKS];
        for i in 0..buf_size / BLOCK_SIZE_512 {
            block.copy_from_slice(&blocks[BLOCK_SIZE_512 * i..BLOCK_SIZE_512 * (i + 1)]);
            let plain_text = cipher.decrypt(block);
            dst_buf[BLOCK_SIZE_512 * i..BLOCK_SIZE_512 * (i + 1)].copy_from_slice(&plain_text);
        }
        dst.write_all(&dst_buf[..buf_size])?;
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

                iv = cipher_text;
            }
        }
        dst.write_all(&dst_buf[..buf_size])?;
    }
    Ok(())
}

fn narrowway384_cbc_encrypt<R, W>(
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

        if buf_size == 0 {
            let cipher_text = cipher.encrypt(iv); // iv = zero_block xor iv
            dst.write_all(&cipher_text)?;
            break;
        }

        let mut dst_buf = vec![0; BLOCK_SIZE_384 * BUFF_BLOCKS];
        for i in 0..BUFF_BLOCKS {
            let mut block = [0; BLOCK_SIZE_384];
            let size = std::cmp::min(BLOCK_SIZE_384, buf_size - i * BLOCK_SIZE_384);
            block.copy_from_slice(&blocks[BLOCK_SIZE_384 * i..BLOCK_SIZE_384 * (i + 1)]);

            if size < BLOCK_SIZE_384 {
                for byte in block[size..].iter_mut() {
                    *byte = size as u8;
                }
                for (i, byte) in block.iter_mut().enumerate() {
                    *byte ^= iv[i];
                }
                let cipher_text = cipher.encrypt(block);
                dst.write_all(&dst_buf[..BLOCK_SIZE_384 * i])?;
                dst.write_all(&cipher_text)?;
                break 'main;
            } else {
                for (i, byte) in block.iter_mut().enumerate() {
                    *byte ^= iv[i];
                }
                let cipher_text = cipher.encrypt(block);
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

fn narrowway512_cbc_encrypt<R, W>(
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

        if buf_size == 0 {
            let cipher_text = cipher.encrypt(iv); // iv = zero_block xor iv
            dst.write_all(&cipher_text)?;
            break;
        }

        let mut dst_buf = vec![0; BLOCK_SIZE_512 * BUFF_BLOCKS];
        for i in 0..BUFF_BLOCKS {
            let mut block = [0; BLOCK_SIZE_512];
            let size = std::cmp::min(BLOCK_SIZE_512, buf_size - i * BLOCK_SIZE_512);
            block.copy_from_slice(&blocks[BLOCK_SIZE_512 * i..BLOCK_SIZE_512 * (i + 1)]);

            if size < BLOCK_SIZE_512 {
                for byte in block[size..].iter_mut() {
                    *byte = size as u8;
                }
                for (i, byte) in block.iter_mut().enumerate() {
                    *byte ^= iv[i];
                }
                let cipher_text = cipher.encrypt(block);
                dst.write_all(&dst_buf[..BLOCK_SIZE_512 * i])?;
                dst.write_all(&cipher_text)?;
                break 'main;
            } else {
                for (i, byte) in block.iter_mut().enumerate() {
                    *byte ^= iv[i];
                }
                let cipher_text = cipher.encrypt(block);
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

fn narrowway384_cbc_decrypt<R>(
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
            dst.set_len(
                dst.metadata()?.len()
                    - (BLOCK_SIZE_384 - plain_text[BLOCK_SIZE_384 - 1] as usize) as u64,
            )?;
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

fn narrowway512_cbc_decrypt<R>(
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
            dst.set_len(
                dst.metadata()?.len()
                    - (BLOCK_SIZE_512 - plain_text[BLOCK_SIZE_512 - 1] as usize) as u64,
            )?;
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

fn main() -> IOResult<()> {
    let mut args = Args::parse();

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

    let orig_key = if let Some(k) = args.key {
        k.as_bytes().to_vec()
    } else {
        std::fs::read(args.key_file.unwrap())?
    };

    match args.command {
        Command::Encrypt => {
            let salt = rand::random();
            match args.algorithm {
                Algorithm::Narrowway256 => match args.block_mode {
                    BlockMode::Ecb => {
                        if !args.raw {
                            dst.write_all(
                                &Format {
                                    key_size: KEY_SIZE_256,
                                    block_mode: BLOCK_MODE_ECB,
                                    salt,
                                }
                                .dump(),
                            )?;
                        }

                        let key = key::gen_key_256(salt, &orig_key);
                        narrowway256_ecb_encrypt(&mut src, &mut dst, key)?;
                    }
                    BlockMode::Cbc => {
                        if !args.raw {
                            dst.write_all(
                                &Format {
                                    key_size: KEY_SIZE_256,
                                    block_mode: BLOCK_MODE_CBC,
                                    salt,
                                }
                                .dump(),
                            )?;
                        }

                        let key = key::gen_key_256(salt, &orig_key);

                        let mut iv = [0; BLOCK_SIZE_256];
                        for byte in &mut iv {
                            *byte = rand::random();
                        }
                        dst.write_all(&iv)?;
                        narrowway256_cbc_encrypt(&mut src, &mut dst, key, iv)?;
                    }
                },
                Algorithm::Narrowway384 => match args.block_mode {
                    BlockMode::Ecb => {
                        if !args.raw {
                            dst.write_all(
                                &Format {
                                    key_size: KEY_SIZE_384,
                                    block_mode: BLOCK_MODE_ECB,
                                    salt,
                                }
                                .dump(),
                            )?;
                        }

                        let key = key::gen_key_384(salt, &orig_key);
                        narrowway384_ecb_encrypt(&mut src, &mut dst, key)?;
                    }
                    BlockMode::Cbc => {
                        if !args.raw {
                            dst.write_all(
                                &Format {
                                    key_size: KEY_SIZE_384,
                                    block_mode: BLOCK_MODE_CBC,
                                    salt,
                                }
                                .dump(),
                            )?;
                        }

                        let key = key::gen_key_384(salt, &orig_key);

                        let mut iv = [0; BLOCK_SIZE_384];
                        for byte in &mut iv {
                            *byte = rand::random();
                        }
                        dst.write_all(&iv)?;
                        narrowway384_cbc_encrypt(&mut src, &mut dst, key, iv)?;
                    }
                },
                Algorithm::Narrowway512 => match args.block_mode {
                    BlockMode::Ecb => {
                        if !args.raw {
                            dst.write_all(
                                &Format {
                                    key_size: KEY_SIZE_512,
                                    block_mode: BLOCK_MODE_ECB,
                                    salt,
                                }
                                .dump(),
                            )?;
                        }

                        let key = key::gen_key_512(salt, &orig_key);
                        narrowway512_ecb_encrypt(&mut src, &mut dst, key)?;
                    }
                    BlockMode::Cbc => {
                        if !args.raw {
                            dst.write_all(
                                &Format {
                                    key_size: KEY_SIZE_512,
                                    block_mode: BLOCK_MODE_CBC,
                                    salt,
                                }
                                .dump(),
                            )?;
                        }

                        let key = key::gen_key_512(salt, &orig_key);

                        let mut iv = [0; BLOCK_SIZE_512];
                        for byte in &mut iv {
                            *byte = rand::random();
                        }
                        dst.write_all(&iv)?;
                        narrowway512_cbc_encrypt(&mut src, &mut dst, key, iv)?;
                    }
                },
            }
        }
        Command::Decrypt => {
            let mut header = [0; 24];
            src.read_exact(&mut header)?;
            let header = Format::load(&header);

            if !args.raw {
                match header.key_size {
                    KEY_SIZE_256 => args.algorithm = Algorithm::Narrowway256,
                    KEY_SIZE_384 => args.algorithm = Algorithm::Narrowway384,
                    KEY_SIZE_512 => args.algorithm = Algorithm::Narrowway512,
                    _ => {}
                }

                match header.block_mode {
                    BLOCK_MODE_CBC => args.block_mode = BlockMode::Cbc,
                    BLOCK_MODE_ECB => args.block_mode = BlockMode::Ecb,
                    _ => {}
                }
            }

            match args.algorithm {
                Algorithm::Narrowway256 => match args.block_mode {
                    BlockMode::Ecb => {
                        let key = key::gen_key_256(header.salt, &orig_key);
                        narrowway256_ecb_decrypt(&mut src, &mut dst, key)?;
                    }
                    BlockMode::Cbc => {
                        let key = key::gen_key_256(header.salt, &orig_key);

                        let mut iv = [0; BLOCK_SIZE_256];
                        src.read_exact(&mut iv)?;
                        narrowway256_cbc_decrypt(&mut src, &mut dst, key, iv)?;
                    }
                },
                Algorithm::Narrowway384 => match args.block_mode {
                    BlockMode::Ecb => {
                        let key = key::gen_key_384(header.salt, &orig_key);
                        narrowway384_ecb_decrypt(&mut src, &mut dst, key)?;
                    }
                    BlockMode::Cbc => {
                        let key = key::gen_key_384(header.salt, &orig_key);

                        let mut iv = [0; BLOCK_SIZE_384];
                        src.read_exact(&mut iv)?;
                        narrowway384_cbc_decrypt(&mut src, &mut dst, key, iv)?;
                    }
                },
                Algorithm::Narrowway512 => match args.block_mode {
                    BlockMode::Ecb => {
                        let key = key::gen_key_512(header.salt, &orig_key);
                        narrowway512_ecb_decrypt(&mut src, &mut dst, key)?;
                    }
                    BlockMode::Cbc => {
                        let key = key::gen_key_512(header.salt, &orig_key);

                        let mut iv = [0; BLOCK_SIZE_512];
                        src.read_exact(&mut iv)?;
                        narrowway512_cbc_decrypt(&mut src, &mut dst, key, iv)?;
                    }
                },
            }
        }
    }

    if !args.keep {
        std::fs::remove_file(&args.input)?;
    }

    Ok(())
}
