mod cbc_mode;
pub mod common;
mod ecb_mode;
mod format;
mod key;
mod ofb_mode;

use clap::{Parser, Subcommand, ValueEnum};
use std::fs::OpenOptions;
use std::io::{Read, Result as IOResult, Write};

use cbc_mode::*;
use common::*;
use ecb_mode::*;
use ofb_mode::*;

use crate::format::*;

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
    Ofb,
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
                    BlockMode::Ofb => {
                        if !args.raw {
                            dst.write_all(
                                &Format {
                                    key_size: KEY_SIZE_256,
                                    block_mode: BLOCK_MODE_OFB,
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
                        narrowway256_ofb_encrypt(&mut src, &mut dst, key, iv)?;
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
                    BlockMode::Ofb => {
                        if !args.raw {
                            dst.write_all(
                                &Format {
                                    key_size: KEY_SIZE_384,
                                    block_mode: BLOCK_MODE_OFB,
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
                        narrowway384_ofb_encrypt(&mut src, &mut dst, key, iv)?;
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
                    BlockMode::Ofb => {
                        if !args.raw {
                            dst.write_all(
                                &Format {
                                    key_size: KEY_SIZE_512,
                                    block_mode: BLOCK_MODE_OFB,
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
                        narrowway512_ofb_encrypt(&mut src, &mut dst, key, iv)?;
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
                    BLOCK_MODE_OFB => args.block_mode = BlockMode::Ofb,
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
                    BlockMode::Ofb => {
                        let key = key::gen_key_256(header.salt, &orig_key);

                        let mut iv = [0; BLOCK_SIZE_256];
                        src.read_exact(&mut iv)?;
                        narrowway256_ofb_decrypt(&mut src, &mut dst, key, iv)?;
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
                    BlockMode::Ofb => {
                        let key = key::gen_key_384(header.salt, &orig_key);

                        let mut iv = [0; BLOCK_SIZE_384];
                        src.read_exact(&mut iv)?;
                        narrowway384_ofb_decrypt(&mut src, &mut dst, key, iv)?;
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
                    BlockMode::Ofb => {
                        let key = key::gen_key_512(header.salt, &orig_key);

                        let mut iv = [0; BLOCK_SIZE_512];
                        src.read_exact(&mut iv)?;
                        narrowway512_ofb_decrypt(&mut src, &mut dst, key, iv)?;
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
