use clap::{Parser, Subcommand};
use crypto::{
    aes::{ecb_decryptor, ecb_encryptor},
    blockmodes::PkcsPadding,
    buffer::{ReadBuffer, RefReadBuffer, RefWriteBuffer, WriteBuffer},
};

#[derive(Parser)]
#[command(name = "aes-codec", version = "5.0", about = "用于加解密AES命令行工具")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// 加密
    Encode {
        /// 用于加密的密钥
        #[arg(short, long)]
        key: String,

        /// 原始内容
        #[arg(short, long)]
        input: String,
    },
    /// 解密
    Decode {
        /// 用于解密的密钥
        #[arg(short, long)]
        key: String,

        /// 被加密的内容
        #[arg(short, long)]
        input: String,
    },
}

fn encode(key: &str, input: &str) -> String {
    let key_bytes: &[u8] = key.as_bytes();
    let mut encryptor = ecb_encryptor(crypto::aes::KeySize::KeySize256, key_bytes, PkcsPadding);
    let mut buffer = [0; 4096];
    let mut write_buffer = RefWriteBuffer::new(&mut buffer);
    let mut read_buffer = RefReadBuffer::new(input.as_bytes());
    let mut final_result = Vec::new();
    loop {
        let result = encryptor
            .encrypt(&mut read_buffer, &mut write_buffer, true)
            .expect("");
        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );
        match result {
            crypto::buffer::BufferResult::BufferUnderflow => break,
            _ => continue,
        }
    }
    hex::encode(final_result)
}

fn decode(key: &str, input: &str) -> String {
    let key_bytes: &[u8] = key.as_bytes();
    let mut decryptor = ecb_decryptor(crypto::aes::KeySize::KeySize256, key_bytes, PkcsPadding);
    let mut buffer = [0; 4096];
    let mut write_buffer = RefWriteBuffer::new(&mut buffer);
    let input_vec_u8 = hex::decode(input).expect("input decode hex error");
    let mut read_buffer = RefReadBuffer::new(input_vec_u8.as_slice());
    let mut final_result = Vec::new();
    loop {
        let result = decryptor
            .decrypt(&mut read_buffer, &mut write_buffer, true)
            .expect("");
        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );
        match result {
            crypto::buffer::BufferResult::BufferUnderflow => break,
            _ => continue,
        }
    }
    String::from_utf8(final_result).expect("")
}

fn main() {
    let cli = Cli::parse();
    match &cli.command {
        Some(Commands::Encode { key, input }) => {
            println!("{}", encode(key, input))
        }
        Some(Commands::Decode { key, input }) => {
            println!("{}", decode(key, input))
        }
        None => {}
    }
}
