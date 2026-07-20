//! Byte-transform recipe engine (encode/cipher/compress peels).

use crate::analyzers::crypt_constants::aes_sbox;
use crate::inflate::{gunzip, inflate_auto};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BakeOp {
    pub op: String,
    #[serde(default)]
    pub args: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BakeResult {
    pub ok: bool,
    pub output_hex: String,
    pub output_utf8: Option<String>,
    pub message: String,
    #[serde(default)]
    pub recipe_applied: Vec<String>,
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn from_hex(s: &str) -> Result<Vec<u8>, String> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.len() % 2 != 0 {
        return Err("hex length must be even".into());
    }
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn b64_decode(input: &[u8]) -> Result<Vec<u8>, String> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' | b'-' => Some(62),
            b'/' | b'_' => Some(63),
            b'=' => Some(0),
            _ if c.is_ascii_whitespace() => None,
            _ => None,
        }
    }
    let mut chars = Vec::new();
    for &c in input {
        if c == b'=' || c.is_ascii_whitespace() {
            if c == b'=' {
                chars.push(c);
            }
            continue;
        }
        if val(c).is_none() {
            return Err(format!("invalid base64 byte {c:#x}"));
        }
        chars.push(c);
    }
    while chars.len() % 4 != 0 {
        chars.push(b'=');
    }
    let mut out = Vec::with_capacity(chars.len() / 4 * 3);
    for chunk in chars.chunks(4) {
        let (a, b, c, d) = (
            val(chunk[0]).unwrap_or(0),
            val(chunk[1]).unwrap_or(0),
            val(chunk[2]).unwrap_or(0),
            val(chunk[3]).unwrap_or(0),
        );
        out.push((a << 2) | (b >> 4));
        if chunk[2] != b'=' {
            out.push((b << 4) | (c >> 2));
        }
        if chunk[3] != b'=' {
            out.push((c << 6) | d);
        }
    }
    Ok(out)
}

fn xor_key(data: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }
    data.iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect()
}

fn rc4(data: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    if key.is_empty() {
        return Err("RC4 key empty".into());
    }
    let mut s: Vec<u8> = (0..=255).collect();
    let mut j: usize = 0;
    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) & 255;
        s.swap(i, j);
    }
    let mut i = 0usize;
    j = 0;
    let mut out = Vec::with_capacity(data.len());
    for &b in data {
        i = (i + 1) & 255;
        j = (j + s[i] as usize) & 255;
        s.swap(i, j);
        let k = s[(s[i] as usize + s[j] as usize) & 255];
        out.push(b ^ k);
    }
    Ok(out)
}

fn mul(a: u8, b: u8) -> u8 {
    let mut a = a;
    let mut b = b;
    let mut p = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    p
}

fn aes_add_round_key(state: &mut [u8; 16], rk: &[u8]) {
    for i in 0..16 {
        state[i] ^= rk[i];
    }
}

fn aes_key_expand_128(key: &[u8; 16]) -> [[u8; 16]; 11] {
    let s = aes_sbox();
    let rcon = [0x01u8, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
    let mut w = [0u8; 176];
    w[..16].copy_from_slice(key);
    let mut bytes_generated = 16usize;
    let mut rcon_i = 0usize;
    let mut temp = [0u8; 4];
    while bytes_generated < 176 {
        temp.copy_from_slice(&w[bytes_generated - 4..bytes_generated]);
        if bytes_generated % 16 == 0 {
            // rot word
            temp = [temp[1], temp[2], temp[3], temp[0]];
            for t in temp.iter_mut() {
                *t = s[*t as usize];
            }
            temp[0] ^= rcon[rcon_i];
            rcon_i += 1;
        }
        for i in 0..4 {
            w[bytes_generated] = w[bytes_generated - 16] ^ temp[i];
            bytes_generated += 1;
        }
    }
    let mut rounds = [[0u8; 16]; 11];
    for r in 0..11 {
        rounds[r].copy_from_slice(&w[r * 16..(r + 1) * 16]);
    }
    rounds
}

fn aes_inv_sbox() -> [u8; 256] {
    let mut inv = [0u8; 256];
    let s = aes_sbox();
    for (i, &v) in s.iter().enumerate() {
        inv[v as usize] = i as u8;
    }
    inv
}

fn aes_inv_sub_bytes(state: &mut [u8; 16], inv: &[u8; 256]) {
    for b in state.iter_mut() {
        *b = inv[*b as usize];
    }
}

fn aes_inv_shift_rows(state: &mut [u8; 16]) {
    let t = *state;
    state[1] = t[13];
    state[5] = t[1];
    state[9] = t[5];
    state[13] = t[9];
    state[2] = t[10];
    state[6] = t[14];
    state[10] = t[2];
    state[14] = t[6];
    state[3] = t[7];
    state[7] = t[11];
    state[11] = t[15];
    state[15] = t[3];
}

fn aes_inv_mix_columns(state: &mut [u8; 16]) {
    for c in 0..4 {
        let i = c * 4;
        let a0 = state[i];
        let a1 = state[i + 1];
        let a2 = state[i + 2];
        let a3 = state[i + 3];
        state[i] = mul(a0, 0x0e) ^ mul(a1, 0x0b) ^ mul(a2, 0x0d) ^ mul(a3, 0x09);
        state[i + 1] = mul(a0, 0x09) ^ mul(a1, 0x0e) ^ mul(a2, 0x0b) ^ mul(a3, 0x0d);
        state[i + 2] = mul(a0, 0x0d) ^ mul(a1, 0x09) ^ mul(a2, 0x0e) ^ mul(a3, 0x0b);
        state[i + 3] = mul(a0, 0x0b) ^ mul(a1, 0x0d) ^ mul(a2, 0x09) ^ mul(a3, 0x0e);
    }
}

fn aes_sub_bytes(state: &mut [u8; 16], sbox: &[u8; 256]) {
    for b in state.iter_mut() {
        *b = sbox[*b as usize];
    }
}

fn aes_shift_rows(state: &mut [u8; 16]) {
    let t = *state;
    state[1] = t[5];
    state[5] = t[9];
    state[9] = t[13];
    state[13] = t[1];
    state[2] = t[10];
    state[6] = t[14];
    state[10] = t[2];
    state[14] = t[6];
    state[3] = t[15];
    state[7] = t[3];
    state[11] = t[7];
    state[15] = t[11];
}

fn aes_mix_columns(state: &mut [u8; 16]) {
    for c in 0..4 {
        let i = c * 4;
        let a0 = state[i];
        let a1 = state[i + 1];
        let a2 = state[i + 2];
        let a3 = state[i + 3];
        state[i] = mul(a0, 2) ^ mul(a1, 3) ^ a2 ^ a3;
        state[i + 1] = a0 ^ mul(a1, 2) ^ mul(a2, 3) ^ a3;
        state[i + 2] = a0 ^ a1 ^ mul(a2, 2) ^ mul(a3, 3);
        state[i + 3] = mul(a0, 3) ^ a1 ^ a2 ^ mul(a3, 2);
    }
}

fn aes_encrypt_block_128(block: &[u8; 16], round_keys: &[[u8; 16]; 11]) -> [u8; 16] {
    let sbox = aes_sbox();
    let mut state = *block;
    aes_add_round_key(&mut state, &round_keys[0]);
    for round in 1..10 {
        aes_sub_bytes(&mut state, sbox);
        aes_shift_rows(&mut state);
        aes_mix_columns(&mut state);
        aes_add_round_key(&mut state, &round_keys[round]);
    }
    aes_sub_bytes(&mut state, sbox);
    aes_shift_rows(&mut state);
    aes_add_round_key(&mut state, &round_keys[10]);
    state
}

fn aes_decrypt_block_128(block: &[u8; 16], round_keys: &[[u8; 16]; 11]) -> [u8; 16] {
    let inv = aes_inv_sbox();
    let mut state = *block;
    aes_add_round_key(&mut state, &round_keys[10]);
    for round in (1..10).rev() {
        aes_inv_shift_rows(&mut state);
        aes_inv_sub_bytes(&mut state, &inv);
        aes_add_round_key(&mut state, &round_keys[round]);
        aes_inv_mix_columns(&mut state);
    }
    aes_inv_shift_rows(&mut state);
    aes_inv_sub_bytes(&mut state, &inv);
    aes_add_round_key(&mut state, &round_keys[0]);
    state
}

fn aes_decrypt(data: &[u8], key: &[u8], iv: Option<&[u8]>, mode: &str) -> Result<Vec<u8>, String> {
    if key.len() != 16 {
        return Err("AES-128 key must be 16 bytes".into());
    }
    if data.is_empty() {
        return Err("AES ciphertext empty".into());
    }
    let mut key_arr = [0u8; 16];
    key_arr.copy_from_slice(key);
    let rk = aes_key_expand_128(&key_arr);
    let mode = mode.to_ascii_lowercase();
    let mut out = Vec::with_capacity(data.len());

    match mode.as_str() {
        "ecb" => {
            if data.len() % 16 != 0 {
                return Err("AES-ECB length must be a multiple of 16".into());
            }
            for chunk in data.chunks(16) {
                let mut blk = [0u8; 16];
                blk.copy_from_slice(chunk);
                out.extend_from_slice(&aes_decrypt_block_128(&blk, &rk));
            }
            Ok(out)
        }
        "cbc" => {
            if data.len() % 16 != 0 {
                return Err("AES-CBC length must be a multiple of 16".into());
            }
            let iv = iv.ok_or_else(|| "AES-CBC requires iv".to_string())?;
            if iv.len() != 16 {
                return Err("AES IV must be 16 bytes".into());
            }
            let mut prev = [0u8; 16];
            prev.copy_from_slice(iv);
            for chunk in data.chunks(16) {
                let mut blk = [0u8; 16];
                blk.copy_from_slice(chunk);
                let plain = aes_decrypt_block_128(&blk, &rk);
                let mut xored = [0u8; 16];
                for i in 0..16 {
                    xored[i] = plain[i] ^ prev[i];
                }
                out.extend_from_slice(&xored);
                prev = blk;
            }
            Ok(out)
        }
        "ctr" | "gcm" => {
            // GCM decrypts with CTR. Authentication is intentionally not claimed here:
            // callers must verify a supplied tag before trusting the returned plaintext.
            let iv = iv.ok_or_else(|| format!("AES-{mode} requires iv"))?;
            let mut counter = [0u8; 16];
            if iv.len() == 16 {
                counter.copy_from_slice(iv);
            } else if iv.len() == 12 {
                counter[..12].copy_from_slice(iv);
                counter[15] = 1;
            } else {
                return Err("AES CTR/GCM IV must be 12 or 16 bytes".into());
            }
            if mode == "gcm" {
                increment_be(&mut counter);
            }
            for chunk in data.chunks(16) {
                let keystream = aes_encrypt_block_128(&counter, &rk);
                for (i, &b) in chunk.iter().enumerate() {
                    out.push(b ^ keystream[i]);
                }
                // increment counter (big-endian)
                increment_be(&mut counter);
            }
            Ok(out)
        }
        "cfb" => {
            let iv = iv.ok_or_else(|| "AES-CFB requires iv".to_string())?;
            if iv.len() != 16 {
                return Err("AES IV must be 16 bytes".into());
            }
            let mut prev = [0u8; 16];
            prev.copy_from_slice(iv);
            for chunk in data.chunks(16) {
                let keystream = aes_encrypt_block_128(&prev, &rk);
                let mut plain = vec![0u8; chunk.len()];
                for i in 0..chunk.len() {
                    plain[i] = chunk[i] ^ keystream[i];
                }
                // CFB feedback is ciphertext
                if chunk.len() == 16 {
                    prev.copy_from_slice(chunk);
                } else {
                    prev[..chunk.len()].copy_from_slice(chunk);
                }
                out.extend_from_slice(&plain);
            }
            Ok(out)
        }
        "ofb" => {
            let iv = iv.ok_or_else(|| "AES-OFB requires iv".to_string())?;
            if iv.len() != 16 {
                return Err("AES IV must be 16 bytes".into());
            }
            let mut prev = [0u8; 16];
            prev.copy_from_slice(iv);
            for chunk in data.chunks(16) {
                prev = aes_encrypt_block_128(&prev, &rk);
                for (i, &b) in chunk.iter().enumerate() {
                    out.push(b ^ prev[i]);
                }
            }
            Ok(out)
        }
        other => Err(format!("unsupported AES mode: {other}")),
    }
}

fn increment_be(counter: &mut [u8; 16]) {
    for i in (0..16).rev() {
        counter[i] = counter[i].wrapping_add(1);
        if counter[i] != 0 {
            break;
        }
    }
}

const BLOWFISH_P_INIT: [u32; 18] = [
    0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
    0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c, 0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917,
    0x9216d5d9, 0x8979fb1b,
];
const BLOWFISH_S_INIT: [[u32; 256]; 4] = [
    [
        0xd1310ba6, 0x98dfb5ac, 0x2ffd72db, 0xd01adfb7, 0xb8e1afed, 0x6a267e96, 0xba7c9045,
        0xf12c7f99, 0x24a19947, 0xb3916cf7, 0x0801f2e2, 0x858efc16, 0x636920d8, 0x71574e69,
        0xa458fea3, 0xf4933d7e, 0x0d95748f, 0x728eb658, 0x718bcd58, 0x82154aee, 0x7b54a41d,
        0xc25a59b5, 0x9c30d539, 0x2af26013, 0xc5d1b023, 0x286085f0, 0xca417918, 0xb8db38ef,
        0x8e79dcb0, 0x603a180e, 0x6c9e0e8b, 0xb01e8a3e, 0xd71577c1, 0xbd314b27, 0x78af2fda,
        0x55605c60, 0xe65525f3, 0xaa55ab94, 0x57489862, 0x63e81440, 0x55ca396a, 0x2aab10b6,
        0xb4cc5c34, 0x1141e8ce, 0xa15486af, 0x7c72e993, 0xb3ee1411, 0x636fbc2a, 0x2ba9c55d,
        0x741831f6, 0xce5c3e16, 0x9b87931e, 0xafd6ba33, 0x6c24cf5c, 0x7a325381, 0x28958677,
        0x3b8f4898, 0x6b4bb9af, 0xc4bfe81b, 0x66282193, 0x61d809cc, 0xfb21a991, 0x487cac60,
        0x5dec8032, 0xef845d5d, 0xe98575b1, 0xdc262302, 0xeb651b88, 0x23893e81, 0xd396acc5,
        0x0f6d6ff3, 0x83f44239, 0x2e0b4482, 0xa4842004, 0x69c8f04a, 0x9e1f9b5e, 0x21c66842,
        0xf6e96c9a, 0x670c9c61, 0xabd388f0, 0x6a51a0d2, 0xd8542f68, 0x960fa728, 0xab5133a3,
        0x6eef0b6c, 0x137a3be4, 0xba3bf050, 0x7efb2a98, 0xa1f1651d, 0x39af0176, 0x66ca593e,
        0x82430e88, 0x8cee8619, 0x456f9fb4, 0x7d84a5c3, 0x3b8b5ebe, 0xe06f75d8, 0x85c12073,
        0x401a449f, 0x56c16aa6, 0x4ed3aa62, 0x363f7706, 0x1bfedf72, 0x429b023d, 0x37d0d724,
        0xd00a1248, 0xdb0fead3, 0x49f1c09b, 0x075372c9, 0x80991b7b, 0x25d479d8, 0xf6e8def7,
        0xe3fe501a, 0xb6794c3b, 0x976ce0bd, 0x04c006ba, 0xc1a94fb6, 0x409f60c4, 0x5e5c9ec2,
        0x196a2463, 0x68fb6faf, 0x3e6c53b5, 0x1339b2eb, 0x3b52ec6f, 0x6dfc511f, 0x9b30952c,
        0xcc814544, 0xaf5ebd09, 0xbee3d004, 0xde334afd, 0x660f2807, 0x192e4bb3, 0xc0cba857,
        0x45c8740f, 0xd20b5f39, 0xb9d3fbdb, 0x5579c0bd, 0x1a60320a, 0xd6a100c6, 0x402c7279,
        0x679f25fe, 0xfb1fa3cc, 0x8ea5e9f8, 0xdb3222f8, 0x3c7516df, 0xfd616b15, 0x2f501ec8,
        0xad0552ab, 0x323db5fa, 0xfd238760, 0x53317b48, 0x3e00df82, 0x9e5c57bb, 0xca6f8ca0,
        0x1a87562e, 0xdf1769db, 0xd542a8f6, 0x287effc3, 0xac6732c6, 0x8c4f5573, 0x695b27b0,
        0xbbca58c8, 0xe1ffa35d, 0xb8f011a0, 0x10fa3d98, 0xfd2183b8, 0x4afcb56c, 0x2dd1d35b,
        0x9a53e479, 0xb6f84565, 0xd28e49bc, 0x4bfb9790, 0xe1ddf2da, 0xa4cb7e33, 0x62fb1341,
        0xcee4c6e8, 0xef20cada, 0x36774c01, 0xd07e9efe, 0x2bf11fb4, 0x95dbda4d, 0xae909198,
        0xeaad8e71, 0x6b93d5a0, 0xd08ed1d0, 0xafc725e0, 0x8e3c5b2f, 0x8e7594b7, 0x8ff6e2fb,
        0xf2122b64, 0x8888b812, 0x900df01c, 0x4fad5ea0, 0x688fc31c, 0xd1cff191, 0xb3a8c1ad,
        0x2f2f2218, 0xbe0e1777, 0xea752dfe, 0x8b021fa1, 0xe5a0cc0f, 0xb56f74e8, 0x18acf3d6,
        0xce89e299, 0xb4a84fe0, 0xfd13e0b7, 0x7cc43b81, 0xd2ada8d9, 0x165fa266, 0x80957705,
        0x93cc7314, 0x211a1477, 0xe6ad2065, 0x77b5fa86, 0xc75442f5, 0xfb9d35cf, 0xebcdaf0c,
        0x7b3e89a0, 0xd6411bd3, 0xae1e7e49, 0x00250e2d, 0x2071b35e, 0x226800bb, 0x57b8e0af,
        0x2464369b, 0xf009b91e, 0x5563911d, 0x59dfa6aa, 0x78c14389, 0xd95a537f, 0x207d5ba2,
        0x02e5b9c5, 0x83260376, 0x6295cfa9, 0x11c81968, 0x4e734a41, 0xb3472dca, 0x7b14a94a,
        0x1b510052, 0x9a532915, 0xd60f573f, 0xbc9bc6e4, 0x2b60a476, 0x81e67400, 0x08ba6fb5,
        0x571be91f, 0xf296ec6b, 0x2a0dd915, 0xb6636521, 0xe7b9f9b6, 0xff34052e, 0xc5855664,
        0x53b02d5d, 0xa99f8fa1, 0x08ba4799, 0x6e85076a,
    ],
    [
        0x4b7a70e9, 0xb5b32944, 0xdb75092e, 0xc4192623, 0xad6ea6b0, 0x49a7df7d, 0x9cee60b8,
        0x8fedb266, 0xecaa8c71, 0x699a17ff, 0x5664526c, 0xc2b19ee1, 0x193602a5, 0x75094c29,
        0xa0591340, 0xe4183a3e, 0x3f54989a, 0x5b429d65, 0x6b8fe4d6, 0x99f73fd6, 0xa1d29c07,
        0xefe830f5, 0x4d2d38e6, 0xf0255dc1, 0x4cdd2086, 0x8470eb26, 0x6382e9c6, 0x021ecc5e,
        0x09686b3f, 0x3ebaefc9, 0x3c971814, 0x6b6a70a1, 0x687f3584, 0x52a0e286, 0xb79c5305,
        0xaa500737, 0x3e07841c, 0x7fdeae5c, 0x8e7d44ec, 0x5716f2b8, 0xb03ada37, 0xf0500c0d,
        0xf01c1f04, 0x0200b3ff, 0xae0cf51a, 0x3cb574b2, 0x25837a58, 0xdc0921bd, 0xd19113f9,
        0x7ca92ff6, 0x94324773, 0x22f54701, 0x3ae5e581, 0x37c2dadc, 0xc8b57634, 0x9af3dda7,
        0xa9446146, 0x0fd0030e, 0xecc8c73e, 0xa4751e41, 0xe238cd99, 0x3bea0e2f, 0x3280bba1,
        0x183eb331, 0x4e548b38, 0x4f6db908, 0x6f420d03, 0xf60a04bf, 0x2cb81290, 0x24977c79,
        0x5679b072, 0xbcaf89af, 0xde9a771f, 0xd9930810, 0xb38bae12, 0xdccf3f2e, 0x5512721f,
        0x2e6b7124, 0x501adde6, 0x9f84cd87, 0x7a584718, 0x7408da17, 0xbc9f9abc, 0xe94b7d8c,
        0xec7aec3a, 0xdb851dfa, 0x63094366, 0xc464c3d2, 0xef1c1847, 0x3215d908, 0xdd433b37,
        0x24c2ba16, 0x12a14d43, 0x2a65c451, 0x50940002, 0x133ae4dd, 0x71dff89e, 0x10314e55,
        0x81ac77d6, 0x5f11199b, 0x043556f1, 0xd7a3c76b, 0x3c11183b, 0x5924a509, 0xf28fe6ed,
        0x97f1fbfa, 0x9ebabf2c, 0x1e153c6e, 0x86e34570, 0xeae96fb1, 0x860e5e0a, 0x5a3e2ab3,
        0x771fe71c, 0x4e3d06fa, 0x2965dcb9, 0x99e71d0f, 0x803e89d6, 0x5266c825, 0x2e4cc978,
        0x9c10b36a, 0xc6150eba, 0x94e2ea78, 0xa5fc3c53, 0x1e0a2df4, 0xf2f74ea7, 0x361d2b3d,
        0x1939260f, 0x19c27960, 0x5223a708, 0xf71312b6, 0xebadfe6e, 0xeac31f66, 0xe3bc4595,
        0xa67bc883, 0xb17f37d1, 0x018cff28, 0xc332ddef, 0xbe6c5aa5, 0x65582185, 0x68ab9802,
        0xeecea50f, 0xdb2f953b, 0x2aef7dad, 0x5b6e2f84, 0x1521b628, 0x29076170, 0xecdd4775,
        0x619f1510, 0x13cca830, 0xeb61bd96, 0x0334fe1e, 0xaa0363cf, 0xb5735c90, 0x4c70a239,
        0xd59e9e0b, 0xcbaade14, 0xeecc86bc, 0x60622ca7, 0x9cab5cab, 0xb2f3846e, 0x648b1eaf,
        0x19bdf0ca, 0xa02369b9, 0x655abb50, 0x40685a32, 0x3c2ab4b3, 0x319ee9d5, 0xc021b8f7,
        0x9b540b19, 0x875fa099, 0x95f7997e, 0x623d7da8, 0xf837889a, 0x97e32d77, 0x11ed935f,
        0x16681281, 0x0e358829, 0xc7e61fd6, 0x96dedfa1, 0x7858ba99, 0x57f584a5, 0x1b227263,
        0x9b83c3ff, 0x1ac24696, 0xcdb30aeb, 0x532e3054, 0x8fd948e4, 0x6dbc3128, 0x58ebf2ef,
        0x34c6ffea, 0xfe28ed61, 0xee7c3c73, 0x5d4a14d9, 0xe864b7e3, 0x42105d14, 0x203e13e0,
        0x45eee2b6, 0xa3aaabea, 0xdb6c4f15, 0xfacb4fd0, 0xc742f442, 0xef6abbb5, 0x654f3b1d,
        0x41cd2105, 0xd81e799e, 0x86854dc7, 0xe44b476a, 0x3d816250, 0xcf62a1f2, 0x5b8d2646,
        0xfc8883a0, 0xc1c7b6a3, 0x7f1524c3, 0x69cb7492, 0x47848a0b, 0x5692b285, 0x095bbf00,
        0xad19489d, 0x1462b174, 0x23820e00, 0x58428d2a, 0x0c55f5ea, 0x1dadf43e, 0x233f7061,
        0x3372f092, 0x8d937e41, 0xd65fecf1, 0x6c223bdb, 0x7cde3759, 0xcbee7460, 0x4085f2a7,
        0xce77326e, 0xa6078084, 0x19f8509e, 0xe8efd855, 0x61d99735, 0xa969a7aa, 0xc50c06c2,
        0x5a04abfc, 0x800bcadc, 0x9e447a2e, 0xc3453484, 0xfdd56705, 0x0e1e9ec9, 0xdb73dbd3,
        0x105588cd, 0x675fda79, 0xe3674340, 0xc5c43465, 0x713e38d8, 0x3d28f89e, 0xf16dff20,
        0x153e21e7, 0x8fb03d4a, 0xe6e39f2b, 0xdb83adf7,
    ],
    [
        0xe93d5a68, 0x948140f7, 0xf64c261c, 0x94692934, 0x411520f7, 0x7602d4f7, 0xbcf46b2e,
        0xd4a20068, 0xd4082471, 0x3320f46a, 0x43b7d4b7, 0x500061af, 0x1e39f62e, 0x97244546,
        0x14214f74, 0xbf8b8840, 0x4d95fc1d, 0x96b591af, 0x70f4ddd3, 0x66a02f45, 0xbfbc09ec,
        0x03bd9785, 0x7fac6dd0, 0x31cb8504, 0x96eb27b3, 0x55fd3941, 0xda2547e6, 0xabca0a9a,
        0x28507825, 0x530429f4, 0x0a2c86da, 0xe9b66dfb, 0x68dc1462, 0xd7486900, 0x680ec0a4,
        0x27a18dee, 0x4f3ffea2, 0xe887ad8c, 0xb58ce006, 0x7af4d6b6, 0xaace1e7c, 0xd3375fec,
        0xce78a399, 0x406b2a42, 0x20fe9e35, 0xd9f385b9, 0xee39d7ab, 0x3b124e8b, 0x1dc9faf7,
        0x4b6d1856, 0x26a36631, 0xeae397b2, 0x3a6efa74, 0xdd5b4332, 0x6841e7f7, 0xca7820fb,
        0xfb0af54e, 0xd8feb397, 0x454056ac, 0xba489527, 0x55533a3a, 0x20838d87, 0xfe6ba9b7,
        0xd096954b, 0x55a867bc, 0xa1159a58, 0xcca92963, 0x99e1db33, 0xa62a4a56, 0x3f3125f9,
        0x5ef47e1c, 0x9029317c, 0xfdf8e802, 0x04272f70, 0x80bb155c, 0x05282ce3, 0x95c11548,
        0xe4c66d22, 0x48c1133f, 0xc70f86dc, 0x07f9c9ee, 0x41041f0f, 0x404779a4, 0x5d886e17,
        0x325f51eb, 0xd59bc0d1, 0xf2bcc18f, 0x41113564, 0x257b7834, 0x602a9c60, 0xdff8e8a3,
        0x1f636c1b, 0x0e12b4c2, 0x02e1329e, 0xaf664fd1, 0xcad18115, 0x6b2395e0, 0x333e92e1,
        0x3b240b62, 0xeebeb922, 0x85b2a20e, 0xe6ba0d99, 0xde720c8c, 0x2da2f728, 0xd0127845,
        0x95b794fd, 0x647d0862, 0xe7ccf5f0, 0x5449a36f, 0x877d48fa, 0xc39dfd27, 0xf33e8d1e,
        0x0a476341, 0x992eff74, 0x3a6f6eab, 0xf4f8fd37, 0xa812dc60, 0xa1ebddf8, 0x991be14c,
        0xdb6e6b0d, 0xc67b5510, 0x6d672c37, 0x2765d43b, 0xdcd0e804, 0xf1290dc7, 0xcc00ffa3,
        0xb5390f92, 0x690fed0b, 0x667b9ffb, 0xcedb7d9c, 0xa091cf0b, 0xd9155ea3, 0xbb132f88,
        0x515bad24, 0x7b9479bf, 0x763bd6eb, 0x37392eb3, 0xcc115979, 0x8026e297, 0xf42e312d,
        0x6842ada7, 0xc66a2b3b, 0x12754ccc, 0x782ef11c, 0x6a124237, 0xb79251e7, 0x06a1bbe6,
        0x4bfb6350, 0x1a6b1018, 0x11caedfa, 0x3d25bdd8, 0xe2e1c3c9, 0x44421659, 0x0a121386,
        0xd90cec6e, 0xd5abea2a, 0x64af674e, 0xda86a85f, 0xbebfe988, 0x64e4c3fe, 0x9dbc8057,
        0xf0f7c086, 0x60787bf8, 0x6003604d, 0xd1fd8346, 0xf6381fb0, 0x7745ae04, 0xd736fccc,
        0x83426b33, 0xf01eab71, 0xb0804187, 0x3c005e5f, 0x77a057be, 0xbde8ae24, 0x55464299,
        0xbf582e61, 0x4e58f48f, 0xf2ddfda2, 0xf474ef38, 0x8789bdc2, 0x5366f9c3, 0xc8b38e74,
        0xb475f255, 0x46fcd9b9, 0x7aeb2661, 0x8b1ddf84, 0x846a0e79, 0x915f95e2, 0x466e598e,
        0x20b45770, 0x8cd55591, 0xc902de4c, 0xb90bace1, 0xbb8205d0, 0x11a86248, 0x7574a99e,
        0xb77f19b6, 0xe0a9dc09, 0x662d09a1, 0xc4324633, 0xe85a1f02, 0x09f0be8c, 0x4a99a025,
        0x1d6efe10, 0x1ab93d1d, 0x0ba5a4df, 0xa186f20f, 0x2868f169, 0xdcb7da83, 0x573906fe,
        0xa1e2ce9b, 0x4fcd7f52, 0x50115e01, 0xa70683fa, 0xa002b5c4, 0x0de6d027, 0x9af88c27,
        0x773f8641, 0xc3604c06, 0x61a806b5, 0xf0177a28, 0xc0f586e0, 0x006058aa, 0x30dc7d62,
        0x11e69ed7, 0x2338ea63, 0x53c2dd94, 0xc2c21634, 0xbbcbee56, 0x90bcb6de, 0xebfc7da1,
        0xce591d76, 0x6f05e409, 0x4b7c0188, 0x39720a3d, 0x7c927c24, 0x86e3725f, 0x724d9db9,
        0x1ac15bb4, 0xd39eb8fc, 0xed545578, 0x08fca5b5, 0xd83d7cd3, 0x4dad0fc4, 0x1e50ef5e,
        0xb161e6f8, 0xa28514d9, 0x6c51133c, 0x6fd5c7e7, 0x56e14ec4, 0x362abfce, 0xddc6c837,
        0xd79a3234, 0x92638212, 0x670efa8e, 0x406000e0,
    ],
    [
        0x3a39ce37, 0xd3faf5cf, 0xabc27737, 0x5ac52d1b, 0x5cb0679e, 0x4fa33742, 0xd3822740,
        0x99bc9bbe, 0xd5118e9d, 0xbf0f7315, 0xd62d1c7e, 0xc700c47b, 0xb78c1b6b, 0x21a19045,
        0xb26eb1be, 0x6a366eb4, 0x5748ab2f, 0xbc946e79, 0xc6a376d2, 0x6549c2c8, 0x530ff8ee,
        0x468dde7d, 0xd5730a1d, 0x4cd04dc6, 0x2939bbdb, 0xa9ba4650, 0xac9526e8, 0xbe5ee304,
        0xa1fad5f0, 0x6a2d519a, 0x63ef8ce2, 0x9a86ee22, 0xc089c2b8, 0x43242ef6, 0xa51e03aa,
        0x9cf2d0a4, 0x83c061ba, 0x9be96a4d, 0x8fe51550, 0xba645bd6, 0x2826a2f9, 0xa73a3ae1,
        0x4ba99586, 0xef5562e9, 0xc72fefd3, 0xf752f7da, 0x3f046f69, 0x77fa0a59, 0x80e4a915,
        0x87b08601, 0x9b09e6ad, 0x3b3ee593, 0xe990fd5a, 0x9e34d797, 0x2cf0b7d9, 0x022b8b51,
        0x96d5ac3a, 0x017da67d, 0xd1cf3ed6, 0x7c7d2d28, 0x1f9f25cf, 0xadf2b89b, 0x5ad6b472,
        0x5a88f54c, 0xe029ac71, 0xe019a5e6, 0x47b0acfd, 0xed93fa9b, 0xe8d3c48d, 0x283b57cc,
        0xf8d56629, 0x79132e28, 0x785f0191, 0xed756055, 0xf7960e44, 0xe3d35e8c, 0x15056dd4,
        0x88f46dba, 0x03a16125, 0x0564f0bd, 0xc3eb9e15, 0x3c9057a2, 0x97271aec, 0xa93a072a,
        0x1b3f6d9b, 0x1e6321f5, 0xf59c66fb, 0x26dcf319, 0x7533d928, 0xb155fdf5, 0x03563482,
        0x8aba3cbb, 0x28517711, 0xc20ad9f8, 0xabcc5167, 0xccad925f, 0x4de81751, 0x3830dc8e,
        0x379d5862, 0x9320f991, 0xea7a90c2, 0xfb3e7bce, 0x5121ce64, 0x774fbe32, 0xa8b6e37e,
        0xc3293d46, 0x48de5369, 0x6413e680, 0xa2ae0810, 0xdd6db224, 0x69852dfd, 0x09072166,
        0xb39a460a, 0x6445c0dd, 0x586cdecf, 0x1c20c8ae, 0x5bbef7dd, 0x1b588d40, 0xccd2017f,
        0x6bb4e3bb, 0xdda26a7e, 0x3a59ff45, 0x3e350a44, 0xbcb4cdd5, 0x72eacea8, 0xfa6484bb,
        0x8d6612ae, 0xbf3c6f47, 0xd29be463, 0x542f5d9e, 0xaec2771b, 0xf64e6370, 0x740e0d8d,
        0xe75b1357, 0xf8721671, 0xaf537d5d, 0x4040cb08, 0x4eb4e2cc, 0x34d2466a, 0x0115af84,
        0xe1b00428, 0x95983a1d, 0x06b89fb4, 0xce6ea048, 0x6f3f3b82, 0x3520ab82, 0x011a1d4b,
        0x277227f8, 0x611560b1, 0xe7933fdc, 0xbb3a792b, 0x344525bd, 0xa08839e1, 0x51ce794b,
        0x2f32c9b7, 0xa01fbac9, 0xe01cc87e, 0xbcc7d1f6, 0xcf0111c3, 0xa1e8aac7, 0x1a908749,
        0xd44fbd9a, 0xd0dadecb, 0xd50ada38, 0x0339c32a, 0xc6913667, 0x8df9317c, 0xe0b12b4f,
        0xf79e59b7, 0x43f5bb3a, 0xf2d519ff, 0x27d9459c, 0xbf97222c, 0x15e6fc2a, 0x0f91fc71,
        0x9b941525, 0xfae59361, 0xceb69ceb, 0xc2a86459, 0x12baa8d1, 0xb6c1075e, 0xe3056a0c,
        0x10d25065, 0xcb03a442, 0xe0ec6e0e, 0x1698db3b, 0x4c98a0be, 0x3278e964, 0x9f1f9532,
        0xe0d392df, 0xd3a0342b, 0x8971f21e, 0x1b0a7441, 0x4ba3348c, 0xc5be7120, 0xc37632d8,
        0xdf359f8d, 0x9b992f2e, 0xe60b6f47, 0x0fe3f11d, 0xe54cda54, 0x1edad891, 0xce6279cf,
        0xcd3e7e6f, 0x1618b166, 0xfd2c1d05, 0x848fd2c5, 0xf6fb2299, 0xf523f357, 0xa6327623,
        0x93a83531, 0x56cccd02, 0xacf08162, 0x5a75ebb5, 0x6e163697, 0x88d273cc, 0xde966292,
        0x81b949d0, 0x4c50901b, 0x71c65614, 0xe6c6c7bd, 0x327a140a, 0x45e1d006, 0xc3f27b9a,
        0xc9aa53fd, 0x62a80f00, 0xbb25bfe2, 0x35bdd2f6, 0x71126905, 0xb2040222, 0xb6cbcf7c,
        0xcd769c2b, 0x53113ec0, 0x1640e3d3, 0x38abbd60, 0x2547adf0, 0xba38209c, 0xf746ce76,
        0x77afa1c5, 0x20756060, 0x85cbfe4e, 0x8ae88dd8, 0x7aaaf9b0, 0x4cf9aa7e, 0x1948c25c,
        0x02fb8a8c, 0x01c36ae4, 0xd6ebe1f9, 0x90d4f869, 0xa65cdea0, 0x3f09252d, 0xc208e69f,
        0xb74e6132, 0xce77e25b, 0x578fdfe3, 0x3ac372e6,
    ],
];

const DES_IP: [u8; 64] = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61,
    53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
];
const DES_FP: [u8; 64] = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
];
const DES_E: [u8; 48] = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18,
    19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
];
const DES_P: [u8; 32] = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19,
    13, 30, 6, 22, 11, 4, 25,
];
const DES_PC1: [u8; 56] = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60,
    52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
];
const DES_PC2: [u8; 48] = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52,
    31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];
const DES_SHIFTS: [u8; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];
const DES_S: [[[u8; 16]; 4]; 8] = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ],
];

fn des_permute(input: u64, input_bits: u8, table: &[u8]) -> u64 {
    table.iter().fold(0, |out, &bit| {
        (out << 1) | ((input >> (input_bits - bit)) & 1)
    })
}

fn des_round_keys(key: &[u8]) -> Result<[u64; 16], String> {
    if key.len() != 8 {
        return Err("DES key must be 8 bytes".into());
    }
    let key = u64::from_be_bytes(key.try_into().expect("checked DES key length"));
    let pc1 = des_permute(key, 64, &DES_PC1);
    let mut c = (pc1 >> 28) as u32;
    let mut d = pc1 as u32 & 0x0fff_ffff;
    let mut round_keys = [0u64; 16];
    for (i, &shift) in DES_SHIFTS.iter().enumerate() {
        c = ((c << shift) | (c >> (28 - shift))) & 0x0fff_ffff;
        d = ((d << shift) | (d >> (28 - shift))) & 0x0fff_ffff;
        round_keys[i] = des_permute((u64::from(c) << 28) | u64::from(d), 56, &DES_PC2);
    }
    Ok(round_keys)
}

fn des_f(right: u32, round_key: u64) -> u32 {
    let x = des_permute(u64::from(right), 32, &DES_E) ^ round_key;
    let mut out = 0u32;
    for (i, sbox) in DES_S.iter().enumerate() {
        let six = ((x >> (42 - i * 6)) & 0x3f) as u8;
        let row = ((six & 0x20) | ((six & 1) << 4)) >> 4;
        let col = (six >> 1) & 0x0f;
        out = (out << 4) | u32::from(sbox[row as usize][col as usize]);
    }
    des_permute(u64::from(out), 32, &DES_P) as u32
}

fn des_crypt_block(block: [u8; 8], round_keys: &[u64; 16], decrypt: bool) -> [u8; 8] {
    let ip = des_permute(u64::from_be_bytes(block), 64, &DES_IP);
    let mut left = (ip >> 32) as u32;
    let mut right = ip as u32;
    for round in 0..16 {
        let key = round_keys[if decrypt { 15 - round } else { round }];
        let next = left ^ des_f(right, key);
        left = right;
        right = next;
    }
    des_permute((u64::from(right) << 32) | u64::from(left), 64, &DES_FP).to_be_bytes()
}

fn decrypt_block_mode<F>(
    data: &[u8],
    iv: Option<&[u8]>,
    mode: &str,
    cipher: &str,
    mut decrypt: F,
) -> Result<Vec<u8>, String>
where
    F: FnMut([u8; 8]) -> [u8; 8],
{
    if data.is_empty() {
        return Err(format!("{cipher} ciphertext empty"));
    }
    if data.len() % 8 != 0 {
        return Err(format!(
            "{cipher} ciphertext length must be a multiple of 8"
        ));
    }
    match mode.to_ascii_lowercase().as_str() {
        "ecb" => Ok(data
            .chunks_exact(8)
            .flat_map(|chunk| decrypt(chunk.try_into().expect("exact block")))
            .collect()),
        "cbc" => {
            let iv = iv.ok_or_else(|| format!("{cipher}-CBC requires iv"))?;
            let mut prev: [u8; 8] = iv
                .try_into()
                .map_err(|_| format!("{cipher} IV must be 8 bytes"))?;
            let mut out = Vec::with_capacity(data.len());
            for chunk in data.chunks_exact(8) {
                let encrypted: [u8; 8] = chunk.try_into().expect("exact block");
                let mut plain = decrypt(encrypted);
                for i in 0..8 {
                    plain[i] ^= prev[i];
                }
                out.extend_from_slice(&plain);
                prev = encrypted;
            }
            Ok(out)
        }
        other => Err(format!("unsupported {cipher} mode: {other}")),
    }
}

fn des_decrypt(data: &[u8], key: &[u8], iv: Option<&[u8]>, mode: &str) -> Result<Vec<u8>, String> {
    let round_keys = des_round_keys(key)?;
    decrypt_block_mode(data, iv, mode, "DES", |block| {
        des_crypt_block(block, &round_keys, true)
    })
}

fn triple_des_decrypt(
    data: &[u8],
    key: &[u8],
    iv: Option<&[u8]>,
    mode: &str,
) -> Result<Vec<u8>, String> {
    let (k1, k2, k3) = match key.len() {
        16 => (&key[..8], &key[8..16], &key[..8]),
        24 => (&key[..8], &key[8..16], &key[16..24]),
        _ => return Err("Triple-DES key must be 16 or 24 bytes".into()),
    };
    let k1 = des_round_keys(k1)?;
    let k2 = des_round_keys(k2)?;
    let k3 = des_round_keys(k3)?;
    decrypt_block_mode(data, iv, mode, "Triple-DES", |block| {
        let block = des_crypt_block(block, &k3, true);
        let block = des_crypt_block(block, &k2, false);
        des_crypt_block(block, &k1, true)
    })
}

struct Blowfish {
    p: [u32; 18],
    s: [[u32; 256]; 4],
}

impl Blowfish {
    fn new(key: &[u8]) -> Result<Self, String> {
        if !(1..=56).contains(&key.len()) {
            return Err("Blowfish key must be 1 to 56 bytes".into());
        }
        let mut state = Self {
            p: BLOWFISH_P_INIT,
            s: BLOWFISH_S_INIT,
        };
        for (i, p) in state.p.iter_mut().enumerate() {
            let mut word = 0u32;
            for j in 0..4 {
                word = (word << 8) | u32::from(key[(i * 4 + j) % key.len()]);
            }
            *p ^= word;
        }
        let mut block = (0, 0);
        for i in (0..18).step_by(2) {
            block = state.encrypt_words(block.0, block.1);
            state.p[i] = block.0;
            state.p[i + 1] = block.1;
        }
        for box_index in 0..4 {
            for i in (0..256).step_by(2) {
                block = state.encrypt_words(block.0, block.1);
                state.s[box_index][i] = block.0;
                state.s[box_index][i + 1] = block.1;
            }
        }
        Ok(state)
    }

    fn f(&self, x: u32) -> u32 {
        ((self.s[0][(x >> 24) as usize].wrapping_add(self.s[1][((x >> 16) & 0xff) as usize]))
            ^ self.s[2][((x >> 8) & 0xff) as usize])
            .wrapping_add(self.s[3][(x & 0xff) as usize])
    }

    fn encrypt_words(&self, mut left: u32, mut right: u32) -> (u32, u32) {
        for i in 0..16 {
            left ^= self.p[i];
            right ^= self.f(left);
            std::mem::swap(&mut left, &mut right);
        }
        std::mem::swap(&mut left, &mut right);
        (left ^ self.p[17], right ^ self.p[16])
    }

    fn decrypt_block(&self, block: [u8; 8]) -> [u8; 8] {
        let value = u64::from_be_bytes(block);
        let (mut left, mut right) = ((value >> 32) as u32, value as u32);
        for i in (2..18).rev() {
            left ^= self.p[i];
            right ^= self.f(left);
            std::mem::swap(&mut left, &mut right);
        }
        std::mem::swap(&mut left, &mut right);
        ((u64::from(left ^ self.p[0]) << 32) | u64::from(right ^ self.p[1])).to_be_bytes()
    }
}

fn blowfish_decrypt(
    data: &[u8],
    key: &[u8],
    iv: Option<&[u8]>,
    mode: &str,
) -> Result<Vec<u8>, String> {
    let cipher = Blowfish::new(key)?;
    decrypt_block_mode(data, iv, mode, "Blowfish", |block| {
        cipher.decrypt_block(block)
    })
}

fn printable_ratio(b: &[u8]) -> f32 {
    if b.is_empty() {
        return 0.0;
    }
    let n = b
        .iter()
        .filter(|&&c| (0x20..=0x7e).contains(&c) || c == b'\n' || c == b'\r' || c == b'\t')
        .count();
    n as f32 / b.len() as f32
}

fn parse_key(args: &serde_json::Value) -> Result<Vec<u8>, String> {
    if let Some(s) = args.get("key_hex").and_then(|v| v.as_str()) {
        return from_hex(s);
    }
    if let Some(s) = args.get("key").and_then(|v| v.as_str()) {
        if args
            .get("key_format")
            .and_then(|v| v.as_str())
            .unwrap_or("utf8")
            .eq_ignore_ascii_case("hex")
        {
            return from_hex(s);
        }
        return Ok(s.as_bytes().to_vec());
    }
    Err("missing key / key_hex".into())
}

fn from_charcode(data: &[u8], encoding: &str) -> Result<Vec<u8>, String> {
    let text =
        std::str::from_utf8(data).map_err(|_| "FromCharcode input is not UTF-8".to_string())?;
    let mut units = Vec::new();
    for part in text.split(|c: char| c == ',' || c == ';' || c.is_ascii_whitespace()) {
        if part.is_empty() {
            continue;
        }
        let part = part.trim();
        let value = part
            .strip_prefix("0x")
            .or_else(|| part.strip_prefix("0X"))
            .map(|v| u32::from_str_radix(v, 16))
            .unwrap_or_else(|| part.parse::<u32>())
            .map_err(|_| format!("invalid character code: {part}"))?;
        let ch =
            char::from_u32(value).ok_or_else(|| format!("invalid Unicode code point: {value}"))?;
        units.push(ch);
    }
    let decoded: String = units.into_iter().collect();
    match encoding.to_ascii_lowercase().as_str() {
        "utf8" | "utf-8" => Ok(decoded.into_bytes()),
        "utf16le" | "utf-16le" => Ok(decoded.encode_utf16().flat_map(u16::to_le_bytes).collect()),
        "utf16be" | "utf-16be" => Ok(decoded.encode_utf16().flat_map(u16::to_be_bytes).collect()),
        other => Err(format!("unsupported FromCharcode encoding: {other}")),
    }
}

fn url_decode(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        match data[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < data.len() => {
                let hex = std::str::from_utf8(&data[i + 1..i + 3])
                    .map_err(|_| "invalid URL escape".to_string())?;
                out.push(
                    u8::from_str_radix(hex, 16).map_err(|_| "invalid URL escape".to_string())?,
                );
                i += 2;
            }
            b'%' => return Err("truncated URL escape".into()),
            b => out.push(b),
        }
        i += 1;
    }
    Ok(out)
}

fn html_entity_decode(data: &[u8]) -> Result<Vec<u8>, String> {
    let text =
        std::str::from_utf8(data).map_err(|_| "HTML entity input is not UTF-8".to_string())?;
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find('&') {
        out.push_str(&rest[..start]);
        rest = &rest[start + 1..];
        let Some(end) = rest.find(';') else {
            out.push('&');
            out.push_str(rest);
            break;
        };
        let entity = &rest[..end];
        let decoded = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" | "#39" => Some('\''),
            _ if entity.starts_with("#x") || entity.starts_with("#X") => {
                u32::from_str_radix(&entity[2..], 16)
                    .ok()
                    .and_then(char::from_u32)
            }
            _ if entity.starts_with('#') => {
                entity[1..].parse::<u32>().ok().and_then(char::from_u32)
            }
            _ => None,
        };
        if let Some(ch) = decoded {
            out.push(ch);
        } else {
            out.push('&');
            out.push_str(entity);
            out.push(';');
        }
        rest = &rest[end + 1..];
    }
    if !rest.is_empty() {
        out.push_str(rest);
    }
    Ok(out.into_bytes())
}

fn chacha20(data: &[u8], key: &[u8], nonce: &[u8], counter: u32) -> Result<Vec<u8>, String> {
    if key.len() != 32 || nonce.len() != 12 {
        return Err("ChaCha20 requires a 32-byte key and 12-byte nonce".into());
    }
    let mut state = [0u32; 16];
    state[..4].copy_from_slice(&[0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574]);
    for (i, word) in key.chunks_exact(4).enumerate() {
        state[4 + i] = u32::from_le_bytes(word.try_into().unwrap());
    }
    state[12] = counter;
    for (i, word) in nonce.chunks_exact(4).enumerate() {
        state[13 + i] = u32::from_le_bytes(word.try_into().unwrap());
    }
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(64) {
        let mut x = state;
        for _ in 0..10 {
            quarter_round(&mut x, 0, 4, 8, 12);
            quarter_round(&mut x, 1, 5, 9, 13);
            quarter_round(&mut x, 2, 6, 10, 14);
            quarter_round(&mut x, 3, 7, 11, 15);
            quarter_round(&mut x, 0, 5, 10, 15);
            quarter_round(&mut x, 1, 6, 11, 12);
            quarter_round(&mut x, 2, 7, 8, 13);
            quarter_round(&mut x, 3, 4, 9, 14);
        }
        let mut stream = [0u8; 64];
        for i in 0..16 {
            stream[i * 4..i * 4 + 4].copy_from_slice(&x[i].wrapping_add(state[i]).to_le_bytes());
        }
        out.extend(chunk.iter().enumerate().map(|(i, b)| b ^ stream[i]));
        state[12] = state[12]
            .checked_add(1)
            .ok_or_else(|| "ChaCha20 counter exhausted".to_string())?;
    }
    Ok(out)
}

fn quarter_round(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(16);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(12);
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(8);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(7);
}

fn apply_op(data: &[u8], op: &BakeOp) -> Result<Vec<u8>, String> {
    let name = op.op.to_ascii_lowercase().replace([' ', '_'], "");
    match name.as_str() {
        "frombase64" | "base64" => b64_decode(data),
        "fromhex" | "hex" => {
            let s = std::str::from_utf8(data).map_err(|e| e.to_string())?;
            from_hex(s)
        }
        "fromcharcode" | "charcode" => from_charcode(
            data,
            op.args
                .get("encoding")
                .and_then(|v| v.as_str())
                .unwrap_or("utf8"),
        ),
        "urldecode" | "url" => url_decode(data),
        "htmlentitydecode" | "htmlentities" => html_entity_decode(data),
        "xor" => {
            let key = parse_key(&op.args)?;
            Ok(xor_key(data, &key))
        }
        "xorbrute" | "xorbruteforce" => {
            let mut best = data.to_vec();
            let mut best_score = printable_ratio(data);
            for k in 0u8..=255 {
                let cand = xor_key(data, &[k]);
                let score = printable_ratio(&cand);
                if score > best_score {
                    best_score = score;
                    best = cand;
                }
            }
            Ok(best)
        }
        "rc4" => {
            let key = parse_key(&op.args)?;
            rc4(data, &key)
        }
        "chacha20decrypt" | "chacha20" => {
            let key = parse_key(&op.args)?;
            let nonce = op
                .args
                .get("nonce_hex")
                .and_then(|v| v.as_str())
                .map(from_hex)
                .transpose()?
                .or_else(|| {
                    op.args
                        .get("nonce")
                        .and_then(|v| v.as_str())
                        .map(|s| s.as_bytes().to_vec())
                })
                .ok_or_else(|| "ChaCha20 requires nonce / nonce_hex".to_string())?;
            let counter = op.args.get("counter").and_then(|v| v.as_u64()).unwrap_or(0);
            let counter =
                u32::try_from(counter).map_err(|_| "ChaCha20 counter exceeds u32".to_string())?;
            chacha20(data, &key, &nonce, counter)
        }
        "aesdecrypt" | "aes" => {
            let key = parse_key(&op.args)?;
            let mode = op
                .args
                .get("mode")
                .and_then(|v| v.as_str())
                .unwrap_or("cbc");
            let iv = if let Some(s) = op.args.get("iv_hex").and_then(|v| v.as_str()) {
                Some(from_hex(s)?)
            } else if let Some(s) = op.args.get("iv").and_then(|v| v.as_str()) {
                Some(s.as_bytes().to_vec())
            } else {
                None
            };
            aes_decrypt(data, &key, iv.as_deref(), mode)
        }
        "desdecrypt" | "des" => {
            let key = parse_key(&op.args)?;
            let mode = op
                .args
                .get("mode")
                .and_then(|v| v.as_str())
                .unwrap_or("cbc");
            let iv = op
                .args
                .get("iv_hex")
                .and_then(|v| v.as_str())
                .map(from_hex)
                .transpose()?
                .or_else(|| {
                    op.args
                        .get("iv")
                        .and_then(|v| v.as_str())
                        .map(|s| s.as_bytes().to_vec())
                });
            des_decrypt(data, &key, iv.as_deref(), mode)
        }
        "tripledesdecrypt" | "des3decrypt" | "3desdecrypt" | "tripledes" | "des3" | "3des" => {
            let key = parse_key(&op.args)?;
            let mode = op
                .args
                .get("mode")
                .and_then(|v| v.as_str())
                .unwrap_or("cbc");
            let iv = op
                .args
                .get("iv_hex")
                .and_then(|v| v.as_str())
                .map(from_hex)
                .transpose()?
                .or_else(|| {
                    op.args
                        .get("iv")
                        .and_then(|v| v.as_str())
                        .map(|s| s.as_bytes().to_vec())
                });
            triple_des_decrypt(data, &key, iv.as_deref(), mode)
        }
        "blowfishdecrypt" | "blowfish" => {
            let key = parse_key(&op.args)?;
            let mode = op
                .args
                .get("mode")
                .and_then(|v| v.as_str())
                .unwrap_or("cbc");
            let iv = op
                .args
                .get("iv_hex")
                .and_then(|v| v.as_str())
                .map(from_hex)
                .transpose()?
                .or_else(|| {
                    op.args
                        .get("iv")
                        .and_then(|v| v.as_str())
                        .map(|s| s.as_bytes().to_vec())
                });
            blowfish_decrypt(data, &key, iv.as_deref(), mode)
        }
        "rot13" => Ok(data
            .iter()
            .map(|&c| match c {
                b'A'..=b'M' | b'a'..=b'm' => c + 13,
                b'N'..=b'Z' | b'n'..=b'z' => c - 13,
                _ => c,
            })
            .collect()),
        "reverse" => {
            let mut v = data.to_vec();
            v.reverse();
            Ok(v)
        }
        "decodeutf16le" | "utf16le" => {
            if data.len() < 2 {
                return Ok(Vec::new());
            }
            let u16s: Vec<u16> = data
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            Ok(String::from_utf16_lossy(&u16s).into_bytes())
        }
        "gunzip" | "gzip" => gunzip(data),
        "inflate" | "zlib" | "deflate" => inflate_auto(data),
        other => Err(format!("unknown op: {other}")),
    }
}

/// Apply an ordered recipe to input bytes.
pub fn bake(input: &[u8], ops: &[BakeOp]) -> BakeResult {
    let mut cur = input.to_vec();
    let mut applied = Vec::new();
    for op in ops {
        match apply_op(&cur, op) {
            Ok(next) => {
                applied.push(op.op.clone());
                cur = next;
            }
            Err(e) => {
                return BakeResult {
                    ok: false,
                    output_hex: to_hex(&cur),
                    output_utf8: None,
                    message: e,
                    recipe_applied: applied,
                };
            }
        }
    }
    let utf8 = String::from_utf8(cur.clone()).ok();
    BakeResult {
        ok: true,
        output_hex: to_hex(&cur),
        output_utf8: utf8,
        message: format!("applied {} op(s)", applied.len()),
        recipe_applied: applied,
    }
}

/// Try common peels; return best printable result + recipe.
pub fn magic(input: &[u8], depth: usize) -> BakeResult {
    magic_with_crib(input, depth, None)
}

/// Try common peels, increasing a candidate's score when it contains `crib`.
///
/// Search depth is clamped to four and candidates below the input printable ratio
/// are pruned, so this is a bounded heuristic rather than a decrypt oracle.
pub fn magic_with_crib(input: &[u8], depth: usize, crib: Option<&str>) -> BakeResult {
    let depth = depth.clamp(1, 4);
    let mut best = BakeResult {
        ok: true,
        output_hex: to_hex(input),
        output_utf8: String::from_utf8(input.to_vec()).ok(),
        message: "identity".into(),
        recipe_applied: vec![],
    };
    let crib = crib.filter(|s| !s.is_empty());
    let mut best_score = printable_ratio(input)
        + crib
            .filter(|needle| {
                std::str::from_utf8(input)
                    .ok()
                    .is_some_and(|s| s.contains(needle))
            })
            .map_or(0.0, |_| 0.25);

    let candidates: Vec<Vec<BakeOp>> = vec![
        vec![BakeOp {
            op: "FromBase64".into(),
            args: serde_json::json!({}),
        }],
        vec![BakeOp {
            op: "FromHex".into(),
            args: serde_json::json!({}),
        }],
        vec![BakeOp {
            op: "XORBrute".into(),
            args: serde_json::json!({}),
        }],
        vec![BakeOp {
            op: "ROT13".into(),
            args: serde_json::json!({}),
        }],
        vec![
            BakeOp {
                op: "FromBase64".into(),
                args: serde_json::json!({}),
            },
            BakeOp {
                op: "DecodeUTF16LE".into(),
                args: serde_json::json!({}),
            },
        ],
        vec![
            BakeOp {
                op: "FromBase64".into(),
                args: serde_json::json!({}),
            },
            BakeOp {
                op: "XORBrute".into(),
                args: serde_json::json!({}),
            },
        ],
        vec![
            BakeOp {
                op: "FromBase64".into(),
                args: serde_json::json!({}),
            },
            BakeOp {
                op: "Gunzip".into(),
                args: serde_json::json!({}),
            },
        ],
        vec![
            BakeOp {
                op: "FromBase64".into(),
                args: serde_json::json!({}),
            },
            BakeOp {
                op: "Inflate".into(),
                args: serde_json::json!({}),
            },
        ],
        vec![
            BakeOp {
                op: "FromBase64".into(),
                args: serde_json::json!({}),
            },
            BakeOp {
                op: "Gunzip".into(),
                args: serde_json::json!({}),
            },
            BakeOp {
                op: "XORBrute".into(),
                args: serde_json::json!({}),
            },
        ],
    ];

    for recipe in candidates {
        if recipe.len() > depth {
            continue;
        }
        let r = bake(input, &recipe);
        if !r.ok {
            continue;
        }
        let bytes = from_hex(&r.output_hex).unwrap_or_default();
        let printable = printable_ratio(&bytes);
        if printable < printable_ratio(input) {
            continue;
        }
        let score = printable
            + crib
                .filter(|needle| {
                    std::str::from_utf8(&bytes)
                        .ok()
                        .is_some_and(|s| s.contains(needle))
                })
                .map_or(0.0, |_| 0.25);
        if score > best_score {
            best_score = score;
            best = r;
            best.message = format!("magic score={best_score:.2}");
        }
    }
    best
}

/// Extract ASCII URLs, IPv4 addresses, and email addresses from bytes.
pub fn extract_iocs(data: &[u8]) -> Vec<String> {
    let s = String::from_utf8_lossy(data);
    let mut out = Vec::new();
    for token in s.split(|c: char| c.is_whitespace() || c == '"' || c == '\'') {
        if token.starts_with("http://") || token.starts_with("https://") {
            out.push(token.to_string());
        }
        // crude IPv4
        let parts: Vec<_> = token.split('.').collect();
        if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
            out.push(token.to_string());
        }
        if let Some((local, domain)) = token.split_once('@') {
            if !local.is_empty()
                && domain.contains('.')
                && local
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b".!#$%&'*+/=?^_`{|}~-".contains(&c))
                && domain
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'-')
            {
                out.push(token.to_string());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_then_xor() {
        // "Hello" xor 0x41 → then base64 of that
        let plain = b"Hello";
        let xored: Vec<u8> = plain.iter().map(|b| b ^ 0x41).collect();
        // bake reverse: we have xored; XOR with 0x41 recovers
        let r = bake(
            &xored,
            &[BakeOp {
                op: "XOR".into(),
                args: serde_json::json!({"key_hex": "41"}),
            }],
        );
        assert!(r.ok);
        assert_eq!(r.output_utf8.as_deref(), Some("Hello"));
    }

    #[test]
    fn from_base64() {
        let r = bake(
            b"SGVsbG8=",
            &[BakeOp {
                op: "FromBase64".into(),
                args: serde_json::json!({}),
            }],
        );
        assert_eq!(r.output_utf8.as_deref(), Some("Hello"));
    }

    #[test]
    fn gunzip_op() {
        let payload = b"Hello";
        let mut gz = vec![0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff];
        gz.push(0x01);
        gz.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        gz.extend_from_slice(&(!(payload.len() as u16)).to_le_bytes());
        gz.extend_from_slice(payload);
        gz.extend_from_slice(&[0u8; 8]);
        let r = bake(
            &gz,
            &[BakeOp {
                op: "Gunzip".into(),
                args: serde_json::json!({}),
            }],
        );
        assert!(r.ok, "{}", r.message);
        assert_eq!(r.output_utf8.as_deref(), Some("Hello"));
    }

    #[test]
    fn base64_gunzip_xor_golden() {
        let r = bake(
            b"H4sIAAAAAAAC/+NXMTJVUU1U09NVVdEHAARoRhcNAAAA",
            &[
                BakeOp {
                    op: "FromBase64".into(),
                    args: serde_json::json!({}),
                },
                BakeOp {
                    op: "Gunzip".into(),
                    args: serde_json::json!({}),
                },
                BakeOp {
                    op: "XOR".into(),
                    args: serde_json::json!({"key_hex": "41"}),
                },
            ],
        );
        assert!(r.ok, "{}", r.message);
        assert_eq!(r.output_utf8.as_deref(), Some("Nested golden"));
    }

    #[test]
    fn decodes_textual_operations() {
        assert_eq!(
            apply_op(
                b"72, 101, 108, 108, 111",
                &BakeOp {
                    op: "FromCharcode".into(),
                    args: serde_json::json!({})
                }
            )
            .unwrap(),
            b"Hello"
        );
        assert_eq!(
            apply_op(
                b"a%2Bb+%26",
                &BakeOp {
                    op: "UrlDecode".into(),
                    args: serde_json::json!({})
                }
            )
            .unwrap(),
            b"a+b &"
        );
        assert_eq!(
            apply_op(
                b"&lt;x&gt;&#33;",
                &BakeOp {
                    op: "HtmlEntityDecode".into(),
                    args: serde_json::json!({})
                }
            )
            .unwrap(),
            b"<x>!"
        );
    }

    #[test]
    fn aes_cbc_nist_golden() {
        let ciphertext = from_hex("7649abac8119b246cee98e9b12e9197d").unwrap();
        let key = from_hex("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        let iv = from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
        assert_eq!(
            aes_decrypt(&ciphertext, &key, Some(&iv), "cbc").unwrap(),
            from_hex("6bc1bee22e409f96e93d7e117393172a").unwrap()
        );
    }

    #[test]
    fn aes_nist_ecb_ctr_cfb_ofb_and_unauthenticated_gcm_paths() {
        let key = from_hex("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        let plain = from_hex("6bc1bee22e409f96e93d7e117393172a").unwrap();
        let iv = from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
        assert_eq!(
            aes_decrypt(&from_hex("3ad77bb40d7a3660a89ecaf32466ef97").unwrap(), &key, None, "ecb").unwrap(),
            plain
        );
        assert_eq!(
            aes_decrypt(
                &from_hex("874d6191b620e3261bef6864990db6ce").unwrap(),
                &key,
                Some(&from_hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").unwrap()),
                "ctr",
            )
            .unwrap(),
            plain
        );
        assert_eq!(
            aes_decrypt(&from_hex("3b3fd92eb72dad20333449f8e83cfb4a").unwrap(), &key, Some(&iv), "cfb").unwrap(),
            plain
        );
        assert_eq!(
            aes_decrypt(&from_hex("3b3fd92eb72dad20333449f8e83cfb4a").unwrap(), &key, Some(&iv), "ofb").unwrap(),
            plain
        );

        // GCM uses the counter-mode plaintext path only. It deliberately does not
        // accept or validate an authentication tag, so this is not authentication.
        assert_eq!(
            aes_decrypt(
                &from_hex("0388dace60b6a392f328c2b971b2fe78").unwrap(),
                &vec![0; 16],
                Some(&vec![0; 12]),
                "gcm",
            )
            .unwrap(),
            vec![0; 16]
        );
    }

    #[test]
    fn des_ecb_known_answer() {
        let key = from_hex("133457799bbcdff1").unwrap();
        let ciphertext = from_hex("85e813540f0ab405").unwrap();
        assert_eq!(
            des_decrypt(&ciphertext, &key, None, "ecb").unwrap(),
            from_hex("0123456789abcdef").unwrap()
        );
    }

    #[test]
    fn triple_des_cbc_known_answer() {
        let key = from_hex("0123456789abcdeff1e0d3c2b5a49786fedcba9876543210").unwrap();
        let iv = from_hex("fedcba9876543210").unwrap();
        let ciphertext =
            from_hex("3fe301c962ac01d02213763c1cbd4cdc799657c064ecf5d41c673812cfde9675").unwrap();
        assert_eq!(
            triple_des_decrypt(&ciphertext, &key, Some(&iv), "cbc").unwrap(),
            from_hex("37363534333231204e6f77206973207468652074696d6520666f722000000000").unwrap()
        );
    }

    #[test]
    fn blowfish_ecb_known_answer() {
        let ciphertext = from_hex("324ed0fef413a203").unwrap();
        assert_eq!(
            blowfish_decrypt(&ciphertext, b"abcdefghijklmnopqrstuvwxyz", None, "ecb").unwrap(),
            b"BLOWFISH"
        );
    }

    #[test]
    fn recipe_text_transforms_iocs_and_inflate_auto_paths() {
        let decode = |input: &[u8], op: &str| {
            bake(
                input,
                &[BakeOp {
                    op: op.into(),
                    args: serde_json::json!({}),
                }],
            )
        };
        assert_eq!(decode(b"48656c6c6f", "FromHex").output_utf8.as_deref(), Some("Hello"));
        assert_eq!(decode(b"Uryyb", "ROT13").output_utf8.as_deref(), Some("Hello"));
        assert_eq!(decode(b"olleH", "Reverse").output_utf8.as_deref(), Some("Hello"));
        assert_eq!(
            decode(b"H\0e\0l\0l\0o\0", "DecodeUTF16LE").output_utf8.as_deref(),
            Some("Hello")
        );
        let brute = decode(b"\xe2\xcf\xc6\xc6\xc5\x8b", "XORBrute");
        assert!(brute.ok);
        assert!(brute.output_utf8.is_some(), "{brute:?}");

        // zlib header + stored DEFLATE "Hello" block + Adler-32.
        assert_eq!(
            decode(
                &[0x78, 0x01, 0x01, 0x05, 0x00, 0xfa, 0xff, b'H', b'e', b'l', b'l', b'o', 0x05, 0x8c, 0x01, 0xf5],
                "Inflate",
            )
            .output_utf8
            .as_deref(),
            Some("Hello")
        );
        let iocs = extract_iocs(b"visit https://example.test/path and 203.0.113.7");
        assert!(iocs.contains(&"https://example.test/path".to_string()));
        assert!(iocs.contains(&"203.0.113.7".to_string()));
    }

    #[test]
    fn chacha20_rfc8439_golden() {
        let key =
            from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
        let nonce = from_hex("000000000000004a00000000").unwrap();
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let output = chacha20(plaintext, &key, &nonce, 1).unwrap();
        assert_eq!(
            to_hex(&output),
            concat!(
                "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b",
                "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8",
                "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736",
                "5af90bbf74a35be6b40b8eedf2785e42874d"
            )
        );
    }

    #[test]
    fn crib_and_email_ioc() {
        let result = magic_with_crib(b"U2VjcmV0IGNyaWI=", 1, Some("crib"));
        assert_eq!(result.output_utf8.as_deref(), Some("Secret crib"));
        assert!(extract_iocs(b"contact analyst@example.test now")
            .contains(&"analyst@example.test".to_string()));
    }
}
