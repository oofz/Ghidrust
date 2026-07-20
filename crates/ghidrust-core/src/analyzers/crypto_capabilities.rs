//! Locate encrypt/decrypt and encoding capabilities via imports, constants, and code idioms.

use super::AnalyzerOutput;
use crate::error::Result;
use crate::program::Program;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CryptoCapabilityHit {
    pub function_va: Option<u64>,
    pub capability: String,
    pub tag: String,
    pub evidence: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attack: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mbc: Option<String>,
}

const DECRYPT_APIS: &[&str] = &[
    "CryptDecrypt",
    "BCryptDecrypt",
    "NCryptDecrypt",
    "CryptUnprotectData",
    "CryptUnprotectMemory",
    "SystemFunction041",
    "DecryptMessage",
];

const ENCRYPT_APIS: &[&str] = &[
    "CryptEncrypt",
    "BCryptEncrypt",
    "NCryptEncrypt",
    "CryptProtectData",
    "CryptProtectMemory",
    "SystemFunction040",
    "EncryptMessage",
    "CryptAcquireContextA",
    "CryptAcquireContextW",
    "CryptGenKey",
    "CryptDeriveKey",
    "CryptImportKey",
];

const OPENSSL_DECRYPT_APIS: &[&str] = &[
    "EVP_DecryptInit",
    "EVP_DecryptInit_ex",
    "EVP_DecryptUpdate",
    "EVP_DecryptFinal_ex",
    "EVP_PKEY_decrypt",
    "AES_decrypt",
    "RSA_private_decrypt",
    "RSA_public_decrypt",
];

const OPENSSL_ENCRYPT_APIS: &[&str] = &[
    "EVP_EncryptInit",
    "EVP_EncryptInit_ex",
    "EVP_EncryptUpdate",
    "EVP_EncryptFinal_ex",
    "EVP_PKEY_encrypt",
    "AES_encrypt",
    "RSA_public_encrypt",
    "RSA_private_encrypt",
    "RC4",
];

const ENCODING_APIS: &[&str] = &[
    "CryptBinaryToStringA",
    "CryptBinaryToStringW",
    "CryptStringToBinaryA",
    "CryptStringToBinaryW",
];

/// WinCrypt CALG_* values commonly embedded next to CryptDecrypt/Encrypt call sites.
const CALG_MARKERS: &[(u32, &str)] = &[
    (0x0000_6610, "CALG_AES_128"),
    (0x0000_6611, "CALG_AES_192"),
    (0x0000_6612, "CALG_AES_256"),
    (0x0000_6603, "CALG_3DES"),
    (0x0000_6601, "CALG_DES"),
    (0x0000_6801, "CALG_RC4"),
    (0x0000_a400, "CALG_RSA_KEYX"),
    (0x0000_2400, "CALG_RSA_SIGN"),
    (0x0000_8003, "CALG_MD5"),
    (0x0000_8004, "CALG_SHA1"),
    (0x0000_800c, "CALG_SHA_256"),
];

/// Standard Base64 alphabet (ASCII) — presence suggests in-binary encoder/decoder.
const BASE64_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const PACKER_MARKERS: &[&[u8]] = &[b"UPX0", b"UPX1", b"UPX!", b"Themida", b"VMProtect"];

fn tag_allowed(tag_filter: Option<&str>, tag: &str) -> bool {
    tag_filter
        .map(|filter| filter.eq_ignore_ascii_case(tag))
        .unwrap_or(true)
}

fn has_calg_rsa(prog: &Program) -> bool {
    prog.exec_blocks().any(|block| {
        block.bytes.windows(4).any(|window| {
            let value = u32::from_le_bytes([window[0], window[1], window[2], window[3]]);
            matches!(value, 0x0000_a400 | 0x0000_2400)
        })
    })
}

fn import_capability(
    name: &str,
    has_rsa_calg: bool,
) -> Option<(
    &'static str,
    &'static str,
    Option<&'static str>,
    Option<&'static str>,
)> {
    if DECRYPT_APIS
        .iter()
        .any(|api| name.eq_ignore_ascii_case(api))
        || OPENSSL_DECRYPT_APIS
            .iter()
            .any(|api| name.eq_ignore_ascii_case(api))
    {
        let capability = if name.eq_ignore_ascii_case("CryptDecrypt") && has_rsa_calg {
            "RSA decrypt via CryptDecrypt with CALG_RSA*"
        } else if name.to_ascii_uppercase().contains("RSA") {
            "RSA decrypt"
        } else {
            "decrypt"
        };
        return Some((capability, "decrypt", Some("T1027"), Some("C0031")));
    }
    if ENCRYPT_APIS
        .iter()
        .any(|api| name.eq_ignore_ascii_case(api))
        || OPENSSL_ENCRYPT_APIS
            .iter()
            .any(|api| name.eq_ignore_ascii_case(api))
    {
        let capability = if name.to_ascii_uppercase().contains("RSA") {
            "RSA encrypt"
        } else {
            "encrypt"
        };
        return Some((capability, "encrypt", Some("T1027"), Some("C0027")));
    }
    if ENCODING_APIS
        .iter()
        .any(|api| name.eq_ignore_ascii_case(api))
    {
        return Some(("encode/decode", "encoding", Some("T1027"), None));
    }
    if name.eq_ignore_ascii_case("SystemFunction032")
        || name.eq_ignore_ascii_case("SystemFunction033")
    {
        return Some(("RC4", "encrypt", Some("T1027"), Some("C0027")));
    }
    if (name.starts_with("BCrypt") || name.starts_with("NCrypt"))
        && name.to_ascii_uppercase().contains("RSA")
    {
        return Some((
            "RSA-related cryptographic operation",
            "encrypt",
            Some("T1027"),
            None,
        ));
    }
    None
}

/// Scan imports + prior analysis for crypto/encoding capabilities.
pub fn scan_crypto_capabilities(
    prog: &Program,
    tag_filter: Option<&str>,
) -> Vec<CryptoCapabilityHit> {
    let mut hits = Vec::new();
    let has_rsa_calg = has_calg_rsa(prog);

    for imp in &prog.imports {
        let Some(ref name_s) = imp.name else {
            continue;
        };
        let name = name_s.as_str();
        let dll = imp.dll.as_str();
        let Some((capability, tag, attack, mbc)) = import_capability(name, has_rsa_calg) else {
            continue;
        };
        if !tag_allowed(tag_filter, tag) {
            continue;
        }
        hits.push(CryptoCapabilityHit {
            function_va: Some(imp.iat_va),
            capability: format!("{capability} via {name}"),
            tag: tag.into(),
            evidence: format!("import {dll}!{name}"),
            attack: attack.map(str::to_string),
            mbc: mbc.map(str::to_string),
        });
    }

    // TEA/XTEA commonly combines the delta with repeated shifts and XORs in one loop body.
    for block in prog.exec_blocks() {
        let bytes = &block.bytes;
        let has_delta = bytes
            .windows(4)
            .any(|window| window == [0xb9, 0x79, 0x37, 0x9e]);
        let shifts = bytes
            .windows(2)
            .filter(|window| {
                matches!(
                    *window,
                    [0xc1, 0xe0..=0xe7] | [0xd1, 0xe0..=0xe7] | [0xc1, 0xf8..=0xff]
                )
            })
            .count();
        let xors = bytes
            .windows(2)
            .filter(|window| {
                matches!(window[0], 0x30..=0x35) || window[0] == 0x31 || window[0] == 0x33
            })
            .count();
        if has_delta && shifts >= 2 && xors >= 2 && tag_allowed(tag_filter, "encrypt") {
            hits.push(CryptoCapabilityHit {
                function_va: Some(block.va),
                capability: "TEA/XTEA loop idiom".into(),
                tag: "encrypt".into(),
                evidence: format!(
                    "TEA delta, {shifts} shifts, and {xors} XORs in {}",
                    block.name
                ),
                attack: Some("T1027".into()),
                mbc: Some("C0027".into()),
            });
        }
    }

    // AES-NI idiom: 66 0F 38 DC (aesenc) / 66 0F 38 DE (aesenclast) / 66 0F 38 DF (aesdeclast)
    for block in prog.exec_blocks() {
        let b = &block.bytes;
        for (i, w) in b.windows(4).enumerate() {
            let is_aes = matches!(
                w,
                [0x66, 0x0F, 0x38, 0xDC]
                    | [0x66, 0x0F, 0x38, 0xDD]
                    | [0x66, 0x0F, 0x38, 0xDE]
                    | [0x66, 0x0F, 0x38, 0xDF]
                    | [0x66, 0x0F, 0x38, 0xDB]
            );
            if !is_aes {
                continue;
            }
            if tag_filter
                .map(|t| !t.eq_ignore_ascii_case("decrypt") && !t.eq_ignore_ascii_case("encrypt"))
                .unwrap_or(false)
            {
                continue;
            }
            let va = block.va + i as u64;
            let decryptish = w[3] == 0xDF || w[3] == 0xDB;
            hits.push(CryptoCapabilityHit {
                function_va: Some(va),
                capability: if decryptish {
                    "AES via x86 extensions (decrypt-ish)".into()
                } else {
                    "AES via x86 extensions".into()
                },
                tag: if decryptish {
                    "decrypt".into()
                } else {
                    "encrypt".into()
                },
                evidence: format!("opcode @ {va:#x}"),
                attack: Some("T1027".into()),
                mbc: Some(if decryptish {
                    "C0031".into()
                } else {
                    "C0027".into()
                }),
            });
        }
    }

    // Seed from Find Crypt hits already on the program.
    for c in &prog.analysis.crypt_constants {
        let tag = if c.algorithm == "MD5" || c.algorithm == "SHA256" || c.algorithm == "CRC32" {
            "hashing"
        } else {
            "encrypt"
        };
        if let Some(f) = tag_filter {
            if !tag.eq_ignore_ascii_case(f) && !f.eq_ignore_ascii_case("encrypt") {
                continue;
            }
        }
        hits.push(CryptoCapabilityHit {
            function_va: Some(c.va),
            capability: format!("{} constants present", c.algorithm),
            tag: tag.into(),
            evidence: format!("{} @ {:#x}", c.constant, c.va),
            attack: Some("T1027".into()),
            mbc: Some("C0027".into()),
        });
    }

    // RC4 KSA/PRGA implementations typically initialize a 256-byte state and perform
    // several byte XORs/modulo-256 operations in the same code block.
    for block in prog.exec_blocks() {
        let bytes = &block.bytes;
        let has_256 = bytes
            .windows(4)
            .any(|window| window == [0x00, 0x01, 0x00, 0x00]);
        let xor_count = bytes
            .windows(2)
            .filter(|window| {
                matches!(window[0], 0x30..=0x35) || window[0] == 0x31 || window[0] == 0x33
            })
            .count();
        let has_mod_256 = bytes
            .windows(5)
            .any(|window| window == [0x25, 0xff, 0x00, 0x00, 0x00]);
        if has_256 && has_mod_256 && xor_count >= 3 && tag_allowed(tag_filter, "encrypt") {
            hits.push(CryptoCapabilityHit {
                function_va: Some(block.va),
                capability: "RC4 KSA/PRGA-like loop idiom".into(),
                tag: "encrypt".into(),
                evidence: format!(
                    "256-byte state, modulo-256 mask, and {xor_count} XORs in {}",
                    block.name
                ),
                attack: Some("T1027".into()),
                mbc: Some("C0027".into()),
            });
        }
    }

    // Stackstring presence from prior obfuscated-string recovery.
    if prog.analysis.obfuscated_strings.iter().any(|s| {
        matches!(
            s.kind,
            super::obfuscated_strings::ObfuscatedStringKind::Stack
        )
    }) {
        if tag_filter
            .map(|t| t.eq_ignore_ascii_case("encoding") || t.eq_ignore_ascii_case("obfuscation"))
            .unwrap_or(true)
        {
            hits.push(CryptoCapabilityHit {
                function_va: None,
                capability: "contain obfuscated stackstrings".into(),
                tag: "encoding".into(),
                evidence: "obfuscated_strings analysis".into(),
                attack: Some("T1027".into()),
                mbc: None,
            });
        }
    }

    // CALG_* immediates in executable code.
    for block in prog.exec_blocks() {
        let b = &block.bytes;
        if b.len() < 5 {
            continue;
        }
        for (i, w) in b.windows(5).enumerate() {
            // mov eax, imm32 → B8 xx xx xx xx
            if w[0] != 0xB8 {
                continue;
            }
            let imm = u32::from_le_bytes([w[1], w[2], w[3], w[4]]);
            if let Some((_, name)) = CALG_MARKERS.iter().find(|(v, _)| *v == imm) {
                if tag_filter
                    .map(|t| {
                        t.eq_ignore_ascii_case("encrypt")
                            || t.eq_ignore_ascii_case("decrypt")
                            || t.eq_ignore_ascii_case("hashing")
                    })
                    .unwrap_or(true)
                {
                    let va = block.va + i as u64;
                    hits.push(CryptoCapabilityHit {
                        function_va: Some(va),
                        capability: format!("algorithm id {name}"),
                        tag: if name.contains("MD5") || name.contains("SHA") {
                            "hashing".into()
                        } else {
                            "encrypt".into()
                        },
                        evidence: format!("imm32 {imm:#x} @ {va:#x}"),
                        attack: Some("T1027".into()),
                        mbc: Some("C0027".into()),
                    });
                }
            }
        }
    }

    // Base64 alphabet table in data.
    for block in &prog.blocks {
        if let Some(rel) = block
            .bytes
            .windows(BASE64_ALPHABET.len())
            .position(|w| w == BASE64_ALPHABET)
        {
            if tag_filter
                .map(|t| t.eq_ignore_ascii_case("encoding"))
                .unwrap_or(true)
            {
                let va = block.va + rel as u64;
                hits.push(CryptoCapabilityHit {
                    function_va: Some(va),
                    capability: "encode/decode via Base64 alphabet".into(),
                    tag: "encoding".into(),
                    evidence: format!("alphabet @ {va:#x}"),
                    attack: Some("T1027".into()),
                    mbc: None,
                });
            }
            break;
        }
    }

    // Dense XOR-imm density → custom encode/decode capability.
    for block in prog.exec_blocks() {
        let xor_imm = block
            .bytes
            .windows(2)
            .filter(|w| w[0] == 0x34 && w[1] != 0)
            .count();
        if xor_imm >= 8 {
            if tag_filter
                .map(|t| t.eq_ignore_ascii_case("encoding") || t.eq_ignore_ascii_case("encrypt"))
                .unwrap_or(true)
            {
                hits.push(CryptoCapabilityHit {
                    function_va: Some(block.va),
                    capability: "encode/decode via XOR loops".into(),
                    tag: "encoding".into(),
                    evidence: format!("{xor_imm} xor-imm sites in {}", block.name),
                    attack: Some("T1027".into()),
                    mbc: None,
                });
            }
        }
    }

    // P2 context only: these are literal image markers, not packer identification.
    for block in &prog.blocks {
        for marker in PACKER_MARKERS {
            if let Some(offset) = block
                .bytes
                .windows(marker.len())
                .position(|window| window == *marker)
            {
                if tag_allowed(tag_filter, "packing") {
                    let va = block.va + offset as u64;
                    hits.push(CryptoCapabilityHit {
                        function_va: Some(va),
                        capability: "packing context marker".into(),
                        tag: "packing".into(),
                        evidence: format!(
                            "literal marker {} @ {va:#x}",
                            String::from_utf8_lossy(marker)
                        ),
                        attack: Some("T1027".into()),
                        mbc: None,
                    });
                }
                break;
            }
        }
    }

    hits
}

/// Suggest bake op names from a capability hit (feeds Phase 3).
pub fn suggest_ops_for_capability(hit: &CryptoCapabilityHit) -> Vec<&'static str> {
    let c = hit.capability.to_ascii_lowercase();
    if c.contains("aes") || c.contains("calg_aes") {
        return vec!["AESDecrypt"];
    }
    if c.contains("rc4") || c.contains("calg_rc4") || c.contains("systemfunction032") {
        return vec!["RC4"];
    }
    if c.contains("base64") && (c.contains("gzip") || c.contains("gunzip")) {
        return vec!["FromBase64", "Gunzip"];
    }
    if c.contains("base64") {
        return vec!["FromBase64"];
    }
    if c.contains("tea") || c.contains("chacha") || c.contains("blowfish") || c.contains("des") {
        return vec!["XORBrute"];
    }
    // RSA and DPAPI require a private key or host-bound credential; no bake operation is honest.
    if c.contains("rsa") || c.contains("dpapi") || c.contains("cryptunprotect") {
        return Vec::new();
    }
    if c.contains("xor") {
        return vec!["XORBrute"];
    }
    if hit.tag == "decrypt" {
        return vec!["AESDecrypt", "RC4", "XORBrute"];
    }
    vec!["FromBase64", "XORBrute"]
}

pub fn run(prog: &mut Program) -> Result<AnalyzerOutput> {
    let hits = scan_crypto_capabilities(prog, None);
    let n = hits.len();
    prog.analysis.crypto_capabilities = hits.clone();
    Ok(AnalyzerOutput {
        name: "Crypto Capabilities".into(),
        status: "ok".into(),
        message: format!("matched {n} crypto/encoding capability hit(s)"),
        crypto_capabilities: Some(hits),
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzers::obfuscated_strings::{ObfuscatedStringHit, ObfuscatedStringKind};
    use crate::program::{ImportEntry, MemoryBlock};

    fn block(name: &str, va: u64, bytes: Vec<u8>, executable: bool) -> MemoryBlock {
        MemoryBlock {
            name: name.into(),
            va,
            size: bytes.len() as u64,
            bytes,
            readable: true,
            writable: false,
            executable,
        }
    }

    #[test]
    fn detects_cryptdecrypt_import() {
        let mut prog = Program::new("t".into(), "raw");
        prog.imports.push(ImportEntry {
            dll: "advapi32.dll".into(),
            name: Some("CryptDecrypt".into()),
            ordinal: None,
            iat_va: 0x401000,
            ilt_va: None,
        });
        let hits = scan_crypto_capabilities(&prog, None);
        assert!(hits
            .iter()
            .any(|hit| hit.tag == "decrypt" && hit.evidence.contains("CryptDecrypt")));
    }

    #[test]
    fn detects_aes_ni_opcode() {
        let mut prog = Program::new("t".into(), "raw");
        prog.blocks
            .push(block(".text", 0x401000, vec![0x66, 0x0f, 0x38, 0xdc], true));
        assert!(scan_crypto_capabilities(&prog, None)
            .iter()
            .any(|hit| hit.capability.contains("AES via x86")));
    }

    #[test]
    fn detects_base64_alphabet() {
        let mut prog = Program::new("t".into(), "raw");
        prog.blocks
            .push(block(".rdata", 0x402000, BASE64_ALPHABET.to_vec(), false));
        assert!(scan_crypto_capabilities(&prog, None)
            .iter()
            .any(|hit| hit.capability.contains("Base64")));
    }

    #[test]
    fn reports_stackstring_context() {
        let mut prog = Program::new("t".into(), "raw");
        prog.analysis.obfuscated_strings.push(ObfuscatedStringHit {
            va: 0x401000,
            value: "test".into(),
            kind: ObfuscatedStringKind::Stack,
            decoder_va: None,
            call_site: None,
        });
        assert!(scan_crypto_capabilities(&prog, None)
            .iter()
            .any(|hit| hit.capability.contains("stackstrings")));
    }

    #[test]
    fn detects_tea_rc4_calg_and_honors_tag_filter() {
        let mut prog = Program::new("idioms".into(), "raw");
        prog.blocks.push(block(
            ".text",
            0x5000,
            vec![
                0xb9, 0x79, 0x37, 0x9e, // TEA delta
                0xc1, 0xe0, 0x04, 0xc1, 0xe1, 0x05, 0x31, 0xc0, 0x33, 0xc9,
                0xb8, 0x01, 0x68, 0x00, 0x00, // CALG_RC4
                0x00, 0x01, 0x00, 0x00, 0x25, 0xff, 0x00, 0x00, 0x00,
                0x31, 0xc0, 0x33, 0xc9, 0x34, 0x12,
            ],
            true,
        ));
        let hits = scan_crypto_capabilities(&prog, Some("encrypt"));
        assert!(hits.iter().any(|hit| hit.capability.contains("TEA/XTEA")), "{hits:?}");
        assert!(hits.iter().any(|hit| hit.capability.contains("RC4 KSA/PRGA")), "{hits:?}");
        assert!(
            hits.iter().any(|hit| hit.capability.contains("CALG_RC4")),
            "{hits:?}"
        );
        assert!(hits.iter().all(|hit| hit.tag == "encrypt"));
        let rc4 = hits
            .iter()
            .find(|hit| hit.capability.contains("RC4"))
            .expect("RC4 capability");
        assert_eq!(suggest_ops_for_capability(rc4), vec!["RC4"]);
    }
}
