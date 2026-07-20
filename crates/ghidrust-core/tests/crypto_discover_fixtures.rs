//! Synthetic, native x86-oriented fixtures for crypto discovery and recipe success metrics.

use ghidrust_core::{
    bake, recover_obfuscated_strings, run_analyzers, scan_crypt_constants,
    run_crypto_pipeline, scan_crypto_capabilities, BakeOp, ImportEntry, MemoryBlock,
    ObfuscatedStringKind, Program,
    RecoverStringsOpts,
};

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

fn hex(input: &str) -> Vec<u8> {
    let input: String = input
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    (0..input.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&input[i..i + 2], 16).unwrap())
        .collect()
}

fn b64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let a = chunk[0];
        let b = *chunk.get(1).unwrap_or(&0);
        let c = *chunk.get(2).unwrap_or(&0);
        out.push(TABLE[(a >> 2) as usize] as char);
        out.push(TABLE[((a & 0x03) << 4 | b >> 4) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[((b & 0x0f) << 2 | c >> 6) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(c & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

#[test]
fn crypto_constants_discovers_aes_sbox_and_tea_delta_and_annotates_symbols() {
    let aes_sbox = hex("
        63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76
        ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0
        b7 fd 93 26 36 3f f7 cc 34 a5 e5 f1 71 d8 31 15
        04 c7 23 c3 18 96 05 9a 07 12 80 e2 eb 27 b2 75
        09 83 2c 1a 1b 6e 5a a0 52 3b d6 b3 29 e3 2f 84
        53 d1 00 ed 20 fc b1 5b 6a cb be 39 4a 4c 58 cf
        d0 ef aa fb 43 4d 33 85 45 f9 02 7f 50 3c 9f a8
        51 a3 40 8f 92 9d 38 f5 bc b6 da 21 10 ff f3 d2
        cd 0c 13 ec 5f 97 44 17 c4 a7 7e 3d 64 5d 19 73
        60 81 4f dc 22 2a 90 88 46 ee b8 14 de 5e 0b db
        e0 32 3a 0a 49 06 24 5c c2 d3 ac 62 91 95 e4 79
        e7 c8 37 6d 8d d5 4e a9 6c 56 f4 ea 65 7a ae 08
        ba 78 25 2e 1c a6 b4 c6 e8 dd 74 1f 4b bd 8b 8a
        70
        3e b5 66 48 03 f6 0e 61 35 57 b9 86 c1 1d 9e e1
        f8 98 11 69 d9 8e 94 9b 1e 87 e9 ce 55 28 df 8c
        a1 89 0d bf e6 42 68 41 99 2d 0f b0 54 bb 16
        ");
    // Keep the fixture native: these are raw bytes in a synthetic read-only data mapping.
    let mut bytes = vec![0x90; 11];
    bytes.extend_from_slice(&aes_sbox);
    bytes.extend_from_slice(&[0x90; 7]);
    bytes.extend_from_slice(&[0xb9, 0x79, 0x37, 0x9e]);

    let mut program = Program::new("crypt-constants".into(), "raw");
    program.blocks.push(block(".rdata", 0x5000, bytes, false));

    let hits = scan_crypt_constants(&program);
    assert!(
        hits.iter()
            .any(|hit| hit.algorithm == "AES" && hit.constant == "SBOX"),
        "{hits:?}"
    );
    assert!(
        hits.iter()
            .any(|hit| hit.algorithm == "TEA" && hit.constant == "DELTA"),
        "{hits:?}"
    );

    let report = run_analyzers(&mut program, &["Find Crypt"]).expect("Find Crypt runs");
    assert_eq!(report.results[0].name, "Find Crypt");
    assert_eq!(report.results[0].status, "ok");
    assert!(
        program
            .analysis
            .symbols
            .iter()
            .any(|symbol| symbol.name == "CRYPT_AES_SBOX"),
        "{:?}",
        program.analysis.symbols
    );
    assert!(
        program
            .analysis
            .symbols
            .iter()
            .any(|symbol| symbol.name == "CRYPT_TEA_DELTA"),
        "{:?}",
        program.analysis.symbols
    );
}

#[test]
fn recover_obfuscated_strings_finds_stack_and_xor_decoder_results() {
    let mut stack_code = Vec::new();
    for (disp, byte) in b"stack\0".iter().enumerate() {
        stack_code.extend_from_slice(&[0xc6, 0x45, disp as u8, *byte]);
    }

    let key = 0x5a;
    let mut xor_code = vec![0x34, key]; // xor al, imm8: decoder pre-filter evidence.
    for (disp, byte) in b"decoded".iter().enumerate() {
        xor_code.extend_from_slice(&[0xc6, 0x45, 0x20 + disp as u8, byte ^ key]);
    }
    for disp in 0x20..0x27 {
        xor_code.extend_from_slice(&[0x80, 0x75, disp, key]); // xor byte ptr [rbp+disp], imm8
    }
    xor_code.extend_from_slice(&[0xeb, 0xfe]); // native short backward edge

    let mut program = Program::new("stack-and-xor".into(), "raw");
    program
        .blocks
        .push(block(".text.stack", 0x401000, stack_code, true));
    program
        .blocks
        .push(block(".text.xor", 0x402000, xor_code, true));

    let hits = recover_obfuscated_strings(&program, &RecoverStringsOpts::default());
    assert!(
        hits.iter()
            .any(|hit| hit.value == "stack" && hit.kind == ObfuscatedStringKind::Stack),
        "{hits:?}"
    );
    let decoded = hits
        .iter()
        .find(|hit| hit.value == "decoded" && hit.kind == ObfuscatedStringKind::Decoded)
        .expect("XOR-decoded string");
    assert_eq!(decoded.decoder_va, Some(0x402000 + 2 + 7 * 4));
}

#[test]
fn bake_peels_base64_gzip_xor_and_decrypts_known_aes_cbc_vector() {
    let plain = b"crypto fixture";
    let key = 0x5a;
    let xored: Vec<u8> = plain.iter().map(|byte| byte ^ key).collect();
    // A deterministic stored-DEFLATE gzip member; the decoder intentionally accepts this
    // minimal synthetic member without requiring a third-party compressor in the test.
    let mut gzip = vec![0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0, 0xff, 0x01];
    gzip.extend_from_slice(&(xored.len() as u16).to_le_bytes());
    gzip.extend_from_slice(&(!(xored.len() as u16)).to_le_bytes());
    gzip.extend_from_slice(&xored);
    gzip.extend_from_slice(&[0; 8]);
    let encoded = b64_encode(&gzip);
    let peel = bake(
        encoded.as_bytes(),
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
                args: serde_json::json!({"key_hex": "5a"}),
            },
        ],
    );
    assert!(peel.ok, "{}", peel.message);
    assert_eq!(peel.output_utf8.as_deref(), Some("crypto fixture"));

    let aes = bake(
        &hex("7649abac8119b246cee98e9b12e9197d"),
        &[BakeOp {
            op: "AESDecrypt".into(),
            args: serde_json::json!({
                "key_hex": "2b7e151628aed2a6abf7158809cf4f3c",
                "iv_hex": "000102030405060708090a0b0c0d0e0f",
                "mode": "cbc"
            }),
        }],
    );
    assert!(aes.ok, "{}", aes.message);
    assert_eq!(aes.output_hex, "6bc1bee22e409f96e93d7e117393172a");
}

#[test]
fn crypto_capabilities_find_import_aesni_and_base64_evidence() {
    let mut program = Program::new("capabilities".into(), "raw");
    program.imports.push(ImportEntry {
        dll: "advapi32.dll".into(),
        name: Some("CryptDecrypt".into()),
        ordinal: None,
        iat_va: 0x7000,
        ilt_va: None,
    });
    program.blocks.push(block(
        ".text",
        0x401000,
        vec![0x90, 0x66, 0x0f, 0x38, 0xdf, 0xc0],
        true,
    ));
    program.blocks.push(block(
        ".rdata",
        0x5000,
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".to_vec(),
        false,
    ));

    let hits = scan_crypto_capabilities(&program, None);
    assert!(
        hits.iter()
            .any(|hit| hit.evidence.contains("CryptDecrypt") && hit.tag == "decrypt"),
        "{hits:?}"
    );
    assert!(
        hits.iter()
            .any(|hit| hit.evidence.contains("opcode @ 0x401001")),
        "{hits:?}"
    );
    assert!(
        hits.iter()
            .any(|hit| hit.capability.contains("Base64") && hit.tag == "encoding"),
        "{hits:?}"
    );
}

#[test]
fn crypto_pipeline_preserves_find_crypt_state_for_capabilities() {
    let mut program = Program::new("pipeline".into(), "raw");
    let mut code = vec![0x90, 0xb9, 0x79, 0x37, 0x9e]; // TEA delta
    for (disp, byte) in b"seed\0".iter().enumerate() {
        code.extend_from_slice(&[0xc6, 0x45, disp as u8, *byte]);
    }
    program.blocks.push(block(".text", 0x401000, code, true));

    let outputs = run_crypto_pipeline(&mut program).expect("crypto pipeline succeeds");
    assert_eq!(
        outputs.iter().map(|output| output.name.as_str()).collect::<Vec<_>>(),
        vec!["Find Crypt", "Obfuscated Strings", "Crypto Capabilities"]
    );
    assert!(
        program
            .analysis
            .crypt_constants
            .iter()
            .any(|hit| hit.algorithm == "TEA"),
        "{:?}",
        program.analysis.crypt_constants
    );
    assert!(
        program
            .analysis
            .obfuscated_strings
            .iter()
            .any(|hit| hit.value == "seed"),
        "{:?}",
        program.analysis.obfuscated_strings
    );
    assert!(
        program
            .analysis
            .crypto_capabilities
            .iter()
            .any(|hit| hit.capability.contains("TEA constants present")),
        "{:?}",
        program.analysis.crypto_capabilities
    );
}
