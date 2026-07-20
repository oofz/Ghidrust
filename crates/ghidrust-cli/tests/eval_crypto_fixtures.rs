//! Focused CLI smoke tests for the crypto discovery and recipe surface.

use ghidrust_core::fixture_path;
use serde_json::Value;
use std::path::PathBuf;
use std::process::{Command, Output};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ghidrust"))
}

fn temp_blob(name: &str, bytes: &[u8]) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "ghidrust_crypto_{name}_{}_{}.bin",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time after epoch")
            .as_nanos()
    ));
    std::fs::write(&path, bytes).expect("write synthetic crypto blob");
    path
}

fn run(args: &[&str]) -> Output {
    bin().args(args).output().expect("run ghidrust")
}

fn json_stdout(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "status={:?}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "invalid JSON: {error}\nstdout={}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

#[test]
fn crypto_discovery_accepts_raw_blob_and_filters() {
    let blob = temp_blob("tea", &[0, 0, 0, 0xb9, 0x79, 0x37, 0x9e, 0]);
    let blob_s = blob.to_str().expect("UTF-8 temp path");

    let constants = json_stdout(&run(&[
        "crypt-constants",
        blob_s,
        "--algo",
        "TEA",
        "--json",
    ]));
    let hits = constants.as_array().expect("constant hits array");
    assert!(
        hits.iter().any(|hit| {
            hit.get("algorithm").and_then(Value::as_str) == Some("TEA")
                && hit.get("constant").and_then(Value::as_str) == Some("DELTA")
        }),
        "expected TEA delta hit: {constants}"
    );

    let recovered = json_stdout(&run(&[
        "recover-strings",
        blob_s,
        "--only",
        "static",
        "--json",
    ]));
    assert!(recovered.is_array(), "expected recovered string array");

    let capabilities = json_stdout(&run(&[
        "crypto-capabilities",
        blob_s,
        "--tag",
        "decrypt",
        "--json",
    ]));
    assert!(capabilities.is_array(), "expected capability array");
    let _ = std::fs::remove_file(blob);
}

#[test]
fn find_crypt_analyzer_keeps_its_cli_identity() {
    let catalog = json_stdout(&run(&["analyzers", "--json"]));
    assert!(
        catalog.to_string().contains("Find Crypt"),
        "Find Crypt missing from analyzer catalog: {catalog}"
    );

    let pe = fixture_path("analysis_lab.pe");
    let analyzed = json_stdout(&run(&[
        "analyze",
        pe.to_str().expect("UTF-8 fixture path"),
        "--analyzer",
        "Find Crypt",
        "--json",
    ]));
    assert!(
        analyzed.to_string().contains("Find Crypt"),
        "Find Crypt missing from analysis result: {analyzed}"
    );
}

#[test]
fn decode_bake_and_magic_recipe_smokes() {
    let base64 = json_stdout(&run(&[
        "decode",
        "bake",
        "-b64",
        "SGVsbG8=",
        "-op",
        "FromBase64",
        "--json",
    ]));
    assert_eq!(base64["result"]["output_utf8"], "Hello");

    let nested = json_stdout(&run(&[
        "decode",
        "bake",
        "-b64",
        "H4sIAAAAAAAC/+NXMTJVUU1U09NVVdEHAARoRhcNAAAA",
        "-op",
        "FromBase64",
        "-op",
        "Gunzip",
        "-op",
        "XOR",
        "-key-hex",
        "41",
        "--json",
    ]));
    assert_eq!(nested["result"]["output_utf8"], "Nested golden");

    let magic = json_stdout(&run(&[
        "decode",
        "magic",
        "-b64",
        "U2VjcmV0IGNyaWI=",
        "-depth",
        "2",
        "-crib",
        "crib",
        "--json",
    ]));
    assert_eq!(magic["output_utf8"], "Secret crib");
}

#[test]
fn decode_bake_cipher_known_answers() {
    let rc4 = json_stdout(&run(&[
        "decode",
        "bake",
        "-hex",
        "bbf316e8d940af0ad3",
        "-op",
        "RC4",
        "-key-hex",
        "4b6579",
        "--json",
    ]));
    assert_eq!(rc4["result"]["output_utf8"], "Plaintext");

    let des = json_stdout(&run(&[
        "decode",
        "bake",
        "-hex",
        "85e813540f0ab405",
        "-op",
        "DESDecrypt",
        "-key-hex",
        "133457799bbcdff1",
        "-mode",
        "ecb",
        "--json",
    ]));
    assert_eq!(des["result"]["output_hex"], "0123456789abcdef");

    let blowfish = json_stdout(&run(&[
        "decode",
        "bake",
        "-hex",
        "324ed0fef413a203",
        "-op",
        "BlowfishDecrypt",
        "-key-hex",
        "6162636465666768696a6b6c6d6e6f707172737475767778797a",
        "-mode",
        "ecb",
        "--json",
    ]));
    assert_eq!(blowfish["result"]["output_utf8"], "BLOWFISH");

    let triple_des = json_stdout(&run(&[
        "decode",
        "bake",
        "-hex",
        "3fe301c962ac01d02213763c1cbd4cdc799657c064ecf5d41c673812cfde9675",
        "-op",
        "TripleDESDecrypt",
        "-key-hex",
        "0123456789abcdeff1e0d3c2b5a49786fedcba9876543210",
        "-iv-hex",
        "fedcba9876543210",
        "-mode",
        "cbc",
        "--json",
    ]));
    assert_eq!(
        triple_des["result"]["output_hex"],
        "37363534333231204e6f77206973207468652074696d6520666f722000000000"
    );
}

#[test]
fn decode_bake_annotation_reports_in_memory_result() {
    let pe = fixture_path("tiny_x64.pe");
    let output = json_stdout(&run(&[
        "decode",
        "bake",
        "-b64",
        "SGVsbG8=",
        "-path",
        pe.to_str().expect("UTF-8 fixture path"),
        "-op",
        "FromBase64",
        "--annotate-va",
        "0x140001000",
        "--json",
    ]));
    assert_eq!(output["result"]["output_utf8"], "Hello");
    assert_eq!(output["annotation"]["applied"], true);
    assert_eq!(output["annotation"]["persisted"], false);
}
