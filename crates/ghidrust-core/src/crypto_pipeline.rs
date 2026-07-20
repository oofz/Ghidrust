//! Cross-tier crypto discovery → recover → bake suggestion pipeline.

use crate::analyzers::{crypt_constants, crypto_capabilities, obfuscated_strings, AnalyzerOutput};
use crate::decode_bake::BakeOp;
use crate::error::Result;
use crate::program::Program;

/// Run Find Crypt → Obfuscated Strings → Crypto Capabilities in order so each tier seeds the next.
pub fn run_crypto_pipeline(prog: &mut Program) -> Result<Vec<AnalyzerOutput>> {
    let mut outs = Vec::new();
    outs.push(crypt_constants::run(prog)?);
    outs.push(obfuscated_strings::run(prog)?);
    outs.push(crypto_capabilities::run(prog)?);
    Ok(outs)
}

/// Suggest a bake recipe from algorithm / capability hint text.
pub fn suggest_recipe_for_hint(hint: &str) -> Vec<BakeOp> {
    let h = hint.to_ascii_uppercase();
    if h.contains("AES") {
        return vec![BakeOp {
            op: "AESDecrypt".into(),
            args: serde_json::json!({"mode": "cbc"}),
        }];
    }
    if h.contains("RC4") {
        return vec![BakeOp {
            op: "RC4".into(),
            args: serde_json::json!({}),
        }];
    }
    if h.contains("DES") && !h.contains("3DES") && !h.contains("TRIPLE") {
        return vec![BakeOp {
            op: "DESDecrypt".into(),
            args: serde_json::json!({"mode": "cbc"}),
        }];
    }
    if h.contains("3DES") || h.contains("TRIPLE DES") {
        return vec![BakeOp {
            op: "TripleDESDecrypt".into(),
            args: serde_json::json!({"mode": "cbc"}),
        }];
    }
    if h.contains("BLOWFISH") {
        return vec![BakeOp {
            op: "BlowfishDecrypt".into(),
            args: serde_json::json!({"mode": "cbc"}),
        }];
    }
    if h.contains("CHACHA") || h.contains("SALSA") {
        return vec![BakeOp {
            op: "ChaCha20Decrypt".into(),
            args: serde_json::json!({}),
        }];
    }
    if h.contains("BASE64") || h.contains("ENCODING") {
        return vec![
            BakeOp {
                op: "FromBase64".into(),
                args: serde_json::json!({}),
            },
            BakeOp {
                op: "Gunzip".into(),
                args: serde_json::json!({}),
            },
        ];
    }
    if h.contains("GZIP") {
        return vec![BakeOp {
            op: "Gunzip".into(),
            args: serde_json::json!({}),
        }];
    }
    if h.contains("ZLIB") || h.contains("INFLATE") {
        return vec![BakeOp {
            op: "Inflate".into(),
            args: serde_json::json!({}),
        }];
    }
    if h.contains("DPAPI") || h.contains("CRYPTPROTECT") || h.contains("DATA PROTECTION") {
        return Vec::new();
    }
    vec![
        BakeOp {
            op: "FromBase64".into(),
            args: serde_json::json!({}),
        },
        BakeOp {
            op: "XORBrute".into(),
            args: serde_json::json!({}),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suggestions_name_native_operations() {
        assert_eq!(suggest_recipe_for_hint("ChaCha20")[0].op, "ChaCha20Decrypt");
        assert_eq!(suggest_recipe_for_hint("gzip stream")[0].op, "Gunzip");
        assert!(suggest_recipe_for_hint("DPAPI CryptProtectData").is_empty());
    }
}

/// Build decoder `--functions` seed list from prior pipeline state on `prog`.
pub fn recover_function_seeds(prog: &Program) -> Vec<u64> {
    obfuscated_strings::decoder_seed_vas(prog)
}
