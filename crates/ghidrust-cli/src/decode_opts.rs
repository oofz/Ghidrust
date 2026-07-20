//! Shared decode / disasm flags for CLI args and MCP JSON.

use ghidrust_core::{Arch, DisasmEngineOpts, Mode, Syntax};
use serde_json::Value;
use std::path::PathBuf;

#[derive(Debug, Clone, Default)]
pub struct DecodeOpts {
    pub arch: Option<Arch>,
    pub mode: Option<Mode>,
    pub syntax: Option<Syntax>,
    pub detail: Option<bool>,
    pub detail_real: Option<bool>,
    pub skipdata: Option<bool>,
    pub skipdata_mnemonic: Option<String>,
    pub skipdata_size: Option<usize>,
    pub unsigned_imm: Option<bool>,
    pub only_offset_branch: Option<bool>,
    pub litbase: Option<u32>,
    pub mnem_overrides: Vec<(u32, String)>,
    pub linear: bool,
    pub flow: bool,
    pub brief: bool,
    pub pretty: bool,
    pub addr: Option<u64>,
    pub count: usize,
    pub skip_bad: bool,
    pub out_path: Option<PathBuf>,
}

impl DecodeOpts {
    pub fn default_count() -> usize {
        16
    }

    pub fn from_cli_args(args: &[String]) -> Result<(PathBuf, Self), String> {
        let args = normalize_cli_flags(args);
        let mut path: Option<PathBuf> = None;
        let mut opts = Self {
            count: Self::default_count(),
            skip_bad: false,
            ..Default::default()
        };
        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "-arch" if i + 1 < args.len() => {
                    opts.arch = Some(parse_arch(&args[i + 1])?);
                    i += 2;
                }
                "-mode" if i + 1 < args.len() => {
                    opts.mode = Some(parse_mode(&args[i + 1])?);
                    i += 2;
                }
                "-syntax" if i + 1 < args.len() => {
                    opts.syntax = Some(parse_syntax(&args[i + 1])?);
                    i += 2;
                }
                "-detail" => {
                    opts.detail = Some(true);
                    i += 1;
                }
                "-no-detail" => {
                    opts.detail = Some(false);
                    i += 1;
                }
                "-detail-real" => {
                    opts.detail_real = Some(true);
                    i += 1;
                }
                "-skipdata" => {
                    opts.skipdata = Some(true);
                    i += 1;
                }
                "-skipdata-mnemonic" if i + 1 < args.len() => {
                    opts.skipdata_mnemonic = Some(args[i + 1].clone());
                    i += 2;
                }
                "-skipdata-size" if i + 1 < args.len() => {
                    opts.skipdata_size = Some(
                        args[i + 1]
                            .parse()
                            .map_err(|e| format!("invalid skipdata-size: {e}"))?,
                    );
                    i += 2;
                }
                "-unsigned-imm" => {
                    opts.unsigned_imm = Some(true);
                    i += 1;
                }
                "-only-offset-branch" => {
                    opts.only_offset_branch = Some(true);
                    i += 1;
                }
                "-litbase" if i + 1 < args.len() => {
                    opts.litbase = Some(parse_u32(&args[i + 1])?);
                    i += 2;
                }
                "-mnem-override" if i + 1 < args.len() => {
                    opts.mnem_overrides.push(parse_mnem_override(&args[i + 1])?);
                    i += 2;
                }
                "-addr" if i + 1 < args.len() => {
                    opts.addr = Some(parse_u64(&args[i + 1])?);
                    i += 2;
                }
                "-count" if i + 1 < args.len() => {
                    opts.count = args[i + 1].parse().unwrap_or(Self::default_count());
                    i += 2;
                }
                "-skip-bad" => {
                    opts.skip_bad = true;
                    i += 1;
                }
                "-linear" => {
                    opts.linear = true;
                    i += 1;
                }
                "-flow" => {
                    opts.flow = true;
                    i += 1;
                }
                "-brief" => {
                    opts.brief = true;
                    i += 1;
                }
                "-pretty" => {
                    opts.pretty = true;
                    i += 1;
                }
                "-out" if i + 1 < args.len() => {
                    opts.out_path = Some(PathBuf::from(&args[i + 1]));
                    i += 2;
                }
                other if !other.starts_with('-') && path.is_none() => {
                    path = Some(PathBuf::from(other));
                    i += 1;
                }
                _ => i += 1,
            }
        }
        let path = path.ok_or_else(|| "missing path".to_string())?;
        Ok((path, opts))
    }

    pub fn from_json(args: &Value) -> Result<Self, String> {
        let mut opts = Self {
            count: args
                .get("count")
                .and_then(|c| c.as_u64())
                .unwrap_or(Self::default_count() as u64) as usize,
            skip_bad: args
                .get("skip_bad")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            ..Default::default()
        };
        if let Some(a) = args.get("arch").and_then(|v| v.as_str()) {
            opts.arch = Some(parse_arch(a)?);
        }
        if let Some(m) = args.get("mode") {
            opts.mode = Some(parse_mode_value(m)?);
        }
        if let Some(s) = args.get("syntax").and_then(|v| v.as_str()) {
            opts.syntax = Some(parse_syntax(s)?);
        }
        if let Some(v) = args.get("detail").and_then(|v| v.as_bool()) {
            opts.detail = Some(v);
        }
        if let Some(v) = args.get("detail_real").and_then(|v| v.as_bool()) {
            opts.detail_real = Some(v);
        }
        if let Some(v) = args.get("skipdata").and_then(|v| v.as_bool()) {
            opts.skipdata = Some(v);
        }
        if let Some(v) = args.get("skipdata_mnemonic").and_then(|v| v.as_str()) {
            opts.skipdata_mnemonic = Some(v.to_string());
        }
        if let Some(v) = args.get("skipdata_size").and_then(|v| v.as_u64()) {
            opts.skipdata_size = Some(v as usize);
        }
        if let Some(v) = args.get("unsigned_imm").and_then(|v| v.as_bool()) {
            opts.unsigned_imm = Some(v);
        }
        if let Some(v) = args.get("only_offset_branch").and_then(|v| v.as_bool()) {
            opts.only_offset_branch = Some(v);
        }
        if let Some(v) = args.get("litbase") {
            opts.litbase = Some(parse_u32_value(v)?);
        }
        if let Some(arr) = args.get("mnem_overrides").and_then(|v| v.as_array()) {
            for item in arr {
                if let Some(pair) = item.as_str() {
                    opts.mnem_overrides.push(parse_mnem_override(pair)?);
                } else if let Some(obj) = item.as_object() {
                    let id = obj
                        .get("id")
                        .ok_or_else(|| "mnem_overrides entry missing id".to_string())
                        .and_then(parse_u32_value)?;
                    let mnemonic = obj
                        .get("mnemonic")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "mnem_overrides entry missing mnemonic".to_string())?
                        .to_string();
                    opts.mnem_overrides.push((id, mnemonic));
                }
            }
        }
        opts.linear = args
            .get("linear")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        opts.flow = args.get("flow").and_then(|v| v.as_bool()).unwrap_or(false);
        if let Some(a) = args.get("addr").and_then(|v| v.as_str()) {
            opts.addr = Some(parse_u64(a)?);
        }
        Ok(opts)
    }

    pub fn to_engine_opts(&self) -> DisasmEngineOpts {
        DisasmEngineOpts {
            arch: self.arch,
            mode: self.mode,
            syntax: self.syntax,
            detail: self.detail,
            detail_real: self.detail_real,
            skipdata: self.skipdata,
            skipdata_mnemonic: self.skipdata_mnemonic.clone(),
            skipdata_size: self.skipdata_size,
            unsigned_imm: self.unsigned_imm,
            only_offset_branch: self.only_offset_branch,
            litbase: self.litbase,
            mnem_overrides: if self.mnem_overrides.is_empty() {
                None
            } else {
                Some(self.mnem_overrides.clone())
            },
        }
    }

    pub fn raw_blob_mode(&self) -> bool {
        self.arch.is_some()
    }
}

/// Normalize GNU-style `--flag` to the CLI's `-flag` form (values unchanged).
pub fn normalize_cli_flags(args: &[String]) -> Vec<String> {
    args.iter()
        .map(|a| {
            if a.starts_with("--") && a.len() > 2 {
                format!("-{}", &a[2..])
            } else {
                a.clone()
            }
        })
        .collect()
}

pub fn parse_u64(s: &str) -> Result<u64, String> {
    let t = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(t, 16)
        .or_else(|_| s.parse::<u64>())
        .map_err(|e| e.to_string())
}

pub fn parse_u32(s: &str) -> Result<u32, String> {
    let t = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    u32::from_str_radix(t, 16)
        .or_else(|_| s.parse::<u32>())
        .map_err(|e| e.to_string())
}

fn parse_u32_value(v: &Value) -> Result<u32, String> {
    if let Some(n) = v.as_u64() {
        return Ok(n as u32);
    }
    if let Some(s) = v.as_str() {
        return parse_u32(s);
    }
    Err("expected u32".into())
}

pub fn parse_arch(s: &str) -> Result<Arch, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "arm" => Ok(Arch::Arm),
        "arm64" | "aarch64" => Ok(Arch::Arm64),
        "mips" => Ok(Arch::Mips),
        "x86" | "x86_64" | "x64" | "amd64" => Ok(Arch::X86),
        "ppc" | "powerpc" => Ok(Arch::Ppc),
        "sparc" => Ok(Arch::Sparc),
        "sysz" | "systemz" | "s390" | "s390x" => Ok(Arch::Sysz),
        "xcore" => Ok(Arch::Xcore),
        "m68k" | "68k" => Ok(Arch::M68k),
        "tms320c64x" | "tms320" | "c64x" => Ok(Arch::Tms320c64x),
        "m680x" | "6800" | "6809" => Ok(Arch::M680x),
        "evm" => Ok(Arch::Evm),
        "mos65xx" | "6502" | "65c02" => Ok(Arch::Mos65xx),
        "wasm" | "webassembly" => Ok(Arch::Wasm),
        "bpf" | "ebpf" => Ok(Arch::Bpf),
        "riscv" | "riscv64" | "riscv32" => Ok(Arch::Riscv),
        "sh" | "superh" => Ok(Arch::Sh),
        "tricore" => Ok(Arch::Tricore),
        "alpha" => Ok(Arch::Alpha),
        "hppa" | "parisc" | "pa-risc" => Ok(Arch::Hppa),
        "loongarch" | "loongarch64" => Ok(Arch::Loongarch),
        "xtensa" => Ok(Arch::Xtensa),
        "arc" => Ok(Arch::Arc),
        other => Err(format!("unknown arch: {other}")),
    }
}

pub fn parse_mode(s: &str) -> Result<Mode, String> {
    parse_mode_value(&Value::String(s.to_string()))
}

pub fn parse_mode_value(v: &Value) -> Result<Mode, String> {
    if let Some(n) = v.as_u64() {
        return Ok(Mode(n as u32));
    }
    let s = v
        .as_str()
        .ok_or_else(|| "mode must be string or integer".to_string())?;
    let t = s.trim().to_ascii_lowercase();
    if let Ok(n) = parse_u32(&t) {
        return Ok(Mode(n));
    }
    Ok(match t.as_str() {
        "16" | "mode16" => Mode::MODE_16,
        "32" | "mode32" | "i386" => Mode::MODE_32,
        "64" | "mode64" | "amd64" | "x64" => Mode::MODE_64,
        "thumb" => Mode::THUMB,
        "mclass" => Mode::MCLASS,
        "v8" => Mode::V8,
        "mips32" => Mode::MIPS32,
        "mips64" => Mode::MIPS64,
        "ppc32" => Mode::PPC32,
        "ppc64" => Mode::PPC64,
        "riscv32" => Mode::RISCV32,
        "riscv64" => Mode::RISCV64,
        "riscv_c" | "rvc" => Mode::RISCV_C,
        "le" | "little" | "little_endian" => Mode::LITTLE_ENDIAN,
        "be" | "big" | "big_endian" => Mode::BIG_ENDIAN,
        "bpf_classic" => Mode::BPF_CLASSIC,
        "bpf_extended" => Mode::BPF_EXTENDED,
        "6502" => Mode::MOS65XX_6502,
        "65c02" => Mode::MOS65XX_65C02,
        other => return Err(format!("unknown mode: {other}")),
    })
}

pub fn parse_syntax(s: &str) -> Result<Syntax, String> {
    Ok(match s.trim().to_ascii_lowercase().as_str() {
        "default" => Syntax::Default,
        "intel" => Syntax::Intel,
        "att" => Syntax::Att,
        "noregname" | "no_reg_name" => Syntax::NoRegName,
        "masm" => Syntax::Masm,
        "motorola" => Syntax::Motorola,
        "cs_reg_alias" | "reg_alias" => Syntax::CsRegAlias,
        "percent" => Syntax::Percent,
        "no_dollar" | "nodollar" => Syntax::NoDollar,
        "no_alias_text" => Syntax::NoAliasText,
        "no_alias_text_compressed" => Syntax::NoAliasTextCompressed,
        other => return Err(format!("unknown syntax: {other}")),
    })
}

fn parse_mnem_override(s: &str) -> Result<(u32, String), String> {
    let (id_s, mnem) = s
        .split_once(':')
        .ok_or_else(|| "mnem-override must be ID:MNEMONIC".to_string())?;
    Ok((parse_u32(id_s)?, mnem.to_string()))
}

pub fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    let t = s.trim().trim_start_matches("0x");
    if t.is_empty() {
        return Ok(Vec::new());
    }
    if t.len() % 2 != 0 {
        return Err("hex bytes must have even length".into());
    }
    (0..t.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&t[i..i + 2], 16).map_err(|e| format!("invalid hex at {i}: {e}"))
        })
        .collect()
}
