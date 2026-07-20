//! Hand-rolled WebAssembly opcode decoder (MVP + numeric ops).

use crate::arch::leb128;
use crate::arch::ArchDecode;
use crate::error::{Error, Result};
use crate::group::GroupId;
use crate::insn::{InsnDetail, InsnId, Instruction};
use crate::names;
use crate::operand::Operand;
use crate::option::EngineOptions;
use crate::reg::RegId;
use crate::support::{Arch, Mode};

pub struct WasmDecoder {
    _mode: Mode,
}

const OPCODE_MNEMONIC: [&str; 256] = {
    let mut table = ["invalid"; 256];
    table[0x00] = "unreachable";
    table[0x01] = "nop";
    table[0x02] = "block";
    table[0x03] = "loop";
    table[0x04] = "if";
    table[0x05] = "else";
    table[0x0b] = "end";
    table[0x0c] = "br";
    table[0x0d] = "br_if";
    table[0x0e] = "br_table";
    table[0x0f] = "return";
    table[0x10] = "call";
    table[0x11] = "call_indirect";
    table[0x1a] = "drop";
    table[0x1b] = "select";
    table[0x20] = "get_local";
    table[0x21] = "set_local";
    table[0x22] = "tee_local";
    table[0x23] = "get_global";
    table[0x24] = "set_global";
    table[0x28] = "i32.load";
    table[0x29] = "i64.load";
    table[0x2a] = "f32.load";
    table[0x2b] = "f64.load";
    table[0x2c] = "i32.load8_s";
    table[0x2d] = "i32.load8_u";
    table[0x2e] = "i32.load16_s";
    table[0x2f] = "i32.load16_u";
    table[0x30] = "i64.load8_s";
    table[0x31] = "i64.load8_u";
    table[0x32] = "i64.load16_s";
    table[0x33] = "i64.load16_u";
    table[0x34] = "i64.load32_s";
    table[0x35] = "i64.load32_u";
    table[0x36] = "i32.store";
    table[0x37] = "i64.store";
    table[0x38] = "f32.store";
    table[0x39] = "f64.store";
    table[0x3a] = "i32.store8";
    table[0x3b] = "i32.store16";
    table[0x3c] = "i64.store8";
    table[0x3d] = "i64.store16";
    table[0x3e] = "i64.store32";
    table[0x3f] = "current_memory";
    table[0x40] = "grow_memory";
    table[0x41] = "i32.const";
    table[0x42] = "i64.const";
    table[0x43] = "f32.const";
    table[0x44] = "f64.const";
    table[0x45] = "i32.eqz";
    table[0x46] = "i32.eq";
    table[0x47] = "i32.ne";
    table[0x48] = "i32.lt_s";
    table[0x49] = "i32.lt_u";
    table[0x4a] = "i32.gt_s";
    table[0x4b] = "i32.gt_u";
    table[0x4c] = "i32.le_s";
    table[0x4d] = "i32.le_u";
    table[0x4e] = "i32.ge_s";
    table[0x4f] = "i32.ge_u";
    table[0x50] = "i64.eqz";
    table[0x51] = "i64.eq";
    table[0x52] = "i64.ne";
    table[0x53] = "i64.lt_s";
    table[0x54] = "i64.lt_u";
    table[0x55] = "i64.gt_s";
    table[0x56] = "i64.gt_u";
    table[0x57] = "i64.le_s";
    table[0x58] = "i64.le_u";
    table[0x59] = "i64.ge_s";
    table[0x5a] = "i64.ge_u";
    table[0x5b] = "f32.eq";
    table[0x5c] = "f32.ne";
    table[0x5d] = "f32.lt";
    table[0x5e] = "f32.gt";
    table[0x5f] = "f32.le";
    table[0x60] = "f32.ge";
    table[0x61] = "f64.eq";
    table[0x62] = "f64.ne";
    table[0x63] = "f64.lt";
    table[0x64] = "f64.gt";
    table[0x65] = "f64.le";
    table[0x66] = "f64.ge";
    table[0x67] = "i32.clz";
    table[0x68] = "i32.ctz";
    table[0x69] = "i32.popcnt";
    table[0x6a] = "i32.add";
    table[0x6b] = "i32.sub";
    table[0x6c] = "i32.mul";
    table[0x6d] = "i32.div_s";
    table[0x6e] = "i32.div_u";
    table[0x6f] = "i32.rem_s";
    table[0x70] = "i32.rem_u";
    table[0x71] = "i32.and";
    table[0x72] = "i32.or";
    table[0x73] = "i32.xor";
    table[0x74] = "i32.shl";
    table[0x75] = "i32.shr_s";
    table[0x76] = "i32.shr_u";
    table[0x77] = "i32.rotl";
    table[0x78] = "i32.rotr";
    table[0x79] = "i64.clz";
    table[0x7a] = "i64.ctz";
    table[0x7b] = "i64.popcnt";
    table[0x7c] = "i64.add";
    table[0x7d] = "i64.sub";
    table[0x7e] = "i64.mul";
    table[0x7f] = "i64.div_s";
    table[0x80] = "i64.div_u";
    table[0x81] = "i64.rem_s";
    table[0x82] = "i64.rem_u";
    table[0x83] = "i64.and";
    table[0x84] = "i64.or";
    table[0x85] = "i64.xor";
    table[0x86] = "i64.shl";
    table[0x87] = "i64.shr_s";
    table[0x88] = "i64.shr_u";
    table[0x89] = "i64.rotl";
    table[0x8a] = "i64.rotr";
    table[0x8b] = "f32.abs";
    table[0x8c] = "f32.neg";
    table[0x8d] = "f32.ceil";
    table[0x8e] = "f32.floor";
    table[0x8f] = "f32.trunc";
    table[0x90] = "f32.nearest";
    table[0x91] = "f32.sqrt";
    table[0x92] = "f32.add";
    table[0x93] = "f32.sub";
    table[0x94] = "f32.mul";
    table[0x95] = "f32.div";
    table[0x96] = "f32.min";
    table[0x97] = "f32.max";
    table[0x98] = "f32.copysign";
    table[0x99] = "f64.abs";
    table[0x9a] = "f64.neg";
    table[0x9b] = "f64.ceil";
    table[0x9c] = "f64.floor";
    table[0x9d] = "f64.trunc";
    table[0x9e] = "f64.nearest";
    table[0x9f] = "f64.sqrt";
    table[0xa0] = "f64.add";
    table[0xa1] = "f64.sub";
    table[0xa2] = "f64.mul";
    table[0xa3] = "f64.div";
    table[0xa4] = "f64.min";
    table[0xa5] = "f64.max";
    table[0xa6] = "f64.copysign";
    table
};

pub(crate) fn decode_raw(bytes: &[u8], address: u64) -> Result<Instruction> {
    if bytes.is_empty() {
        return Err(Error::Decode("empty input".into()));
    }
    let opcode = bytes[0];
    let mnemonic = OPCODE_MNEMONIC[opcode as usize];
    if mnemonic == "invalid" {
        return Ok(Instruction::with_text(
            address,
            vec![opcode],
            "invalid",
            String::new(),
            1,
        ));
    }
    let (extra, operands) = decode_immediates(opcode, &bytes[1..])?;
    let len = 1 + extra;
    Ok(Instruction::with_text(
        address,
        bytes[..len].to_vec(),
        mnemonic,
        operands,
        len as u8,
    ))
}

fn decode_immediates(opcode: u8, tail: &[u8]) -> Result<(usize, String)> {
    Ok(match opcode {
        0x02 | 0x03 | 0x04 => {
            let (ty, n) = leb128::read_i7(tail)?;
            let op = if ty == 0 && !tail.is_empty() && tail[0] == 0x40 {
                "void".to_string()
            } else {
                format!("{ty}")
            };
            (n, op)
        }
        0x0c | 0x0d | 0x10 | 0x11 | 0x20 | 0x21 | 0x22 | 0x23 | 0x24 => {
            let (idx, n) = leb128::read_u32(tail)?;
            (n, format!("{idx}"))
        }
        0x0e => decode_br_table(tail)?,
        0x28..=0x3e => {
            let (align, n1) = leb128::read_u32(tail)?;
            let (offset, n2) = leb128::read_u32(&tail[n1..])?;
            (n1 + n2, format!("{align}, {offset}"))
        }
        0x41 => {
            let (v, n) = leb128::read_i32(tail)?;
            (n, format!("{v}"))
        }
        0x42 => {
            let (v, n) = leb128::read_i64(tail)?;
            (n, format!("{v}"))
        }
        0x43 => {
            if tail.len() < 4 {
                return Err(Error::Decode("truncated f32.const".into()));
            }
            let bits = u32::from_le_bytes([tail[0], tail[1], tail[2], tail[3]]);
            (4, format!("{bits:#x}"))
        }
        0x44 => {
            if tail.len() < 8 {
                return Err(Error::Decode("truncated f64.const".into()));
            }
            let bits = u64::from_le_bytes([
                tail[0], tail[1], tail[2], tail[3], tail[4], tail[5], tail[6], tail[7],
            ]);
            (8, format!("{bits:#x}"))
        }
        _ => (0, String::new()),
    })
}

fn decode_br_table(tail: &[u8]) -> Result<(usize, String)> {
    let (count, n1) = leb128::read_u32(tail)?;
    let mut off = n1;
    let mut targets = Vec::with_capacity(count as usize + 1);
    for _ in 0..=count {
        let (label, n) = leb128::read_u32(&tail[off..])?;
        off += n;
        targets.push(label.to_string());
    }
    Ok((off, targets.join(", ")))
}

impl ArchDecode for WasmDecoder {
    fn arch(&self) -> Arch {
        Arch::Wasm
    }

    fn open(mode: Mode) -> Result<Self> {
        if !mode.is_valid_for(Arch::Wasm) {
            return Err(Error::Mode(format!("invalid wasm mode {:#x}", mode.bits())));
        }
        Ok(Self { _mode: mode })
    }

    fn decode_one(&self, bytes: &[u8], address: u64, opts: &EngineOptions) -> Result<Instruction> {
        let mut insn = decode_raw(bytes, address)?;
        insn.id = names::insn_id_for_mnemonic(Arch::Wasm, &insn.mnemonic);
        if opts.detail {
            insn.detail = Some(InsnDetail {
                groups: groups_for_mnemonic(&insn.mnemonic),
                operands: typed_operands(&insn),
                ..InsnDetail::default()
            });
        }
        Ok(insn)
    }
}

fn typed_operands(insn: &Instruction) -> Vec<Operand> {
    if insn.operands.is_empty() {
        return Vec::new();
    }
    insn.operands
        .split(", ")
        .filter_map(|p| {
            p.parse::<i64>()
                .ok()
                .map(|v| Operand::Imm { value: v, size: 4 })
        })
        .collect()
}

fn groups_for_mnemonic(mnemonic: &str) -> Vec<GroupId> {
    match mnemonic {
        "block" | "loop" | "if" | "else" | "end" | "br" | "br_if" | "br_table" | "return"
        | "call" | "call_indirect" => vec![GroupId::Jump],
        "i32.const" | "i64.const" | "f32.const" | "f64.const" => vec![GroupId::Arch(2)],
        m if m.contains("load") || m.contains("store") || m.contains("memory") => {
            vec![GroupId::Arch(3)]
        }
        m if m.contains("local") || m.contains("global") => vec![GroupId::Arch(4)],
        m if m.contains('.') => vec![GroupId::Arch(2)],
        _ => Vec::new(),
    }
}

pub fn reg_name(_reg: RegId) -> Option<&'static str> {
    None
}

pub fn insn_name(id: InsnId) -> Option<&'static str> {
    let raw = id.raw();
    if raw < 256 {
        let name = OPCODE_MNEMONIC[raw as usize];
        if name != "invalid" {
            Some(name)
        } else {
            None
        }
    } else {
        None
    }
}

pub fn group_name(group: GroupId) -> Option<&'static str> {
    match group {
        GroupId::Jump => Some("control"),
        GroupId::Arch(2) => Some("numeric"),
        GroupId::Arch(3) => Some("memory"),
        GroupId::Arch(4) => Some("variable"),
        _ => None,
    }
}

pub fn insn_id_for_mnemonic(mnemonic: &str) -> InsnId {
    for (i, name) in OPCODE_MNEMONIC.iter().enumerate() {
        if *name == mnemonic {
            return InsnId(i as u32);
        }
    }
    InsnId::INVALID
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::option::EngineOptions;

    #[test]
    fn wasm_i32_const_and_add() {
        let dec = WasmDecoder::open(Mode::LITTLE_ENDIAN).unwrap();
        let c = dec
            .decode_one(&[0x41, 0xfb, 0x00], 0, &EngineOptions::default())
            .unwrap();
        assert_eq!(c.mnemonic, "i32.const");
        assert_eq!(c.operands, "123");
        assert_eq!(c.length, 3);

        let add = dec
            .decode_one(&[0x6a], 0, &EngineOptions::default())
            .unwrap();
        assert_eq!(add.mnemonic, "i32.add");
        assert_eq!(add.length, 1);
    }

    #[test]
    fn wasm_call_and_block() {
        let dec = WasmDecoder::open(Mode::LITTLE_ENDIAN).unwrap();
        let call = dec
            .decode_one(&[0x10, 0x03], 0, &EngineOptions::default())
            .unwrap();
        assert_eq!(call.mnemonic, "call");
        assert_eq!(call.operands, "3");

        let block = dec
            .decode_one(&[0x02, 0x40], 0, &EngineOptions::default())
            .unwrap();
        assert_eq!(block.mnemonic, "block");
        assert_eq!(block.operands, "void");
    }

    #[test]
    fn wasm_load_store() {
        let dec = WasmDecoder::open(Mode::LITTLE_ENDIAN).unwrap();
        let load = dec
            .decode_one(&[0x28, 0x02, 0x04], 0, &EngineOptions::default())
            .unwrap();
        assert_eq!(load.mnemonic, "i32.load");
        assert_eq!(load.operands, "2, 4");
        assert_eq!(load.length, 3);
    }
}
