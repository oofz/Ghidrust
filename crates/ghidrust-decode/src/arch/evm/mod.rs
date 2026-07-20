//! Hand-rolled Ethereum VM (EVM) opcode decoder.

use crate::arch::ArchDecode;
use crate::error::{Error, Result};
use crate::group::GroupId;
use crate::insn::{InsnDetail, InsnId, Instruction};
use crate::names;
use crate::option::EngineOptions;
use crate::support::{Arch, Mode};

pub struct EvmDecoder {
    _mode: Mode,
}

const OPCODE_MNEMONIC: [&str; 256] = {
    let mut table = ["invalid"; 256];
    table[0x00] = "stop";
    table[0x01] = "add";
    table[0x02] = "mul";
    table[0x03] = "sub";
    table[0x04] = "div";
    table[0x05] = "sdiv";
    table[0x06] = "mod";
    table[0x07] = "smod";
    table[0x08] = "addmod";
    table[0x09] = "mulmod";
    table[0x0a] = "exp";
    table[0x0b] = "signextend";
    table[0x10] = "lt";
    table[0x11] = "gt";
    table[0x12] = "slt";
    table[0x13] = "sgt";
    table[0x14] = "eq";
    table[0x15] = "iszero";
    table[0x16] = "and";
    table[0x17] = "or";
    table[0x18] = "xor";
    table[0x19] = "not";
    table[0x1a] = "byte";
    table[0x1b] = "shl";
    table[0x1c] = "shr";
    table[0x1d] = "sar";
    table[0x20] = "sha3";
    table[0x30] = "address";
    table[0x31] = "balance";
    table[0x32] = "origin";
    table[0x33] = "caller";
    table[0x34] = "callvalue";
    table[0x35] = "calldataload";
    table[0x36] = "calldatasize";
    table[0x37] = "calldatacopy";
    table[0x38] = "codesize";
    table[0x39] = "codecopy";
    table[0x3a] = "gasprice";
    table[0x3b] = "extcodesize";
    table[0x3c] = "extcodecopy";
    table[0x3d] = "returndatasize";
    table[0x3e] = "returndatacopy";
    table[0x40] = "blockhash";
    table[0x41] = "coinbase";
    table[0x42] = "timestamp";
    table[0x43] = "number";
    table[0x44] = "difficulty";
    table[0x45] = "gaslimit";
    table[0x46] = "chainid";
    table[0x47] = "selfbalance";
    table[0x48] = "basefee";
    table[0x49] = "blobhash";
    table[0x4a] = "blobbasefee";
    table[0x50] = "pop";
    table[0x51] = "mload";
    table[0x52] = "mstore";
    table[0x53] = "mstore8";
    table[0x54] = "sload";
    table[0x55] = "sstore";
    table[0x56] = "jump";
    table[0x57] = "jumpi";
    table[0x58] = "pc";
    table[0x59] = "msize";
    table[0x5a] = "gas";
    table[0x5b] = "jumpdest";
    table[0x5c] = "tload";
    table[0x5d] = "tstore";
    table[0x5e] = "mcopy";
    table[0x5f] = "push0";
    let mut op = 0x60u8;
    while op <= 0x7f {
        table[op as usize] = match op - 0x60 + 1 {
            1 => "push1",
            2 => "push2",
            3 => "push3",
            4 => "push4",
            5 => "push5",
            6 => "push6",
            7 => "push7",
            8 => "push8",
            9 => "push9",
            10 => "push10",
            11 => "push11",
            12 => "push12",
            13 => "push13",
            14 => "push14",
            15 => "push15",
            16 => "push16",
            17 => "push17",
            18 => "push18",
            19 => "push19",
            20 => "push20",
            21 => "push21",
            22 => "push22",
            23 => "push23",
            24 => "push24",
            25 => "push25",
            26 => "push26",
            27 => "push27",
            28 => "push28",
            29 => "push29",
            30 => "push30",
            31 => "push31",
            _ => "push32",
        };
        op += 1;
    }
    table[0x80] = "dup1";
    table[0x81] = "dup2";
    table[0x82] = "dup3";
    table[0x83] = "dup4";
    table[0x84] = "dup5";
    table[0x85] = "dup6";
    table[0x86] = "dup7";
    table[0x87] = "dup8";
    table[0x88] = "dup9";
    table[0x89] = "dup10";
    table[0x8a] = "dup11";
    table[0x8b] = "dup12";
    table[0x8c] = "dup13";
    table[0x8d] = "dup14";
    table[0x8e] = "dup15";
    table[0x8f] = "dup16";
    table[0x90] = "swap1";
    table[0x91] = "swap2";
    table[0x92] = "swap3";
    table[0x93] = "swap4";
    table[0x94] = "swap5";
    table[0x95] = "swap6";
    table[0x96] = "swap7";
    table[0x97] = "swap8";
    table[0x98] = "swap9";
    table[0x99] = "swap10";
    table[0x9a] = "swap11";
    table[0x9b] = "swap12";
    table[0x9c] = "swap13";
    table[0x9d] = "swap14";
    table[0x9e] = "swap15";
    table[0x9f] = "swap16";
    table[0xa0] = "log0";
    table[0xa1] = "log1";
    table[0xa2] = "log2";
    table[0xa3] = "log3";
    table[0xa4] = "log4";
    table[0xf0] = "create";
    table[0xf1] = "call";
    table[0xf2] = "callcode";
    table[0xf3] = "return";
    table[0xf4] = "delegatecall";
    table[0xf5] = "create2";
    table[0xfa] = "staticcall";
    table[0xfd] = "revert";
    table[0xff] = "selfdestruct";
    table
};

const PUSH1: u8 = 0x60;
const PUSH32: u8 = 0x7f;

pub(crate) fn decode_raw(bytes: &[u8], address: u64) -> Result<Instruction> {
    if bytes.is_empty() {
        return Err(Error::Decode("empty input".into()));
    }
    let opcode = bytes[0];
    let mnemonic = OPCODE_MNEMONIC[opcode as usize];
    let (length, operands) = if opcode >= PUSH1 && opcode <= PUSH32 {
        let imm_len = (opcode - PUSH1 + 1) as usize;
        if bytes.len() < 1 + imm_len {
            return Err(Error::Decode("truncated push immediate".into()));
        }
        let imm_bytes = &bytes[1..=imm_len];
        let hex = imm_bytes
            .iter()
            .rev()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let imm_display = format!("0x{hex}");
        (1 + imm_len as u8, imm_display)
    } else if mnemonic == "invalid" {
        (1, String::new())
    } else {
        (1, String::new())
    };
    Ok(Instruction::with_text(
        address,
        bytes[..length as usize].to_vec(),
        mnemonic,
        operands,
        length,
    ))
}

impl ArchDecode for EvmDecoder {
    fn arch(&self) -> Arch {
        Arch::Evm
    }

    fn open(mode: Mode) -> Result<Self> {
        if !mode.is_valid_for(Arch::Evm) {
            return Err(Error::Mode(format!("invalid evm mode {:#x}", mode.bits())));
        }
        Ok(Self { _mode: mode })
    }

    fn decode_one(&self, bytes: &[u8], address: u64, opts: &EngineOptions) -> Result<Instruction> {
        let mut insn = decode_raw(bytes, address)?;
        insn.id = names::insn_id_for_mnemonic(Arch::Evm, &insn.mnemonic);
        if opts.detail {
            insn.detail = Some(InsnDetail {
                groups: groups_for_mnemonic(&insn.mnemonic),
                ..InsnDetail::default()
            });
        }
        Ok(insn)
    }
}

fn groups_for_mnemonic(mnemonic: &str) -> Vec<GroupId> {
    match mnemonic {
        "jump" | "jumpi" => vec![GroupId::Jump],
        "call" | "callcode" | "delegatecall" | "staticcall" => vec![GroupId::Call],
        "return" | "revert" => vec![GroupId::Ret],
        "stop" | "selfdestruct" => vec![GroupId::Arch(8)], // halt
        m if m.starts_with("push") => vec![GroupId::Arch(6)], // stack_write
        "pop" | "dup1" | "dup2" | "dup3" | "dup4" | "dup5" | "dup6" | "dup7" | "dup8" | "dup9"
        | "dup10" | "dup11" | "dup12" | "dup13" | "dup14" | "dup15" | "dup16" => {
            vec![GroupId::Arch(5)] // stack_read
        }
        "mstore" | "mstore8" | "calldatacopy" | "codecopy" | "extcodecopy" | "mcopy" => {
            vec![GroupId::Arch(7)] // mem_write
        }
        "mload" | "create" | "create2" => vec![GroupId::Arch(4)], // mem_read
        "sstore" | "tstore" => vec![GroupId::Arch(9)],            // store_write
        "sload" | "tload" => vec![GroupId::Arch(10)],             // store_read
        "add" | "mul" | "sub" | "div" | "sdiv" | "mod" | "smod" | "addmod" | "mulmod" | "exp"
        | "signextend" | "shl" | "shr" | "sar" => vec![GroupId::Arch(3)], // math
        _ => Vec::new(),
    }
}

pub fn reg_name(_reg: crate::reg::RegId) -> Option<&'static str> {
    None
}

pub fn insn_name(id: InsnId) -> Option<&'static str> {
    let raw = id.raw();
    if raw < 256 {
        Some(OPCODE_MNEMONIC[raw as usize])
    } else {
        None
    }
}

pub fn group_name(group: GroupId) -> Option<&'static str> {
    match group {
        GroupId::Jump => Some("jump"),
        GroupId::Call => Some("call"),
        GroupId::Ret => Some("ret"),
        GroupId::Arch(3) => Some("math"),
        GroupId::Arch(4) => Some("mem_read"),
        GroupId::Arch(5) => Some("stack_read"),
        GroupId::Arch(6) => Some("stack_write"),
        GroupId::Arch(7) => Some("mem_write"),
        GroupId::Arch(8) => Some("halt"),
        GroupId::Arch(9) => Some("store_write"),
        GroupId::Arch(10) => Some("store_read"),
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
    fn evm_stop_and_push1() {
        let dec = EvmDecoder::open(Mode::LITTLE_ENDIAN).unwrap();
        let stop = dec
            .decode_one(&[0x00], 0, &EngineOptions::default())
            .unwrap();
        assert_eq!(stop.mnemonic, "stop");
        assert_eq!(stop.length, 1);

        let push = dec
            .decode_one(&[0x60, 0x2a], 0x10, &EngineOptions::default())
            .unwrap();
        assert_eq!(push.mnemonic, "push1");
        assert_eq!(push.length, 2);
        assert_eq!(push.operands, "0x2a");
    }

    #[test]
    fn evm_call_and_invalid() {
        let dec = EvmDecoder::open(Mode::LITTLE_ENDIAN).unwrap();
        let call = dec
            .decode_one(&[0xf1], 0, &EngineOptions::default())
            .unwrap();
        assert_eq!(call.mnemonic, "call");

        let bad = dec
            .decode_one(&[0x0c], 0, &EngineOptions::default())
            .unwrap();
        assert_eq!(bad.mnemonic, "invalid");
    }

    #[test]
    fn evm_push32_length() {
        let dec = EvmDecoder::open(Mode::LITTLE_ENDIAN).unwrap();
        let mut bytes = vec![0x7f];
        bytes.extend(std::iter::repeat_n(0xab_u8, 32));
        let insn = dec
            .decode_one(&bytes, 0, &EngineOptions::default())
            .unwrap();
        assert_eq!(insn.mnemonic, "push32");
        assert_eq!(insn.length, 33);
    }
}
