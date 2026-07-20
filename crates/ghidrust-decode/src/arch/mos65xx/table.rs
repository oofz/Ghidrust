//! Auto-generated 6502 / 65C02 opcode tables .

use super::{AddrMode, InsnId, OpEntry};

pub const TABLE_6502: [OpEntry; 256] = [
    OpEntry {
        mnemonic: "brk",
        insn: InsnId::BRK,
        mode: AddrMode::Int,
        operand_bytes: 1,
    }, // 0x00
    OpEntry {
        mnemonic: "ora",
        insn: InsnId::ORA,
        mode: AddrMode::ZpXInd,
        operand_bytes: 1,
    }, // 0x01
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x02
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x03
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x04
    OpEntry {
        mnemonic: "ora",
        insn: InsnId::ORA,
        mode: AddrMode::Zp,
        operand_bytes: 1,
    }, // 0x05
    OpEntry {
        mnemonic: "asl",
        insn: InsnId::ASL,
        mode: AddrMode::Zp,
        operand_bytes: 1,
    }, // 0x06
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x07
    OpEntry {
        mnemonic: "php",
        insn: InsnId::PHP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x08
    OpEntry {
        mnemonic: "ora",
        insn: InsnId::ORA,
        mode: AddrMode::Imm,
        operand_bytes: 1,
    }, // 0x09
    OpEntry {
        mnemonic: "asl",
        insn: InsnId::ASL,
        mode: AddrMode::Acc,
        operand_bytes: 0,
    }, // 0x0a
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x0b
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x0c
    OpEntry {
        mnemonic: "ora",
        insn: InsnId::ORA,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0x0d
    OpEntry {
        mnemonic: "asl",
        insn: InsnId::ASL,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0x0e
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x0f
    OpEntry {
        mnemonic: "bpl",
        insn: InsnId::BPL,
        mode: AddrMode::Rel,
        operand_bytes: 1,
    }, // 0x10
    OpEntry {
        mnemonic: "ora",
        insn: InsnId::ORA,
        mode: AddrMode::ZpIndY,
        operand_bytes: 1,
    }, // 0x11
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x12
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x13
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x14
    OpEntry {
        mnemonic: "ora",
        insn: InsnId::ORA,
        mode: AddrMode::ZpX,
        operand_bytes: 1,
    }, // 0x15
    OpEntry {
        mnemonic: "asl",
        insn: InsnId::ASL,
        mode: AddrMode::ZpX,
        operand_bytes: 1,
    }, // 0x16
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x17
    OpEntry {
        mnemonic: "clc",
        insn: InsnId::CLC,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x18
    OpEntry {
        mnemonic: "ora",
        insn: InsnId::ORA,
        mode: AddrMode::AbsY,
        operand_bytes: 2,
    }, // 0x19
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x1a
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x1b
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x1c
    OpEntry {
        mnemonic: "ora",
        insn: InsnId::ORA,
        mode: AddrMode::AbsX,
        operand_bytes: 2,
    }, // 0x1d
    OpEntry {
        mnemonic: "asl",
        insn: InsnId::ASL,
        mode: AddrMode::AbsX,
        operand_bytes: 2,
    }, // 0x1e
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x1f
    OpEntry {
        mnemonic: "jsr",
        insn: InsnId::JSR,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0x20
    OpEntry {
        mnemonic: "and",
        insn: InsnId::AND,
        mode: AddrMode::ZpXInd,
        operand_bytes: 1,
    }, // 0x21
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x22
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x23
    OpEntry {
        mnemonic: "bit",
        insn: InsnId::BIT,
        mode: AddrMode::Zp,
        operand_bytes: 1,
    }, // 0x24
    OpEntry {
        mnemonic: "and",
        insn: InsnId::AND,
        mode: AddrMode::Zp,
        operand_bytes: 1,
    }, // 0x25
    OpEntry {
        mnemonic: "rol",
        insn: InsnId::ROL,
        mode: AddrMode::Zp,
        operand_bytes: 1,
    }, // 0x26
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x27
    OpEntry {
        mnemonic: "plp",
        insn: InsnId::PLP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x28
    OpEntry {
        mnemonic: "and",
        insn: InsnId::AND,
        mode: AddrMode::Imm,
        operand_bytes: 1,
    }, // 0x29
    OpEntry {
        mnemonic: "rol",
        insn: InsnId::ROL,
        mode: AddrMode::Acc,
        operand_bytes: 0,
    }, // 0x2a
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x2b
    OpEntry {
        mnemonic: "bit",
        insn: InsnId::BIT,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0x2c
    OpEntry {
        mnemonic: "and",
        insn: InsnId::AND,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0x2d
    OpEntry {
        mnemonic: "rol",
        insn: InsnId::ROL,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0x2e
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x2f
    OpEntry {
        mnemonic: "bmi",
        insn: InsnId::BMI,
        mode: AddrMode::Rel,
        operand_bytes: 1,
    }, // 0x30
    OpEntry {
        mnemonic: "and",
        insn: InsnId::AND,
        mode: AddrMode::ZpIndY,
        operand_bytes: 1,
    }, // 0x31
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x32
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x33
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x34
    OpEntry {
        mnemonic: "and",
        insn: InsnId::AND,
        mode: AddrMode::ZpX,
        operand_bytes: 1,
    }, // 0x35
    OpEntry {
        mnemonic: "rol",
        insn: InsnId::ROL,
        mode: AddrMode::ZpX,
        operand_bytes: 1,
    }, // 0x36
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x37
    OpEntry {
        mnemonic: "sec",
        insn: InsnId::SEC,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x38
    OpEntry {
        mnemonic: "and",
        insn: InsnId::AND,
        mode: AddrMode::AbsY,
        operand_bytes: 2,
    }, // 0x39
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x3a
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x3b
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x3c
    OpEntry {
        mnemonic: "and",
        insn: InsnId::AND,
        mode: AddrMode::AbsX,
        operand_bytes: 2,
    }, // 0x3d
    OpEntry {
        mnemonic: "rol",
        insn: InsnId::ROL,
        mode: AddrMode::AbsX,
        operand_bytes: 2,
    }, // 0x3e
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x3f
    OpEntry {
        mnemonic: "rti",
        insn: InsnId::RTI,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x40
    OpEntry {
        mnemonic: "eor",
        insn: InsnId::EOR,
        mode: AddrMode::ZpXInd,
        operand_bytes: 1,
    }, // 0x41
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x42
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x43
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x44
    OpEntry {
        mnemonic: "eor",
        insn: InsnId::EOR,
        mode: AddrMode::Zp,
        operand_bytes: 1,
    }, // 0x45
    OpEntry {
        mnemonic: "lsr",
        insn: InsnId::LSR,
        mode: AddrMode::Zp,
        operand_bytes: 1,
    }, // 0x46
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x47
    OpEntry {
        mnemonic: "pha",
        insn: InsnId::PHA,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x48
    OpEntry {
        mnemonic: "eor",
        insn: InsnId::EOR,
        mode: AddrMode::Imm,
        operand_bytes: 1,
    }, // 0x49
    OpEntry {
        mnemonic: "lsr",
        insn: InsnId::LSR,
        mode: AddrMode::Acc,
        operand_bytes: 0,
    }, // 0x4a
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x4b
    OpEntry {
        mnemonic: "jmp",
        insn: InsnId::JMP,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0x4c
    OpEntry {
        mnemonic: "eor",
        insn: InsnId::EOR,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0x4d
    OpEntry {
        mnemonic: "lsr",
        insn: InsnId::LSR,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0x4e
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x4f
    OpEntry {
        mnemonic: "bvc",
        insn: InsnId::BVC,
        mode: AddrMode::Rel,
        operand_bytes: 1,
    }, // 0x50
    OpEntry {
        mnemonic: "eor",
        insn: InsnId::EOR,
        mode: AddrMode::ZpIndY,
        operand_bytes: 1,
    }, // 0x51
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x52
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x53
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x54
    OpEntry {
        mnemonic: "eor",
        insn: InsnId::EOR,
        mode: AddrMode::ZpX,
        operand_bytes: 1,
    }, // 0x55
    OpEntry {
        mnemonic: "lsr",
        insn: InsnId::LSR,
        mode: AddrMode::ZpX,
        operand_bytes: 1,
    }, // 0x56
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x57
    OpEntry {
        mnemonic: "cli",
        insn: InsnId::CLI,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x58
    OpEntry {
        mnemonic: "eor",
        insn: InsnId::EOR,
        mode: AddrMode::AbsY,
        operand_bytes: 2,
    }, // 0x59
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x5a
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x5b
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x5c
    OpEntry {
        mnemonic: "eor",
        insn: InsnId::EOR,
        mode: AddrMode::AbsX,
        operand_bytes: 2,
    }, // 0x5d
    OpEntry {
        mnemonic: "lsr",
        insn: InsnId::LSR,
        mode: AddrMode::AbsX,
        operand_bytes: 2,
    }, // 0x5e
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x5f
    OpEntry {
        mnemonic: "rts",
        insn: InsnId::RTS,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x60
    OpEntry {
        mnemonic: "adc",
        insn: InsnId::ADC,
        mode: AddrMode::ZpXInd,
        operand_bytes: 1,
    }, // 0x61
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x62
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x63
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x64
    OpEntry {
        mnemonic: "adc",
        insn: InsnId::ADC,
        mode: AddrMode::Zp,
        operand_bytes: 1,
    }, // 0x65
    OpEntry {
        mnemonic: "ror",
        insn: InsnId::ROR,
        mode: AddrMode::Zp,
        operand_bytes: 1,
    }, // 0x66
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x67
    OpEntry {
        mnemonic: "pla",
        insn: InsnId::PLA,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x68
    OpEntry {
        mnemonic: "adc",
        insn: InsnId::ADC,
        mode: AddrMode::Imm,
        operand_bytes: 1,
    }, // 0x69
    OpEntry {
        mnemonic: "ror",
        insn: InsnId::ROR,
        mode: AddrMode::Acc,
        operand_bytes: 0,
    }, // 0x6a
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x6b
    OpEntry {
        mnemonic: "jmp",
        insn: InsnId::JMP,
        mode: AddrMode::AbsInd,
        operand_bytes: 2,
    }, // 0x6c
    OpEntry {
        mnemonic: "adc",
        insn: InsnId::ADC,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0x6d
    OpEntry {
        mnemonic: "ror",
        insn: InsnId::ROR,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0x6e
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x6f
    OpEntry {
        mnemonic: "bvs",
        insn: InsnId::BVS,
        mode: AddrMode::Rel,
        operand_bytes: 1,
    }, // 0x70
    OpEntry {
        mnemonic: "adc",
        insn: InsnId::ADC,
        mode: AddrMode::ZpIndY,
        operand_bytes: 1,
    }, // 0x71
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x72
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x73
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x74
    OpEntry {
        mnemonic: "adc",
        insn: InsnId::ADC,
        mode: AddrMode::ZpX,
        operand_bytes: 1,
    }, // 0x75
    OpEntry {
        mnemonic: "ror",
        insn: InsnId::ROR,
        mode: AddrMode::ZpX,
        operand_bytes: 1,
    }, // 0x76
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x77
    OpEntry {
        mnemonic: "sei",
        insn: InsnId::SEI,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x78
    OpEntry {
        mnemonic: "adc",
        insn: InsnId::ADC,
        mode: AddrMode::AbsY,
        operand_bytes: 2,
    }, // 0x79
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x7a
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x7b
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x7c
    OpEntry {
        mnemonic: "adc",
        insn: InsnId::ADC,
        mode: AddrMode::AbsX,
        operand_bytes: 2,
    }, // 0x7d
    OpEntry {
        mnemonic: "ror",
        insn: InsnId::ROR,
        mode: AddrMode::AbsX,
        operand_bytes: 2,
    }, // 0x7e
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x7f
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x80
    OpEntry {
        mnemonic: "sta",
        insn: InsnId::STA,
        mode: AddrMode::ZpXInd,
        operand_bytes: 1,
    }, // 0x81
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x82
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x83
    OpEntry {
        mnemonic: "sty",
        insn: InsnId::STY,
        mode: AddrMode::Zp,
        operand_bytes: 1,
    }, // 0x84
    OpEntry {
        mnemonic: "sta",
        insn: InsnId::STA,
        mode: AddrMode::Zp,
        operand_bytes: 1,
    }, // 0x85
    OpEntry {
        mnemonic: "stx",
        insn: InsnId::STX,
        mode: AddrMode::Zp,
        operand_bytes: 1,
    }, // 0x86
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x87
    OpEntry {
        mnemonic: "dey",
        insn: InsnId::DEY,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x88
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x89
    OpEntry {
        mnemonic: "txa",
        insn: InsnId::TXA,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x8a
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x8b
    OpEntry {
        mnemonic: "sty",
        insn: InsnId::STY,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0x8c
    OpEntry {
        mnemonic: "sta",
        insn: InsnId::STA,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0x8d
    OpEntry {
        mnemonic: "stx",
        insn: InsnId::STX,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0x8e
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x8f
    OpEntry {
        mnemonic: "bcc",
        insn: InsnId::BCC,
        mode: AddrMode::Rel,
        operand_bytes: 1,
    }, // 0x90
    OpEntry {
        mnemonic: "sta",
        insn: InsnId::STA,
        mode: AddrMode::ZpIndY,
        operand_bytes: 1,
    }, // 0x91
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x92
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x93
    OpEntry {
        mnemonic: "sty",
        insn: InsnId::STY,
        mode: AddrMode::ZpX,
        operand_bytes: 1,
    }, // 0x94
    OpEntry {
        mnemonic: "sta",
        insn: InsnId::STA,
        mode: AddrMode::ZpX,
        operand_bytes: 1,
    }, // 0x95
    OpEntry {
        mnemonic: "stx",
        insn: InsnId::STX,
        mode: AddrMode::ZpY,
        operand_bytes: 1,
    }, // 0x96
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x97
    OpEntry {
        mnemonic: "tya",
        insn: InsnId::TYA,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x98
    OpEntry {
        mnemonic: "sta",
        insn: InsnId::STA,
        mode: AddrMode::AbsY,
        operand_bytes: 2,
    }, // 0x99
    OpEntry {
        mnemonic: "txs",
        insn: InsnId::TXS,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x9a
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x9b
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x9c
    OpEntry {
        mnemonic: "sta",
        insn: InsnId::STA,
        mode: AddrMode::AbsX,
        operand_bytes: 2,
    }, // 0x9d
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x9e
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0x9f
    OpEntry {
        mnemonic: "ldy",
        insn: InsnId::LDY,
        mode: AddrMode::Imm,
        operand_bytes: 1,
    }, // 0xa0
    OpEntry {
        mnemonic: "lda",
        insn: InsnId::LDA,
        mode: AddrMode::ZpXInd,
        operand_bytes: 1,
    }, // 0xa1
    OpEntry {
        mnemonic: "ldx",
        insn: InsnId::LDX,
        mode: AddrMode::Imm,
        operand_bytes: 1,
    }, // 0xa2
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0xa3
    OpEntry {
        mnemonic: "ldy",
        insn: InsnId::LDY,
        mode: AddrMode::Zp,
        operand_bytes: 1,
    }, // 0xa4
    OpEntry {
        mnemonic: "lda",
        insn: InsnId::LDA,
        mode: AddrMode::Zp,
        operand_bytes: 1,
    }, // 0xa5
    OpEntry {
        mnemonic: "ldx",
        insn: InsnId::LDX,
        mode: AddrMode::Zp,
        operand_bytes: 1,
    }, // 0xa6
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0xa7
    OpEntry {
        mnemonic: "tay",
        insn: InsnId::TAY,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0xa8
    OpEntry {
        mnemonic: "lda",
        insn: InsnId::LDA,
        mode: AddrMode::Imm,
        operand_bytes: 1,
    }, // 0xa9
    OpEntry {
        mnemonic: "tax",
        insn: InsnId::TAX,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0xaa
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0xab
    OpEntry {
        mnemonic: "ldy",
        insn: InsnId::LDY,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0xac
    OpEntry {
        mnemonic: "lda",
        insn: InsnId::LDA,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0xad
    OpEntry {
        mnemonic: "ldx",
        insn: InsnId::LDX,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0xae
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0xaf
    OpEntry {
        mnemonic: "bcs",
        insn: InsnId::BCS,
        mode: AddrMode::Rel,
        operand_bytes: 1,
    }, // 0xb0
    OpEntry {
        mnemonic: "lda",
        insn: InsnId::LDA,
        mode: AddrMode::ZpIndY,
        operand_bytes: 1,
    }, // 0xb1
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0xb2
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0xb3
    OpEntry {
        mnemonic: "ldy",
        insn: InsnId::LDY,
        mode: AddrMode::ZpX,
        operand_bytes: 1,
    }, // 0xb4
    OpEntry {
        mnemonic: "lda",
        insn: InsnId::LDA,
        mode: AddrMode::ZpX,
        operand_bytes: 1,
    }, // 0xb5
    OpEntry {
        mnemonic: "ldx",
        insn: InsnId::LDX,
        mode: AddrMode::ZpY,
        operand_bytes: 1,
    }, // 0xb6
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0xb7
    OpEntry {
        mnemonic: "clv",
        insn: InsnId::CLV,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0xb8
    OpEntry {
        mnemonic: "lda",
        insn: InsnId::LDA,
        mode: AddrMode::AbsY,
        operand_bytes: 2,
    }, // 0xb9
    OpEntry {
        mnemonic: "tsx",
        insn: InsnId::TSX,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0xba
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0xbb
    OpEntry {
        mnemonic: "ldy",
        insn: InsnId::LDY,
        mode: AddrMode::AbsX,
        operand_bytes: 2,
    }, // 0xbc
    OpEntry {
        mnemonic: "lda",
        insn: InsnId::LDA,
        mode: AddrMode::AbsX,
        operand_bytes: 2,
    }, // 0xbd
    OpEntry {
        mnemonic: "ldx",
        insn: InsnId::LDX,
        mode: AddrMode::AbsY,
        operand_bytes: 2,
    }, // 0xbe
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0xbf
    OpEntry {
        mnemonic: "cpy",
        insn: InsnId::CPY,
        mode: AddrMode::Imm,
        operand_bytes: 1,
    }, // 0xc0
    OpEntry {
        mnemonic: "cmp",
        insn: InsnId::CMP,
        mode: AddrMode::ZpXInd,
        operand_bytes: 1,
    }, // 0xc1
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0xc2
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0xc3
    OpEntry {
        mnemonic: "cpy",
        insn: InsnId::CPY,
        mode: AddrMode::Zp,
        operand_bytes: 1,
    }, // 0xc4
    OpEntry {
        mnemonic: "cmp",
        insn: InsnId::CMP,
        mode: AddrMode::Zp,
        operand_bytes: 1,
    }, // 0xc5
    OpEntry {
        mnemonic: "dec",
        insn: InsnId::DEC,
        mode: AddrMode::Zp,
        operand_bytes: 1,
    }, // 0xc6
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0xc7
    OpEntry {
        mnemonic: "iny",
        insn: InsnId::INY,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0xc8
    OpEntry {
        mnemonic: "cmp",
        insn: InsnId::CMP,
        mode: AddrMode::Imm,
        operand_bytes: 1,
    }, // 0xc9
    OpEntry {
        mnemonic: "dex",
        insn: InsnId::DEX,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0xca
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0xcb
    OpEntry {
        mnemonic: "cpy",
        insn: InsnId::CPY,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0xcc
    OpEntry {
        mnemonic: "cmp",
        insn: InsnId::CMP,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0xcd
    OpEntry {
        mnemonic: "dec",
        insn: InsnId::DEC,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0xce
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0xcf
    OpEntry {
        mnemonic: "bne",
        insn: InsnId::BNE,
        mode: AddrMode::Rel,
        operand_bytes: 1,
    }, // 0xd0
    OpEntry {
        mnemonic: "cmp",
        insn: InsnId::CMP,
        mode: AddrMode::ZpIndY,
        operand_bytes: 1,
    }, // 0xd1
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0xd2
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0xd3
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0xd4
    OpEntry {
        mnemonic: "cmp",
        insn: InsnId::CMP,
        mode: AddrMode::ZpX,
        operand_bytes: 1,
    }, // 0xd5
    OpEntry {
        mnemonic: "dec",
        insn: InsnId::DEC,
        mode: AddrMode::ZpX,
        operand_bytes: 1,
    }, // 0xd6
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0xd7
    OpEntry {
        mnemonic: "cld",
        insn: InsnId::CLD,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0xd8
    OpEntry {
        mnemonic: "cmp",
        insn: InsnId::CMP,
        mode: AddrMode::AbsY,
        operand_bytes: 2,
    }, // 0xd9
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0xda
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0xdb
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0xdc
    OpEntry {
        mnemonic: "cmp",
        insn: InsnId::CMP,
        mode: AddrMode::AbsX,
        operand_bytes: 2,
    }, // 0xdd
    OpEntry {
        mnemonic: "dec",
        insn: InsnId::DEC,
        mode: AddrMode::AbsX,
        operand_bytes: 2,
    }, // 0xde
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0xdf
    OpEntry {
        mnemonic: "cpx",
        insn: InsnId::CPX,
        mode: AddrMode::Imm,
        operand_bytes: 1,
    }, // 0xe0
    OpEntry {
        mnemonic: "sbc",
        insn: InsnId::SBC,
        mode: AddrMode::ZpXInd,
        operand_bytes: 1,
    }, // 0xe1
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0xe2
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0xe3
    OpEntry {
        mnemonic: "cpx",
        insn: InsnId::CPX,
        mode: AddrMode::Zp,
        operand_bytes: 1,
    }, // 0xe4
    OpEntry {
        mnemonic: "sbc",
        insn: InsnId::SBC,
        mode: AddrMode::Zp,
        operand_bytes: 1,
    }, // 0xe5
    OpEntry {
        mnemonic: "inc",
        insn: InsnId::INC,
        mode: AddrMode::Zp,
        operand_bytes: 1,
    }, // 0xe6
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0xe7
    OpEntry {
        mnemonic: "inx",
        insn: InsnId::INX,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0xe8
    OpEntry {
        mnemonic: "sbc",
        insn: InsnId::SBC,
        mode: AddrMode::Imm,
        operand_bytes: 1,
    }, // 0xe9
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0xea
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0xeb
    OpEntry {
        mnemonic: "cpx",
        insn: InsnId::CPX,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0xec
    OpEntry {
        mnemonic: "sbc",
        insn: InsnId::SBC,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0xed
    OpEntry {
        mnemonic: "inc",
        insn: InsnId::INC,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0xee
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0xef
    OpEntry {
        mnemonic: "beq",
        insn: InsnId::BEQ,
        mode: AddrMode::Rel,
        operand_bytes: 1,
    }, // 0xf0
    OpEntry {
        mnemonic: "sbc",
        insn: InsnId::SBC,
        mode: AddrMode::ZpIndY,
        operand_bytes: 1,
    }, // 0xf1
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0xf2
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0xf3
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0xf4
    OpEntry {
        mnemonic: "sbc",
        insn: InsnId::SBC,
        mode: AddrMode::ZpX,
        operand_bytes: 1,
    }, // 0xf5
    OpEntry {
        mnemonic: "inc",
        insn: InsnId::INC,
        mode: AddrMode::ZpX,
        operand_bytes: 1,
    }, // 0xf6
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0xf7
    OpEntry {
        mnemonic: "sed",
        insn: InsnId::SED,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0xf8
    OpEntry {
        mnemonic: "sbc",
        insn: InsnId::SBC,
        mode: AddrMode::AbsY,
        operand_bytes: 2,
    }, // 0xf9
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0xfa
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0xfb
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0xfc
    OpEntry {
        mnemonic: "sbc",
        insn: InsnId::SBC,
        mode: AddrMode::AbsX,
        operand_bytes: 2,
    }, // 0xfd
    OpEntry {
        mnemonic: "inc",
        insn: InsnId::INC,
        mode: AddrMode::AbsX,
        operand_bytes: 2,
    }, // 0xfe
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::INVALID,
        mode: AddrMode::None,
        operand_bytes: 0,
    }, // 0xff
];

pub const TABLE_65C02: [OpEntry; 256] = [
    OpEntry {
        mnemonic: "brk",
        insn: InsnId::BRK,
        mode: AddrMode::Int,
        operand_bytes: 1,
    }, // 0x00
    OpEntry {
        mnemonic: "ora",
        insn: InsnId::ORA,
        mode: AddrMode::ZpXInd,
        operand_bytes: 1,
    }, // 0x01
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 1,
    }, // 0x02
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x03
    OpEntry {
        mnemonic: "tsb",
        insn: InsnId::TSB,
        mode: AddrMode::Zp,
        operand_bytes: 1,
    }, // 0x04
    OpEntry {
        mnemonic: "ora",
        insn: InsnId::ORA,
        mode: AddrMode::Zp,
        operand_bytes: 1,
    }, // 0x05
    OpEntry {
        mnemonic: "asl",
        insn: InsnId::ASL,
        mode: AddrMode::Zp,
        operand_bytes: 1,
    }, // 0x06
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x07
    OpEntry {
        mnemonic: "php",
        insn: InsnId::PHP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x08
    OpEntry {
        mnemonic: "ora",
        insn: InsnId::ORA,
        mode: AddrMode::Imm,
        operand_bytes: 1,
    }, // 0x09
    OpEntry {
        mnemonic: "asl",
        insn: InsnId::ASL,
        mode: AddrMode::Acc,
        operand_bytes: 0,
    }, // 0x0a
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x0b
    OpEntry {
        mnemonic: "tsb",
        insn: InsnId::TSB,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0x0c
    OpEntry {
        mnemonic: "ora",
        insn: InsnId::ORA,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0x0d
    OpEntry {
        mnemonic: "asl",
        insn: InsnId::ASL,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0x0e
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x0f
    OpEntry {
        mnemonic: "bpl",
        insn: InsnId::BPL,
        mode: AddrMode::Rel,
        operand_bytes: 1,
    }, // 0x10
    OpEntry {
        mnemonic: "ora",
        insn: InsnId::ORA,
        mode: AddrMode::ZpIndY,
        operand_bytes: 1,
    }, // 0x11
    OpEntry {
        mnemonic: "ora",
        insn: InsnId::ORA,
        mode: AddrMode::ZpInd,
        operand_bytes: 1,
    }, // 0x12
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x13
    OpEntry {
        mnemonic: "trb",
        insn: InsnId::TRB,
        mode: AddrMode::Zp,
        operand_bytes: 1,
    }, // 0x14
    OpEntry {
        mnemonic: "ora",
        insn: InsnId::ORA,
        mode: AddrMode::ZpX,
        operand_bytes: 1,
    }, // 0x15
    OpEntry {
        mnemonic: "asl",
        insn: InsnId::ASL,
        mode: AddrMode::ZpX,
        operand_bytes: 1,
    }, // 0x16
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x17
    OpEntry {
        mnemonic: "clc",
        insn: InsnId::CLC,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x18
    OpEntry {
        mnemonic: "ora",
        insn: InsnId::ORA,
        mode: AddrMode::AbsY,
        operand_bytes: 2,
    }, // 0x19
    OpEntry {
        mnemonic: "inc",
        insn: InsnId::INC,
        mode: AddrMode::Acc,
        operand_bytes: 0,
    }, // 0x1a
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x1b
    OpEntry {
        mnemonic: "trb",
        insn: InsnId::TRB,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0x1c
    OpEntry {
        mnemonic: "ora",
        insn: InsnId::ORA,
        mode: AddrMode::AbsX,
        operand_bytes: 2,
    }, // 0x1d
    OpEntry {
        mnemonic: "asl",
        insn: InsnId::ASL,
        mode: AddrMode::AbsX,
        operand_bytes: 2,
    }, // 0x1e
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x1f
    OpEntry {
        mnemonic: "jsr",
        insn: InsnId::JSR,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0x20
    OpEntry {
        mnemonic: "and",
        insn: InsnId::AND,
        mode: AddrMode::ZpXInd,
        operand_bytes: 1,
    }, // 0x21
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 1,
    }, // 0x22
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x23
    OpEntry {
        mnemonic: "bit",
        insn: InsnId::BIT,
        mode: AddrMode::Zp,
        operand_bytes: 1,
    }, // 0x24
    OpEntry {
        mnemonic: "and",
        insn: InsnId::AND,
        mode: AddrMode::Zp,
        operand_bytes: 1,
    }, // 0x25
    OpEntry {
        mnemonic: "rol",
        insn: InsnId::ROL,
        mode: AddrMode::Zp,
        operand_bytes: 1,
    }, // 0x26
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x27
    OpEntry {
        mnemonic: "plp",
        insn: InsnId::PLP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x28
    OpEntry {
        mnemonic: "and",
        insn: InsnId::AND,
        mode: AddrMode::Imm,
        operand_bytes: 1,
    }, // 0x29
    OpEntry {
        mnemonic: "rol",
        insn: InsnId::ROL,
        mode: AddrMode::Acc,
        operand_bytes: 0,
    }, // 0x2a
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x2b
    OpEntry {
        mnemonic: "bit",
        insn: InsnId::BIT,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0x2c
    OpEntry {
        mnemonic: "and",
        insn: InsnId::AND,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0x2d
    OpEntry {
        mnemonic: "rol",
        insn: InsnId::ROL,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0x2e
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x2f
    OpEntry {
        mnemonic: "bmi",
        insn: InsnId::BMI,
        mode: AddrMode::Rel,
        operand_bytes: 1,
    }, // 0x30
    OpEntry {
        mnemonic: "and",
        insn: InsnId::AND,
        mode: AddrMode::ZpIndY,
        operand_bytes: 1,
    }, // 0x31
    OpEntry {
        mnemonic: "and",
        insn: InsnId::AND,
        mode: AddrMode::ZpInd,
        operand_bytes: 1,
    }, // 0x32
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x33
    OpEntry {
        mnemonic: "bit",
        insn: InsnId::BIT,
        mode: AddrMode::ZpX,
        operand_bytes: 1,
    }, // 0x34
    OpEntry {
        mnemonic: "and",
        insn: InsnId::AND,
        mode: AddrMode::ZpX,
        operand_bytes: 1,
    }, // 0x35
    OpEntry {
        mnemonic: "rol",
        insn: InsnId::ROL,
        mode: AddrMode::ZpX,
        operand_bytes: 1,
    }, // 0x36
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x37
    OpEntry {
        mnemonic: "sec",
        insn: InsnId::SEC,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x38
    OpEntry {
        mnemonic: "and",
        insn: InsnId::AND,
        mode: AddrMode::AbsY,
        operand_bytes: 2,
    }, // 0x39
    OpEntry {
        mnemonic: "dec",
        insn: InsnId::DEC,
        mode: AddrMode::Acc,
        operand_bytes: 0,
    }, // 0x3a
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x3b
    OpEntry {
        mnemonic: "bit",
        insn: InsnId::BIT,
        mode: AddrMode::AbsX,
        operand_bytes: 2,
    }, // 0x3c
    OpEntry {
        mnemonic: "and",
        insn: InsnId::AND,
        mode: AddrMode::AbsX,
        operand_bytes: 2,
    }, // 0x3d
    OpEntry {
        mnemonic: "rol",
        insn: InsnId::ROL,
        mode: AddrMode::AbsX,
        operand_bytes: 2,
    }, // 0x3e
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x3f
    OpEntry {
        mnemonic: "rti",
        insn: InsnId::RTI,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x40
    OpEntry {
        mnemonic: "eor",
        insn: InsnId::EOR,
        mode: AddrMode::ZpXInd,
        operand_bytes: 1,
    }, // 0x41
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 1,
    }, // 0x42
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x43
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 1,
    }, // 0x44
    OpEntry {
        mnemonic: "eor",
        insn: InsnId::EOR,
        mode: AddrMode::Zp,
        operand_bytes: 1,
    }, // 0x45
    OpEntry {
        mnemonic: "lsr",
        insn: InsnId::LSR,
        mode: AddrMode::Zp,
        operand_bytes: 1,
    }, // 0x46
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x47
    OpEntry {
        mnemonic: "pha",
        insn: InsnId::PHA,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x48
    OpEntry {
        mnemonic: "eor",
        insn: InsnId::EOR,
        mode: AddrMode::Imm,
        operand_bytes: 1,
    }, // 0x49
    OpEntry {
        mnemonic: "lsr",
        insn: InsnId::LSR,
        mode: AddrMode::Acc,
        operand_bytes: 0,
    }, // 0x4a
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x4b
    OpEntry {
        mnemonic: "jmp",
        insn: InsnId::JMP,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0x4c
    OpEntry {
        mnemonic: "eor",
        insn: InsnId::EOR,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0x4d
    OpEntry {
        mnemonic: "lsr",
        insn: InsnId::LSR,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0x4e
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x4f
    OpEntry {
        mnemonic: "bvc",
        insn: InsnId::BVC,
        mode: AddrMode::Rel,
        operand_bytes: 1,
    }, // 0x50
    OpEntry {
        mnemonic: "eor",
        insn: InsnId::EOR,
        mode: AddrMode::ZpIndY,
        operand_bytes: 1,
    }, // 0x51
    OpEntry {
        mnemonic: "eor",
        insn: InsnId::EOR,
        mode: AddrMode::ZpInd,
        operand_bytes: 1,
    }, // 0x52
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x53
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 1,
    }, // 0x54
    OpEntry {
        mnemonic: "eor",
        insn: InsnId::EOR,
        mode: AddrMode::ZpX,
        operand_bytes: 1,
    }, // 0x55
    OpEntry {
        mnemonic: "lsr",
        insn: InsnId::LSR,
        mode: AddrMode::ZpX,
        operand_bytes: 1,
    }, // 0x56
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x57
    OpEntry {
        mnemonic: "cli",
        insn: InsnId::CLI,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x58
    OpEntry {
        mnemonic: "eor",
        insn: InsnId::EOR,
        mode: AddrMode::AbsY,
        operand_bytes: 2,
    }, // 0x59
    OpEntry {
        mnemonic: "phy",
        insn: InsnId::PHY,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x5a
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x5b
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 2,
    }, // 0x5c
    OpEntry {
        mnemonic: "eor",
        insn: InsnId::EOR,
        mode: AddrMode::AbsX,
        operand_bytes: 2,
    }, // 0x5d
    OpEntry {
        mnemonic: "lsr",
        insn: InsnId::LSR,
        mode: AddrMode::AbsX,
        operand_bytes: 2,
    }, // 0x5e
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x5f
    OpEntry {
        mnemonic: "rts",
        insn: InsnId::RTS,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x60
    OpEntry {
        mnemonic: "adc",
        insn: InsnId::ADC,
        mode: AddrMode::ZpXInd,
        operand_bytes: 1,
    }, // 0x61
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 1,
    }, // 0x62
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x63
    OpEntry {
        mnemonic: "stz",
        insn: InsnId::STZ,
        mode: AddrMode::Zp,
        operand_bytes: 1,
    }, // 0x64
    OpEntry {
        mnemonic: "adc",
        insn: InsnId::ADC,
        mode: AddrMode::Zp,
        operand_bytes: 1,
    }, // 0x65
    OpEntry {
        mnemonic: "ror",
        insn: InsnId::ROR,
        mode: AddrMode::Zp,
        operand_bytes: 1,
    }, // 0x66
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x67
    OpEntry {
        mnemonic: "pla",
        insn: InsnId::PLA,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x68
    OpEntry {
        mnemonic: "adc",
        insn: InsnId::ADC,
        mode: AddrMode::Imm,
        operand_bytes: 1,
    }, // 0x69
    OpEntry {
        mnemonic: "ror",
        insn: InsnId::ROR,
        mode: AddrMode::Acc,
        operand_bytes: 0,
    }, // 0x6a
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x6b
    OpEntry {
        mnemonic: "jmp",
        insn: InsnId::JMP,
        mode: AddrMode::AbsInd,
        operand_bytes: 2,
    }, // 0x6c
    OpEntry {
        mnemonic: "adc",
        insn: InsnId::ADC,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0x6d
    OpEntry {
        mnemonic: "ror",
        insn: InsnId::ROR,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0x6e
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x6f
    OpEntry {
        mnemonic: "bvs",
        insn: InsnId::BVS,
        mode: AddrMode::Rel,
        operand_bytes: 1,
    }, // 0x70
    OpEntry {
        mnemonic: "adc",
        insn: InsnId::ADC,
        mode: AddrMode::ZpIndY,
        operand_bytes: 1,
    }, // 0x71
    OpEntry {
        mnemonic: "adc",
        insn: InsnId::ADC,
        mode: AddrMode::ZpInd,
        operand_bytes: 1,
    }, // 0x72
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x73
    OpEntry {
        mnemonic: "stz",
        insn: InsnId::STZ,
        mode: AddrMode::ZpX,
        operand_bytes: 1,
    }, // 0x74
    OpEntry {
        mnemonic: "adc",
        insn: InsnId::ADC,
        mode: AddrMode::ZpX,
        operand_bytes: 1,
    }, // 0x75
    OpEntry {
        mnemonic: "ror",
        insn: InsnId::ROR,
        mode: AddrMode::ZpX,
        operand_bytes: 1,
    }, // 0x76
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x77
    OpEntry {
        mnemonic: "sei",
        insn: InsnId::SEI,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x78
    OpEntry {
        mnemonic: "adc",
        insn: InsnId::ADC,
        mode: AddrMode::AbsY,
        operand_bytes: 2,
    }, // 0x79
    OpEntry {
        mnemonic: "ply",
        insn: InsnId::PLY,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x7a
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x7b
    OpEntry {
        mnemonic: "jmp",
        insn: InsnId::JMP,
        mode: AddrMode::AbsXInd,
        operand_bytes: 2,
    }, // 0x7c
    OpEntry {
        mnemonic: "adc",
        insn: InsnId::ADC,
        mode: AddrMode::AbsX,
        operand_bytes: 2,
    }, // 0x7d
    OpEntry {
        mnemonic: "ror",
        insn: InsnId::ROR,
        mode: AddrMode::AbsX,
        operand_bytes: 2,
    }, // 0x7e
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x7f
    OpEntry {
        mnemonic: "bra",
        insn: InsnId::BRA,
        mode: AddrMode::Rel,
        operand_bytes: 1,
    }, // 0x80
    OpEntry {
        mnemonic: "sta",
        insn: InsnId::STA,
        mode: AddrMode::ZpXInd,
        operand_bytes: 1,
    }, // 0x81
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 1,
    }, // 0x82
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x83
    OpEntry {
        mnemonic: "sty",
        insn: InsnId::STY,
        mode: AddrMode::Zp,
        operand_bytes: 1,
    }, // 0x84
    OpEntry {
        mnemonic: "sta",
        insn: InsnId::STA,
        mode: AddrMode::Zp,
        operand_bytes: 1,
    }, // 0x85
    OpEntry {
        mnemonic: "stx",
        insn: InsnId::STX,
        mode: AddrMode::Zp,
        operand_bytes: 1,
    }, // 0x86
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x87
    OpEntry {
        mnemonic: "dey",
        insn: InsnId::DEY,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x88
    OpEntry {
        mnemonic: "bit",
        insn: InsnId::BIT,
        mode: AddrMode::Imm,
        operand_bytes: 1,
    }, // 0x89
    OpEntry {
        mnemonic: "txa",
        insn: InsnId::TXA,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x8a
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x8b
    OpEntry {
        mnemonic: "sty",
        insn: InsnId::STY,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0x8c
    OpEntry {
        mnemonic: "sta",
        insn: InsnId::STA,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0x8d
    OpEntry {
        mnemonic: "stx",
        insn: InsnId::STX,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0x8e
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x8f
    OpEntry {
        mnemonic: "bcc",
        insn: InsnId::BCC,
        mode: AddrMode::Rel,
        operand_bytes: 1,
    }, // 0x90
    OpEntry {
        mnemonic: "sta",
        insn: InsnId::STA,
        mode: AddrMode::ZpIndY,
        operand_bytes: 1,
    }, // 0x91
    OpEntry {
        mnemonic: "sta",
        insn: InsnId::STA,
        mode: AddrMode::ZpInd,
        operand_bytes: 1,
    }, // 0x92
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x93
    OpEntry {
        mnemonic: "sty",
        insn: InsnId::STY,
        mode: AddrMode::ZpX,
        operand_bytes: 1,
    }, // 0x94
    OpEntry {
        mnemonic: "sta",
        insn: InsnId::STA,
        mode: AddrMode::ZpX,
        operand_bytes: 1,
    }, // 0x95
    OpEntry {
        mnemonic: "stx",
        insn: InsnId::STX,
        mode: AddrMode::ZpY,
        operand_bytes: 1,
    }, // 0x96
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x97
    OpEntry {
        mnemonic: "tya",
        insn: InsnId::TYA,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x98
    OpEntry {
        mnemonic: "sta",
        insn: InsnId::STA,
        mode: AddrMode::AbsY,
        operand_bytes: 2,
    }, // 0x99
    OpEntry {
        mnemonic: "txs",
        insn: InsnId::TXS,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x9a
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x9b
    OpEntry {
        mnemonic: "stz",
        insn: InsnId::STZ,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0x9c
    OpEntry {
        mnemonic: "sta",
        insn: InsnId::STA,
        mode: AddrMode::AbsX,
        operand_bytes: 2,
    }, // 0x9d
    OpEntry {
        mnemonic: "stz",
        insn: InsnId::STZ,
        mode: AddrMode::AbsX,
        operand_bytes: 2,
    }, // 0x9e
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0x9f
    OpEntry {
        mnemonic: "ldy",
        insn: InsnId::LDY,
        mode: AddrMode::Imm,
        operand_bytes: 1,
    }, // 0xa0
    OpEntry {
        mnemonic: "lda",
        insn: InsnId::LDA,
        mode: AddrMode::ZpXInd,
        operand_bytes: 1,
    }, // 0xa1
    OpEntry {
        mnemonic: "ldx",
        insn: InsnId::LDX,
        mode: AddrMode::Imm,
        operand_bytes: 1,
    }, // 0xa2
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0xa3
    OpEntry {
        mnemonic: "ldy",
        insn: InsnId::LDY,
        mode: AddrMode::Zp,
        operand_bytes: 1,
    }, // 0xa4
    OpEntry {
        mnemonic: "lda",
        insn: InsnId::LDA,
        mode: AddrMode::Zp,
        operand_bytes: 1,
    }, // 0xa5
    OpEntry {
        mnemonic: "ldx",
        insn: InsnId::LDX,
        mode: AddrMode::Zp,
        operand_bytes: 1,
    }, // 0xa6
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0xa7
    OpEntry {
        mnemonic: "tay",
        insn: InsnId::TAY,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0xa8
    OpEntry {
        mnemonic: "lda",
        insn: InsnId::LDA,
        mode: AddrMode::Imm,
        operand_bytes: 1,
    }, // 0xa9
    OpEntry {
        mnemonic: "tax",
        insn: InsnId::TAX,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0xaa
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0xab
    OpEntry {
        mnemonic: "ldy",
        insn: InsnId::LDY,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0xac
    OpEntry {
        mnemonic: "lda",
        insn: InsnId::LDA,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0xad
    OpEntry {
        mnemonic: "ldx",
        insn: InsnId::LDX,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0xae
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0xaf
    OpEntry {
        mnemonic: "bcs",
        insn: InsnId::BCS,
        mode: AddrMode::Rel,
        operand_bytes: 1,
    }, // 0xb0
    OpEntry {
        mnemonic: "lda",
        insn: InsnId::LDA,
        mode: AddrMode::ZpIndY,
        operand_bytes: 1,
    }, // 0xb1
    OpEntry {
        mnemonic: "lda",
        insn: InsnId::LDA,
        mode: AddrMode::ZpInd,
        operand_bytes: 1,
    }, // 0xb2
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0xb3
    OpEntry {
        mnemonic: "ldy",
        insn: InsnId::LDY,
        mode: AddrMode::ZpX,
        operand_bytes: 1,
    }, // 0xb4
    OpEntry {
        mnemonic: "lda",
        insn: InsnId::LDA,
        mode: AddrMode::ZpX,
        operand_bytes: 1,
    }, // 0xb5
    OpEntry {
        mnemonic: "ldx",
        insn: InsnId::LDX,
        mode: AddrMode::ZpY,
        operand_bytes: 1,
    }, // 0xb6
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0xb7
    OpEntry {
        mnemonic: "clv",
        insn: InsnId::CLV,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0xb8
    OpEntry {
        mnemonic: "lda",
        insn: InsnId::LDA,
        mode: AddrMode::AbsY,
        operand_bytes: 2,
    }, // 0xb9
    OpEntry {
        mnemonic: "tsx",
        insn: InsnId::TSX,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0xba
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0xbb
    OpEntry {
        mnemonic: "ldy",
        insn: InsnId::LDY,
        mode: AddrMode::AbsX,
        operand_bytes: 2,
    }, // 0xbc
    OpEntry {
        mnemonic: "lda",
        insn: InsnId::LDA,
        mode: AddrMode::AbsX,
        operand_bytes: 2,
    }, // 0xbd
    OpEntry {
        mnemonic: "ldx",
        insn: InsnId::LDX,
        mode: AddrMode::AbsY,
        operand_bytes: 2,
    }, // 0xbe
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0xbf
    OpEntry {
        mnemonic: "cpy",
        insn: InsnId::CPY,
        mode: AddrMode::Imm,
        operand_bytes: 1,
    }, // 0xc0
    OpEntry {
        mnemonic: "cmp",
        insn: InsnId::CMP,
        mode: AddrMode::ZpXInd,
        operand_bytes: 1,
    }, // 0xc1
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 1,
    }, // 0xc2
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0xc3
    OpEntry {
        mnemonic: "cpy",
        insn: InsnId::CPY,
        mode: AddrMode::Zp,
        operand_bytes: 1,
    }, // 0xc4
    OpEntry {
        mnemonic: "cmp",
        insn: InsnId::CMP,
        mode: AddrMode::Zp,
        operand_bytes: 1,
    }, // 0xc5
    OpEntry {
        mnemonic: "dec",
        insn: InsnId::DEC,
        mode: AddrMode::Zp,
        operand_bytes: 1,
    }, // 0xc6
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0xc7
    OpEntry {
        mnemonic: "iny",
        insn: InsnId::INY,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0xc8
    OpEntry {
        mnemonic: "cmp",
        insn: InsnId::CMP,
        mode: AddrMode::Imm,
        operand_bytes: 1,
    }, // 0xc9
    OpEntry {
        mnemonic: "dex",
        insn: InsnId::DEX,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0xca
    OpEntry {
        mnemonic: "wai",
        insn: InsnId::WAI,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0xcb
    OpEntry {
        mnemonic: "cpy",
        insn: InsnId::CPY,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0xcc
    OpEntry {
        mnemonic: "cmp",
        insn: InsnId::CMP,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0xcd
    OpEntry {
        mnemonic: "dec",
        insn: InsnId::DEC,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0xce
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0xcf
    OpEntry {
        mnemonic: "bne",
        insn: InsnId::BNE,
        mode: AddrMode::Rel,
        operand_bytes: 1,
    }, // 0xd0
    OpEntry {
        mnemonic: "cmp",
        insn: InsnId::CMP,
        mode: AddrMode::ZpIndY,
        operand_bytes: 1,
    }, // 0xd1
    OpEntry {
        mnemonic: "cmp",
        insn: InsnId::CMP,
        mode: AddrMode::ZpInd,
        operand_bytes: 1,
    }, // 0xd2
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0xd3
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 1,
    }, // 0xd4
    OpEntry {
        mnemonic: "cmp",
        insn: InsnId::CMP,
        mode: AddrMode::ZpX,
        operand_bytes: 1,
    }, // 0xd5
    OpEntry {
        mnemonic: "dec",
        insn: InsnId::DEC,
        mode: AddrMode::ZpX,
        operand_bytes: 1,
    }, // 0xd6
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0xd7
    OpEntry {
        mnemonic: "cld",
        insn: InsnId::CLD,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0xd8
    OpEntry {
        mnemonic: "cmp",
        insn: InsnId::CMP,
        mode: AddrMode::AbsY,
        operand_bytes: 2,
    }, // 0xd9
    OpEntry {
        mnemonic: "phx",
        insn: InsnId::PHX,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0xda
    OpEntry {
        mnemonic: "stp",
        insn: InsnId::STP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0xdb
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 2,
    }, // 0xdc
    OpEntry {
        mnemonic: "cmp",
        insn: InsnId::CMP,
        mode: AddrMode::AbsX,
        operand_bytes: 2,
    }, // 0xdd
    OpEntry {
        mnemonic: "dec",
        insn: InsnId::DEC,
        mode: AddrMode::AbsX,
        operand_bytes: 2,
    }, // 0xde
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0xdf
    OpEntry {
        mnemonic: "cpx",
        insn: InsnId::CPX,
        mode: AddrMode::Imm,
        operand_bytes: 1,
    }, // 0xe0
    OpEntry {
        mnemonic: "sbc",
        insn: InsnId::SBC,
        mode: AddrMode::ZpXInd,
        operand_bytes: 1,
    }, // 0xe1
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 1,
    }, // 0xe2
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0xe3
    OpEntry {
        mnemonic: "cpx",
        insn: InsnId::CPX,
        mode: AddrMode::Zp,
        operand_bytes: 1,
    }, // 0xe4
    OpEntry {
        mnemonic: "sbc",
        insn: InsnId::SBC,
        mode: AddrMode::Zp,
        operand_bytes: 1,
    }, // 0xe5
    OpEntry {
        mnemonic: "inc",
        insn: InsnId::INC,
        mode: AddrMode::Zp,
        operand_bytes: 1,
    }, // 0xe6
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0xe7
    OpEntry {
        mnemonic: "inx",
        insn: InsnId::INX,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0xe8
    OpEntry {
        mnemonic: "sbc",
        insn: InsnId::SBC,
        mode: AddrMode::Imm,
        operand_bytes: 1,
    }, // 0xe9
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0xea
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0xeb
    OpEntry {
        mnemonic: "cpx",
        insn: InsnId::CPX,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0xec
    OpEntry {
        mnemonic: "sbc",
        insn: InsnId::SBC,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0xed
    OpEntry {
        mnemonic: "inc",
        insn: InsnId::INC,
        mode: AddrMode::Abs,
        operand_bytes: 2,
    }, // 0xee
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0xef
    OpEntry {
        mnemonic: "beq",
        insn: InsnId::BEQ,
        mode: AddrMode::Rel,
        operand_bytes: 1,
    }, // 0xf0
    OpEntry {
        mnemonic: "sbc",
        insn: InsnId::SBC,
        mode: AddrMode::ZpIndY,
        operand_bytes: 1,
    }, // 0xf1
    OpEntry {
        mnemonic: "sbc",
        insn: InsnId::SBC,
        mode: AddrMode::ZpInd,
        operand_bytes: 1,
    }, // 0xf2
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0xf3
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 1,
    }, // 0xf4
    OpEntry {
        mnemonic: "sbc",
        insn: InsnId::SBC,
        mode: AddrMode::ZpX,
        operand_bytes: 1,
    }, // 0xf5
    OpEntry {
        mnemonic: "inc",
        insn: InsnId::INC,
        mode: AddrMode::ZpX,
        operand_bytes: 1,
    }, // 0xf6
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0xf7
    OpEntry {
        mnemonic: "sed",
        insn: InsnId::SED,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0xf8
    OpEntry {
        mnemonic: "sbc",
        insn: InsnId::SBC,
        mode: AddrMode::AbsY,
        operand_bytes: 2,
    }, // 0xf9
    OpEntry {
        mnemonic: "plx",
        insn: InsnId::PLX,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0xfa
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0xfb
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 2,
    }, // 0xfc
    OpEntry {
        mnemonic: "sbc",
        insn: InsnId::SBC,
        mode: AddrMode::AbsX,
        operand_bytes: 2,
    }, // 0xfd
    OpEntry {
        mnemonic: "inc",
        insn: InsnId::INC,
        mode: AddrMode::AbsX,
        operand_bytes: 2,
    }, // 0xfe
    OpEntry {
        mnemonic: "nop",
        insn: InsnId::NOP,
        mode: AddrMode::Imp,
        operand_bytes: 0,
    }, // 0xff
];
