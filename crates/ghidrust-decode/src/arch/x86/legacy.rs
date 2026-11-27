//! Minimal x86-64 decoder slice (hand-rolled). Enough for common prologue / fixture bytes.

use crate::insn::Instruction;
use crate::names;
use crate::support::Arch;
use crate::{Error, Result};

const REGS64: [&str; 16] = [
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13",
    "r14", "r15",
];
const REGS32: [&str; 16] = [
    "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d", "r12d",
    "r13d", "r14d", "r15d",
];
const REGS16: [&str; 16] = [
    "ax", "cx", "dx", "bx", "sp", "bp", "si", "di", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w",
    "r14w", "r15w",
];
const REGS8: [&str; 16] = [
    "al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil", "r8b", "r9b", "r10b", "r11b", "r12b",
    "r13b", "r14b", "r15b",
];
const REGS8_HIGH: [&str; 8] = ["al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"];

#[derive(Clone, Copy, Default)]
struct Prefix {
    rex_w: bool,
    rex_r: bool,
    rex_x: bool,
    rex_b: bool,
    has_rex: bool,
    op_size: bool,   // 0x66
    addr_size: bool, // 0x67
    rep: bool,
    repne: bool,
    lock: bool,
    seg: Option<&'static str>,
}

fn reg_name(idx: u8, w: bool, op16: bool, byte_op: bool) -> &'static str {
    let i = (idx & 0xf) as usize;
    if byte_op {
        REGS8[i]
    } else if op16 {
        REGS16[i]
    } else if w {
        REGS64[i]
    } else {
        REGS32[i]
    }
}

fn byte_reg_name(idx: u8, has_rex: bool) -> &'static str {
    let i = (idx & 0xf) as usize;
    if has_rex {
        REGS8[i]
    } else {
        REGS8_HIGH[i & 7]
    }
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
    start: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            start: 0,
        }
    }
    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }
    fn get(&mut self) -> Result<u8> {
        if self.pos >= self.data.len() {
            return Err(Error::Decode("truncated instruction stream".into()));
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }
    fn peek(&self) -> Result<u8> {
        self.data
            .get(self.pos)
            .copied()
            .ok_or_else(|| Error::Decode("truncated".into()))
    }
    fn take_imm(&mut self, n: usize) -> Result<u64> {
        if self.remaining() < n {
            return Err(Error::Decode("imm truncated".into()));
        }
        let mut v = 0u64;
        for i in 0..n {
            v |= (self.data[self.pos + i] as u64) << (8 * i);
        }
        self.pos += n;
        Ok(v)
    }
    fn bytes_taken(&self) -> &[u8] {
        &self.data[self.start..self.pos]
    }
}

fn sign_hex(v: i64) -> String {
    if v < 0 {
        format!("-{:#x}", -v)
    } else {
        format!("{v:#x}")
    }
}

fn size_prefix(sz: u32) -> &'static str {
    match sz {
        1 => "byte ptr ",
        2 => "word ptr ",
        4 => "dword ptr ",
        8 => "qword ptr ",
        _ => "",
    }
}

/// Wrapper around [`decode_modrm_mem`] that annotates the r/m side with an
/// explicit width hint when it names memory. `reg_byte` still forces the
/// register-side (mod == 3) to use the 1-byte name set; `mem_size` labels
/// the memory access width (1/2/4/8) so downstream lift can pick the right
/// load/store width without needing to reparse the mnemonic.
fn xmm_name(reg: u8) -> String {
    format!("xmm{}", reg & 0xf)
}

/// Decode ModRM for SSE xmm, xmm/m128 forms. Returns (xmm_reg, rm_operand).
fn decode_sse_xmm_rm(cur: &mut Cursor<'_>, pfx: Prefix) -> Result<(String, String)> {
    decode_sse_xmm_rm_sized(cur, pfx, None)
}

/// Decode an XMM ModRM form with an optional scalar memory width annotation.
fn decode_sse_xmm_rm_sized(
    cur: &mut Cursor<'_>,
    pfx: Prefix,
    mem_size: Option<u32>,
) -> Result<(String, String)> {
    let modrm = cur.get()?;
    let reg = ((modrm >> 3) & 7) | if pfx.rex_r { 8 } else { 0 };
    let xmm = xmm_name(reg);
    if (modrm >> 6) == 3 {
        let rm = (modrm & 7) | if pfx.rex_b { 8 } else { 0 };
        Ok((xmm, xmm_name(rm)))
    } else if let Some(mem_size) = mem_size {
        let (_r, rm) = decode_modrm_sized(cur, modrm, pfx, false, mem_size)?;
        Ok((xmm, rm))
    } else {
        let (_r, rm) = decode_modrm_mem(cur, modrm, pfx, false)?;
        Ok((xmm, rm))
    }
}

fn gp_width(pfx: Prefix) -> u32 {
    if pfx.rex_w {
        8
    } else if pfx.op_size {
        2
    } else {
        4
    }
}

fn gp_name(index: u8, pfx: Prefix) -> &'static str {
    match gp_width(pfx) {
        8 => reg_name(index, true, false, false),
        2 => reg_name(index, false, true, false),
        _ => reg_name(index, false, false, false),
    }
}

fn decode_modrm_sized(
    cur: &mut Cursor<'_>,
    modrm: u8,
    pfx: Prefix,
    reg_byte: bool,
    mem_size: u32,
) -> Result<(u8, String)> {
    let (reg, s) = decode_modrm_mem(cur, modrm, pfx, reg_byte)?;
    if (modrm >> 6) != 3 {
        let prefix = size_prefix(mem_size);
        if !prefix.is_empty() && !s.contains(" ptr ") {
            return Ok((reg, format!("{prefix}{s}")));
        }
    }
    Ok((reg, s))
}

fn decode_modrm_mem(
    cur: &mut Cursor<'_>,
    modrm: u8,
    pfx: Prefix,
    byte_op: bool,
) -> Result<(u8, String)> {
    let mod_ = modrm >> 6;
    let reg = ((modrm >> 3) & 7) | if pfx.rex_r { 8 } else { 0 };
    let rm = (modrm & 7) | if pfx.rex_b { 8 } else { 0 };
    let op16 = pfx.op_size && !pfx.rex_w;

    if mod_ == 3 {
        let name = if byte_op {
            byte_reg_name(rm, pfx.has_rex)
        } else if pfx.rex_w {
            reg_name(rm, true, false, false)
        } else if op16 {
            reg_name(rm, false, true, false)
        } else {
            reg_name(rm, false, false, false)
        };
        return Ok((reg, name.to_string()));
    }

    // SIB if rm low 3 bits == 4 (without rex_b folded for encoding check)
    let rm_enc = modrm & 7;
    let mut parts = String::new();
    if rm_enc == 4 {
        let sib = cur.get()?;
        let scale = 1u32 << (sib >> 6);
        let index = ((sib >> 3) & 7) | if pfx.rex_x { 8 } else { 0 };
        let base = (sib & 7) | if pfx.rex_b { 8 } else { 0 };
        let mut terms = Vec::new();
        if !(mod_ == 0 && (sib & 7) == 5) {
            terms.push(REGS64[base as usize].to_string());
        }
        if index != 4 {
            if scale == 1 {
                terms.push(REGS64[index as usize].to_string());
            } else {
                terms.push(format!("{}*{}", REGS64[index as usize], scale));
            }
        }
        let disp = match mod_ {
            0 if (sib & 7) == 5 => Some(cur.take_imm(4)? as i32 as i64),
            1 => Some(cur.take_imm(1)? as i8 as i64),
            2 => Some(cur.take_imm(4)? as i32 as i64),
            _ => None,
        };
        if let Some(d) = disp {
            if d != 0 || terms.is_empty() {
                parts = if terms.is_empty() {
                    format!("[{}]", sign_hex(d))
                } else {
                    format!(
                        "[{}{}{}]",
                        terms.join("+"),
                        if d < 0 { "" } else { "+" },
                        sign_hex(d)
                    )
                };
            } else {
                parts = format!("[{}]", terms.join("+"));
            }
        } else {
            parts = format!("[{}]", terms.join("+"));
        }
    } else if mod_ == 0 && rm_enc == 5 {
        // RIP-relative
        let disp = cur.take_imm(4)? as i32 as i64;
        parts = if disp < 0 {
            format!("[rip{}]", sign_hex(disp))
        } else {
            format!("[rip+{}]", sign_hex(disp))
        };
    } else {
        let base = REGS64[rm as usize];
        match mod_ {
            0 => parts = format!("[{base}]"),
            1 => {
                let d = cur.take_imm(1)? as i8 as i64;
                parts = format!("[{base}{}{}]", if d < 0 { "" } else { "+" }, sign_hex(d));
            }
            2 => {
                let d = cur.take_imm(4)? as i32 as i64;
                parts = format!("[{base}{}{}]", if d < 0 { "" } else { "+" }, sign_hex(d));
            }
            _ => {}
        }
    }
    if let Some(seg) = pfx.seg {
        parts = format!("{seg}:{parts}");
    }
    Ok((reg, parts))
}

/// Decode one instruction from raw bytes at `address` (VA for display only).
pub fn decode_one(bytes: &[u8], address: u64) -> Result<Instruction> {
    if bytes.is_empty() {
        return Err(Error::Decode("empty".into()));
    }
    let mut cur = Cursor::new(bytes);
    let mut pfx = Prefix::default();

    // prefixes
    loop {
        let b = cur.peek()?;
        match b {
            0xF0 => {
                cur.get()?;
                pfx.lock = true;
            }
            0xF2 => {
                cur.get()?;
                pfx.repne = true;
            }
            0xF3 => {
                cur.get()?;
                pfx.rep = true;
            }
            0x2E => {
                cur.get()?;
                pfx.seg = Some("cs");
            }
            0x36 => {
                cur.get()?;
                pfx.seg = Some("ss");
            }
            0x3E => {
                cur.get()?;
                pfx.seg = Some("ds");
            }
            0x26 => {
                cur.get()?;
                pfx.seg = Some("es");
            }
            0x64 => {
                cur.get()?;
                pfx.seg = Some("fs");
            }
            0x65 => {
                cur.get()?;
                pfx.seg = Some("gs");
            }
            0x66 => {
                cur.get()?;
                pfx.op_size = true;
            }
            0x67 => {
                cur.get()?;
                pfx.addr_size = true;
            }
            x if x & 0xf0 == 0x40 => {
                let rex = cur.get()?;
                pfx.has_rex = true;
                pfx.rex_w = rex & 0x8 != 0;
                pfx.rex_r = rex & 0x4 != 0;
                pfx.rex_x = rex & 0x2 != 0;
                pfx.rex_b = rex & 0x1 != 0;
            }
            _ => break,
        }
        if cur.pos > 15 {
            return Err(Error::Decode("too many prefixes".into()));
        }
    }

    let op = cur.get()?;
    let w64 = pfx.rex_w;
    let op16 = pfx.op_size && !pfx.rex_w;

    let (mnemonic, operands): (String, String) = match op {
        // PUSH r64: 50+rd
        0x50..=0x57 => {
            let r = (op - 0x50) | if pfx.rex_b { 8 } else { 0 };
            ("push".into(), REGS64[r as usize].to_string())
        }
        // POP r64
        0x58..=0x5F => {
            let r = (op - 0x58) | if pfx.rex_b { 8 } else { 0 };
            ("pop".into(), REGS64[r as usize].to_string())
        }
        // MOV r/m, r
        0x89 => {
            let modrm = cur.get()?;
            let (reg, rm) = decode_modrm_mem(&mut cur, modrm, pfx, false)?;
            let reg_s = if w64 {
                reg_name(reg, true, false, false)
            } else if op16 {
                reg_name(reg, false, true, false)
            } else {
                reg_name(reg, false, false, false)
            };
            ("mov".into(), format!("{rm}, {reg_s}"))
        }
        // MOV r, r/m
        0x8B => {
            let modrm = cur.get()?;
            let (reg, rm) = decode_modrm_mem(&mut cur, modrm, pfx, false)?;
            let reg_s = if w64 {
                reg_name(reg, true, false, false)
            } else if op16 {
                reg_name(reg, false, true, false)
            } else {
                reg_name(reg, false, false, false)
            };
            ("mov".into(), format!("{reg_s}, {rm}"))
        }
        // MOV r/m8, r8
        0x88 => {
            let modrm = cur.get()?;
            let (reg, rm) = decode_modrm_mem(&mut cur, modrm, pfx, true)?;
            (
                "mov".into(),
                format!("{rm}, {}", byte_reg_name(reg, pfx.has_rex)),
            )
        }
        // MOV r8, r/m8
        0x8A => {
            let modrm = cur.get()?;
            let (reg, rm) = decode_modrm_mem(&mut cur, modrm, pfx, true)?;
            (
                "mov".into(),
                format!("{}, {rm}", byte_reg_name(reg, pfx.has_rex)),
            )
        }
        // MOV r/m, imm32 (C7 /0)
        0xC7 => {
            let modrm = cur.get()?;
            let reg_field = (modrm >> 3) & 7;
            if reg_field != 0 {
                return Err(Error::Decode(format!("unhandled C7 /{reg_field}")));
            }
            let (_reg, rm) = decode_modrm_mem(&mut cur, modrm, pfx, false)?;
            let imm = if w64 {
                // C7 still uses 32-bit imm sign-extended
                cur.take_imm(4)? as i32 as i64
            } else if op16 {
                cur.take_imm(2)? as i16 as i64
            } else {
                cur.take_imm(4)? as i32 as i64
            };
            ("mov".into(), format!("{rm}, {imm:#x}"))
        }
        // MOV r64/r32, imm
        0xB8..=0xBF => {
            let r = (op - 0xB8) | if pfx.rex_b { 8 } else { 0 };
            if w64 {
                let imm = cur.take_imm(8)?;
                (
                    "mov".into(),
                    format!("{}, {imm:#x}", reg_name(r, true, false, false)),
                )
            } else if op16 {
                let imm = cur.take_imm(2)?;
                (
                    "mov".into(),
                    format!("{}, {imm:#x}", reg_name(r, false, true, false)),
                )
            } else {
                let imm = cur.take_imm(4)?;
                (
                    "mov".into(),
                    format!("{}, {imm:#x}", reg_name(r, false, false, false)),
                )
            }
        }
        // MOV r8, imm8
        0xB0..=0xB7 => {
            let r = (op - 0xB0) | if pfx.rex_b { 8 } else { 0 };
            let imm = cur.take_imm(1)?;
            (
                "mov".into(),
                format!("{}, {imm:#x}", byte_reg_name(r, pfx.has_rex)),
            )
        }
        // ADD r/m8, r8 / AND r8, r/m8.
        0x00 | 0x22 => {
            let modrm = cur.get()?;
            let (reg, rm) = decode_modrm_sized(&mut cur, modrm, pfx, true, 1)?;
            let reg = byte_reg_name(reg, pfx.has_rex);
            if op == 0x00 {
                ("add".into(), format!("{rm}, {reg}"))
            } else {
                ("and".into(), format!("{reg}, {rm}"))
            }
        }
        // Arithmetic/logical accumulator with immediate (AL/AX/EAX/RAX).
        0x04 | 0x05 | 0x0C | 0x0D | 0x14 | 0x15 | 0x1C | 0x1D | 0x24 | 0x25 | 0x2C | 0x2D
        | 0x34 | 0x35 | 0x3C | 0x3D => {
            let mnemonic = match op & 0xF8 {
                0x00 => "add",
                0x08 => "or",
                0x10 => "adc",
                0x18 => "sbb",
                0x20 => "and",
                0x28 => "sub",
                0x30 => "xor",
                0x38 => "cmp",
                _ => unreachable!(),
            };
            let byte_form = op & 1 == 0;
            let (accumulator, immediate) = if byte_form {
                ("al", cur.take_imm(1)? as u8 as i8 as i64)
            } else {
                let width = gp_width(pfx);
                let immediate = if width == 2 {
                    cur.take_imm(2)? as u16 as i16 as i64
                } else {
                    // In 64-bit mode these encodings carry imm32, sign-extended
                    // by the processor to RAX.
                    cur.take_imm(4)? as u32 as i32 as i64
                };
                (gp_name(0, pfx), immediate)
            };
            (
                mnemonic.into(),
                format!("{accumulator}, {}", sign_hex(immediate)),
            )
        }
        // LEA r, m
        0x8D => {
            let modrm = cur.get()?;
            let (reg, rm) = decode_modrm_mem(&mut cur, modrm, pfx, false)?;
            let reg_s = if w64 {
                reg_name(reg, true, false, false)
            } else if op16 {
                reg_name(reg, false, true, false)
            } else {
                reg_name(reg, false, false, false)
            };
            ("lea".into(), format!("{reg_s}, {rm}"))
        }
        // ADD/OR/ADC/SBB/AND/SUB/XOR/CMP r/m, r (01 family)
        // CMP r/m8, r8 / CMP r8, r/m8
        0x38 | 0x3A => {
            let modrm = cur.get()?;
            let (reg, rm) = decode_modrm_sized(&mut cur, modrm, pfx, true, 1)?;
            let reg = byte_reg_name(reg, pfx.has_rex);
            if op == 0x38 {
                ("cmp".into(), format!("{rm}, {reg}"))
            } else {
                ("cmp".into(), format!("{reg}, {rm}"))
            }
        }
        0x01 | 0x09 | 0x11 | 0x19 | 0x21 | 0x29 | 0x31 | 0x39 => {
            let mnem = match op {
                0x01 => "add",
                0x09 => "or",
                0x11 => "adc",
                0x19 => "sbb",
                0x21 => "and",
                0x29 => "sub",
                0x31 => "xor",
                0x39 => "cmp",
                _ => unreachable!(),
            };
            let modrm = cur.get()?;
            let (reg, rm) = decode_modrm_mem(&mut cur, modrm, pfx, false)?;
            let reg_s = if w64 {
                reg_name(reg, true, false, false)
            } else if op16 {
                reg_name(reg, false, true, false)
            } else {
                reg_name(reg, false, false, false)
            };
            (mnem.into(), format!("{rm}, {reg_s}"))
        }
        // same r, r/m
        0x03 | 0x0B | 0x13 | 0x1B | 0x23 | 0x2B | 0x33 | 0x3B => {
            let mnem = match op {
                0x03 => "add",
                0x0B => "or",
                0x13 => "adc",
                0x1B => "sbb",
                0x23 => "and",
                0x2B => "sub",
                0x33 => "xor",
                0x3B => "cmp",
                _ => unreachable!(),
            };
            let modrm = cur.get()?;
            let (reg, rm) = decode_modrm_mem(&mut cur, modrm, pfx, false)?;
            let reg_s = if w64 {
                reg_name(reg, true, false, false)
            } else if op16 {
                reg_name(reg, false, true, false)
            } else {
                reg_name(reg, false, false, false)
            };
            (mnem.into(), format!("{reg_s}, {rm}"))
        }
        // XOR r/m8,r8 etc skip; XOR r32,r/m already covered
        // TEST
        0x85 => {
            let modrm = cur.get()?;
            let (reg, rm) = decode_modrm_mem(&mut cur, modrm, pfx, false)?;
            let reg_s = if w64 {
                reg_name(reg, true, false, false)
            } else {
                reg_name(reg, false, op16, false)
            };
            ("test".into(), format!("{rm}, {reg_s}"))
        }
        // TEST r/m8, r8
        0x84 => {
            let modrm = cur.get()?;
            let (reg, rm) = decode_modrm_sized(&mut cur, modrm, pfx, true, 1)?;
            (
                "test".into(),
                format!("{rm}, {}", byte_reg_name(reg, pfx.has_rex)),
            )
        }
        // TEST r/m, imm (F6 /0, F7 /0) — handled in F6/F7 groups below.
        // XCHG r/m, r
        0x87 => {
            let modrm = cur.get()?;
            let (reg, rm) = decode_modrm_mem(&mut cur, modrm, pfx, false)?;
            let reg_s = if w64 {
                reg_name(reg, true, false, false)
            } else if op16 {
                reg_name(reg, false, true, false)
            } else {
                reg_name(reg, false, false, false)
            };
            ("xchg".into(), format!("{rm}, {reg_s}"))
        }
        // XCHG r/m8, r8
        0x86 => {
            let modrm = cur.get()?;
            let (reg, rm) = decode_modrm_sized(&mut cur, modrm, pfx, true, 1)?;
            (
                "xchg".into(),
                format!("{rm}, {}", byte_reg_name(reg, pfx.has_rex)),
            )
        }
        // MOV r/m8, imm8 (C6 /0)
        0xC6 => {
            let modrm = cur.get()?;
            let reg_field = (modrm >> 3) & 7;
            if reg_field != 0 {
                return Err(Error::Decode(format!("unhandled C6 /{reg_field}")));
            }
            let (_reg, rm) = decode_modrm_sized(&mut cur, modrm, pfx, true, 1)?;
            let imm = cur.take_imm(1)? as i8 as i64;
            ("mov".into(), format!("{rm}, {imm:#x}"))
        }
        // MOVSXD r64, r/m32 (Windows compilers use this constantly).
        0x63 => {
            let modrm = cur.get()?;
            let (reg, rm_raw) = decode_modrm_mem(&mut cur, modrm, pfx, false)?;
            // Source is r/m32; when mod=3 name it as a 32-bit register even
            // if REX.W is set. Memory forms get a "dword ptr" hint.
            let rm = if (modrm >> 6) == 3 {
                let src = (modrm & 7) | if pfx.rex_b { 8 } else { 0 };
                reg_name(src, false, false, false).to_string()
            } else if !rm_raw.contains(" ptr ") {
                format!("{}{}", size_prefix(4), rm_raw)
            } else {
                rm_raw
            };
            let dst = if w64 {
                reg_name(reg, true, false, false)
            } else {
                reg_name(reg, false, false, false)
            };
            let mnem = if w64 { "movsxd" } else { "mov" };
            (mnem.into(), format!("{dst}, {rm}"))
        }
        // IMUL r, r/m, imm8
        0x6B => {
            let modrm = cur.get()?;
            let (reg, rm) = decode_modrm_mem(&mut cur, modrm, pfx, false)?;
            let imm = cur.take_imm(1)? as i8 as i64;
            let dst = if w64 {
                reg_name(reg, true, false, false)
            } else if op16 {
                reg_name(reg, false, true, false)
            } else {
                reg_name(reg, false, false, false)
            };
            ("imul".into(), format!("{dst}, {rm}, {imm:#x}"))
        }
        // IMUL r, r/m, imm32
        0x69 => {
            let modrm = cur.get()?;
            let (reg, rm) = decode_modrm_mem(&mut cur, modrm, pfx, false)?;
            let imm = if op16 {
                cur.take_imm(2)? as i16 as i64
            } else {
                cur.take_imm(4)? as i32 as i64
            };
            let dst = if w64 {
                reg_name(reg, true, false, false)
            } else if op16 {
                reg_name(reg, false, true, false)
            } else {
                reg_name(reg, false, false, false)
            };
            ("imul".into(), format!("{dst}, {rm}, {imm:#x}"))
        }
        // Group 2 shift r/m, 1 (D0/D1) or r/m, cl (D2/D3)
        0xD0 | 0xD1 | 0xD2 | 0xD3 => {
            let modrm = cur.get()?;
            let reg_field = (modrm >> 3) & 7;
            let mnem = match reg_field {
                0 => "rol",
                1 => "ror",
                2 => "rcl",
                3 => "rcr",
                4 => "shl",
                5 => "shr",
                6 => "shl",
                7 => "sar",
                _ => "grp2",
            };
            let byte_op = op == 0xD0 || op == 0xD2;
            let mem_size = if byte_op {
                1
            } else if w64 {
                8
            } else if op16 {
                2
            } else {
                4
            };
            let (_reg, rm) = decode_modrm_sized(&mut cur, modrm, pfx, byte_op, mem_size)?;
            let count = if op == 0xD0 || op == 0xD1 {
                "1".to_string()
            } else {
                "cl".to_string()
            };
            (mnem.into(), format!("{rm}, {count}"))
        }
        // Group 2 shift r/m, imm8 (C0/C1)
        0xC0 | 0xC1 => {
            let modrm = cur.get()?;
            let reg_field = (modrm >> 3) & 7;
            let mnem = match reg_field {
                0 => "rol",
                1 => "ror",
                2 => "rcl",
                3 => "rcr",
                4 => "shl",
                5 => "shr",
                6 => "shl",
                7 => "sar",
                _ => "grp2",
            };
            let byte_op = op == 0xC0;
            let mem_size = if byte_op {
                1
            } else if w64 {
                8
            } else if op16 {
                2
            } else {
                4
            };
            let (_reg, rm) = decode_modrm_sized(&mut cur, modrm, pfx, byte_op, mem_size)?;
            let imm = cur.take_imm(1)? as u8 as i64;
            (mnem.into(), format!("{rm}, {imm:#x}"))
        }
        // Group 3 F6/F7 — test/not/neg/mul/imul/div/idiv r/m
        0xF6 | 0xF7 => {
            let modrm = cur.get()?;
            let reg_field = (modrm >> 3) & 7;
            let byte_op = op == 0xF6;
            let mem_size = if byte_op {
                1
            } else if w64 {
                8
            } else if op16 {
                2
            } else {
                4
            };
            let (_reg, rm) = decode_modrm_sized(&mut cur, modrm, pfx, byte_op, mem_size)?;
            match reg_field {
                0 | 1 => {
                    // test r/m, imm
                    let imm = if byte_op {
                        cur.take_imm(1)? as i8 as i64
                    } else if op16 {
                        cur.take_imm(2)? as i16 as i64
                    } else {
                        cur.take_imm(4)? as i32 as i64
                    };
                    ("test".into(), format!("{rm}, {imm:#x}"))
                }
                2 => ("not".into(), rm),
                3 => ("neg".into(), rm),
                4 => ("mul".into(), rm),
                5 => ("imul".into(), rm),
                6 => ("div".into(), rm),
                7 => ("idiv".into(), rm),
                _ => ("grp3".into(), rm),
            }
        }
        // NOP
        0x90 => ("nop".into(), String::new()),
        // CBW / CWDE / CDQE
        0x98 => {
            if w64 {
                ("cdqe".into(), String::new())
            } else if op16 {
                ("cbw".into(), String::new())
            } else {
                ("cwde".into(), String::new())
            }
        }
        // PUSHF / POPF (rex.w doesn't matter — these push RFLAGS)
        0x9C => ("pushfq".into(), String::new()),
        0x9D => ("popfq".into(), String::new()),
        // HLT
        0xF4 => ("hlt".into(), String::new()),
        // RET
        0xC3 => ("ret".into(), String::new()),
        0xC2 => {
            let imm = cur.take_imm(2)?;
            ("ret".into(), format!("{imm:#x}"))
        }
        // CALL rel32
        0xE8 => {
            let rel = cur.take_imm(4)? as i32 as i64;
            let target = address
                .wrapping_add(cur.pos as u64)
                .wrapping_add(rel as u64);
            ("call".into(), format!("{target:#x}"))
        }
        // JMP rel32
        0xE9 => {
            let rel = cur.take_imm(4)? as i32 as i64;
            let target = address
                .wrapping_add(cur.pos as u64)
                .wrapping_add(rel as u64);
            ("jmp".into(), format!("{target:#x}"))
        }
        // JMP rel8
        0xEB => {
            let rel = cur.take_imm(1)? as i8 as i64;
            let target = address
                .wrapping_add(cur.pos as u64)
                .wrapping_add(rel as u64);
            ("jmp".into(), format!("{target:#x}"))
        }
        // Jcc rel8
        0x70..=0x7F => {
            let names = [
                "jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja", "js", "jns", "jp", "jnp", "jl",
                "jge", "jle", "jg",
            ];
            let rel = cur.take_imm(1)? as i8 as i64;
            let target = address
                .wrapping_add(cur.pos as u64)
                .wrapping_add(rel as u64);
            (names[(op - 0x70) as usize].into(), format!("{target:#x}"))
        }
        // INT3
        0xCC => ("int3".into(), String::new()),
        // CDQ / CQO
        0x99 => {
            if w64 {
                ("cqo".into(), String::new())
            } else {
                ("cdq".into(), String::new())
            }
        }
        // LEAVE
        0xC9 => ("leave".into(), String::new()),
        // Group1 Eb,Ib — ADD/OR/…/CMP r/m8, imm8 (80 /x); 82 is an alias
        0x80 | 0x82 => {
            let modrm = cur.get()?;
            let reg_field = (modrm >> 3) & 7;
            let mnem = match reg_field {
                0 => "add",
                1 => "or",
                2 => "adc",
                3 => "sbb",
                4 => "and",
                5 => "sub",
                6 => "xor",
                7 => "cmp",
                _ => "grp",
            };
            let (_reg, rm) = decode_modrm_sized(&mut cur, modrm, pfx, true, 1)?;
            let imm = cur.take_imm(1)? as i8 as i64;
            (mnem.into(), format!("{rm}, {imm:#x}"))
        }
        // SUB/ADD r/m, imm8 (83 /x)
        0x83 => {
            let modrm = cur.get()?;
            let reg_field = (modrm >> 3) & 7;
            let mnem = match reg_field {
                0 => "add",
                1 => "or",
                2 => "adc",
                3 => "sbb",
                4 => "and",
                5 => "sub",
                6 => "xor",
                7 => "cmp",
                _ => "grp",
            };
            let (_reg, rm) = decode_modrm_mem(&mut cur, modrm, pfx, false)?;
            let imm = cur.take_imm(1)? as i8 as i64;
            (mnem.into(), format!("{rm}, {imm:#x}"))
        }
        // group 81 r/m, imm32
        0x81 => {
            let modrm = cur.get()?;
            let reg_field = (modrm >> 3) & 7;
            let mnem = match reg_field {
                0 => "add",
                1 => "or",
                2 => "adc",
                3 => "sbb",
                4 => "and",
                5 => "sub",
                6 => "xor",
                7 => "cmp",
                _ => "grp",
            };
            let (_reg, rm) = decode_modrm_mem(&mut cur, modrm, pfx, false)?;
            let imm = if op16 {
                cur.take_imm(2)? as i16 as i64
            } else {
                cur.take_imm(4)? as i32 as i64
            };
            (mnem.into(), format!("{rm}, {imm:#x}"))
        }
        // two-byte 0F
        0x0F => {
            let op2 = cur.get()?;
            match op2 {
                // MOVUPS xmm, xmm/m128 / MOVUPS xmm/m128, xmm
                0x10 | 0x11 => {
                    let (xmm, rm) = decode_sse_xmm_rm(&mut cur, pfx)?;
                    if op2 == 0x10 {
                        ("movups".into(), format!("{xmm}, {rm}"))
                    } else {
                        ("movups".into(), format!("{rm}, {xmm}"))
                    }
                }
                // MOVAPS xmm, xmm/m128 / MOVAPS xmm/m128, xmm
                0x28 | 0x29 => {
                    let (xmm, rm) = decode_sse_xmm_rm(&mut cur, pfx)?;
                    if op2 == 0x28 {
                        ("movaps".into(), format!("{xmm}, {rm}"))
                    } else {
                        ("movaps".into(), format!("{rm}, {xmm}"))
                    }
                }
                // MOVDQA xmm, xmm/m128 / MOVDQA xmm/m128, xmm (66 0F 6F / 7F)
                0x6F | 0x7F if pfx.op_size => {
                    let (xmm, rm) = decode_sse_xmm_rm(&mut cur, pfx)?;
                    if op2 == 0x6F {
                        ("movdqa".into(), format!("{xmm}, {rm}"))
                    } else {
                        ("movdqa".into(), format!("{rm}, {xmm}"))
                    }
                }
                // MOVD r/m32 <-> xmm (66 0F 6E / 7E). Operand-size 66 is
                // mandatory here; the GPR/memory operand remains 32-bit.
                0x6E | 0x7E if pfx.op_size => {
                    let modrm = cur.get()?;
                    let xmm = xmm_name(((modrm >> 3) & 7) | if pfx.rex_r { 8 } else { 0 });
                    let rm = if modrm >> 6 == 3 {
                        let index = (modrm & 7) | if pfx.rex_b { 8 } else { 0 };
                        REGS32[index as usize].to_string()
                    } else {
                        let (_, operand) = decode_modrm_sized(&mut cur, modrm, pfx, false, 4)?;
                        operand
                    };
                    if op2 == 0x6E {
                        ("movd".into(), format!("{xmm}, {rm}"))
                    } else {
                        ("movd".into(), format!("{rm}, {xmm}"))
                    }
                }
                // CVTSI2SS / CVTSI2SD xmm, r/m32 or r/m64.
                0x2A if pfx.rep || pfx.repne => {
                    if pfx.rep && pfx.repne {
                        return Err(Error::Decode(
                            "conflicting mandatory prefixes on 0F 2A".into(),
                        ));
                    }
                    let (mnemonic, width) = if pfx.rep {
                        ("cvtsi2ss", if pfx.rex_w { 8 } else { 4 })
                    } else {
                        ("cvtsi2sd", if pfx.rex_w { 8 } else { 4 })
                    };
                    let modrm = cur.get()?;
                    let xmm = xmm_name(((modrm >> 3) & 7) | if pfx.rex_r { 8 } else { 0 });
                    let (_, rm) = decode_modrm_sized(&mut cur, modrm, pfx, false, width)?;
                    (mnemonic.into(), format!("{xmm}, {rm}"))
                }
                // CVTTSS2SI / CVTTSD2SI r32/r64, xmm/m32/m64.
                0x2C if pfx.rep || pfx.repne => {
                    if pfx.rep && pfx.repne {
                        return Err(Error::Decode(
                            "conflicting mandatory prefixes on 0F 2C".into(),
                        ));
                    }
                    let (mnemonic, width) = if pfx.rep {
                        ("cvttss2si", 4)
                    } else {
                        ("cvttsd2si", 8)
                    };
                    let modrm = cur.get()?;
                    let dst = ((modrm >> 3) & 7) | if pfx.rex_r { 8 } else { 0 };
                    let src = if modrm >> 6 == 3 {
                        let xmm = (modrm & 7) | if pfx.rex_b { 8 } else { 0 };
                        xmm_name(xmm)
                    } else {
                        let (_, operand) = decode_modrm_sized(&mut cur, modrm, pfx, false, width)?;
                        operand
                    };
                    (mnemonic.into(), format!("{}, {src}", gp_name(dst, pfx)))
                }
                // UCOMISS/COMISS xmm, xmm/m32; 66 selects the double form.
                0x2E | 0x2F if !pfx.rep && !pfx.repne => {
                    let (mnemonic, width) = match (op2, pfx.op_size) {
                        (0x2E, false) => ("ucomiss", 4),
                        (0x2E, true) => ("ucomisd", 8),
                        (0x2F, false) => ("comiss", 4),
                        (0x2F, true) => ("comisd", 8),
                        _ => unreachable!(),
                    };
                    let (xmm, rm) = decode_sse_xmm_rm_sized(&mut cur, pfx, Some(width))?;
                    (mnemonic.into(), format!("{xmm}, {rm}"))
                }
                // ADDPS/ADDPD/ADDSS/ADDSD and MULPS/MULPD/MULSS/MULSD.
                0x58 | 0x59 => {
                    if (pfx.rep && pfx.repne) || (pfx.op_size && (pfx.rep || pfx.repne)) {
                        return Err(Error::Decode(format!(
                            "conflicting prefixes on 0F {op2:02x}"
                        )));
                    }
                    let (stem, suffix, width) = if pfx.rep {
                        (if op2 == 0x58 { "add" } else { "mul" }, "ss", Some(4))
                    } else if pfx.repne {
                        (if op2 == 0x58 { "add" } else { "mul" }, "sd", Some(8))
                    } else if pfx.op_size {
                        (if op2 == 0x58 { "add" } else { "mul" }, "pd", None)
                    } else {
                        (if op2 == 0x58 { "add" } else { "mul" }, "ps", None)
                    };
                    let (xmm, rm) = decode_sse_xmm_rm_sized(&mut cur, pfx, width)?;
                    (format!("{stem}{suffix}"), format!("{xmm}, {rm}"))
                }
                // SUBPS/SUBPD/SUBSS/SUBSD and DIVPS/DIVPD/DIVSS/DIVSD.
                0x5C | 0x5E => {
                    if (pfx.rep && pfx.repne) || (pfx.op_size && (pfx.rep || pfx.repne)) {
                        return Err(Error::Decode(format!(
                            "conflicting prefixes on 0F {op2:02x}"
                        )));
                    }
                    let (stem, suffix, width) = if pfx.rep {
                        (if op2 == 0x5C { "sub" } else { "div" }, "ss", Some(4))
                    } else if pfx.repne {
                        (if op2 == 0x5C { "sub" } else { "div" }, "sd", Some(8))
                    } else if pfx.op_size {
                        (if op2 == 0x5C { "sub" } else { "div" }, "pd", None)
                    } else {
                        (if op2 == 0x5C { "sub" } else { "div" }, "ps", None)
                    };
                    let (xmm, rm) = decode_sse_xmm_rm_sized(&mut cur, pfx, width)?;
                    (format!("{stem}{suffix}"), format!("{xmm}, {rm}"))
                }
                // ANDPS / ANDPD.
                0x54 if !pfx.rep && !pfx.repne => {
                    let (xmm, rm) = decode_sse_xmm_rm(&mut cur, pfx)?;
                    let mnemonic = if pfx.op_size { "andpd" } else { "andps" };
                    (mnemonic.into(), format!("{xmm}, {rm}"))
                }
                // CVTPS2PD/CVTPD2PS/CVTSS2SD/CVTSD2SS.
                0x5A => {
                    if (pfx.rep && pfx.repne) || (pfx.op_size && (pfx.rep || pfx.repne)) {
                        return Err(Error::Decode("conflicting prefixes on 0F 5A".into()));
                    }
                    let (mnemonic, width) = if pfx.rep {
                        ("cvtss2sd", Some(4))
                    } else if pfx.repne {
                        ("cvtsd2ss", Some(8))
                    } else if pfx.op_size {
                        ("cvtpd2ps", None)
                    } else {
                        ("cvtps2pd", Some(8))
                    };
                    let (xmm, rm) = decode_sse_xmm_rm_sized(&mut cur, pfx, width)?;
                    (mnemonic.into(), format!("{xmm}, {rm}"))
                }
                // F3 0F 7E MOVQ xmm, xmm/m64.
                0x7E if pfx.rep && !pfx.repne && !pfx.op_size => {
                    let (xmm, rm) = decode_sse_xmm_rm_sized(&mut cur, pfx, Some(8))?;
                    ("movq".into(), format!("{xmm}, {rm}"))
                }
                // 66 0F DB PAND xmm, xmm/m128.
                0xDB if pfx.op_size && !pfx.rep && !pfx.repne => {
                    let (xmm, rm) = decode_sse_xmm_rm(&mut cur, pfx)?;
                    ("pand".into(), format!("{xmm}, {rm}"))
                }
                // BSR r, r/m; F3 selects LZCNT.
                0xBD if !pfx.repne => {
                    let modrm = cur.get()?;
                    let (reg, rm) = decode_modrm_sized(&mut cur, modrm, pfx, false, gp_width(pfx))?;
                    let mnemonic = if pfx.rep { "lzcnt" } else { "bsr" };
                    (mnemonic.into(), format!("{}, {rm}", gp_name(reg, pfx)))
                }
                // SHLD r/m, r, CL.
                0xA5 => {
                    let modrm = cur.get()?;
                    let (reg, rm) = decode_modrm_sized(&mut cur, modrm, pfx, false, gp_width(pfx))?;
                    ("shld".into(), format!("{rm}, {}, cl", gp_name(reg, pfx)))
                }
                // CMPXCHG r/m, r. Preserve LOCK in the mnemonic because the
                // instruction representation has no separate prefix field.
                0xB1 => {
                    let modrm = cur.get()?;
                    if pfx.lock && modrm >> 6 == 3 {
                        return Err(Error::Decode(
                            "LOCK CMPXCHG requires a memory operand".into(),
                        ));
                    }
                    let (reg, rm) = decode_modrm_sized(&mut cur, modrm, pfx, false, gp_width(pfx))?;
                    let mnemonic = if pfx.lock { "lock cmpxchg" } else { "cmpxchg" };
                    (mnemonic.into(), format!("{rm}, {}", gp_name(reg, pfx)))
                }
                // SHRD r/m, r, imm8.
                0xAC => {
                    let modrm = cur.get()?;
                    let (reg, rm) = decode_modrm_sized(&mut cur, modrm, pfx, false, gp_width(pfx))?;
                    let imm = cur.take_imm(1)?;
                    (
                        "shrd".into(),
                        format!("{rm}, {}, {imm:#x}", gp_name(reg, pfx)),
                    )
                }
                // 66 0F D6 MOVQ r/m64, xmm.
                0xD6 if pfx.op_size && !pfx.rep && !pfx.repne => {
                    let (xmm, rm) = decode_sse_xmm_rm_sized(&mut cur, pfx, Some(8))?;
                    ("movq".into(), format!("{rm}, {xmm}"))
                }
                // PAND is handled above; 0F 22 moves a GP register to a control register.
                0x22 if !pfx.op_size && !pfx.rep && !pfx.repne => {
                    let modrm = cur.get()?;
                    if modrm >> 6 != 3 {
                        return Err(Error::Decode("MOV CR requires register ModRM form".into()));
                    }
                    let cr = ((modrm >> 3) & 7) | if pfx.rex_r { 8 } else { 0 };
                    let cr = match cr {
                        0 | 2 | 3 | 4 | 8 => cr,
                        _ => {
                            return Err(Error::Decode(format!("reserved control register CR{cr}")))
                        }
                    };
                    let gp = (modrm & 7) | if pfx.rex_b { 8 } else { 0 };
                    ("mov".into(), format!("cr{cr}, {}", REGS64[gp as usize]))
                }
                // XORPS xmm, xmm/m128
                0x57 => {
                    let (xmm, rm) = decode_sse_xmm_rm(&mut cur, pfx)?;
                    ("xorps".into(), format!("{xmm}, {rm}"))
                }
                // PXOR xmm, xmm/m128 (66 0F EF)
                0xEF if pfx.op_size => {
                    let (xmm, rm) = decode_sse_xmm_rm(&mut cur, pfx)?;
                    ("pxor".into(), format!("{xmm}, {rm}"))
                }
                // Jcc rel32
                0x80..=0x8F => {
                    let names = [
                        "jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja", "js", "jns", "jp",
                        "jnp", "jl", "jge", "jle", "jg",
                    ];
                    let rel = cur.take_imm(4)? as i32 as i64;
                    let target = address
                        .wrapping_add(cur.pos as u64)
                        .wrapping_add(rel as u64);
                    (names[(op2 - 0x80) as usize].into(), format!("{target:#x}"))
                }
                // CMOVcc r, r/m
                0x40..=0x4F => {
                    let names = [
                        "cmovo", "cmovno", "cmovb", "cmovae", "cmove", "cmovne", "cmovbe", "cmova",
                        "cmovs", "cmovns", "cmovp", "cmovnp", "cmovl", "cmovge", "cmovle", "cmovg",
                    ];
                    let modrm = cur.get()?;
                    let mem_size = if w64 {
                        8
                    } else if op16 {
                        2
                    } else {
                        4
                    };
                    let (reg, rm) = decode_modrm_sized(&mut cur, modrm, pfx, false, mem_size)?;
                    let dst = if w64 {
                        reg_name(reg, true, false, false)
                    } else if op16 {
                        reg_name(reg, false, true, false)
                    } else {
                        reg_name(reg, false, false, false)
                    };
                    (names[(op2 - 0x40) as usize].into(), format!("{dst}, {rm}"))
                }
                // SETcc r/m8
                0x90..=0x9F => {
                    let names = [
                        "seto", "setno", "setb", "setae", "sete", "setne", "setbe", "seta", "sets",
                        "setns", "setp", "setnp", "setl", "setge", "setle", "setg",
                    ];
                    let modrm = cur.get()?;
                    let (_r, rm) = decode_modrm_sized(&mut cur, modrm, pfx, true, 1)?;
                    (names[(op2 - 0x90) as usize].into(), rm)
                }
                // MOVZX r, r/m8
                0xB6 => {
                    let modrm = cur.get()?;
                    let (reg, rm) = decode_modrm_sized(&mut cur, modrm, pfx, true, 1)?;
                    let dst = if w64 {
                        reg_name(reg, true, false, false)
                    } else if op16 {
                        reg_name(reg, false, true, false)
                    } else {
                        reg_name(reg, false, false, false)
                    };
                    ("movzx".into(), format!("{dst}, {rm}"))
                }
                // MOVZX r, r/m16
                0xB7 => {
                    let modrm = cur.get()?;
                    // r/m is 16-bit; when mod=3 that's a word reg.
                    let (reg, rm_raw) = decode_modrm_mem(&mut cur, modrm, pfx, false)?;
                    let rm = if (modrm >> 6) == 3 {
                        // Force word regnames on the source.
                        let src = (modrm & 7) | if pfx.rex_b { 8 } else { 0 };
                        reg_name(src, false, true, false).to_string()
                    } else if !rm_raw.contains(" ptr ") {
                        format!("{}{}", size_prefix(2), rm_raw)
                    } else {
                        rm_raw
                    };
                    let dst = if w64 {
                        reg_name(reg, true, false, false)
                    } else if op16 {
                        reg_name(reg, false, true, false)
                    } else {
                        reg_name(reg, false, false, false)
                    };
                    ("movzx".into(), format!("{dst}, {rm}"))
                }
                // MOVSX r, r/m8
                0xBE => {
                    let modrm = cur.get()?;
                    let (reg, rm) = decode_modrm_sized(&mut cur, modrm, pfx, true, 1)?;
                    let dst = if w64 {
                        reg_name(reg, true, false, false)
                    } else if op16 {
                        reg_name(reg, false, true, false)
                    } else {
                        reg_name(reg, false, false, false)
                    };
                    ("movsx".into(), format!("{dst}, {rm}"))
                }
                // MOVSX r, r/m16
                0xBF => {
                    let modrm = cur.get()?;
                    let (reg, rm_raw) = decode_modrm_mem(&mut cur, modrm, pfx, false)?;
                    let rm = if (modrm >> 6) == 3 {
                        let src = (modrm & 7) | if pfx.rex_b { 8 } else { 0 };
                        reg_name(src, false, true, false).to_string()
                    } else if !rm_raw.contains(" ptr ") {
                        format!("{}{}", size_prefix(2), rm_raw)
                    } else {
                        rm_raw
                    };
                    let dst = if w64 {
                        reg_name(reg, true, false, false)
                    } else if op16 {
                        reg_name(reg, false, true, false)
                    } else {
                        reg_name(reg, false, false, false)
                    };
                    ("movsx".into(), format!("{dst}, {rm}"))
                }
                // IMUL r, r/m
                0xAF => {
                    let modrm = cur.get()?;
                    let (reg, rm) = decode_modrm_mem(&mut cur, modrm, pfx, false)?;
                    let dst = if w64 {
                        reg_name(reg, true, false, false)
                    } else if op16 {
                        reg_name(reg, false, true, false)
                    } else {
                        reg_name(reg, false, false, false)
                    };
                    ("imul".into(), format!("{dst}, {rm}"))
                }
                // BSWAP r32/r64
                0xC8..=0xCF => {
                    let r = (op2 - 0xC8) | if pfx.rex_b { 8 } else { 0 };
                    let reg = if w64 {
                        reg_name(r, true, false, false)
                    } else {
                        reg_name(r, false, false, false)
                    };
                    ("bswap".into(), reg.to_string())
                }
                // UD2
                0x0B => ("ud2".into(), String::new()),
                // ENDBR64 / ENDBR32 (F3 0F 1E FA / FB) — with F3 already consumed as `rep`.
                0x1E if pfx.rep => {
                    let modrm = cur.get()?;
                    let m = match modrm {
                        0xFA => "endbr64",
                        0xFB => "endbr32",
                        _ => "endbr",
                    };
                    (m.into(), String::new())
                }
                0x1F => {
                    // NOP r/m
                    let modrm = cur.get()?;
                    let (_r, rm) = decode_modrm_mem(&mut cur, modrm, pfx, false)?;
                    ("nop".into(), rm)
                }
                0x05 => ("syscall".into(), String::new()),
                0xA2 => ("cpuid".into(), String::new()),
                _ => {
                    return Err(Error::Decode(format!("unhandled 0F {op2:02x}")));
                }
            }
        }
        // FF /0 INC, /1 DEC, /2 CALL, /4 JMP, /6 PUSH
        0xFF => {
            let modrm = cur.get()?;
            let reg_field = (modrm >> 3) & 7;
            let (_r, rm) = decode_modrm_mem(&mut cur, modrm, pfx, false)?;
            match reg_field {
                0 => ("inc".into(), rm),
                1 => ("dec".into(), rm),
                2 => ("call".into(), rm),
                4 => ("jmp".into(), rm),
                6 => ("push".into(), rm),
                _ => {
                    return Err(Error::Decode(format!("unhandled FF /{reg_field}")));
                }
            }
        }
        // MOVSQ/MOVSD/MOVSW string move. F3 repeats the selected width.
        0xA5 => {
            let mnemonic = match gp_width(pfx) {
                8 => "movsq",
                2 => "movsw",
                _ => "movsd",
            };
            let mnemonic = if pfx.rep {
                format!("rep {mnemonic}")
            } else if pfx.repne {
                format!("repne {mnemonic}")
            } else {
                mnemonic.to_string()
            };
            (mnemonic, String::new())
        }
        // OR/XOR r8,r8 forms used with and without a REX prefix.
        0x08 | 0x0A | 0x30 | 0x32 => {
            let modrm = cur.get()?;
            let (reg, rm) = decode_modrm_sized(&mut cur, modrm, pfx, true, 1)?;
            let mnem = if op == 0x08 || op == 0x0A {
                "or"
            } else {
                "xor"
            };
            if op == 0x08 || op == 0x30 {
                (
                    mnem.into(),
                    format!("{rm}, {}", byte_reg_name(reg, pfx.has_rex)),
                )
            } else {
                (
                    mnem.into(),
                    format!("{}, {rm}", byte_reg_name(reg, pfx.has_rex)),
                )
            }
        }
        other => {
            return Err(Error::Decode(format!(
                "unhandled opcode {other:02x} at {address:#x}"
            )));
        }
    };

    let taken = cur.bytes_taken().to_vec();
    Ok(Instruction {
        id: names::insn_id_for_mnemonic(Arch::X86, &mnemonic),
        address,
        length: taken.len() as u8,
        bytes: taken,
        mnemonic,
        operands,
        detail: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_push_rbp_mov_rbp_rsp() {
        // 55 push rbp
        // 48 89 e5 mov rbp, rsp
        let b = [0x55, 0x48, 0x89, 0xe5];
        let i0 = decode_one(&b, 0x1000).unwrap();
        assert_eq!(i0.mnemonic, "push");
        assert_eq!(i0.operands, "rbp");
        assert_eq!(i0.length, 1);
        let i1 = decode_one(&b[1..], 0x1001).unwrap();
        assert_eq!(i1.mnemonic, "mov");
        assert_eq!(i1.operands, "rbp, rsp");
    }

    #[test]
    fn decode_xor_eax_eax_ret() {
        // 31 c0 xor eax, eax
        // c3 ret
        let b = [0x31, 0xc0, 0xc3];
        let i0 = decode_one(&b, 0).unwrap();
        assert_eq!(i0.mnemonic, "xor");
        assert_eq!(i0.operands, "eax, eax");
        let i1 = decode_one(&b[2..], 2).unwrap();
        assert_eq!(i1.mnemonic, "ret");
    }

    #[test]
    fn decode_cmovcc_register() {
        // 48 0f 45 c8 cmovne rcx, rax
        let i = decode_one(&[0x48, 0x0f, 0x45, 0xc8], 0).unwrap();
        assert_eq!(i.mnemonic, "cmovne");
        assert_eq!(i.operands, "rcx, rax");
        assert_eq!(i.length, 4);
    }

    #[test]
    fn decode_setcc_r8() {
        // 0f 94 c0 sete al
        let i = decode_one(&[0x0f, 0x94, 0xc0], 0).unwrap();
        assert_eq!(i.mnemonic, "sete");
        assert_eq!(i.operands, "al");
    }

    #[test]
    fn decode_movzx_r32_r8() {
        // 0f b6 c1 movzx eax, cl
        let i = decode_one(&[0x0f, 0xb6, 0xc1], 0).unwrap();
        assert_eq!(i.mnemonic, "movzx");
        assert_eq!(i.operands, "eax, cl");
    }

    #[test]
    fn decode_movsxd_r64_r32() {
        // 48 63 c1 movsxd rax, ecx
        let i = decode_one(&[0x48, 0x63, 0xc1], 0).unwrap();
        assert_eq!(i.mnemonic, "movsxd");
        assert_eq!(i.operands, "rax, ecx");
    }

    #[test]
    fn decode_shr_by_cl_and_shl_imm() {
        // c1 e0 03 shl eax, 3
        let a = decode_one(&[0xc1, 0xe0, 0x03], 0).unwrap();
        assert_eq!(a.mnemonic, "shl");
        assert_eq!(a.operands, "eax, 0x3");
        // d3 e8 shr eax, cl
        let b = decode_one(&[0xd3, 0xe8], 0).unwrap();
        assert_eq!(b.mnemonic, "shr");
        assert_eq!(b.operands, "eax, cl");
    }

    #[test]
    fn decode_group3_neg_and_not() {
        // f7 d8 neg eax
        let a = decode_one(&[0xf7, 0xd8], 0).unwrap();
        assert_eq!(a.mnemonic, "neg");
        assert_eq!(a.operands, "eax");
        // f7 d0 not eax
        let b = decode_one(&[0xf7, 0xd0], 0).unwrap();
        assert_eq!(b.mnemonic, "not");
    }

    #[test]
    fn decode_hlt_and_int3() {
        assert_eq!(decode_one(&[0xf4], 0).unwrap().mnemonic, "hlt");
        assert_eq!(decode_one(&[0xcc], 0).unwrap().mnemonic, "int3");
    }

    #[test]
    fn decode_endbr64() {
        // f3 0f 1e fa endbr64
        let i = decode_one(&[0xf3, 0x0f, 0x1e, 0xfa], 0).unwrap();
        assert_eq!(i.mnemonic, "endbr64");
    }

    #[test]
    fn decode_imul_with_imm() {
        // 6b c0 03 imul eax, eax, 3
        let i = decode_one(&[0x6b, 0xc0, 0x03], 0).unwrap();
        assert_eq!(i.mnemonic, "imul");
        assert_eq!(i.operands, "eax, eax, 0x3");
    }

    #[test]
    fn decode_ud2_and_bswap() {
        assert_eq!(decode_one(&[0x0f, 0x0b], 0).unwrap().mnemonic, "ud2");
        // 0f c8 bswap eax
        let b = decode_one(&[0x0f, 0xc8], 0).unwrap();
        assert_eq!(b.mnemonic, "bswap");
        assert_eq!(b.operands, "eax");
    }

    #[test]
    fn decode_sib_with_scale_still_valid() {
        // 8b 04 88 mov eax, [rax+rcx*4]
        let i = decode_one(&[0x8b, 0x04, 0x88], 0).unwrap();
        assert_eq!(i.mnemonic, "mov");
        assert!(
            i.operands.contains("rcx*4"),
            "expected SIB scale 4, got '{}'",
            i.operands
        );
    }

    #[test]
    fn decode_group1_byte_cmp_mem_imm8() {
        // 80 b9 e1 01 00 00 00 cmp byte ptr [rcx+0x1e1], 0x0
        let i = decode_one(&[0x80, 0xb9, 0xe1, 0x01, 0x00, 0x00, 0x00], 0).unwrap();
        assert_eq!(i.mnemonic, "cmp");
        assert_eq!(i.length, 7);
        assert!(
            i.operands.contains("byte ptr") && i.operands.contains("[rcx+0x1e1]"),
            "got '{}'",
            i.operands
        );
        assert!(
            i.operands.ends_with(", 0x0") || i.operands.ends_with(", 0"),
            "got '{}'",
            i.operands
        );
    }

    #[test]
    fn decode_movups_load_store() {
        // 0f 10 1a movups xmm3, [rdx]
        let load = decode_one(&[0x0f, 0x10, 0x1a], 0).unwrap();
        assert_eq!(load.mnemonic, "movups");
        assert_eq!(load.operands, "xmm3, [rdx]");
        // 0f 11 59 10 movups [rcx+0x10], xmm3
        let store = decode_one(&[0x0f, 0x11, 0x59, 0x10], 0).unwrap();
        assert_eq!(store.mnemonic, "movups");
        assert_eq!(store.operands, "[rcx+0x10], xmm3");
    }

    #[test]
    fn decode_movaps_reg_reg() {
        // 0f 28 c1 movaps xmm0, xmm1
        let i = decode_one(&[0x0f, 0x28, 0xc1], 0).unwrap();
        assert_eq!(i.mnemonic, "movaps");
        assert_eq!(i.operands, "xmm0, xmm1");
    }

    #[test]
    fn decode_xorps_zeroing() {
        // 0f 57 c0 xorps xmm0, xmm0
        let i = decode_one(&[0x0f, 0x57, 0xc0], 0).unwrap();
        assert_eq!(i.mnemonic, "xorps");
        assert_eq!(i.operands, "xmm0, xmm0");
    }

    #[test]
    fn decode_pxor_and_movdqa() {
        // 66 0f ef c9 pxor xmm1, xmm1
        let i = decode_one(&[0x66, 0x0f, 0xef, 0xc9], 0).unwrap();
        assert_eq!(i.mnemonic, "pxor");
        assert_eq!(i.operands, "xmm1, xmm1");
        // 66 0f 6f c1 movdqa xmm0, xmm1
        let m = decode_one(&[0x66, 0x0f, 0x6f, 0xc1], 0).unwrap();
        assert_eq!(m.mnemonic, "movdqa");
        assert_eq!(m.operands, "xmm0, xmm1");
    }

    #[test]
    fn decode_sqlite_movd_xmm_from_dword_memory() {
        // 66 0f 6e 4c 24 28 movd xmm1, dword ptr [rsp+0x28]
        let i = decode_one(&[0x66, 0x0f, 0x6e, 0x4c, 0x24, 0x28], 0x1000).unwrap();
        assert_eq!(i.mnemonic, "movd");
        assert_eq!(i.operands, "xmm1, dword ptr [rsp+0x28]");
        assert_eq!(i.length, 6);
    }

    #[test]
    fn decode_ripgrep_dec_r9d() {
        // 41 ff c9 dec r9d
        let i = decode_one(&[0x41, 0xff, 0xc9], 0x1000).unwrap();
        assert_eq!(i.mnemonic, "dec");
        assert_eq!(i.operands, "r9d");
        assert_eq!(i.length, 3);
    }

    #[test]
    fn decode_rex_byte_or_and_legacy_high_byte_register() {
        // 40 08 68 01 or byte ptr [rax+0x1], bpl
        let i = decode_one(&[0x40, 0x08, 0x68, 0x01], 0x1000).unwrap();
        assert_eq!(i.mnemonic, "or");
        assert_eq!(i.operands, "byte ptr [rax+0x1], bpl");
        assert_eq!(i.length, 4);

        // Without REX, the same ModRM reg field names CH, not BPL.
        let legacy = decode_one(&[0x08, 0xe8], 0x2000).unwrap();
        assert_eq!(legacy.operands, "al, ch");
    }

    #[test]
    fn decode_accumulator_immediate_widths_and_directions() {
        let cases: &[(&[u8], &str, &str, u8)] = &[
            (&[0x04, 1], "add", "al, 0x1", 2),
            (&[0x05, 1, 0, 0, 0], "add", "eax, 0x1", 5),
            (&[0x0c, 1], "or", "al, 0x1", 2),
            (&[0x0d, 1, 0, 0, 0], "or", "eax, 0x1", 5),
            (&[0x14, 1], "adc", "al, 0x1", 2),
            (&[0x15, 1, 0, 0, 0], "adc", "eax, 0x1", 5),
            (&[0x1c, 1], "sbb", "al, 0x1", 2),
            (&[0x1d, 1, 0, 0, 0], "sbb", "eax, 0x1", 5),
            (&[0x24, 0x0f], "and", "al, 0xf", 2),
            (&[0x48, 0x25, 0xff, 0xff, 0xff, 0xff], "and", "rax, -0x1", 6),
            (&[0x2c, 1], "sub", "al, 0x1", 2),
            (&[0x2d, 2, 0, 0, 0], "sub", "eax, 0x2", 5),
            (&[0x34, 1], "xor", "al, 0x1", 2),
            (&[0x35, 3, 0, 0, 0], "xor", "eax, 0x3", 5),
            (&[0x3c, 0x7f], "cmp", "al, 0x7f", 2),
            (&[0x66, 0x3d, 0x34, 0x12], "cmp", "ax, 0x1234", 4),
            (&[0x3d, 1, 0, 0, 0], "cmp", "eax, 0x1", 5),
        ];
        for (bytes, mnemonic, operands, length) in cases {
            let insn = decode_one(bytes, 0x1000).unwrap();
            assert_eq!(insn.mnemonic, *mnemonic, "bytes {bytes:02x?}");
            assert_eq!(insn.operands, *operands, "bytes {bytes:02x?}");
            assert_eq!(insn.length, *length, "bytes {bytes:02x?}");
        }
    }

    #[test]
    fn decode_cmp_byte_register_and_memory_forms() {
        let mem = decode_one(&[0x38, 0x4c, 0x24, 0x10], 0x1000).unwrap();
        assert_eq!(mem.mnemonic, "cmp");
        assert_eq!(mem.operands, "byte ptr [rsp+0x10], cl");
        assert_eq!(mem.length, 4);

        let reg = decode_one(&[0x3a, 0xc8], 0x1000).unwrap();
        assert_eq!(reg.operands, "cl, al");
    }

    #[test]
    fn decode_scalar_integer_float_conversions_and_compare_widths() {
        let single = decode_one(&[0xf3, 0x0f, 0x2a, 0xc1], 0x1000).unwrap();
        assert_eq!(single.mnemonic, "cvtsi2ss");
        assert_eq!(single.operands, "xmm0, ecx");
        assert_eq!(single.length, 4);

        let double = decode_one(&[0xf2, 0x48, 0x0f, 0x2a, 0x44, 0x24, 0x08], 0x1000).unwrap();
        assert_eq!(double.mnemonic, "cvtsi2sd");
        assert_eq!(double.operands, "xmm0, qword ptr [rsp+0x8]");
        assert_eq!(double.length, 7);

        let cmp_single = decode_one(&[0x0f, 0x2e, 0x44, 0x24, 0x04], 0x1000).unwrap();
        assert_eq!(cmp_single.mnemonic, "ucomiss");
        assert_eq!(cmp_single.operands, "xmm0, dword ptr [rsp+0x4]");

        let cmp_double = decode_one(&[0x66, 0x0f, 0x2f, 0xc1], 0x1000).unwrap();
        assert_eq!(cmp_double.mnemonic, "comisd");
        assert_eq!(cmp_double.operands, "xmm0, xmm1");

        let cmp_double_unordered = decode_one(&[0x66, 0x0f, 0x2e, 0xc1], 0x1000).unwrap();
        assert_eq!(cmp_double_unordered.mnemonic, "ucomisd");

        let cmp_single_ordered = decode_one(&[0x0f, 0x2f, 0xc1], 0x1000).unwrap();
        assert_eq!(cmp_single_ordered.mnemonic, "comiss");
    }

    #[test]
    fn decode_sse_arithmetic_and_conversion_prefixes() {
        let packed = decode_one(&[0x0f, 0x58, 0xc1], 0x1000).unwrap();
        assert_eq!(packed.mnemonic, "addps");
        assert_eq!(packed.operands, "xmm0, xmm1");

        let scalar = decode_one(&[0xf3, 0x0f, 0x59, 0x44, 0x24, 0x04], 0x1000).unwrap();
        assert_eq!(scalar.mnemonic, "mulss");
        assert_eq!(scalar.operands, "xmm0, dword ptr [rsp+0x4]");

        let packed_double = decode_one(&[0x66, 0x0f, 0x58, 0x44, 0x24, 0x10], 0x1000).unwrap();
        assert_eq!(packed_double.mnemonic, "addpd");
        assert_eq!(packed_double.operands, "xmm0, [rsp+0x10]");

        let scalar_double = decode_one(&[0xf2, 0x0f, 0x59, 0xc1], 0x1000).unwrap();
        assert_eq!(scalar_double.mnemonic, "mulsd");
        assert_eq!(scalar_double.operands, "xmm0, xmm1");

        let packed_mul = decode_one(&[0x66, 0x0f, 0x59, 0xc1], 0x1000).unwrap();
        assert_eq!(packed_mul.mnemonic, "mulpd");

        let cvt = decode_one(&[0xf2, 0x0f, 0x5a, 0xc1], 0x1000).unwrap();
        assert_eq!(cvt.mnemonic, "cvtsd2ss");
        assert_eq!(cvt.operands, "xmm0, xmm1");

        let cvt_f32_f64 = decode_one(&[0xf3, 0x0f, 0x5a, 0x44, 0x24, 0x04], 0x1000).unwrap();
        assert_eq!(cvt_f32_f64.mnemonic, "cvtss2sd");
        assert_eq!(cvt_f32_f64.operands, "xmm0, dword ptr [rsp+0x4]");

        let cvt_packed = decode_one(&[0x0f, 0x5a, 0xc1], 0x1000).unwrap();
        assert_eq!(cvt_packed.mnemonic, "cvtps2pd");

        let cvt_packed_reverse = decode_one(&[0x66, 0x0f, 0x5a, 0xc1], 0x1000).unwrap();
        assert_eq!(cvt_packed_reverse.mnemonic, "cvtpd2ps");

        let movq = decode_one(&[0xf3, 0x0f, 0x7e, 0x44, 0x24, 0x08], 0x1000).unwrap();
        assert_eq!(movq.mnemonic, "movq");
        assert_eq!(movq.operands, "xmm0, qword ptr [rsp+0x8]");

        let pand = decode_one(&[0x66, 0x0f, 0xdb, 0xc1], 0x1000).unwrap();
        assert_eq!(pand.mnemonic, "pand");
        assert_eq!(pand.operands, "xmm0, xmm1");

        let movd_reverse = decode_one(&[0x66, 0x0f, 0x7e, 0xc1], 0x1000).unwrap();
        assert_eq!(movd_reverse.mnemonic, "movd");
        assert_eq!(movd_reverse.operands, "ecx, xmm0");
    }

    #[test]
    fn decode_bsr_lzcnt_shld_and_control_register_move() {
        let bsr = decode_one(&[0x0f, 0xbd, 0xc1], 0x1000).unwrap();
        assert_eq!(bsr.mnemonic, "bsr");
        assert_eq!(bsr.operands, "eax, ecx");

        let lzcnt = decode_one(&[0xf3, 0x48, 0x0f, 0xbd, 0xc1], 0x1000).unwrap();
        assert_eq!(lzcnt.mnemonic, "lzcnt");
        assert_eq!(lzcnt.operands, "rax, rcx");

        let shld = decode_one(&[0x48, 0x0f, 0xa5, 0xc8], 0x1000).unwrap();
        assert_eq!(shld.mnemonic, "shld");
        assert_eq!(shld.operands, "rax, rcx, cl");

        let mov_cr = decode_one(&[0x0f, 0x22, 0xc0], 0x1000).unwrap();
        assert_eq!(mov_cr.mnemonic, "mov");
        assert_eq!(mov_cr.operands, "cr0, rax");

        let mov_cr8 = decode_one(&[0x44, 0x0f, 0x22, 0xc0], 0x1000).unwrap();
        assert_eq!(mov_cr8.operands, "cr8, rax");

        let inc = decode_one(&[0x48, 0xff, 0xc0], 0x1000).unwrap();
        assert_eq!(inc.mnemonic, "inc");
        assert_eq!(inc.operands, "rax");
    }

    #[test]
    fn decode_sqlite_byte_add_and_and_forms() {
        let add = decode_one(&[0x00, 0x45, 0xff], 0x1000).unwrap();
        assert_eq!(add.mnemonic, "add");
        assert_eq!(add.operands, "byte ptr [rbp-0x1], al");
        assert_eq!(add.length, 3);

        let and = decode_one(&[0x22, 0x85, 0x8f, 0, 0, 0], 0x1000).unwrap();
        assert_eq!(and.mnemonic, "and");
        assert_eq!(and.operands, "al, byte ptr [rbp+0x8f]");
        assert_eq!(and.length, 6);
    }

    #[test]
    fn decode_sqlite_float_divide_subtract_and_and() {
        let div_sd = decode_one(&[0xf2, 0x0f, 0x5e, 0xc1], 0x1000).unwrap();
        assert_eq!(div_sd.mnemonic, "divsd");
        assert_eq!(div_sd.operands, "xmm0, xmm1");

        let sub_ss = decode_one(&[0xf3, 0x0f, 0x5c, 0xc1], 0x1000).unwrap();
        assert_eq!(sub_ss.mnemonic, "subss");

        let sub_sd_mem = decode_one(&[0xf2, 0x0f, 0x5c, 0x44, 0x24, 0x08], 0x1000).unwrap();
        assert_eq!(sub_sd_mem.mnemonic, "subsd");
        assert_eq!(sub_sd_mem.operands, "xmm0, qword ptr [rsp+0x8]");

        let and_pd = decode_one(&[0x66, 0x0f, 0x54, 0xc1], 0x1000).unwrap();
        assert_eq!(and_pd.mnemonic, "andpd");
        assert_eq!(and_pd.operands, "xmm0, xmm1");
    }

    #[test]
    fn decode_sqlite_truncating_convert_and_atomic_compare_exchange() {
        let cvtt = decode_one(&[0xf2, 0x48, 0x0f, 0x2c, 0xc0], 0x1000).unwrap();
        assert_eq!(cvtt.mnemonic, "cvttsd2si");
        assert_eq!(cvtt.operands, "rax, xmm0");
        assert_eq!(cvtt.length, 5);

        let cmpxchg = decode_one(&[0xf0, 0x48, 0x0f, 0xb1, 0x0a], 0x1000).unwrap();
        assert_eq!(cmpxchg.mnemonic, "lock cmpxchg");
        assert_eq!(cmpxchg.operands, "qword ptr [rdx], rcx");
        assert_eq!(cmpxchg.length, 5);
        assert!(decode_one(&[0xf0, 0x48, 0x0f, 0xb1, 0xc8], 0x1000).is_err());
    }

    #[test]
    fn decode_sqlite_double_shift_moveq_and_string_move() {
        let shrd = decode_one(&[0x48, 0x0f, 0xac, 0xd0, 0x20], 0x1000).unwrap();
        assert_eq!(shrd.mnemonic, "shrd");
        assert_eq!(shrd.operands, "rax, rdx, 0x20");
        assert_eq!(shrd.length, 5);

        let movq = decode_one(&[0x66, 0x0f, 0xd6, 0x45, 0xf0], 0x1000).unwrap();
        assert_eq!(movq.mnemonic, "movq");
        assert_eq!(movq.operands, "qword ptr [rbp-0x10], xmm0");

        let movsq = decode_one(&[0xf3, 0x48, 0xa5], 0x1000).unwrap();
        assert_eq!(movsq.mnemonic, "rep movsq");
        assert_eq!(movsq.operands, "");
        assert_eq!(movsq.length, 3);
    }
}
