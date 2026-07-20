use crate::reg::RegId;
use crate::support::Arch;

pub fn gpr(n: u32) -> &'static str {
    match n & 0xf {
 0 => "r0",
 1 => "r1",
 2 => "r2",
 3 => "r3",
 4 => "r4",
 5 => "r5",
 6 => "r6",
 7 => "r7",
 8 => "r8",
 9 => "r9",
 10 => "r10",
 11 => "r11",
 12 => "r12",
 13 => "sp",
 14 => "lr",
 15 => "pc",
 _ => "r0",
    }
}

pub fn reg_id(n: u32) -> RegId {
    RegId::tagged(Arch::Arm, (n & 0xf) as u16)
}

pub fn neon_d(n: u32) -> String {
 format!("d{}", n & 0x1f)
}

pub fn neon_q(n: u32) -> String {
 format!("q{}", n & 0xf)
}

pub fn psr_field(field: u32) -> &'static str {
    match field {
 0b10000 => "c",
 0b01000 => "x",
 0b00100 => "s",
 0b00010 => "f",
 0b11111 => "cpsr",
 0b11110 => "spsr",
 _ => "cpsr",
    }
}

pub fn banked_reg(r: u32, mode: u32) -> String {
    match (r, mode) {
 (13, 0b10000) => "sp_usr".into(),
 (14, 0b10000) => "lr_usr".into(),
 (13, 0b10001) => "sp_fiq".into(),
 (14, 0b10001) => "lr_fiq".into(),
 (13, 0b10010) => "sp_irq".into(),
 (14, 0b10010) => "lr_irq".into(),
 (13, 0b10011) => "sp_svc".into(),
 (14, 0b10011) => "lr_svc".into(),
 (13, 0b10100) => "sp_abt".into(),
 (14, 0b10100) => "lr_abt".into(),
 (13, 0b10110) => "sp_und".into(),
 (14, 0b10110) => "lr_und".into(),
        _ => gpr(r).into(),
    }
}
