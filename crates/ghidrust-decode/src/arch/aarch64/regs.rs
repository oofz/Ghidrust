use crate::reg::RegId;
use crate::support::Arch;

pub fn x(n: u32) -> String {
    if n == 31 {
        "xzr".into()
    } else {
        format!("x{n}")
    }
}

pub fn w(n: u32) -> String {
    if n == 31 {
        "wzr".into()
    } else {
        format!("w{n}")
    }
}

pub fn sp() -> &'static str {
    "sp"
}

pub fn b(n: u32) -> String {
    format!("b{n}")
}

pub fn h(n: u32) -> String {
    format!("h{n}")
}

pub fn s(n: u32) -> String {
    format!("s{n}")
}

pub fn d(n: u32) -> String {
    format!("d{n}")
}

pub fn v(n: u32) -> String {
    format!("v{n}")
}

pub fn reg_id(n: u32) -> RegId {
    RegId::tagged(Arch::Arm64, n as u16)
}
