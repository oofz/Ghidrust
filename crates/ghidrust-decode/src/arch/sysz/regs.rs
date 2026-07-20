pub fn g_reg(n: u8) -> String {
    format!("r{n}")
}

pub fn reg_name(reg: crate::reg::RegId) -> Option<&'static str> {
    match reg.index() {
        0 => Some("r0"),
        1 => Some("r1"),
        2 => Some("r2"),
        14 => Some("r14"),
        15 => Some("r15"),
        _ => None,
    }
}
