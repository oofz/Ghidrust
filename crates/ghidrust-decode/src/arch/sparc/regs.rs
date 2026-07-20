pub fn g_reg(n: u32) -> String {
    match n {
        0..=7 => format!("%g{n}"),
        8..=15 => format!("%o{}", n - 8),
        16..=23 => format!("%l{}", n - 16),
        24..=31 => format!("%i{}", n - 24),
        _ => format!("%r{n}"),
    }
}

pub fn reg_name(reg: crate::reg::RegId) -> Option<&'static str> {
    match reg.index() {
        0 => Some("g0"),
        1 => Some("g1"),
        8 => Some("o0"),
        14 => Some("o6"),
        15 => Some("o7"),
        31 => Some("i7"),
        _ => None,
    }
}
