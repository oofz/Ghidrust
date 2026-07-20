use crate::reg::RegId;

pub fn reg_name(reg: RegId) -> Option<&'static str> {
    match reg.index() {
 0 => Some("zero"),
 1 => Some("ra"),
 2 => Some("sp"),
 3 => Some("gp"),
 4 => Some("tp"),
 5 => Some("t0"),
 6 => Some("t1"),
 7 => Some("t2"),
 8 => Some("s0"),
 9 => Some("s1"),
 10 => Some("a0"),
 11 => Some("a1"),
 12 => Some("a2"),
 13 => Some("a3"),
 14 => Some("a4"),
 15 => Some("a5"),
 16 => Some("a6"),
 17 => Some("a7"),
 18 => Some("s2"),
 19 => Some("s3"),
 20 => Some("s4"),
 21 => Some("s5"),
 22 => Some("s6"),
 23 => Some("s7"),
 24 => Some("s8"),
 25 => Some("s9"),
 26 => Some("s10"),
 27 => Some("s11"),
 28 => Some("t3"),
 29 => Some("t4"),
 30 => Some("t5"),
 31 => Some("t6"),
        _ => None,
    }
}

pub fn reg_name_num(n: u32) -> &'static str {
 reg_name(RegId::new(n)).unwrap_or("?")
}
