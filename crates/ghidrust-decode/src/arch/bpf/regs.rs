use crate::reg::RegId;

pub fn reg_name(reg: RegId) -> Option<&'static str> {
    match reg.index() {
        0 => Some("a"),
        1..=10 => Some(match reg.index() {
            1 => "r0",
            2 => "r1",
            3 => "r2",
            4 => "r3",
            5 => "r4",
            6 => "r5",
            7 => "r6",
            8 => "r7",
            9 => "r8",
            10 => "r9",
            _ => "r10",
        }),
        11 => Some("x"),
        _ => None,
    }
}
