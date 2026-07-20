use crate::reg::RegId;

pub fn reg_name(reg: RegId) -> Option<&'static str> {
    match reg.index() {
        1 => Some("a"),
        2 => Some("x"),
        3 => Some("y"),
        4 => Some("p"),
        5 => Some("sp"),
        _ => None,
    }
}

pub const REG_A: RegId = RegId::new(1);
pub const REG_X: RegId = RegId::new(2);
pub const REG_Y: RegId = RegId::new(3);
pub const REG_P: RegId = RegId::new(4);
pub const REG_SP: RegId = RegId::new(5);
