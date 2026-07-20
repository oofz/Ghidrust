use crate::insn::InsnId as CoreInsnId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InsnId(pub u16);

impl InsnId {
    pub const INVALID: InsnId = InsnId(0);
    pub const BRK: InsnId = InsnId(1);
    pub const ORA: InsnId = InsnId(2);
    pub const ASL: InsnId = InsnId(3);
    pub const PHP: InsnId = InsnId(4);
    pub const BPL: InsnId = InsnId(5);
    pub const CLC: InsnId = InsnId(6);
    pub const JSR: InsnId = InsnId(7);
    pub const AND: InsnId = InsnId(8);
    pub const BIT: InsnId = InsnId(9);
    pub const ROL: InsnId = InsnId(10);
    pub const PLP: InsnId = InsnId(11);
    pub const BMI: InsnId = InsnId(12);
    pub const SEC: InsnId = InsnId(13);
    pub const RTI: InsnId = InsnId(14);
    pub const EOR: InsnId = InsnId(15);
    pub const LSR: InsnId = InsnId(16);
    pub const PHA: InsnId = InsnId(17);
    pub const JMP: InsnId = InsnId(18);
    pub const BVC: InsnId = InsnId(19);
    pub const CLI: InsnId = InsnId(20);
    pub const RTS: InsnId = InsnId(21);
    pub const ADC: InsnId = InsnId(22);
    pub const ROR: InsnId = InsnId(23);
    pub const PLA: InsnId = InsnId(24);
    pub const BVS: InsnId = InsnId(25);
    pub const SEI: InsnId = InsnId(26);
    pub const STA: InsnId = InsnId(27);
    pub const STY: InsnId = InsnId(28);
    pub const STX: InsnId = InsnId(29);
    pub const DEY: InsnId = InsnId(30);
    pub const TXA: InsnId = InsnId(31);
    pub const BCC: InsnId = InsnId(32);
    pub const TYA: InsnId = InsnId(33);
    pub const TXS: InsnId = InsnId(34);
    pub const LDY: InsnId = InsnId(35);
    pub const LDA: InsnId = InsnId(36);
    pub const LDX: InsnId = InsnId(37);
    pub const TAY: InsnId = InsnId(38);
    pub const TAX: InsnId = InsnId(39);
    pub const BCS: InsnId = InsnId(40);
    pub const CLV: InsnId = InsnId(41);
    pub const TSX: InsnId = InsnId(42);
    pub const CPY: InsnId = InsnId(43);
    pub const CMP: InsnId = InsnId(44);
    pub const DEC: InsnId = InsnId(45);
    pub const INY: InsnId = InsnId(46);
    pub const DEX: InsnId = InsnId(47);
    pub const BNE: InsnId = InsnId(48);
    pub const CLD: InsnId = InsnId(49);
    pub const CPX: InsnId = InsnId(50);
    pub const SBC: InsnId = InsnId(51);
    pub const INC: InsnId = InsnId(52);
    pub const INX: InsnId = InsnId(53);
    pub const NOP: InsnId = InsnId(54);
    pub const BEQ: InsnId = InsnId(55);
    pub const SED: InsnId = InsnId(56);
    pub const BRA: InsnId = InsnId(57);
    pub const PHX: InsnId = InsnId(58);
    pub const PLX: InsnId = InsnId(59);
    pub const PHY: InsnId = InsnId(60);
    pub const PLY: InsnId = InsnId(61);
    pub const STZ: InsnId = InsnId(62);
    pub const TRB: InsnId = InsnId(63);
    pub const TSB: InsnId = InsnId(64);
    pub const STP: InsnId = InsnId(65);
    pub const WAI: InsnId = InsnId(66);
}

pub fn insn_name(id: InsnId) -> Option<&'static str> {
    match id.0 {
        0 => Some("nop"),
        1 => Some("brk"),
        2 => Some("ora"),
        3 => Some("asl"),
        4 => Some("php"),
        5 => Some("bpl"),
        6 => Some("clc"),
        7 => Some("jsr"),
        8 => Some("and"),
        9 => Some("bit"),
        10 => Some("rol"),
        11 => Some("plp"),
        12 => Some("bmi"),
        13 => Some("sec"),
        14 => Some("rti"),
        15 => Some("eor"),
        16 => Some("lsr"),
        17 => Some("pha"),
        18 => Some("jmp"),
        19 => Some("bvc"),
        20 => Some("cli"),
        21 => Some("rts"),
        22 => Some("adc"),
        23 => Some("ror"),
        24 => Some("pla"),
        25 => Some("bvs"),
        26 => Some("sei"),
        27 => Some("sta"),
        28 => Some("sty"),
        29 => Some("stx"),
        30 => Some("dey"),
        31 => Some("txa"),
        32 => Some("bcc"),
        33 => Some("tya"),
        34 => Some("txs"),
        35 => Some("ldy"),
        36 => Some("lda"),
        37 => Some("ldx"),
        38 => Some("tay"),
        39 => Some("tax"),
        40 => Some("bcs"),
        41 => Some("clv"),
        42 => Some("tsx"),
        43 => Some("cpy"),
        44 => Some("cmp"),
        45 => Some("dec"),
        46 => Some("iny"),
        47 => Some("dex"),
        48 => Some("bne"),
        49 => Some("cld"),
        50 => Some("cpx"),
        51 => Some("sbc"),
        52 => Some("inc"),
        53 => Some("inx"),
        54 => Some("nop"),
        55 => Some("beq"),
        56 => Some("sed"),
        57 => Some("bra"),
        58 => Some("phx"),
        59 => Some("plx"),
        60 => Some("phy"),
        61 => Some("ply"),
        62 => Some("stz"),
        63 => Some("trb"),
        64 => Some("tsb"),
        65 => Some("stp"),
        66 => Some("wai"),
        _ => None,
    }
}

pub fn to_core(id: InsnId) -> CoreInsnId {
    CoreInsnId(id.0 as u32)
}

pub fn id_for_mnemonic(mnemonic: &str) -> InsnId {
    for i in 0..=66u16 {
        let id = InsnId(i);
        if insn_name(id).is_some_and(|n| n == mnemonic) {
            return id;
        }
    }
    InsnId::INVALID
}
