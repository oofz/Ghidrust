/// architecture identifiers (24 values + `Max`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Arch {
    Arm = 0,
    Arm64 = 1,
    Mips = 2,
    X86 = 3,
    Ppc = 4,
    Sparc = 5,
    Sysz = 6,
    Xcore = 7,
    M68k = 8,
    Tms320c64x = 9,
    M680x = 10,
    Evm = 11,
    Mos65xx = 12,
    Wasm = 13,
    Bpf = 14,
    Riscv = 15,
    Tricore = 16,
    Alpha = 17,
    Hppa = 18,
    Loongarch = 19,
    Arc = 20,
    Sh = 21,
    Xtensa = 22,
    Max = 23,
}

impl Arch {
    pub const ALL: [Arch; 23] = [
        Arch::Arm,
        Arch::Arm64,
        Arch::Mips,
        Arch::X86,
        Arch::Ppc,
        Arch::Sparc,
        Arch::Sysz,
        Arch::Xcore,
        Arch::M68k,
        Arch::Tms320c64x,
        Arch::M680x,
        Arch::Evm,
        Arch::Mos65xx,
        Arch::Wasm,
        Arch::Bpf,
        Arch::Riscv,
        Arch::Tricore,
        Arch::Alpha,
        Arch::Hppa,
        Arch::Loongarch,
        Arch::Arc,
        Arch::Sh,
        Arch::Xtensa,
    ];

    pub const fn from_raw(v: u8) -> Self {
        match v {
            0 => Arch::Arm,
            1 => Arch::Arm64,
            2 => Arch::Mips,
            3 => Arch::X86,
            4 => Arch::Ppc,
            5 => Arch::Sparc,
            6 => Arch::Sysz,
            7 => Arch::Xcore,
            8 => Arch::M68k,
            9 => Arch::Tms320c64x,
            10 => Arch::M680x,
            11 => Arch::Evm,
            12 => Arch::Mos65xx,
            13 => Arch::Wasm,
            14 => Arch::Bpf,
            15 => Arch::Riscv,
            16 => Arch::Tricore,
            17 => Arch::Alpha,
            18 => Arch::Hppa,
            19 => Arch::Loongarch,
            20 => Arch::Arc,
            21 => Arch::Sh,
            22 => Arch::Xtensa,
            _ => Arch::Max,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Arch::Arm => "arm",
            Arch::Arm64 => "arm64",
            Arch::Mips => "mips",
            Arch::X86 => "x86",
            Arch::Ppc => "ppc",
            Arch::Sparc => "sparc",
            Arch::Sysz => "sysz",
            Arch::Xcore => "xcore",
            Arch::M68k => "m68k",
            Arch::Tms320c64x => "tms320c64x",
            Arch::M680x => "m680x",
            Arch::Evm => "evm",
            Arch::Mos65xx => "mos65xx",
            Arch::Wasm => "wasm",
            Arch::Bpf => "bpf",
            Arch::Riscv => "riscv",
            Arch::Tricore => "tricore",
            Arch::Alpha => "alpha",
            Arch::Hppa => "hppa",
            Arch::Loongarch => "loongarch",
            Arch::Arc => "arc",
            Arch::Sh => "sh",
            Arch::Xtensa => "xtensa",
            Arch::Max => "max",
        }
    }
}

/// mode bitfield (`cs_mode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Mode(pub u32);

impl Mode {
    pub const LITTLE_ENDIAN: Mode = Mode(0);
    pub const BIG_ENDIAN: Mode = Mode(1 << 31);
    pub const MODE_16: Mode = Mode(1 << 1);
    pub const MODE_32: Mode = Mode(1 << 2);
    pub const MODE_64: Mode = Mode(1 << 3);
    pub const THUMB: Mode = Mode(1 << 4);
    pub const MCLASS: Mode = Mode(1 << 5);
    pub const V8: Mode = Mode(1 << 6);
    pub const MICRO: Mode = Mode(1 << 4);
    pub const MIPS3: Mode = Mode(1 << 5);
    pub const MIPS32R6: Mode = Mode(1 << 6);
    pub const MIPS2: Mode = Mode(1 << 7);
    pub const V9: Mode = Mode(1 << 4);
    pub const PPC32: Mode = Mode(1 << 4);
    pub const PPC64: Mode = Mode(1 << 5);
    pub const QPX: Mode = Mode(1 << 6);
    pub const MIPS32: Mode = Mode(1 << 2);
    pub const MIPS64: Mode = Mode(1 << 3);
    pub const ARM: Mode = Mode(0);
    pub const BPF_CLASSIC: Mode = Mode(0);
    pub const BPF_EXTENDED: Mode = Mode(1 << 0);
    pub const MOS65XX_6502: Mode = Mode(1 << 1);
    pub const MOS65XX_65C02: Mode = Mode(1 << 2);
    pub const RISCV32: Mode = Mode(1 << 0);
    pub const RISCV64: Mode = Mode(1 << 1);
    pub const RISCV_C: Mode = Mode(1 << 2);

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn contains(self, flag: Mode) -> bool {
        (self.0 & flag.0) == flag.0
    }

    pub const fn intersects(self, flag: Mode) -> bool {
        (self.0 & flag.0) != 0
    }

    pub const fn union(self, other: Mode) -> Mode {
        Mode(self.0 | other.0)
    }

    pub const fn with(self, flag: Mode) -> Mode {
        self.union(flag)
    }

    pub const fn without(self, flag: Mode) -> Mode {
        Mode(self.0 & !flag.0)
    }

    pub fn is_valid_for(self, arch: Arch) -> bool {
        match arch {
            Arch::X86 => {
                let width = self.intersects(Self::MODE_16)
                    || self.intersects(Self::MODE_32)
                    || self.intersects(Self::MODE_64);
                width || self == Self::LITTLE_ENDIAN
            }
            Arch::Evm | Arch::Wasm => !self.intersects(Self::BIG_ENDIAN),
            Arch::Mos65xx => !self.intersects(Self::BIG_ENDIAN),
            Arch::Bpf => !self.intersects(Self::BIG_ENDIAN),
            Arch::Riscv => {
                !self.intersects(Self::BIG_ENDIAN)
                    && (self.intersects(Self::RISCV32)
                        || self.intersects(Self::RISCV64)
                        || self == Self::LITTLE_ENDIAN)
            }
            Arch::Arm => {
                self == Self::LITTLE_ENDIAN
                    || self == Self::BIG_ENDIAN
                    || self.contains(Self::THUMB)
                    || self.contains(Self::MCLASS)
                    || self.contains(Self::V8)
            }
            Arch::Arm64 => {
                self == Self::LITTLE_ENDIAN || self == Self::BIG_ENDIAN || self.contains(Self::V8)
            }
            Arch::Mips => {
                self.contains(Self::MIPS32)
                    || self.contains(Self::MIPS64)
                    || self == Self::LITTLE_ENDIAN
                    || self == Self::BIG_ENDIAN
            }
            Arch::Ppc => {
                self.contains(Self::PPC32)
                    || self.contains(Self::PPC64)
                    || self == Self::LITTLE_ENDIAN
                    || self == Self::BIG_ENDIAN
            }
            Arch::Sparc => {
                self.contains(Self::V9) || self == Self::LITTLE_ENDIAN || self == Self::BIG_ENDIAN
            }
            Arch::Sysz | Arch::Hppa => {
                self == Self::LITTLE_ENDIAN
                    || self == Self::BIG_ENDIAN
                    || self.contains(Self::MODE_64)
            }
            Arch::Xcore | Arch::M68k | Arch::Tricore | Arch::Arc | Arch::Sh | Arch::Loongarch => {
                self == Self::LITTLE_ENDIAN
                    || self == Self::BIG_ENDIAN
                    || self.contains(Self::MODE_32)
                    || self.contains(Self::MODE_64)
            }
            Arch::Tms320c64x | Arch::Alpha | Arch::Xtensa | Arch::M680x => {
                self == Self::LITTLE_ENDIAN
                    || self == Self::BIG_ENDIAN
                    || self.contains(Self::MODE_32)
            }
            Arch::Max => false,
        }
    }
}

const IMPLEMENTED: [Arch; 23] = Arch::ALL;

/// Runtime support query .
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportQuery {
    Arch(Arch),
    All,
    Diet,
    X86Reduce,
}

impl SupportQuery {
    pub fn supported(self) -> bool {
        match self {
            SupportQuery::Arch(arch) => IMPLEMENTED.contains(&arch),
            SupportQuery::All => IMPLEMENTED.len() == Arch::ALL.len(),
            SupportQuery::Diet => cfg!(feature = "diet"),
            SupportQuery::X86Reduce => cfg!(feature = "x86-reduce"),
        }
    }
}

pub fn support(query: SupportQuery) -> bool {
    query.supported()
}
