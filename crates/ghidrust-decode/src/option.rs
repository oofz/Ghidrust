use crate::support::Mode;
use std::collections::HashMap;

/// Assembly syntax flavor .
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Syntax {
    #[default]
    Default,
    Intel,
    Att,
    NoRegName,
    Masm,
    Motorola,
    CsRegAlias,
    Percent,
    NoDollar,
    NoAliasText,
    NoAliasTextCompressed,
}

/// Per-instruction mnemonic override.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MnemOverride {
    pub id: u32,
    pub mnemonic: String,
}

/// Engine option .
#[derive(Debug, Clone)]
pub enum Opt {
    Syntax(Syntax),
    Detail(bool),
    DetailReal(bool),
    Mode(Mode),
    Skipdata(bool),
    SkipdataSetup(crate::skipdata::SkipdataConfig),
    Mnemonic(MnemOverride),
    Unsigned(bool),
    OnlyOffsetBranch(bool),
    Litbase(u32),
}

/// Resolved engine configuration.
#[derive(Debug, Clone)]
pub struct EngineOptions {
    pub syntax: Syntax,
    pub detail: bool,
    pub detail_real: bool,
    pub mode: Mode,
    pub skipdata: bool,
    pub skipdata_setup: crate::skipdata::SkipdataConfig,
    pub mnemonic_overrides: HashMap<u32, String>,
    pub unsigned: bool,
    pub only_offset_branch: bool,
    pub litbase: u32,
}

impl Default for EngineOptions {
    fn default() -> Self {
        Self {
            syntax: Syntax::default(),
            detail: false,
            detail_real: false,
            mode: Mode::MODE_64,
            skipdata: false,
            skipdata_setup: crate::skipdata::SkipdataConfig::default(),
            mnemonic_overrides: HashMap::new(),
            unsigned: false,
            only_offset_branch: false,
            litbase: 0,
        }
    }
}

impl EngineOptions {
    pub fn apply(&mut self, opt: Opt) -> crate::error::Result<()> {
        match opt {
            Opt::Syntax(v) => self.syntax = v,
            Opt::Detail(v) => self.detail = v,
            Opt::DetailReal(v) => self.detail_real = v,
            Opt::Mode(v) => self.mode = v,
            Opt::Skipdata(v) => self.skipdata = v,
            Opt::SkipdataSetup(v) => self.skipdata_setup = v,
            Opt::Mnemonic(v) => {
                self.mnemonic_overrides.insert(v.id, v.mnemonic);
            }
            Opt::Unsigned(v) => self.unsigned = v,
            Opt::OnlyOffsetBranch(v) => self.only_offset_branch = v,
            Opt::Litbase(v) => self.litbase = v,
        }
        Ok(())
    }
}
