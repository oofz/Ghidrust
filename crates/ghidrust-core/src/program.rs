use crate::edits::ProgramEdits;
use crate::rtti::RttiReport;
use serde::{Deserialize, Serialize};

/// One mapped memory region (section/segment) with raw bytes.
#[derive(Debug, Clone, Serialize)]
pub struct MemoryBlock {
    pub name: String,
    pub va: u64,
    pub size: u64,
    pub bytes: Vec<u8>,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

/// Section metadata (subset of loader view).
#[derive(Debug, Clone, Serialize)]
pub struct SectionInfo {
    pub name: String,
    pub va: u64,
    pub virtual_size: u64,
    pub raw_size: u64,
    pub file_offset: u64,
    pub characteristics: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FunctionInfo {
    pub entry: u64,
    pub end: u64,
    pub name: String,
    pub calling_convention: Option<String>,
    pub noreturn: bool,
    pub varargs: bool,
    /// Recovered parameters: name + storage description.
    pub parameters: Vec<String>,
    /// Stack locals as "offset:size" or name.
    pub stack_locals: Vec<String>,
}

/// One PE import / IAT slot (ELF imports may be added later).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportEntry {
    pub dll: String,
    pub name: Option<String>,
    pub ordinal: Option<u16>,
    /// VA of the IAT slot (pointer that calls resolve through).
    pub iat_va: u64,
    /// VA of the matching ILT slot when present.
    pub ilt_va: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SymbolInfo {
    pub va: u64,
    pub name: String,
    pub demangled: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReferenceInfo {
    pub from: u64,
    pub to: u64,
    pub kind: String,
}

/// Classification of what an address-table's entries predominantly point at.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AddressTableRole {
    #[default]
    Unknown,
    /// Majority of entries land in executable blocks.
    CodePtrs,
    /// Majority of entries land in non-executable mapped blocks (strings, data).
    DataPtrs,
    /// No clear majority.
    Mixed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AddressTableInfo {
    pub base: u64,
    pub count: usize,
    pub entries: Vec<u64>,
    #[serde(default)]
    pub role: AddressTableRole,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CallFixupInfo {
    pub call_va: u64,
    pub fixup_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MediaHit {
    pub va: u64,
    pub kind: String,
    pub length: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FidMatch {
    pub entry: u64,
    pub matched_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceInfo {
    pub type_id: u32,
    pub name: String,
    pub va: u64,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SwitchInfo {
    pub jump_va: u64,
    pub cases: Vec<(i64, u64)>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoveredRange {
    pub start: u64,
    pub end: u64,
}

/// Analysis-side state attached to a loaded program (mutated by analyzers).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnalysisState {
    pub functions: Vec<FunctionInfo>,
    pub symbols: Vec<SymbolInfo>,
    pub references: Vec<ReferenceInfo>,
    pub address_tables: Vec<AddressTableInfo>,
    pub call_fixups: Vec<CallFixupInfo>,
    pub media: Vec<MediaHit>,
    pub fid_matches: Vec<FidMatch>,
    pub resources: Vec<ResourceInfo>,
    pub switches: Vec<SwitchInfo>,
    pub recovered_code: Vec<DiscoveredRange>,
    pub shared_returns: Vec<u64>,
    pub pdb_symbols: Vec<SymbolInfo>,
}

/// Loaded program model shared by disasm, RTTI, CLI, MCP, GUI.
#[derive(Debug, Clone, Serialize)]
pub struct Program {
    pub name: String,
    pub format: String,
    pub image_base: u64,
    pub entry: Option<u64>,
    pub sections: Vec<SectionInfo>,
    pub blocks: Vec<MemoryBlock>,
    /// Original file bytes (for file-offset relative structures).
    #[serde(skip)]
    pub file_bytes: Vec<u8>,
    pub rtti: RttiReport,
    pub analysis: AnalysisState,
    /// PE import directory entries (IAT VAs + names). Empty for ELF until wired.
    #[serde(default)]
    pub imports: Vec<ImportEntry>,
    /// User-facing edits (renames, comments, retypes, function signatures, user types).
    /// Stored side-car so analyzer output remains "honest / never fabricated".
    #[serde(default)]
    pub edits: ProgramEdits,
}

impl Program {
    pub fn new(name: String, format: &str) -> Self {
        Self {
            name,
            format: format.into(),
            image_base: 0,
            entry: None,
            sections: Vec::new(),
            blocks: Vec::new(),
            file_bytes: Vec::new(),
            rtti: RttiReport::default(),
            analysis: AnalysisState::default(),
            imports: Vec::new(),
            edits: ProgramEdits::default(),
        }
    }

    /// Read up to `len` bytes at virtual address `va`.
    pub fn read_va(&self, va: u64, len: usize) -> Option<Vec<u8>> {
        for b in &self.blocks {
            if va >= b.va && va < b.va.saturating_add(b.size) {
                let off = (va - b.va) as usize;
                if off >= b.bytes.len() {
                    return None;
                }
                let end = (off + len).min(b.bytes.len());
                return Some(b.bytes[off..end].to_vec());
            }
        }
        None
    }

    pub fn byte_at(&self, va: u64) -> Option<u8> {
        self.read_va(va, 1).and_then(|v| v.first().copied())
    }

    /// Translate VA → file offset when the VA lands in a known section.
    pub fn va_to_file_offset(&self, va: u64) -> Option<u64> {
        for s in &self.sections {
            let end = s.va.saturating_add(s.virtual_size.max(s.raw_size));
            if va >= s.va && va < end {
                let delta = va - s.va;
                if delta < s.raw_size {
                    return Some(s.file_offset + delta);
                }
            }
        }
        None
    }

    pub fn contains_va(&self, va: u64) -> bool {
        self.blocks
            .iter()
            .any(|b| va >= b.va && va < b.va.saturating_add(b.size))
    }

    pub fn exec_blocks(&self) -> impl Iterator<Item = &MemoryBlock> {
        self.blocks.iter().filter(|b| b.executable)
    }

    pub fn function_at(&self, entry: u64) -> Option<&FunctionInfo> {
        self.analysis.functions.iter().find(|f| f.entry == entry)
    }

    pub fn function_at_mut(&mut self, entry: u64) -> Option<&mut FunctionInfo> {
        self.analysis.functions.iter_mut().find(|f| f.entry == entry)
    }

    /// Tightest analyzed function whose `[entry, end)` contains `va`.
    /// Prefers the greatest `entry` ≤ `va` among covering intervals.
    pub fn function_containing(&self, va: u64) -> Option<&FunctionInfo> {
        self.analysis
            .functions
            .iter()
            .filter(|f| va >= f.entry && va < f.end.max(f.entry.saturating_add(1)))
            .max_by_key(|f| f.entry)
    }
}
