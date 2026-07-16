//! User-editable program state — Ghidra `ProgramDB` equivalent for the Ghidrust GUI.
//!
//! Rename / retype / edit-signature / comment operations mutate this side-car
//! store rather than the primary analysis output. This preserves the "analyzer
//! output is honest" invariant while still letting the UI persist user
//! decisions across saves.
//!
//! Keys are **virtual addresses** (Ghidra `Address`). Where a symbol has both
//! an analyzer-provided name and a user rename, the user rename wins in
//! [`Program::display_name_at`] / [`Program::display_function_name_at`].

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::program::Program;

/// Ghidra comment kinds attached to a code unit (per [Comment types] in
/// `CodeUnit.EOL_COMMENT` etc).
///
/// [Comment types]: https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/CodeUnit.html
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CommentKind {
    Eol,
    Pre,
    Post,
    Plate,
    Repeatable,
}

impl CommentKind {
    pub const ALL: &'static [CommentKind] = &[
        CommentKind::Eol,
        CommentKind::Pre,
        CommentKind::Post,
        CommentKind::Plate,
        CommentKind::Repeatable,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            CommentKind::Eol => "EOL",
            CommentKind::Pre => "Pre",
            CommentKind::Post => "Post",
            CommentKind::Plate => "Plate",
            CommentKind::Repeatable => "Repeatable",
        }
    }
}

/// One record for a function-signature edit (Ghidra's `Edit Function Signature`).
///
/// Values are captured as strings so Stage-0 doesn't need to depend on a real
/// C parser; the plan (Phase C+) is to attach a parsed `FunctionPrototype`
/// once the DTM has real types.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionSignatureEdit {
    /// Full signature string, e.g. `int foo(char *, size_t)`.
    pub signature: String,
    /// Calling convention override (if user changed it).
    pub calling_convention: Option<String>,
    /// User-committed parameters as `type name` pairs (for Commit Params).
    pub parameters: Vec<String>,
    /// User-committed return type (for Commit Return).
    pub return_type: Option<String>,
    /// User-committed locals list (for Commit Locals).
    pub locals: Vec<String>,
}

/// One record for a variable/global retype (`Ctrl+L` in Ghidra).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetypeEdit {
    pub type_desc: String,
}

/// Side-car user-edit store for a [`Program`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProgramEdits {
    /// Function / symbol renames keyed by VA.
    #[serde(default)]
    pub renames: BTreeMap<u64, String>,
    /// Retypes keyed by VA (parameter / local / global).
    #[serde(default)]
    pub retypes: BTreeMap<u64, RetypeEdit>,
    /// Comments keyed by (VA, kind). Empty string = deleted.
    ///
    /// Serialized as a flat `Vec` because JSON map keys must be strings.
    /// Bincode and the round-trip test both agree on the flat encoding.
    #[serde(default, with = "comments_serde")]
    pub comments: BTreeMap<(u64, CommentKind), String>,
    /// Function-signature edits keyed by function entry VA.
    #[serde(default)]
    pub function_signatures: BTreeMap<u64, FunctionSignatureEdit>,
    /// User-defined data types (name → Ghidra-C style description).
    /// Stage-0 stores as strings; Phase D+ upgrades to a parsed structure.
    #[serde(default)]
    pub user_types: BTreeMap<String, String>,
    /// User-applied types at specific VAs (Listing "Data Type" apply).
    #[serde(default)]
    pub applied_types: BTreeMap<u64, String>,
}

/// Serde helper — turns the comments map into `Vec<(u64, CommentKind, String)>`
/// so both JSON (string-keyed) and bincode (any-keyed) can round-trip it.
mod comments_serde {
    use super::CommentKind;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::BTreeMap;

    #[derive(Serialize, Deserialize)]
    struct Row {
        va: u64,
        kind: CommentKind,
        text: String,
    }

    pub fn serialize<S: Serializer>(
        map: &BTreeMap<(u64, CommentKind), String>,
        ser: S,
    ) -> Result<S::Ok, S::Error> {
        let rows: Vec<Row> = map
            .iter()
            .map(|((va, kind), text)| Row {
                va: *va,
                kind: *kind,
                text: text.clone(),
            })
            .collect();
        rows.serialize(ser)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        de: D,
    ) -> Result<BTreeMap<(u64, CommentKind), String>, D::Error> {
        let rows: Vec<Row> = Vec::deserialize(de)?;
        Ok(rows
            .into_iter()
            .map(|r| ((r.va, r.kind), r.text))
            .collect())
    }
}

impl ProgramEdits {
    /// Look up the user-visible name at `va`, if any.
    pub fn rename_at(&self, va: u64) -> Option<&str> {
        self.renames.get(&va).map(String::as_str)
    }

    /// Set / clear a rename. Empty `new_name` clears the entry.
    pub fn set_rename(&mut self, va: u64, new_name: impl Into<String>) {
        let new_name = new_name.into();
        if new_name.is_empty() {
            self.renames.remove(&va);
        } else {
            self.renames.insert(va, new_name);
        }
    }

    /// Set / clear a retype at `va`.
    pub fn set_retype(&mut self, va: u64, type_desc: impl Into<String>) {
        let type_desc = type_desc.into();
        if type_desc.is_empty() {
            self.retypes.remove(&va);
        } else {
            self.retypes.insert(va, RetypeEdit { type_desc });
        }
    }

    pub fn retype_at(&self, va: u64) -> Option<&str> {
        self.retypes.get(&va).map(|r| r.type_desc.as_str())
    }

    /// Set or clear a comment. Empty `text` clears the entry.
    pub fn set_comment(&mut self, va: u64, kind: CommentKind, text: impl Into<String>) {
        let text = text.into();
        if text.is_empty() {
            self.comments.remove(&(va, kind));
        } else {
            self.comments.insert((va, kind), text);
        }
    }

    pub fn comment_at(&self, va: u64, kind: CommentKind) -> Option<&str> {
        self.comments.get(&(va, kind)).map(String::as_str)
    }

    /// Every kind of comment attached to `va`, ordered by [`CommentKind::ALL`].
    pub fn comments_at(&self, va: u64) -> Vec<(CommentKind, &str)> {
        CommentKind::ALL
            .iter()
            .copied()
            .filter_map(|k| self.comment_at(va, k).map(|t| (k, t)))
            .collect()
    }

    /// Set / update a function-signature edit.
    pub fn set_function_signature(&mut self, entry: u64, sig: FunctionSignatureEdit) {
        self.function_signatures.insert(entry, sig);
    }

    pub fn function_signature(&self, entry: u64) -> Option<&FunctionSignatureEdit> {
        self.function_signatures.get(&entry)
    }

    /// Commit inferred parameters as user edits (Decompiler → Commit Params).
    pub fn commit_params(&mut self, entry: u64, parameters: Vec<String>) {
        let e = self.function_signatures.entry(entry).or_default();
        e.parameters = parameters;
    }

    /// Commit inferred return type as user edit (Decompiler → Commit Return).
    pub fn commit_return_type(&mut self, entry: u64, return_type: impl Into<String>) {
        let e = self.function_signatures.entry(entry).or_default();
        e.return_type = Some(return_type.into());
    }

    /// Commit inferred locals as user edits (Decompiler → Commit Locals).
    pub fn commit_locals(&mut self, entry: u64, locals: Vec<String>) {
        let e = self.function_signatures.entry(entry).or_default();
        e.locals = locals;
    }

    /// Define / redefine a user data type (DTM `New Structure` / `New Enum`).
    pub fn set_user_type(&mut self, name: impl Into<String>, desc: impl Into<String>) {
        self.user_types.insert(name.into(), desc.into());
    }

    /// Look up the stored body for a user type by name.
    pub fn user_type(&self, name: &str) -> Option<&str> {
        self.user_types.get(name).map(String::as_str)
    }

    /// Delete a user type. Any `applied_types` referencing it are cleared so
    /// the Listing doesn't display dangling names. Returns `true` if the type
    /// was present.
    pub fn delete_user_type(&mut self, name: &str) -> bool {
        let removed = self.user_types.remove(name).is_some();
        if removed {
            self.applied_types.retain(|_, t| t != name);
        }
        removed
    }

    /// Rename a user type. Also rewrites `applied_types` so a downstream
    /// Listing keeps its `<TypeName>` decoration in sync. Returns `true` if
    /// the rename actually applied (i.e. `old` existed and `new` differs).
    pub fn rename_user_type(&mut self, old: &str, new: &str) -> bool {
        if old == new || new.is_empty() {
            return false;
        }
        let Some(body) = self.user_types.remove(old) else {
            return false;
        };
        self.user_types.insert(new.to_string(), body);
        for t in self.applied_types.values_mut() {
            if t == old {
                *t = new.to_string();
            }
        }
        true
    }

    /// Apply a data type at `va` (Listing "Choose Data Type" apply).
    pub fn set_applied_type(&mut self, va: u64, type_name: impl Into<String>) {
        let name = type_name.into();
        if name.is_empty() {
            self.applied_types.remove(&va);
        } else {
            self.applied_types.insert(va, name);
        }
    }

    pub fn applied_type_at(&self, va: u64) -> Option<&str> {
        self.applied_types.get(&va).map(String::as_str)
    }

    /// Summary counters for status/UX chips.
    pub fn totals(&self) -> ProgramEditTotals {
        ProgramEditTotals {
            renames: self.renames.len(),
            retypes: self.retypes.len(),
            comments: self.comments.len(),
            function_signatures: self.function_signatures.len(),
            user_types: self.user_types.len(),
            applied_types: self.applied_types.len(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProgramEditTotals {
    pub renames: usize,
    pub retypes: usize,
    pub comments: usize,
    pub function_signatures: usize,
    pub user_types: usize,
    pub applied_types: usize,
}

impl Program {
    /// User-facing display name for `va` — checks edits first, then analyzer output.
    pub fn display_name_at(&self, va: u64) -> Option<&str> {
        if let Some(n) = self.edits.rename_at(va) {
            return Some(n);
        }
        if let Some(f) = self.function_at(va) {
            return Some(f.name.as_str());
        }
        self.analysis
            .symbols
            .iter()
            .find(|s| s.va == va)
            .map(|s| s.name.as_str())
    }

    /// Convenience for the Symbol Tree Functions category and the Decompiler
    /// header — prefers a user rename over the analyzer-provided one.
    pub fn display_function_name_at(&self, entry: u64) -> Option<String> {
        self.function_at(entry).map(|f| {
            self.edits
                .rename_at(entry)
                .map(str::to_string)
                .unwrap_or_else(|| f.name.clone())
        })
    }
}

/// Built-in data types Ghidra exposes in the "BuiltInTypes" archive (subset relevant
/// to Ghidrust's Stage-0 rendering). Ordered as Ghidra shows them in the DTM.
pub const BUILTIN_TYPES: &[&str] = &[
    "void", "bool",
    "byte", "sbyte", "word", "sword", "dword", "sdword", "qword", "sqword",
    "int8_t", "uint8_t", "int16_t", "uint16_t", "int32_t", "uint32_t",
    "int64_t", "uint64_t",
    "char", "uchar", "wchar_t", "wchar16", "wchar32",
    "short", "ushort", "int", "uint", "long", "ulong", "longlong", "ulonglong",
    "float", "double", "longdouble",
    "pointer", "pointer32", "pointer64",
    "undefined", "undefined1", "undefined2", "undefined4", "undefined8",
    "string", "unicode", "TerminatedCString", "TerminatedUnicode",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rename_replaces_and_clears() {
        let mut e = ProgramEdits::default();
        assert!(e.rename_at(0x1000).is_none());
        e.set_rename(0x1000, "foo");
        assert_eq!(e.rename_at(0x1000), Some("foo"));
        e.set_rename(0x1000, "");
        assert!(e.rename_at(0x1000).is_none());
    }

    #[test]
    fn comment_kinds_stack() {
        let mut e = ProgramEdits::default();
        e.set_comment(0x1000, CommentKind::Eol, "eol!");
        e.set_comment(0x1000, CommentKind::Plate, "**PLATE**");
        let all = e.comments_at(0x1000);
        assert_eq!(all.len(), 2);
        assert!(all.iter().any(|(k, t)| *k == CommentKind::Eol && *t == "eol!"));
        e.set_comment(0x1000, CommentKind::Eol, "");
        assert_eq!(e.comments_at(0x1000).len(), 1);
    }

    #[test]
    fn retype_and_signature_commit_flow() {
        let mut e = ProgramEdits::default();
        e.set_retype(0x2000, "int32_t *");
        assert_eq!(e.retype_at(0x2000), Some("int32_t *"));
        e.commit_params(0x3000, vec!["int a".into(), "char *b".into()]);
        e.commit_return_type(0x3000, "int");
        let sig = e.function_signature(0x3000).unwrap();
        assert_eq!(sig.parameters.len(), 2);
        assert_eq!(sig.return_type.as_deref(), Some("int"));
    }

    #[test]
    fn user_types_and_applied() {
        let mut e = ProgramEdits::default();
        e.set_user_type("Widget", "struct Widget { int id; }");
        assert_eq!(
            e.user_types.get("Widget").map(String::as_str),
            Some("struct Widget { int id; }")
        );
        e.set_applied_type(0x1000, "Widget");
        assert_eq!(e.applied_type_at(0x1000), Some("Widget"));
        e.set_applied_type(0x1000, "");
        assert!(e.applied_type_at(0x1000).is_none());
    }

    #[test]
    fn rename_user_type_rewrites_applied() {
        let mut e = ProgramEdits::default();
        e.set_user_type("Widget", "struct Widget { int id; }");
        e.set_applied_type(0x1000, "Widget");
        e.set_applied_type(0x1004, "Widget");
        assert!(e.rename_user_type("Widget", "Gadget"));
        assert!(e.user_type("Widget").is_none());
        assert!(e.user_type("Gadget").is_some());
        assert_eq!(e.applied_type_at(0x1000), Some("Gadget"));
        assert_eq!(e.applied_type_at(0x1004), Some("Gadget"));
        // No-ops.
        assert!(!e.rename_user_type("missing", "x"));
        assert!(!e.rename_user_type("Gadget", ""));
        assert!(!e.rename_user_type("Gadget", "Gadget"));
    }

    #[test]
    fn delete_user_type_clears_applied() {
        let mut e = ProgramEdits::default();
        e.set_user_type("Widget", "struct");
        e.set_applied_type(0x2000, "Widget");
        assert!(e.delete_user_type("Widget"));
        assert!(e.applied_type_at(0x2000).is_none());
        assert!(!e.delete_user_type("Widget"));
    }

    #[test]
    fn totals_counts() {
        let mut e = ProgramEdits::default();
        e.set_rename(1, "a");
        e.set_rename(2, "b");
        e.set_retype(3, "int");
        e.set_comment(4, CommentKind::Eol, "hi");
        let t = e.totals();
        assert_eq!(t.renames, 2);
        assert_eq!(t.retypes, 1);
        assert_eq!(t.comments, 1);
    }

    #[test]
    fn builtin_types_include_essentials() {
        let want = ["void", "byte", "word", "dword", "qword", "char", "int", "pointer"];
        for w in want {
            assert!(BUILTIN_TYPES.contains(&w), "missing builtin type {w}");
        }
    }
}
