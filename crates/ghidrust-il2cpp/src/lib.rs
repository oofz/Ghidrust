//! Hand-rolled IL2CPP metadata + binary correlation for Ghidrust.
//!
//! No Il2CppDumper / Cpp2IL / goblin at runtime — formats reimplemented in-tree.
//! See `docs/IL2CPP.md` for the supported version matrix.

pub mod binary;
pub mod error;
pub mod icall;
pub mod metadata;
pub mod stubs;

pub use binary::{
    correlate, load_and_correlate, to_script_json, MethodMap, MethodMapEntry, ScriptJson,
};
pub use error::{Error, Result, ENCRYPTED_METADATA_NEXT_STEPS};
pub use icall::{
    filter_entries, resolve_icalls, resolve_icalls_path, ICallEntry, ICallResolveReport, ICallTable,
    ICallTableLayout,
};
pub use metadata::{
    build_synthetic, build_synthetic_v31, Il2CppMetadata, MetadataDialect, METADATA_MAGIC,
};
pub use stubs::{
    classify_at, find_resolve_stubs, follow_stub_target, is_resolve_stub_va, stub_matches_filter,
    Il2CppKind, ResolveStub,
};
