//! Hand-rolled IL2CPP metadata + binary correlation for Ghidrust.
//!
//! No Il2CppDumper / Cpp2IL / at runtime — formats reimplemented in-tree.
//! See `docs/IL2CPP.md` for the supported version matrix.

pub mod binary;
pub mod body;
pub mod error;
pub mod icall;
pub mod metadata;
pub mod stubs;
pub mod touch_map;

pub use binary::{
    compare_baseline, correlate, enrich_bodies, load_and_correlate, load_baseline_map,
    to_script_json, BuildSkew, MethodMap, MethodMapEntry, ScriptJson, SkewMoved, SkewName,
};
pub use body::{
    collapse_shared_stubs, fingerprint_body, fingerprint_body_norm, semantics_mismatch, BodyClass,
    BodyFingerprint, SharedStubSummary,
};
pub use error::{Error, Result, ENCRYPTED_METADATA_NEXT_STEPS};
pub use icall::{
    filter_entries, resolve_icalls, resolve_icalls_path, ICallEntry, ICallResolveReport,
    ICallTable, ICallTableLayout,
};
pub use metadata::{
    build_synthetic, build_synthetic_v31, load_from_meta_sections_dir, load_metadata_flexible,
    Il2CppMetadata, MetadataDialect, METADATA_MAGIC,
};
pub use stubs::{
    classify_at, find_resolve_stubs, follow_stub_target, is_resolve_stub_va, stub_matches_filter,
    Il2CppKind, ResolveStub,
};
pub use touch_map::{
    build_touch_map, touch_map, TouchConfidence, TouchKind, TouchMapReport, TouchMapRow,
};
