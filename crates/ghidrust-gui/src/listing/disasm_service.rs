//! Reload listing disassembly via `ghidrust_core` decode APIs.

use super::model::{DecodeUiOpts, WalkMode};
use ghidrust_core::{disassemble_range_ex_opts, DisasmRangeResult, Program};

/// Disassemble at `start` using engine options from the GUI.
pub fn reload(
    prog: &Program,
    start: u64,
    opts: &DecodeUiOpts,
) -> Result<DisasmRangeResult, String> {
    let engine = opts.to_engine_opts();
    let bound_end = prog
        .function_containing(start)
        .map(|f| f.end)
        .filter(|e| *e > start);
    disassemble_range_ex_opts(
        prog,
        start,
        opts.max_insns,
        opts.skip_bad,
        opts.walk_mode.to_disasm_mode(),
        bound_end,
        Some(&engine),
    )
    .map_err(|e| e.to_string())
}

/// Pick a sensible reload VA when none is focused.
pub fn default_start_va(prog: &Program, focus: Option<u64>) -> u64 {
    focus.unwrap_or_else(|| prog.entry.unwrap_or(prog.image_base))
}

/// Default listing window size for navigation reloads.
pub const GOTO_MAX_INSNS: usize = 64;

/// Reload helper tuned for go-to navigation (smaller window).
pub fn reload_for_goto(prog: &Program, va: u64, opts: &DecodeUiOpts) -> Result<Vec<ghidrust_core::Instruction>, String> {
    let mut nav_opts = opts.clone();
    nav_opts.max_insns = GOTO_MAX_INSNS;
    nav_opts.walk_mode = WalkMode::Bounded;
    reload(prog, va, &nav_opts).map(|r| r.insns)
}
