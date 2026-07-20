//! Synthetic truncated-bounds fixture: short stored end vs multi-block body.

use ghidrust_core::{
    assess_bounds_honesty, create_function, disassemble_range_ex, grow_function, DisasmMode,
    DisasmStopReason, FunctionInfo, FunctionSeedKind, MemoryBlock, Program,
};

fn multi_block_prog() -> Program {
    let mut prog = Program::new("truncated_bounds_lab".into(), "PE32+");
    let mut code = vec![
        0x55, 0x48, 0x89, 0xE5, // push rbp; mov rbp, rsp
        0x41, 0x56, // push r14
        0x48, 0x83, 0xEC, 0x20, // sub rsp, 0x20
    ];
    code.extend(vec![0x90u8; 64]);
    code.extend_from_slice(&[
        0x31, 0xC0, // xor eax,eax
        0x48, 0x83, 0xC4, 0x20, // add rsp,0x20
        0x41, 0x5E, // pop r14
        0x5D, // pop rbp
        0xC3, // ret
        0xCC, 0xCC,
    ]);
    prog.blocks.push(MemoryBlock {
        name: ".text".into(),
        va: 0x140001000,
        size: code.len() as u64,
        bytes: code,
        readable: true,
        writable: false,
        executable: true,
    });
    prog.entry = Some(0x140001000);
    prog.image_base = 0x140000000;
    prog
}

#[test]
fn linear_returns_more_than_prologue_only_bounded() {
    let mut prog = multi_block_prog();
    let entry = 0x140001000;
    // Prologue-only stored end (~17 bytes through early pushes).
    let short_end = entry + 0x11;
    prog.analysis.functions.push(
        FunctionInfo::new(entry, short_end, "FUN_trunc").with_seed_kind(FunctionSeedKind::Manual),
    );

    let bounded = disassemble_range_ex(
        &prog,
        entry,
        80,
        false,
        DisasmMode::Bounded,
        Some(short_end),
    )
    .expect("bounded");
    let linear = disassemble_range_ex(&prog, entry, 80, false, DisasmMode::Linear, None)
        .expect("linear");

    assert_eq!(bounded.stop_reason, DisasmStopReason::FunctionEnd);
    assert!(
        linear.insns.len() > bounded.insns.len() + 5,
        "linear={} bounded={}",
        linear.insns.len(),
        bounded.insns.len()
    );

    let honesty = assess_bounds_honesty(
        &prog,
        Some(entry),
        Some(short_end),
        bounded.insns.len(),
        bounded.stop_reason,
    );
    assert!(honesty.bounds_suspect, "expected truncated-bounds warning");
    assert!(honesty.suggested_end.unwrap() > short_end);

    let healed = create_function(&mut prog, entry, None);
    assert!(healed.end > short_end);
    assert_eq!(healed.end, grow_function(&prog, entry, None));
}
