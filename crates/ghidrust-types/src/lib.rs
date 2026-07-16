//! **Ghidrust type lattice + local/parameter recovery** over
//! [`ghidrust_ssa::SsaFunction`].
//!
//! Ghidra `Ghidra/Features/Decompiler`'s `DataType` and `typeprop` pass are
//! the *reference*. Everything here is hand-rolled per the workspace
//! dependency policy — we deliberately keep the initial lattice small so
//! Stage-1 emit has enough information to name locals/params without
//! fabricating aggressive type inferences.
//!
//! ## Lattice
//!
//! ```text
//!                        Any
//!             /   |    |     |     |    \
//!         Ptr   I64   I32   I16   I8   Bool
//!             \   |    |     |     |    /
//!                       Bottom
//! ```
//!
//! * `Bottom` = "no information yet" (initial state for every value).
//! * `Any` = "conflicting / >1 concrete types observed" (top).
//! * `IntN` is the width-sniffed integer bucket per varnode size.
//! * `Bool` seeds from flag-register writes (`ZF`/`CF`/`SF`/`OF`) and
//!   `BoolNegate`/`BoolAnd`/`BoolOr` outputs.
//! * `Ptr` seeds from `Load`/`Store` addresses.
//!
//! ## Recovery outputs
//!
//! * [`TypeMap`] — `(space, offset) → RustType` for every value that has a
//!   non-`Bottom` type.
//! * [`LocalMap`] — stack locals keyed by `(offset, size)`; each carries a
//!   generated `local_N` name so Stage-1 emit doesn't have to reinvent one.
//! * [`ParamList`] — x86-64 SysV / Windows integer register params inferred
//!   from live-in reads in the entry block.

use ghidrust_ir::{AddrSpace, OpCode};
use ghidrust_ssa::{SsaFunction, SsaOp, SsaOperand};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Small type lattice — see module docs. Kept intentionally compact; new
/// buckets should join in through `join` / `refine` without breaking the
/// existing monotonicity contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RustType {
    /// No info observed yet.
    Bottom,
    /// 1-bit boolean-shaped value (flag register or bool op output).
    Bool,
    /// Fixed-width unsigned integer.
    IntN {
        /// Width in bytes (1, 2, 4, 8).
        width: u32,
    },
    /// A pointer produced by a `Load`/`Store` address computation.
    Ptr {
        /// Pointee width in bytes when known; `0` when unknown.
        pointee_width: u32,
    },
    /// Conflicting observations (top).
    Any,
}

impl RustType {
    pub fn int(width: u32) -> Self {
        Self::IntN { width }
    }
    pub fn ptr(pointee_width: u32) -> Self {
        Self::Ptr { pointee_width }
    }

    /// Least upper bound in the lattice — the meet of two observations.
    pub fn join(self, other: Self) -> Self {
        use RustType::*;
        match (self, other) {
            (Bottom, x) | (x, Bottom) => x,
            (a, b) if a == b => a,
            (IntN { width: a }, IntN { width: b }) => IntN {
                width: a.max(b),
            },
            (Ptr { pointee_width: a }, Ptr { pointee_width: b }) => Ptr {
                pointee_width: a.max(b),
            },
            _ => Any,
        }
    }

    pub fn c_style(&self) -> String {
        match self {
            RustType::Bottom => "undefined".into(),
            RustType::Bool => "bool".into(),
            RustType::IntN { width } => match width {
                1 => "uint8_t".into(),
                2 => "uint16_t".into(),
                4 => "uint32_t".into(),
                8 => "uint64_t".into(),
                w => format!("uint{}_t", w * 8),
            },
            RustType::Ptr { pointee_width } => match pointee_width {
                0 => "void*".into(),
                1 => "uint8_t*".into(),
                2 => "uint16_t*".into(),
                4 => "uint32_t*".into(),
                8 => "uint64_t*".into(),
                w => format!("uint{}_t*", w * 8),
            },
            RustType::Any => "void*".into(),
        }
    }
}

/// Recovered per-`(space, offset)` types after propagation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TypeMap(pub BTreeMap<(AddrSpace, u64), RustType>);

impl TypeMap {
    pub fn get(&self, space: AddrSpace, offset: u64) -> RustType {
        self.0.get(&(space, offset)).copied().unwrap_or(RustType::Bottom)
    }
    pub fn set(&mut self, space: AddrSpace, offset: u64, t: RustType) {
        let e = self.0.entry((space, offset)).or_insert(RustType::Bottom);
        *e = e.join(t);
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// One recovered stack local.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackLocal {
    pub offset: u64,
    pub width: u32,
    pub name: String,
    pub ty: RustType,
}

/// Stack locals keyed by (offset, size). Locals are named `local_<hex-off>`
/// with a bytes suffix when helpful.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LocalMap(pub BTreeMap<(u64, u32), StackLocal>);

impl LocalMap {
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn iter(&self) -> impl Iterator<Item = &StackLocal> {
        self.0.values()
    }
}

/// One recovered parameter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Parameter {
    /// Zero-based param index in the calling convention order.
    pub index: usize,
    /// x86-64 register name (as `ghidrust_lift::X86Reg` label).
    pub register: String,
    pub width: u32,
    pub name: String,
    pub ty: RustType,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ParamList(pub Vec<Parameter>);

impl ParamList {
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn iter(&self) -> impl Iterator<Item = &Parameter> {
        self.0.iter()
    }
}

/// Choice of x86-64 calling convention for parameter recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallConv {
    /// System V AMD64: RDI, RSI, RDX, RCX, R8, R9.
    SystemV,
    /// Microsoft x64: RCX, RDX, R8, R9.
    Windows,
}

/// Full recovery result for a function: types, stack locals, parameters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TypeRecovery {
    pub types: TypeMap,
    pub locals: LocalMap,
    pub params: ParamList,
}

impl TypeRecovery {
    pub fn coverage_ratio(&self, denominator: usize) -> f32 {
        if denominator == 0 {
            return 0.0;
        }
        self.types.len() as f32 / denominator as f32
    }
}

/// Propagate a type through the SSA graph until a fixed point is reached.
/// The lattice is finite so a monotone worklist terminates in bounded
/// iterations. Stops after `MAX_ITER` iterations to defend against future
/// non-monotone rules.
pub fn infer_types(func: &SsaFunction) -> TypeMap {
    const MAX_ITER: usize = 8;
    let mut map = TypeMap::default();
    let flag_offsets: BTreeSet<u64> = [
        ghidrust_lift_flag_off(),
    ]
    .into_iter()
    .flatten()
    .collect();

    for _ in 0..MAX_ITER {
        let before = map.0.clone();
        for b in &func.blocks {
            for op in &b.ops {
                seed_op(op, &mut map, &flag_offsets);
            }
        }
        if map.0 == before {
            break;
        }
    }
    map
}

fn ghidrust_lift_flag_off() -> Vec<u64> {
    use ghidrust_lift::flag_off::*;
    vec![CF, PF, AF, ZF, SF, OF, DF]
}

fn seed_op(op: &SsaOp, map: &mut TypeMap, flags: &BTreeSet<u64>) {
    match op.opcode {
        OpCode::BoolAnd | OpCode::BoolOr | OpCode::BoolNegate => {
            if let Some(out) = op.output {
                map.set(out.space, out.offset, RustType::Bool);
            }
        }
        OpCode::IntEqual
        | OpCode::IntNotEqual
        | OpCode::IntLess
        | OpCode::IntLessEqual
        | OpCode::IntSLess
        | OpCode::IntSLessEqual => {
            if let Some(out) = op.output {
                map.set(out.space, out.offset, RustType::Bool);
            }
        }
        OpCode::Load => {
            if let Some(out) = op.output {
                map.set(out.space, out.offset, RustType::int(out.size));
            }
            if let Some(addr) = op.inputs.first().and_then(SsaOperand::as_value) {
                map.set(addr.space, addr.offset, RustType::ptr(op.output.map(|o| o.size).unwrap_or(0)));
            }
        }
        OpCode::Store => {
            if let Some(addr) = op.inputs.first().and_then(SsaOperand::as_value) {
                let pointee = op.inputs.get(1).and_then(SsaOperand::as_value).map(|v| v.size).unwrap_or(0);
                map.set(addr.space, addr.offset, RustType::ptr(pointee));
            }
        }
        OpCode::IntAdd
        | OpCode::IntSub
        | OpCode::IntXor
        | OpCode::IntAnd
        | OpCode::IntOr
        | OpCode::IntMult
        | OpCode::IntLeft
        | OpCode::IntRight
        | OpCode::IntSRight
        | OpCode::IntNegate
        | OpCode::IntNot
        | OpCode::Copy => {
            if let Some(out) = op.output {
                let t = if flags.contains(&out.offset) && out.space == AddrSpace::Register {
                    RustType::Bool
                } else {
                    RustType::int(out.size)
                };
                map.set(out.space, out.offset, t);
            }
        }
        _ => {}
    }
}

/// Recover stack locals by scanning `Stack`-space reads/writes across the
/// function body. Each unique `(offset, width)` becomes one local; widths
/// pick the widest observed access.
pub fn recover_locals(func: &SsaFunction, types: &TypeMap) -> LocalMap {
    let mut seen: BTreeMap<u64, u32> = BTreeMap::new();
    for b in &func.blocks {
        for op in &b.ops {
            if let Some(out) = op.output {
                if out.space == AddrSpace::Stack {
                    let e = seen.entry(out.offset).or_insert(out.size);
                    *e = (*e).max(out.size);
                }
            }
            for inp in &op.inputs {
                if let Some(v) = inp.as_value() {
                    if v.space == AddrSpace::Stack {
                        let e = seen.entry(v.offset).or_insert(v.size);
                        *e = (*e).max(v.size);
                    }
                }
            }
        }
    }
    let mut map = LocalMap::default();
    for (offset, width) in seen {
        let ty = types.get(AddrSpace::Stack, offset);
        let ty = if ty == RustType::Bottom {
            RustType::int(width)
        } else {
            ty
        };
        let name = format!("local_{:x}", offset);
        map.0.insert(
            (offset, width),
            StackLocal {
                offset,
                width,
                name,
                ty,
            },
        );
    }
    map
}

/// Recover parameter register slots by looking at the entry block's live-
/// in values (uses that were never previously defined). Only integer
/// register slots that match the selected calling convention are counted.
pub fn recover_params(func: &SsaFunction, types: &TypeMap, conv: CallConv) -> ParamList {
    if func.blocks.is_empty() {
        return ParamList::default();
    }
    let entry_block = &func.blocks[func.entry as usize];
    let mut live_in: BTreeSet<(u64, u32)> = BTreeSet::new();
    // Track which register keys have been defined so far in the entry block.
    let mut defined: BTreeSet<u64> = BTreeSet::new();
    for op in &entry_block.ops {
        for inp in &op.inputs {
            if let Some(v) = inp.as_value() {
                if v.space == AddrSpace::Register && v.version == 0 && !defined.contains(&v.offset) {
                    live_in.insert((v.offset, v.size));
                }
            }
        }
        if let Some(out) = op.output {
            if out.space == AddrSpace::Register {
                defined.insert(out.offset);
            }
        }
    }
    // Also treat every phi that references a live-in value as an implicit
    // live-in.
    for phi in &entry_block.phis {
        if phi.out.space == AddrSpace::Register {
            for (_, val) in &phi.incoming {
                if let Some(v) = val {
                    if v.version == 0 {
                        live_in.insert((v.offset, v.size));
                    }
                }
            }
        }
    }
    let order: &[(u64, &str)] = match conv {
        CallConv::SystemV => &[
            (7, "rdi"),
            (6, "rsi"),
            (2, "rdx"),
            (1, "rcx"),
            (8, "r8"),
            (9, "r9"),
        ],
        CallConv::Windows => &[
            (1, "rcx"),
            (2, "rdx"),
            (8, "r8"),
            (9, "r9"),
        ],
    };
    let mut params = Vec::new();
    for (index, &(reg_off, reg_name)) in order.iter().enumerate() {
        let width_opt = live_in.iter().find(|(off, _)| *off == reg_off).map(|(_, w)| *w);
        if let Some(width) = width_opt {
            let ty = types.get(AddrSpace::Register, reg_off);
            let ty = if ty == RustType::Bottom {
                RustType::int(width)
            } else {
                ty
            };
            params.push(Parameter {
                index,
                register: reg_name.to_string(),
                width,
                name: format!("param_{}", index + 1),
                ty,
            });
        }
    }
    ParamList(params)
}

/// One-shot: run type inference + local + param recovery on `func`.
pub fn recover(func: &SsaFunction, conv: CallConv) -> TypeRecovery {
    let types = infer_types(func);
    let locals = recover_locals(func, &types);
    let params = recover_params(func, &types, conv);
    TypeRecovery {
        types,
        locals,
        params,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidrust_decode::decode_bytes;
    use ghidrust_lift::lift_instructions;
    use ghidrust_ssa::{build_cfg, build_ssa};

    fn recover_bytes(bytes: &[u8], base: u64, conv: CallConv) -> TypeRecovery {
        let insns = decode_bytes(bytes, base, 64).unwrap();
        let last = insns.last().unwrap();
        let end = last.address + last.length as u64;
        let seq = lift_instructions(&insns);
        let cfg = build_cfg(&seq, base, end);
        let ssa = build_ssa(&cfg);
        recover(&ssa, conv)
    }

    #[test]
    fn xor_eax_eax_marks_zf_sf_as_bool() {
        // 31 c0  xor eax, eax  → sets ZF/SF flags in the lifter.
        let rec = recover_bytes(&[0x31, 0xc0], 0x1000, CallConv::SystemV);
        use ghidrust_lift::flag_off::*;
        assert_eq!(
            rec.types.get(AddrSpace::Register, ZF),
            RustType::Bool,
            "zf should be bool"
        );
        assert_eq!(
            rec.types.get(AddrSpace::Register, SF),
            RustType::Bool
        );
    }

    #[test]
    fn add_seeds_int_type_on_output() {
        // 83 c4 08  add esp, 8
        let rec = recover_bytes(&[0x83, 0xc4, 0x08], 0x2000, CallConv::SystemV);
        let esp = rec.types.get(AddrSpace::Register, 4); // rsp id = 4
        assert!(
            matches!(esp, RustType::IntN { .. }),
            "esp should be IntN after add, got {:?}",
            esp
        );
    }

    #[test]
    fn params_recovered_from_liveins_systemv() {
        // Function reads rdi then rsi at entry.
        // 48 89 f8  mov rax, rdi ; 48 01 f0  add rax, rsi ; c3 ret
        let bytes = [0x48, 0x89, 0xf8, 0x48, 0x01, 0xf0, 0xc3];
        let rec = recover_bytes(&bytes, 0x3000, CallConv::SystemV);
        let names: Vec<String> = rec.params.iter().map(|p| p.register.clone()).collect();
        assert!(names.contains(&"rdi".to_string()), "rdi expected: {names:?}");
        assert!(names.contains(&"rsi".to_string()), "rsi expected: {names:?}");
        assert_eq!(rec.params.0[0].name, "param_1");
    }

    #[test]
    fn params_recovered_from_liveins_windows() {
        // Function reads rcx then rdx.
        // 48 89 c8  mov rax, rcx ; 48 01 d0  add rax, rdx ; c3
        let bytes = [0x48, 0x89, 0xc8, 0x48, 0x01, 0xd0, 0xc3];
        let rec = recover_bytes(&bytes, 0x4000, CallConv::Windows);
        let regs: Vec<String> = rec.params.iter().map(|p| p.register.clone()).collect();
        assert!(regs.contains(&"rcx".to_string()));
        assert!(regs.contains(&"rdx".to_string()));
    }

    #[test]
    fn locals_recovered_when_stack_writes_present() {
        // Synthetic: hand-build an SSA with a stack write so we don't need
        // full memory operand lift.
        use ghidrust_ir::{IrSequence, PcodeOp, Varnode};
        let mut seq = IrSequence::new();
        seq.push_addressed(
            0x0,
            2,
            PcodeOp::new(
                OpCode::Store,
                None,
                vec![Varnode::stack(0x10, 8), Varnode::constant(0, 8)],
            ),
        );
        seq.push_addressed(
            0x2,
            2,
            PcodeOp::new(
                OpCode::Copy,
                Some(Varnode::stack(0x10, 8)),
                vec![Varnode::constant(0x1234, 8)],
            ),
        );
        seq.push_addressed(0x4, 1, PcodeOp::new(OpCode::Return, None, vec![]));
        let cfg = build_cfg(&seq, 0x0, 0x5);
        let ssa = build_ssa(&cfg);
        let rec = recover(&ssa, CallConv::SystemV);
        assert!(!rec.locals.is_empty(), "should recover the stack local");
        let l = rec.locals.iter().next().unwrap();
        assert_eq!(l.offset, 0x10);
        assert_eq!(l.width, 8);
        assert!(l.name.starts_with("local_"));
    }

    #[test]
    fn type_lattice_join_widens_widths() {
        let a = RustType::int(4);
        let b = RustType::int(8);
        assert_eq!(a.join(b), RustType::int(8));
        assert_eq!(RustType::Bool.join(RustType::int(1)), RustType::Any);
        assert_eq!(RustType::Bottom.join(a), a);
    }

    #[test]
    fn c_style_emits_named_types() {
        assert_eq!(RustType::int(4).c_style(), "uint32_t");
        assert_eq!(RustType::Bool.c_style(), "bool");
        assert_eq!(RustType::ptr(4).c_style(), "uint32_t*");
    }
}
