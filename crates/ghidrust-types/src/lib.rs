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
///
/// Phase-C additions carry structural shape information without turning the
/// lattice into a full C type system: pointer-target width, void return, and
/// struct/array seeds. The join rule keeps everything monotone — new
/// observations either widen a width, promote a scalar to a struct-typed
/// pointer, or collapse to `Any` when observations conflict.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    /// Signed integer variant. Introduced by explicit `IntSExt` /
    /// `IntSLess*` seeds so Stage-1 emit can print `int32_t` instead of the
    /// unsigned default. Widths match [`RustType::IntN`].
    IntSigned { width: u32 },
    /// A pointer produced by a `Load`/`Store` address computation.
    Ptr {
        /// Pointee width in bytes when known; `0` when unknown.
        pointee_width: u32,
    },
    /// Void — used for function return type when no register is written.
    Void,
    /// A pointer to a recovered struct seed (`ptr_key`), so Stage-1 emit
    /// can print `struct s_<key>*` and print field accesses as `p->field_N`
    /// instead of raw `*(uint64_t*)(p + K)`.
    StructPtr {
        /// Stable key into [`TypeRecovery::structs`].
        key: u32,
    },
    /// A pointer to a recovered array seed: element width in bytes and the
    /// count of distinct constant-index touches we observed. `count == 0`
    /// means unknown / open-ended.
    ArrayPtr { elem_width: u32, count: u32 },
    /// IEEE float/double (R4). Seeded from SSE/x87-shaped notes or explicit
    /// float ops — never invented from integer arithmetic alone.
    Float {
        /// Width in bytes (4 = float, 8 = double).
        width: u32,
    },
    /// Conflicting observations (top).
    Any,
}

impl RustType {
    pub fn int(width: u32) -> Self {
        Self::IntN { width }
    }
    pub fn signed(width: u32) -> Self {
        Self::IntSigned { width }
    }
    pub fn ptr(pointee_width: u32) -> Self {
        Self::Ptr { pointee_width }
    }
    pub fn struct_ptr(key: u32) -> Self {
        Self::StructPtr { key }
    }
    pub fn array_ptr(elem_width: u32, count: u32) -> Self {
        Self::ArrayPtr { elem_width, count }
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
            (IntSigned { width: a }, IntSigned { width: b }) => IntSigned {
                width: a.max(b),
            },
            // A signed observation combined with the same-width unsigned
            // one prefers the signed shape — Stage-1 emit reads the operand
            // as a signed compare / sext output which is more informative
            // than the width-only unsigned bucket.
            (IntSigned { width: a }, IntN { width: b })
            | (IntN { width: b }, IntSigned { width: a }) => IntSigned {
                width: a.max(b),
            },
            (Ptr { pointee_width: a }, Ptr { pointee_width: b }) => Ptr {
                pointee_width: a.max(b),
            },
            // A struct pointer subsumes an untyped raw pointer with the same
            // key already known; conflicting keys collapse to `Any`.
            (StructPtr { key: a }, StructPtr { key: b }) if a == b => StructPtr { key: a },
            (StructPtr { key }, Ptr { .. }) | (Ptr { .. }, StructPtr { key }) => {
                StructPtr { key }
            }
            // Struct/Array pointer observations subsume the same-width raw
            // integer seed on the base register (from the ambient Copy /
            // IntAdd chain that computed the address). This lets Stage-1
            // treat `rdi` as `struct s_1*` even though the base first flowed
            // through a `Copy` that seeded `IntN{8}`.
            (StructPtr { key }, IntN { width: 8 }) | (IntN { width: 8 }, StructPtr { key }) => {
                StructPtr { key }
            }
            (ArrayPtr { elem_width: aw, count: ac }, ArrayPtr { elem_width: bw, count: bc })
                if aw == bw =>
            {
                ArrayPtr { elem_width: aw, count: ac.max(bc) }
            }
            (ArrayPtr { elem_width, count }, Ptr { pointee_width })
            | (Ptr { pointee_width }, ArrayPtr { elem_width, count })
                if pointee_width == 0 || pointee_width == elem_width =>
            {
                ArrayPtr { elem_width, count }
            }
            (ArrayPtr { elem_width, count }, IntN { width: 8 })
            | (IntN { width: 8 }, ArrayPtr { elem_width, count }) => {
                ArrayPtr { elem_width, count }
            }
            (Float { width: a }, Float { width: b }) => Float {
                width: a.max(b),
            },
            // Same-width int + float observation prefers float (SSE move of
            // a 4/8-byte slot that also saw integer Copy still prints as float).
            (Float { width: fw }, IntN { width: iw })
            | (IntN { width: iw }, Float { width: fw })
                if fw == iw =>
            {
                Float { width: fw }
            }
            _ => Any,
        }
    }

    /// Refine this type toward another observation without ever narrowing
    /// (monotone). Convenience wrapper over [`Self::join`] that keeps the
    /// call site readable when we intentionally want side-effect updates.
    pub fn refine(&mut self, other: Self) {
        let old = std::mem::replace(self, RustType::Bottom);
        *self = old.join(other);
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
            RustType::IntSigned { width } => match width {
                1 => "int8_t".into(),
                2 => "int16_t".into(),
                4 => "int32_t".into(),
                8 => "int64_t".into(),
                w => format!("int{}_t", w * 8),
            },
            RustType::Ptr { pointee_width } => match pointee_width {
                0 => "void*".into(),
                1 => "uint8_t*".into(),
                2 => "uint16_t*".into(),
                4 => "uint32_t*".into(),
                8 => "uint64_t*".into(),
                w => format!("uint{}_t*", w * 8),
            },
            RustType::Void => "void".into(),
            RustType::StructPtr { key } => format!("struct s_{:x}*", key),
            RustType::ArrayPtr { elem_width, count } => {
                let base = match elem_width {
                    1 => "uint8_t".to_string(),
                    2 => "uint16_t".to_string(),
                    4 => "uint32_t".to_string(),
                    8 => "uint64_t".to_string(),
                    w => format!("uint{}_t", w * 8),
                };
                if *count == 0 {
                    format!("{base}*")
                } else {
                    format!("{base}*/*[{count}]*/")
                }
            }
            RustType::Float { width } => match width {
                4 => "float".into(),
                8 => "double".into(),
                w => format!("float{}_t", w * 8),
            },
            RustType::Any => "void*".into(),
        }
    }

    /// Width in bytes for scalar types; 0 for aggregates / unknown / void.
    /// Used by prototype rendering when we want a bare `uintN_t` size hint.
    pub fn scalar_width(&self) -> u32 {
        match self {
            RustType::Bool => 1,
            RustType::IntN { width }
            | RustType::IntSigned { width }
            | RustType::Float { width } => *width,
            RustType::Ptr { .. } | RustType::StructPtr { .. } | RustType::ArrayPtr { .. } => 8,
            _ => 0,
        }
    }
}

/// Recovered per-`(space, offset)` types after propagation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TypeMap(pub BTreeMap<(AddrSpace, u64), RustType>);

impl TypeMap {
    pub fn get(&self, space: AddrSpace, offset: u64) -> RustType {
        self.0
            .get(&(space, offset))
            .cloned()
            .unwrap_or(RustType::Bottom)
    }
    pub fn set(&mut self, space: AddrSpace, offset: u64, t: RustType) {
        let e = self.0.entry((space, offset)).or_insert(RustType::Bottom);
        *e = e.clone().join(t);
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// One recovered struct: pointer-target seed with concrete field offsets
/// observed on `Load` / `Store` addresses that read `base + K`.
///
/// The `key` is a stable id issued during recovery; Stage-1 emit prints
/// `struct s_<key>` for typed pointers. Fields are keyed by byte offset
/// from the base; each field carries the widest access we saw.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructSeed {
    pub key: u32,
    /// Byte-offset → (widest width in bytes, refined field type).
    pub fields: BTreeMap<u64, StructField>,
    /// Human tag — usually `s_<key>`; can be renamed by the caller.
    pub tag: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructField {
    pub offset: u64,
    pub width: u32,
    pub ty: RustType,
}

impl StructSeed {
    /// Total observed size in bytes (last field offset + width). Zero for
    /// empty seeds.
    pub fn observed_size(&self) -> u64 {
        self.fields
            .iter()
            .last()
            .map(|(off, f)| off + f.width as u64)
            .unwrap_or(0)
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

/// Where a parameter's storage lives on entry — register or stack slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParamStorage {
    /// Passed in an integer register (see [`Parameter::register`]).
    Register(String),
    /// Passed on the caller-set-up stack slot at `offset` bytes above the
    /// return address (i.e. after the shadow space on Windows, or the
    /// spill area on SysV).
    Stack { offset: u64 },
}

/// One recovered parameter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Parameter {
    /// Zero-based param index in the calling convention order.
    pub index: usize,
    /// x86-64 register name (as `ghidrust_lift::X86Reg` label). Empty when
    /// the parameter is stack-passed.
    pub register: String,
    pub storage: ParamStorage,
    pub width: u32,
    pub name: String,
    pub ty: RustType,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
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

impl Default for RustType {
    fn default() -> Self {
        RustType::Bottom
    }
}

/// A recovered function signature — the object Stage-1 emit and GUI
/// `Commit Params / Return` write into `ProgramEdits`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionSignature {
    pub name: String,
    pub calling_convention: String,
    pub return_type: RustType,
    /// Prototype params in declaration order — includes stack slots when the
    /// entry block reads them. Each carries recovered type + register/stack
    /// storage so the caller can render Windows __fastcall or SysV.
    pub params: ParamList,
}

impl FunctionSignature {
    /// Render the signature as a C prototype string:
    /// `<ret> <name>(<param0>, <param1>, …)` (or `void` for no params).
    pub fn to_prototype(&self) -> String {
        let ret = self.return_type.c_style();
        let mut s = format!("{ret} {}(", self.name);
        if self.params.is_empty() {
            s.push_str("void");
        } else {
            for (i, p) in self.params.iter().enumerate() {
                if i > 0 {
                    s.push_str(", ");
                }
                s.push_str(&format!("{} {}", p.ty.c_style(), p.name));
            }
        }
        s.push(')');
        s
    }

    /// Same as [`Self::to_prototype`] but with the calling-convention keyword
    /// (`__fastcall` for Windows) inserted before the function name.
    pub fn to_prototype_with_cc(&self) -> String {
        let cc = match self.calling_convention.as_str() {
            "Windows" => "__fastcall ",
            _ => "",
        };
        let ret = self.return_type.c_style();
        let mut s = format!("{ret} {cc}{}(", self.name);
        if self.params.is_empty() {
            s.push_str("void");
        } else {
            for (i, p) in self.params.iter().enumerate() {
                if i > 0 {
                    s.push_str(", ");
                }
                s.push_str(&format!("{} {}", p.ty.c_style(), p.name));
            }
        }
        s.push(')');
        s
    }
}

/// Full recovery result for a function: types, stack locals, parameters,
/// structs, and the resulting prototype.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TypeRecovery {
    pub types: TypeMap,
    pub locals: LocalMap,
    pub params: ParamList,
    /// Recovered struct seeds keyed by their stable id.
    pub structs: BTreeMap<u32, StructSeed>,
    /// Whole-function prototype (built from `params` + return-type recovery
    /// after seeding). The `name` field is empty until [`recover_with_name`]
    /// is called.
    pub signature: FunctionSignature,
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
        | OpCode::IntLessEqual => {
            if let Some(out) = op.output {
                map.set(out.space, out.offset, RustType::Bool);
            }
        }
        OpCode::IntSLess | OpCode::IntSLessEqual => {
            // Signed comparison output is bool. We intentionally do NOT
            // propagate a signed hint back to the inputs — flag setup
            // (`sf = IntSLess(dst, 0)`) fires on every arithmetic op and
            // would otherwise blanket-tag registers as signed.
            if let Some(out) = op.output {
                map.set(out.space, out.offset, RustType::Bool);
            }
        }
        OpCode::IntSDiv | OpCode::IntSRem | OpCode::IntSRight => {
            // Genuine signed arithmetic — outputs are strictly signed.
            if let Some(out) = op.output {
                map.set(out.space, out.offset, RustType::signed(out.size));
            }
        }
        OpCode::Load => {
            if let Some(out) = op.output {
                map.set(out.space, out.offset, RustType::int(out.size));
            }
            if let Some(addr) = op.inputs.first().and_then(SsaOperand::as_value) {
                map.set(
                    addr.space,
                    addr.offset,
                    RustType::ptr(op.output.map(|o| o.size).unwrap_or(0)),
                );
            }
        }
        OpCode::Store => {
            if let Some(addr) = op.inputs.first().and_then(SsaOperand::as_value) {
                let pointee = op
                    .inputs
                    .get(1)
                    .and_then(SsaOperand::as_value)
                    .map(|v| v.size)
                    .unwrap_or(0);
                map.set(addr.space, addr.offset, RustType::ptr(pointee));
            }
        }
        OpCode::IntAdd
        | OpCode::IntSub
        | OpCode::IntXor
        | OpCode::IntAnd
        | OpCode::IntOr
        | OpCode::IntMult
        | OpCode::IntDiv
        | OpCode::IntRem
        | OpCode::IntLeft
        | OpCode::IntRight
        | OpCode::IntNegate
        | OpCode::IntNot
        | OpCode::IntZExt
        | OpCode::Copy
        | OpCode::Cast
        | OpCode::Piece
        | OpCode::Subpiece => {
            if let Some(out) = op.output {
                let t = if flags.contains(&out.offset) && out.space == AddrSpace::Register {
                    RustType::Bool
                } else {
                    RustType::int(out.size)
                };
                map.set(out.space, out.offset, t);
            }
        }
        OpCode::Ptradd => {
            if let Some(out) = op.output {
                // `base + index * elem_size` — output is address-shaped.
                map.set(out.space, out.offset, RustType::ptr(0));
            }
            if let Some(base) = op.inputs.first().and_then(SsaOperand::as_value) {
                map.set(base.space, base.offset, RustType::ptr(0));
            }
        }
        _ => {}
    }
    // R4: SSE/x87 mnemonic notes → float/double (evidence-gated).
    if let Some(note) = op.note.as_deref() {
        let n = note.to_ascii_lowercase();
        let is_ss = n.contains("movss")
            || n.contains("addss")
            || n.contains("mulss")
            || n.contains("subss")
            || n.contains("divss");
        let is_sd = n.contains("movsd")
            || n.contains("addsd")
            || n.contains("mulsd")
            || n.contains("subsd")
            || n.contains("divsd");
        if (is_ss || is_sd) && op.output.is_some() {
            let out = op.output.unwrap();
            let w = if is_sd { 8 } else { 4 };
            map.set(out.space, out.offset, RustType::Float { width: w });
        }
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

/// Detect struct/array seeds by scanning `Load` / `Store` addresses that
/// look like `base + K` for multiple constant `K` values on the same SSA
/// base value. Each recovered pattern is either promoted to a
/// [`StructSeed`] (distinct offsets) or an array shape (equal-stride
/// accesses).
///
/// Populates [`TypeRecovery::structs`] and refines [`TypeMap`] entries for
/// the pointer register to [`RustType::StructPtr`] or
/// [`RustType::ArrayPtr`] as appropriate. Conservative — a single field is
/// allowed only when the base is already typed as [`RustType::Ptr`] (R4);
/// otherwise two distinct offsets remain the minimum.
pub fn recover_structs(func: &SsaFunction, types: &mut TypeMap) -> BTreeMap<u32, StructSeed> {
    use ghidrust_ssa::SsaValue;
    let mut per_base: BTreeMap<SsaValue, BTreeMap<u64, u32>> = BTreeMap::new();
    for b in &func.blocks {
        for op in &b.ops {
            let (addr_operand, access_size) = match op.opcode {
                OpCode::Load => (op.inputs.first(), op.output.map(|v| v.size).unwrap_or(0)),
                OpCode::Store => (
                    op.inputs.first(),
                    op.inputs
                        .get(1)
                        .and_then(SsaOperand::as_value)
                        .map(|v| v.size)
                        .unwrap_or(0),
                ),
                _ => continue,
            };
            let Some(addr) = addr_operand else { continue };
            let (base, offset) = decompose_addr(addr, func);
            let Some(base) = base else { continue };
            if base.space == AddrSpace::Constant {
                continue;
            }
            let entry = per_base.entry(base).or_default();
            let field = entry.entry(offset).or_insert(0);
            *field = (*field).max(access_size.max(1));
        }
    }
    let mut structs: BTreeMap<u32, StructSeed> = BTreeMap::new();
    let mut next_key: u32 = 1;
    for (base, fields) in per_base {
        let base_is_ptr = matches!(
            types.get(base.space, base.offset),
            RustType::Ptr { .. } | RustType::StructPtr { .. }
        );
        if fields.len() < 2 && !(fields.len() == 1 && base_is_ptr) {
            continue;
        }
        // Array vs struct heuristic: if every field width is equal and the
        // offsets form an arithmetic progression, promote to array.
        let widths: BTreeSet<u32> = fields.values().copied().collect();
        let offs: Vec<u64> = fields.keys().copied().collect();
        let elem_w = *widths.iter().next().unwrap_or(&0);
        let is_array = widths.len() == 1
            && elem_w > 0
            && offs.windows(2).all(|w| w[1] - w[0] == elem_w as u64);
        if is_array {
            types.set(
                base.space,
                base.offset,
                RustType::array_ptr(elem_w, offs.len() as u32),
            );
            continue;
        }
        let key = next_key;
        next_key += 1;
        let mut seed = StructSeed {
            key,
            fields: BTreeMap::new(),
            tag: format!("s_{key:x}"),
        };
        for (off, w) in fields {
            seed.fields.insert(
                off,
                StructField {
                    offset: off,
                    width: w,
                    ty: RustType::int(w),
                },
            );
        }
        types.set(base.space, base.offset, RustType::struct_ptr(key));
        structs.insert(key, seed);
    }
    structs
}

/// Try to decompose an address operand into `(base_value, constant_offset)`
/// by walking one hop through preceding `IntAdd`/`Ptradd` chains recorded
/// as the operand's def. Falls back to `(operand_as_value, 0)` for the
/// direct-load case (`*base`).
fn decompose_addr(
    addr: &SsaOperand,
    func: &SsaFunction,
) -> (Option<ghidrust_ssa::SsaValue>, u64) {
    let SsaOperand::Value(v) = addr else {
        return (None, 0);
    };
    // Search all blocks for the defining op — small n; SSA lookup by output
    // value is cheap for the fixture corpus. A future refinement can cache
    // this map per function.
    for b in &func.blocks {
        for op in &b.ops {
            let Some(out) = op.output else { continue };
            if out == *v && matches!(op.opcode, OpCode::IntAdd | OpCode::Ptradd) {
                let a = op.inputs.first();
                let c = op.inputs.get(1);
                let base = a.and_then(|o| o.as_value());
                let offset = c.and_then(SsaOperand::as_const).unwrap_or(0);
                if base.is_some() {
                    return (base, offset);
                }
            }
        }
    }
    (Some(*v), 0)
}

/// Recover the function's return type by looking at the value written to
/// RAX at return blocks. When no value is written or when RAX only carries
/// the phi of an entry-live value (i.e. we return whatever the caller had),
/// the type is [`RustType::Void`].
pub fn recover_return_type(func: &SsaFunction, types: &TypeMap) -> RustType {
    if func.blocks.is_empty() {
        return RustType::Void;
    }
    let mut best = RustType::Bottom;
    let mut wrote_rax = false;
    for b in &func.blocks {
        let Some(last) = b.ops.last() else { continue };
        if last.opcode != OpCode::Return {
            continue;
        }
        // Look for the most recent definition of RAX (offset 0) in this
        // block that isn't a live-in phi passthrough.
        for op in b.ops.iter().rev() {
            let Some(out) = op.output else { continue };
            if out.space == AddrSpace::Register && out.offset == 0 {
                wrote_rax = true;
                let t = types.get(AddrSpace::Register, 0);
                let t = if t == RustType::Bottom {
                    RustType::int(out.size)
                } else {
                    t
                };
                best = best.clone().join(t);
                break;
            }
        }
    }
    if !wrote_rax {
        return RustType::Void;
    }
    if best == RustType::Bottom {
        RustType::int(8)
    } else {
        best
    }
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
        let width_opt = live_in
            .iter()
            .find(|(off, _)| *off == reg_off)
            .map(|(_, w)| *w);
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
                storage: ParamStorage::Register(reg_name.to_string()),
                width,
                name: format!("param_{}", index + 1),
                ty,
            });
        }
    }

    // Detect stack-passed parameters as positive-offset reads of the
    // caller-set-up stack (offsets above the return-address slot). Ghidrust
    // stack-space offsets are relative to the frame base, so positive
    // offsets correspond to caller arguments. We stop at the first gap so
    // spilled locals aren't confused for parameters.
    let base = params.len();
    let mut stack_live_ins: BTreeMap<u64, u32> = BTreeMap::new();
    let mut defined_stack: BTreeSet<u64> = BTreeSet::new();
    for op in &entry_block.ops {
        for inp in &op.inputs {
            if let Some(v) = inp.as_value() {
                if v.space == AddrSpace::Stack
                    && v.version == 0
                    && !defined_stack.contains(&v.offset)
                    && (v.offset as i64) > 0
                {
                    stack_live_ins.entry(v.offset).or_insert(v.size);
                }
            }
        }
        if let Some(out) = op.output {
            if out.space == AddrSpace::Stack {
                defined_stack.insert(out.offset);
            }
        }
    }
    for (idx, (off, width)) in stack_live_ins.into_iter().enumerate() {
        let ty = types.get(AddrSpace::Stack, off);
        let ty = if ty == RustType::Bottom {
            RustType::int(width)
        } else {
            ty
        };
        let index = base + idx;
        params.push(Parameter {
            index,
            register: String::new(),
            storage: ParamStorage::Stack { offset: off },
            width,
            name: format!("param_{}", index + 1),
            ty,
        });
    }
    ParamList(params)
}

/// One-shot: run type inference + local + param recovery on `func`.
pub fn recover(func: &SsaFunction, conv: CallConv) -> TypeRecovery {
    recover_with_name(func, conv, "")
}

/// Same as [`recover`] but seeds the resulting [`FunctionSignature`] with
/// the caller's function name so the whole result set can be handed
/// straight to a GUI `Commit Params/Return` action or serialized into
/// `ProgramEdits`.
pub fn recover_with_name(func: &SsaFunction, conv: CallConv, name: &str) -> TypeRecovery {
    let mut types = infer_types(func);
    let structs = recover_structs(func, &mut types);
    let locals = recover_locals(func, &types);
    // Refine local types using the newly-known struct/array pointer keys.
    let params = recover_params(func, &types, conv);
    let return_type = recover_return_type(func, &types);
    let cc_name = match conv {
        CallConv::SystemV => "SystemV",
        CallConv::Windows => "Windows",
    };
    let signature = FunctionSignature {
        name: name.to_string(),
        calling_convention: cc_name.to_string(),
        return_type,
        params: params.clone(),
    };
    TypeRecovery {
        types,
        locals,
        params,
        structs,
        signature,
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
        assert_eq!(a.clone().join(b), RustType::int(8));
        assert_eq!(RustType::Bool.join(RustType::int(1)), RustType::Any);
        assert_eq!(RustType::Bottom.join(a.clone()), a);
    }

    #[test]
    fn c_style_float_and_double() {
        assert_eq!(RustType::Float { width: 4 }.c_style(), "float");
        assert_eq!(RustType::Float { width: 8 }.c_style(), "double");
    }

    #[test]
    fn c_style_emits_named_types() {
        assert_eq!(RustType::int(4).c_style(), "uint32_t");
        assert_eq!(RustType::Bool.c_style(), "bool");
        assert_eq!(RustType::ptr(4).c_style(), "uint32_t*");
        assert_eq!(RustType::signed(4).c_style(), "int32_t");
        assert_eq!(RustType::Void.c_style(), "void");
        assert_eq!(
            RustType::struct_ptr(3).c_style(),
            "struct s_3*"
        );
        assert_eq!(
            RustType::array_ptr(4, 5).c_style(),
            "uint32_t*/*[5]*/"
        );
    }

    #[test]
    fn signed_join_wins_against_same_width_unsigned() {
        let s = RustType::signed(4);
        let u = RustType::int(4);
        assert!(matches!(s.clone().join(u), RustType::IntSigned { width: 4 }));
    }

    #[test]
    fn struct_ptr_and_raw_ptr_join_prefers_struct() {
        let s = RustType::struct_ptr(1);
        let p = RustType::ptr(0);
        assert!(matches!(s.clone().join(p), RustType::StructPtr { key: 1 }));
    }

    #[test]
    fn return_type_void_when_rax_not_written() {
        // Only reads rdi and returns → rax never written, so return type is
        // void.
        // 48 89 c1  mov rcx, rax  (rax read; rcx write)
        // c3       ret
        let bytes = [0x48, 0x89, 0xc1, 0xc3];
        let rec = recover_bytes(&bytes, 0x9000, CallConv::SystemV);
        assert_eq!(rec.signature.return_type, RustType::Void, "rax not written");
    }

    #[test]
    fn return_type_int_when_rax_written() {
        // mov rax, rdi ; ret
        let bytes = [0x48, 0x89, 0xf8, 0xc3];
        let rec = recover_bytes(&bytes, 0xa000, CallConv::SystemV);
        assert!(
            matches!(rec.signature.return_type, RustType::IntN { .. } | RustType::Ptr { .. }),
            "expected typed return, got {:?}",
            rec.signature.return_type
        );
    }

    #[test]
    fn prototype_string_renders_calling_convention() {
        let bytes = [0x48, 0x89, 0xf8, 0xc3];
        let mut rec = recover_bytes(&bytes, 0xb000, CallConv::Windows);
        rec.signature.name = "myfn".into();
        let proto = rec.signature.to_prototype_with_cc();
        assert!(proto.contains("__fastcall myfn"), "proto: {proto}");
        assert!(proto.starts_with(&rec.signature.return_type.c_style()));
    }

    #[test]
    fn struct_seed_recovered_from_two_field_load_pattern() {
        // Two Load ops from base+0 (uint32_t) and base+8 (uint64_t) →
        // mixed-width fields prevent the array heuristic from firing so
        // the pointer promotes to a struct seed.
        use ghidrust_ir::{IrSequence, PcodeOp, Varnode};
        let mut seq = IrSequence::new();
        // t0 = rdi (base pointer)
        let t_base = Varnode::unique(1, 8);
        // t1 = t0 + 0
        let t1 = Varnode::unique(2, 8);
        // load4(t1) → t2
        let t2 = Varnode::unique(3, 4);
        // t3 = t0 + 8
        let t3 = Varnode::unique(4, 8);
        // load8(t3) → t4
        let t4 = Varnode::unique(5, 8);
        seq.push_addressed(
            0x0,
            1,
            PcodeOp::new(
                OpCode::Copy,
                Some(t_base.clone()),
                vec![Varnode::register(7, 8)],
            ),
        );
        seq.push_addressed(
            0x1,
            1,
            PcodeOp::new(
                OpCode::IntAdd,
                Some(t1.clone()),
                vec![t_base.clone(), Varnode::constant(0, 8)],
            ),
        );
        seq.push_addressed(
            0x2,
            1,
            PcodeOp::new(OpCode::Load, Some(t2), vec![t1]),
        );
        seq.push_addressed(
            0x3,
            1,
            PcodeOp::new(
                OpCode::IntAdd,
                Some(t3.clone()),
                vec![t_base.clone(), Varnode::constant(8, 8)],
            ),
        );
        seq.push_addressed(
            0x4,
            1,
            PcodeOp::new(OpCode::Load, Some(t4), vec![t3]),
        );
        seq.push_addressed(0x5, 1, PcodeOp::new(OpCode::Return, None, vec![]));
        let cfg = build_cfg(&seq, 0x0, 0x6);
        let ssa = build_ssa(&cfg);
        let rec = recover(&ssa, CallConv::SystemV);
        assert!(
            !rec.structs.is_empty(),
            "expected recovered struct seed, got {} structs",
            rec.structs.len()
        );
        let s = rec.structs.values().next().unwrap();
        assert!(s.fields.contains_key(&0), "field @ 0 missing: {:?}", s.fields);
        assert!(s.fields.contains_key(&8), "field @ 8 missing: {:?}", s.fields);
    }

    #[test]
    fn array_seed_recovered_from_equal_stride_pattern() {
        // Three loads at base+0, base+4, base+8 (all width 4) → array of
        // uint32_t*.
        use ghidrust_ir::{IrSequence, PcodeOp, Varnode};
        let mut seq = IrSequence::new();
        let t_base = Varnode::unique(0, 8);
        seq.push_addressed(
            0x0,
            1,
            PcodeOp::new(
                OpCode::Copy,
                Some(t_base.clone()),
                vec![Varnode::register(7, 8)],
            ),
        );
        for (i, off) in [(1u64, 0u64), (2, 4), (3, 8)] {
            let addr = Varnode::unique(100 + i, 8);
            seq.push_addressed(
                0x0 + i,
                1,
                PcodeOp::new(
                    OpCode::IntAdd,
                    Some(addr.clone()),
                    vec![t_base.clone(), Varnode::constant(off, 8)],
                ),
            );
            let out = Varnode::unique(200 + i, 4);
            seq.push_addressed(
                0x10 + i,
                1,
                PcodeOp::new(OpCode::Load, Some(out), vec![addr]),
            );
        }
        seq.push_addressed(0x100, 1, PcodeOp::new(OpCode::Return, None, vec![]));
        let cfg = build_cfg(&seq, 0x0, 0x101);
        let ssa = build_ssa(&cfg);
        let rec = recover(&ssa, CallConv::SystemV);
        // No struct seeded — should be array. Look for ArrayPtr in the
        // type map on the base register.
        let arr_present = rec.types.0.values().any(|t| {
            matches!(t, RustType::ArrayPtr { elem_width: 4, count } if *count >= 3)
        });
        assert!(
            arr_present,
            "expected ArrayPtr in type map: {:?}",
            rec.types.0
        );
    }
}
