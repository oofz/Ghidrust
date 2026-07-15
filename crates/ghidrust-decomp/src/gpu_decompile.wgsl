// Multi-pass GPU decompile kernels — all buffers stay in VRAM until final emit readback.
// Stages: decode_walk → mark_leaders → build_blocks → emit_text

struct Params {
    ncode: u32,
    max_ir: u32,
    max_blocks: u32,
    max_emit: u32,
    entry_lo: u32,
    entry_hi: u32,
    _p0: u32,
    _p1: u32,
}

struct IrSlot {
    valid: u32,
    off: u32,
    length: u32,
    opcode: u32,
    imm: u32,
    has_imm: u32,
    _pad0: u32,
    _pad1: u32,
}

@group(0) @binding(0) var<storage, read> code: array<u32>; // packed bytes as u32 words
@group(0) @binding(1) var<storage, read_write> ir: array<IrSlot>;
@group(0) @binding(2) var<storage, read_write> leaders: array<u32>;
@group(0) @binding(3) var<storage, read_write> blocks: array<u32>; // 8 u32 per block
@group(0) @binding(4) var<storage, read_write> edges: array<u32>;  // 4 u32 per edge
@group(0) @binding(5) var<storage, read_write> stage_meta: array<u32>;   // ir_count,block_count,edge_count,emit_len
@group(0) @binding(6) var<storage, read_write> emit: array<u32>;   // packed ASCII
@group(0) @binding(7) var<uniform> params: Params;

const OP_PUSH: u32 = 1u;
const OP_MOV: u32 = 2u;
const OP_XOR: u32 = 3u;
const OP_POP: u32 = 4u;
const OP_RET: u32 = 5u;
const OP_INT3: u32 = 6u;
const OP_JMP: u32 = 7u;
const OP_JCC: u32 = 8u;
const OP_OTHER: u32 = 9u;

fn load_byte(off: u32) -> u32 {
    let word = code[off / 4u];
    let shift = (off % 4u) * 8u;
    return (word >> shift) & 0xffu;
}

fn store_byte(off: u32, b: u32) {
    // emit is u32 packed; atomic-less RMW for single-thread emit_text
    let idx = off / 4u;
    let shift = (off % 4u) * 8u;
    let mask = 0xffu << shift;
    let cur = emit[idx];
    emit[idx] = (cur & ~mask) | ((b & 0xffu) << shift);
}

fn i8_as_i32(b: u32) -> i32 {
    var v = i32(b);
    if ((b & 0x80u) != 0u) {
        v = v - 256;
    }
    return v;
}

// ── K1: sequential walk decode into IR slots (single workgroup) ──────────
@compute @workgroup_size(1)
fn decode_walk(@builtin(global_invocation_id) gid: vec3<u32>) {
    if (gid.x != 0u) { return; }
    var off: u32 = 0u;
    var n: u32 = 0u;
    loop {
        if (off >= params.ncode || n >= params.max_ir) { break; }
        let b0 = load_byte(off);
        var len: u32 = 1u;
        var op: u32 = OP_OTHER;
        var imm: u32 = 0u;
        var has_imm: u32 = 0u;

        if (b0 == 0xc3u) {
            op = OP_RET; len = 1u;
        } else if (b0 == 0xccu) {
            op = OP_INT3; len = 1u;
        } else if (b0 >= 0x50u && b0 <= 0x57u) {
            op = OP_PUSH; len = 1u;
        } else if (b0 >= 0x58u && b0 <= 0x5fu) {
            op = OP_POP; len = 1u;
        } else if (b0 == 0x48u && off + 2u < params.ncode && load_byte(off + 1u) == 0x89u) {
            op = OP_MOV; len = 3u;
        } else if (b0 == 0x31u && off + 1u < params.ncode) {
            op = OP_XOR; len = 2u;
        } else if (b0 == 0xebu && off + 1u < params.ncode) {
            op = OP_JMP; len = 2u; has_imm = 1u;
            imm = u32(i8_as_i32(load_byte(off + 1u)));
        } else if (b0 == 0xe9u && off + 4u < params.ncode) {
            op = OP_JMP; len = 5u; has_imm = 1u;
            imm = load_byte(off + 1u)
                | (load_byte(off + 2u) << 8u)
                | (load_byte(off + 3u) << 16u)
                | (load_byte(off + 4u) << 24u);
        } else if (b0 >= 0x70u && b0 <= 0x7fu && off + 1u < params.ncode) {
            op = OP_JCC; len = 2u; has_imm = 1u;
            imm = u32(i8_as_i32(load_byte(off + 1u)));
        } else if (b0 == 0x0fu && off + 5u < params.ncode) {
            let b1 = load_byte(off + 1u);
            if (b1 >= 0x80u && b1 <= 0x8fu) {
                op = OP_JCC; len = 6u; has_imm = 1u;
                imm = load_byte(off + 2u)
                    | (load_byte(off + 3u) << 8u)
                    | (load_byte(off + 4u) << 16u)
                    | (load_byte(off + 5u) << 24u);
            }
        }

        ir[n] = IrSlot(1u, off, len, op, imm, has_imm, 0u, 0u);
        n = n + 1u;
        if (op == OP_RET) { break; }
        off = off + len;
    }
    stage_meta[0] = n; // ir_count
}

// ── K2: mark leaders (parallel over IR slots) ────────────────────────────
// Race-free: buffer is zero-initialized; threads ONLY write 1 (never 0).
// Writing 0 would clobber another thread's branch-target mark.
@compute @workgroup_size(256)
fn mark_leaders(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x;
    let n = stage_meta[0];
    if (i >= n) { return; }

    // entry is always a leader
    if (i == 0u) {
        leaders[0] = 1u;
    }
    // fall-through after terminator is a leader
    if (i > 0u) {
        let prev = ir[i - 1u];
        if (prev.opcode == OP_RET || prev.opcode == OP_JMP || prev.opcode == OP_JCC) {
            leaders[i] = 1u;
        }
    }
    // branch targets are leaders (only write 1)
    if (ir[i].has_imm == 1u && (ir[i].opcode == OP_JMP || ir[i].opcode == OP_JCC)) {
        let target_off = i32(ir[i].off) + i32(ir[i].length) + i32(ir[i].imm);
        for (var j: u32 = 0u; j < n; j = j + 1u) {
            if (i32(ir[j].off) == target_off) {
                leaders[j] = 1u;
            }
        }
    }
}

// ── K3: compact leaders into block table + edges (single thread) ──────────
@compute @workgroup_size(1)
fn build_blocks(@builtin(global_invocation_id) gid: vec3<u32>) {
    if (gid.x != 0u) { return; }
    let n = stage_meta[0];
    var bc: u32 = 0u;
    var ec: u32 = 0u;
    var starts: array<u32, 64>;
    var ns: u32 = 0u;
    for (var i: u32 = 0u; i < n; i = i + 1u) {
        if (leaders[i] == 1u && ns < 64u) {
            starts[ns] = i;
            ns = ns + 1u;
        }
    }
    if (ns == 0u && n > 0u) {
        starts[0] = 0u;
        ns = 1u;
    }
    for (var b: u32 = 0u; b < ns && b < params.max_blocks; b = b + 1u) {
        let si = starts[b];
        var ei = n;
        if (b + 1u < ns) { ei = starts[b + 1u]; }
        let first = ir[si];
        let last = ir[ei - 1u];
        let base = b * 8u;
        blocks[base + 0u] = first.off;
        blocks[base + 1u] = last.off + last.length;
        blocks[base + 2u] = si;
        blocks[base + 3u] = ei - si;
        blocks[base + 4u] = select(0u, 1u, last.opcode == OP_RET);
        blocks[base + 5u] = select(0u, 1u, last.opcode == OP_JMP || last.opcode == OP_JCC);
        blocks[base + 6u] = 0u;
        blocks[base + 7u] = 0u;
        bc = bc + 1u;

        // edges
        if (last.opcode != OP_RET && ec < params.max_blocks * 2u) {
            if (last.opcode == OP_JMP && last.has_imm == 1u) {
                let target_off = i32(last.off) + i32(last.length) + i32(last.imm);
                for (var t: u32 = 0u; t < ns; t = t + 1u) {
                    if (i32(ir[starts[t]].off) == target_off && ec < 128u) {
                        let ebase = ec * 4u;
                        edges[ebase + 0u] = b;
                        edges[ebase + 1u] = t;
                        edges[ebase + 2u] = 1u; // jmp
                        edges[ebase + 3u] = 0u;
                        ec = ec + 1u;
                    }
                }
            } else if (last.opcode == OP_JCC && last.has_imm == 1u) {
                let target_off = i32(last.off) + i32(last.length) + i32(last.imm);
                for (var t: u32 = 0u; t < ns; t = t + 1u) {
                    if (i32(ir[starts[t]].off) == target_off && ec < 128u) {
                        let ebase = ec * 4u;
                        edges[ebase + 0u] = b;
                        edges[ebase + 1u] = t;
                        edges[ebase + 2u] = 2u; // jcc_taken
                        edges[ebase + 3u] = 0u;
                        ec = ec + 1u;
                    }
                }
                if (b + 1u < ns && ec < 128u) {
                    let ebase = ec * 4u;
                    edges[ebase + 0u] = b;
                    edges[ebase + 1u] = b + 1u;
                    edges[ebase + 2u] = 3u; // fall
                    edges[ebase + 3u] = 0u;
                    ec = ec + 1u;
                }
            } else if (b + 1u < ns && ec < 128u) {
                let ebase = ec * 4u;
                edges[ebase + 0u] = b;
                edges[ebase + 1u] = b + 1u;
                edges[ebase + 2u] = 3u;
                edges[ebase + 3u] = 0u;
                ec = ec + 1u;
            }
        }
    }
    stage_meta[1] = bc;
    stage_meta[2] = ec;
}

fn append_char(pos: ptr<function, u32>, ch: u32) {
    if (*pos < params.max_emit) {
        store_byte(*pos, ch);
        *pos = *pos + 1u;
    }
}

fn append_str(pos: ptr<function, u32>, s: ptr<function, array<u32, 64>>, n: u32) {
    for (var i: u32 = 0u; i < n; i = i + 1u) {
        append_char(pos, (*s)[i]);
    }
}

fn append_lit(pos: ptr<function, u32>, lit: u32) {
    // pack up to 4 ASCII in a u32 little-endian
    append_char(pos, lit & 0xffu);
    let b1 = (lit >> 8u) & 0xffu;
    if (b1 != 0u) { append_char(pos, b1); }
    let b2 = (lit >> 16u) & 0xffu;
    if (b2 != 0u) { append_char(pos, b2); }
    let b3 = (lit >> 24u) & 0xffu;
    if (b3 != 0u) { append_char(pos, b3); }
}

// ── K4: emit pseudo-C into device text buffer (single thread) ────────────
@compute @workgroup_size(1)
fn emit_text(@builtin(global_invocation_id) gid: vec3<u32>) {
    if (gid.x != 0u) { return; }
    var pos: u32 = 0u;
    let bc = stage_meta[1];
    let n = stage_meta[0];

    // header lines (ASCII)
    // "// GPU decompile\nvoid FUN(void) {\n"
    let h1 = array<u32, 32>(
        0x2f,0x2f,0x20,0x47,0x50,0x55,0x20,0x64,0x65,0x63,0x6f,0x6d,0x70,0x69,0x6c,0x65,
        0x0a,0x76,0x6f,0x69,0x64,0x20,0x46,0x55,0x4e,0x28,0x76,0x6f,0x69,0x64,0x29,0x20
    );
    for (var i: u32 = 0u; i < 32u; i = i + 1u) { append_char(&pos, h1[i]); }
    append_char(&pos, 0x7bu); // {
    append_char(&pos, 0x0au);

    for (var b: u32 = 0u; b < bc; b = b + 1u) {
        let base = b * 8u;
        let si = blocks[base + 2u];
        let cnt = blocks[base + 3u];
        // "  // block_N\n  block_N:\n"
        append_char(&pos, 0x20u); append_char(&pos, 0x20u);
        append_char(&pos, 0x2fu); append_char(&pos, 0x2fu); append_char(&pos, 0x20u);
        // block_
        append_char(&pos, 0x62u); append_char(&pos, 0x6cu); append_char(&pos, 0x6fu);
        append_char(&pos, 0x63u); append_char(&pos, 0x6bu); append_char(&pos, 0x5fu);
        append_char(&pos, 0x30u + (b % 10u));
        append_char(&pos, 0x0au);
        append_char(&pos, 0x20u); append_char(&pos, 0x20u);
        append_char(&pos, 0x62u); append_char(&pos, 0x6cu); append_char(&pos, 0x6fu);
        append_char(&pos, 0x63u); append_char(&pos, 0x6bu); append_char(&pos, 0x5fu);
        append_char(&pos, 0x30u + (b % 10u));
        append_char(&pos, 0x3au); append_char(&pos, 0x0au);

        for (var k: u32 = 0u; k < cnt; k = k + 1u) {
            let slot = ir[si + k];
            append_char(&pos, 0x20u); append_char(&pos, 0x20u);
            append_char(&pos, 0x20u); append_char(&pos, 0x20u);
            if (slot.opcode == OP_RET) {
                // return;
                append_char(&pos, 0x72u); append_char(&pos, 0x65u); append_char(&pos, 0x74u);
                append_char(&pos, 0x75u); append_char(&pos, 0x72u); append_char(&pos, 0x6eu);
                append_char(&pos, 0x3bu); append_char(&pos, 0x0au);
            } else if (slot.opcode == OP_JCC) {
                // if (/* jcc */) { goto block_T; }  // fall → block_F
                var taken: u32 = 0xffffffffu;
                var fall: u32 = 0xffffffffu;
                let ec = stage_meta[2];
                for (var e: u32 = 0u; e < ec; e = e + 1u) {
                    let ebase = e * 4u;
                    if (edges[ebase + 0u] == b) {
                        if (edges[ebase + 2u] == 2u) { taken = edges[ebase + 1u]; }
                        if (edges[ebase + 2u] == 3u) { fall = edges[ebase + 1u]; }
                    }
                }
                append_char(&pos, 0x69u); append_char(&pos, 0x66u); append_char(&pos, 0x20u);
                append_char(&pos, 0x28u); append_char(&pos, 0x2fu); append_char(&pos, 0x2au);
                append_char(&pos, 0x20u); append_char(&pos, 0x6au); append_char(&pos, 0x63u);
                append_char(&pos, 0x63u); append_char(&pos, 0x20u); append_char(&pos, 0x2au);
                append_char(&pos, 0x2fu); append_char(&pos, 0x29u); append_char(&pos, 0x20u);
                append_char(&pos, 0x7bu); append_char(&pos, 0x0au);
                // "      goto block_T;\n"
                append_char(&pos, 0x20u); append_char(&pos, 0x20u);
                append_char(&pos, 0x20u); append_char(&pos, 0x20u);
                append_char(&pos, 0x20u); append_char(&pos, 0x20u);
                append_char(&pos, 0x67u); append_char(&pos, 0x6fu); append_char(&pos, 0x74u);
                append_char(&pos, 0x6fu); append_char(&pos, 0x20u);
                append_char(&pos, 0x62u); append_char(&pos, 0x6cu); append_char(&pos, 0x6fu);
                append_char(&pos, 0x63u); append_char(&pos, 0x6bu); append_char(&pos, 0x5fu);
                if (taken != 0xffffffffu) {
                    append_char(&pos, 0x30u + (taken % 10u));
                } else {
                    append_char(&pos, 0x3fu);
                }
                append_char(&pos, 0x3bu); append_char(&pos, 0x0au);
                // "}\n"
                append_char(&pos, 0x20u); append_char(&pos, 0x20u);
                append_char(&pos, 0x20u); append_char(&pos, 0x20u);
                append_char(&pos, 0x7du); append_char(&pos, 0x0au);
                // "// fall block_F\n" (matches CPU multipass emit)
                if (fall != 0xffffffffu) {
                    append_char(&pos, 0x20u); append_char(&pos, 0x20u);
                    append_char(&pos, 0x20u); append_char(&pos, 0x20u);
                    append_char(&pos, 0x2fu); append_char(&pos, 0x2fu); append_char(&pos, 0x20u);
                    append_char(&pos, 0x66u); append_char(&pos, 0x61u); append_char(&pos, 0x6cu);
                    append_char(&pos, 0x6cu); append_char(&pos, 0x20u);
                    append_char(&pos, 0x62u); append_char(&pos, 0x6cu); append_char(&pos, 0x6fu);
                    append_char(&pos, 0x63u); append_char(&pos, 0x6bu); append_char(&pos, 0x5fu);
                    append_char(&pos, 0x30u + (fall % 10u));
                    append_char(&pos, 0x0au);
                }
            } else if (slot.opcode == OP_JMP) {
                var taken: u32 = 0xffffffffu;
                let ec = stage_meta[2];
                for (var e: u32 = 0u; e < ec; e = e + 1u) {
                    let ebase = e * 4u;
                    if (edges[ebase + 0u] == b && edges[ebase + 2u] == 1u) {
                        taken = edges[ebase + 1u];
                    }
                }
                append_char(&pos, 0x67u); append_char(&pos, 0x6fu); append_char(&pos, 0x74u);
                append_char(&pos, 0x6fu); append_char(&pos, 0x20u);
                append_char(&pos, 0x62u); append_char(&pos, 0x6cu); append_char(&pos, 0x6fu);
                append_char(&pos, 0x63u); append_char(&pos, 0x6bu); append_char(&pos, 0x5fu);
                if (taken != 0xffffffffu) {
                    append_char(&pos, 0x30u + (taken % 10u));
                } else {
                    append_char(&pos, 0x3fu);
                }
                append_char(&pos, 0x3bu); append_char(&pos, 0x0au);
            } else {
                // /* op */;
                append_char(&pos, 0x2fu); append_char(&pos, 0x2au); append_char(&pos, 0x20u);
                if (slot.opcode == OP_PUSH) {
                    append_char(&pos, 0x70u); append_char(&pos, 0x75u); append_char(&pos, 0x73u);
                    append_char(&pos, 0x68u);
                } else if (slot.opcode == OP_MOV) {
                    append_char(&pos, 0x6du); append_char(&pos, 0x6fu); append_char(&pos, 0x76u);
                } else if (slot.opcode == OP_XOR) {
                    append_char(&pos, 0x78u); append_char(&pos, 0x6fu); append_char(&pos, 0x72u);
                } else if (slot.opcode == OP_POP) {
                    append_char(&pos, 0x70u); append_char(&pos, 0x6fu); append_char(&pos, 0x70u);
                } else {
                    append_char(&pos, 0x6fu); append_char(&pos, 0x70u);
                }
                append_char(&pos, 0x20u); append_char(&pos, 0x2au); append_char(&pos, 0x2fu);
                append_char(&pos, 0x3bu); append_char(&pos, 0x0au);
            }
        }
        append_char(&pos, 0x0au);
    }
    append_char(&pos, 0x7du); // }
    append_char(&pos, 0x0au);
    stage_meta[3] = pos; // emit_len
}

