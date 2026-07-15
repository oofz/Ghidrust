// SIMT analyzer kernels — one work item per byte offset, atomic hit append.
// Distinct algorithms per strategy (not a single printable kernel rebranded).

struct Params {
    n: u32,
    mode: u32,
    needle0: u32,
    needle1: u32,
    needle2: u32,
    needle3: u32,
    needle_len: u32,
    max_hits: u32,
    image_base_lo: u32,
    image_base_hi: u32,
    image_end_lo: u32,
    image_end_hi: u32,
    /// Invocation base for multi-dispatch when n > 65535*workgroup (large PEs).
    base_inv: u32,
    _p1: u32,
    _p2: u32,
    _p3: u32,
}

@group(0) @binding(0) var<storage, read> hay: array<u32>;
@group(0) @binding(1) var<storage, read_write> hits: array<u32>;
@group(0) @binding(2) var<storage, read_write> hit_count: array<atomic<u32>>;
@group(0) @binding(3) var<uniform> params: Params;
// optional: hash values parallel to hits for FID
@group(0) @binding(4) var<storage, read_write> hit_aux: array<u32>;

fn load_b(off: u32) -> u32 {
    let w = hay[off / 4u];
    let s = (off % 4u) * 8u;
    return (w >> s) & 0xffu;
}

fn is_print(b: u32) -> bool {
    return (b >= 0x20u && b <= 0x7eu) || (b == 0x09u);
}

fn push_hit(off: u32) {
    let i = atomicAdd(&hit_count[0], 1u);
    if (i < params.max_hits) {
        hits[i] = off;
    }
}

fn push_hit_aux(off: u32, aux: u32) {
    let i = atomicAdd(&hit_count[0], 1u);
    if (i < params.max_hits) {
        hits[i] = off;
        hit_aux[i] = aux;
    }
}

fn in_image(lo: u32, hi: u32) -> bool {
    let blo = params.image_base_lo;
    let bhi = params.image_base_hi;
    let elo = params.image_end_lo;
    let ehi = params.image_end_hi;
    if (hi > bhi || (hi == bhi && lo >= blo)) {
        if (hi < ehi || (hi == ehi && lo < elo)) {
            return true;
        }
    }
    return false;
}

// ── printable_run: run starts of length >= 4 (SIMT) ──────────────────────
@compute @workgroup_size(256)
fn k_printable(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x + params.base_inv;
    if (i >= params.n) { return; }
    if (!is_print(load_b(i))) { return; }
    if (i > 0u && is_print(load_b(i - 1u))) { return; } // only starts
    // measure run length
    var j = i;
    loop {
        if (j >= params.n || !is_print(load_b(j))) { break; }
        j = j + 1u;
    }
    if (j - i >= 4u) {
        push_hit(i);
    }
}

// ── magic_media: PNG/JPEG/GIF/RIFF (SIMT) ────────────────────────────────
@compute @workgroup_size(256)
fn k_magic_media(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x + params.base_inv;
    if (i >= params.n) { return; }
    let b0 = load_b(i);
    // PNG: 4 bytes
    if (i + 4u <= params.n && b0 == 0x89u && load_b(i+1u) == 0x50u
        && load_b(i+2u) == 0x4eu && load_b(i+3u) == 0x47u) {
        push_hit(i); return;
    }
    // JPEG SOI
    if (i + 3u <= params.n && b0 == 0xffu && load_b(i+1u) == 0xd8u && load_b(i+2u) == 0xffu) {
        push_hit(i); return;
    }
    // GIF
    if (i + 3u <= params.n && b0 == 0x47u && load_b(i+1u) == 0x49u && load_b(i+2u) == 0x46u) {
        push_hit(i); return;
    }
    // RIFF
    if (i + 4u <= params.n && b0 == 0x52u && load_b(i+1u) == 0x49u
        && load_b(i+2u) == 0x46u && load_b(i+3u) == 0x46u) {
        push_hit(i);
    }
}

// ── magic_res: VS_VERSION_INFO / RS ──────────────────────────────────────
@compute @workgroup_size(256)
fn k_magic_res(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x + params.base_inv;
    if (i + 2u < params.n && load_b(i) == 0x56u && load_b(i + 1u) == 0x00u && load_b(i + 2u) == 0x53u) {
        push_hit(i); return;
    }
    if (i + 1u < params.n && load_b(i) == 0x52u && load_b(i + 1u) == 0x53u) {
        push_hit(i);
    }
}

// ── prologue_seed: 55 48 89 e5 / 48 83 ec ────────────────────────────────
@compute @workgroup_size(256)
fn k_prologue(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x + params.base_inv;
    if (i + 3u < params.n && load_b(i) == 0x55u && load_b(i+1u) == 0x48u
        && load_b(i+2u) == 0x89u && load_b(i+3u) == 0xe5u) {
        push_hit(i); return;
    }
    if (i + 2u < params.n && load_b(i) == 0x48u && load_b(i+1u) == 0x83u && load_b(i+2u) == 0xecu) {
        // skip if mid-frame after 55 48 89 e5
        if (i >= 4u && load_b(i-4u) == 0x55u && load_b(i-3u) == 0x48u
            && load_b(i-2u) == 0x89u && load_b(i-1u) == 0xe5u) {
            return;
        }
        push_hit(i);
    }
}

// ── ptr_chain: table base if 3+ consecutive in-image u64 ─────────────────
@compute @workgroup_size(256)
fn k_ptr_u64(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = (gid.x + params.base_inv) * 8u; // 8-byte aligned candidates
    if (i + 24u > params.n) { return; }
    var run: u32 = 0u;
    var j = i;
    loop {
        if (j + 8u > params.n || run >= 64u) { break; }
        let lo = load_b(j) | (load_b(j+1u) << 8u) | (load_b(j+2u) << 16u) | (load_b(j+3u) << 24u);
        let hi = load_b(j+4u) | (load_b(j+5u) << 8u) | (load_b(j+6u) << 16u) | (load_b(j+7u) << 24u);
        if (in_image(lo, hi)) {
            run = run + 1u;
            j = j + 8u;
        } else {
            break;
        }
    }
    if (run >= 3u) {
        push_hit(i);
    }
}

// ── rtti_scan ────────────────────────────────────────────────────────────
@compute @workgroup_size(256)
fn k_rtti(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x + params.base_inv;
    if (i + 4u > params.n) { return; }
    if (load_b(i) == 0x2eu && load_b(i+1u) == 0x3fu && load_b(i+2u) == 0x41u
        && (load_b(i+3u) == 0x56u || load_b(i+3u) == 0x55u)) {
        push_hit(i); return;
    }
    if (load_b(i) == 0x5fu && load_b(i+1u) == 0x5au && load_b(i+2u) == 0x54u && load_b(i+3u) == 0x53u) {
        push_hit(i);
    }
}

// ── code_density: windows of non-cc density ──────────────────────────────
@compute @workgroup_size(256)
fn k_code_density(@builtin(global_invocation_id) gid: vec3<u32>) {
    let win = 16u;
    let i = (gid.x + params.base_inv) * win;
    if (i + win > params.n) { return; }
    var non: u32 = 0u;
    for (var k: u32 = 0u; k < win; k = k + 1u) {
        let b = load_b(i + k);
        if (b != 0xccu && b != 0u) { non = non + 1u; }
    }
    if (non >= 12u) { push_hit(i); }
}

// ── hash_window: FNV-1a over 8 bytes at prologue-like starts; aux=hash ───
@compute @workgroup_size(256)
fn k_hash_win(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x + params.base_inv;
    if (i + 8u > params.n) { return; }
    let b0 = load_b(i);
    if (!(b0 == 0x55u || (b0 == 0x48u && load_b(i + 1u) == 0x83u))) { return; }
    var h: u32 = 2166136261u;
    for (var k: u32 = 0u; k < 8u; k = k + 1u) {
        h = (h ^ load_b(i + k)) * 16777619u;
    }
    push_hit_aux(i, h);
}

// ── ret_epilogue ─────────────────────────────────────────────────────────
@compute @workgroup_size(256)
fn k_ret(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x + params.base_inv;
    if (i >= params.n) { return; }
    let b = load_b(i);
    if (b == 0xc3u || b == 0xc2u) { push_hit(i); }
}

// ── spill_scan ───────────────────────────────────────────────────────────
@compute @workgroup_size(256)
fn k_spill(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x + params.base_inv;
    if (i + 2u < params.n && load_b(i) == 0x48u && load_b(i+1u) == 0x89u) {
        let m = load_b(i+2u);
        if (m == 0x4cu || m == 0x54u || m == 0x44u || m == 0x4du || m == 0x45u) {
            push_hit(i);
        }
    }
    if (i + 1u < params.n && load_b(i) == 0x4cu && load_b(i+1u) == 0x89u) {
        push_hit(i);
    }
}

// ── stack_frame ──────────────────────────────────────────────────────────
@compute @workgroup_size(256)
fn k_stack(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x + params.base_inv;
    if (i + 2u < params.n && load_b(i) == 0x48u
        && (load_b(i+1u) == 0x83u || load_b(i+1u) == 0x81u) && load_b(i+2u) == 0xecu) {
        push_hit(i); return;
    }
    if (i + 2u < params.n && load_b(i) == 0x48u && load_b(i+1u) == 0x89u
        && (load_b(i+2u) == 0x45u || load_b(i+2u) == 0x4du)) {
        push_hit(i);
    }
}

// ── cstr multi-needle (one needle per dispatch) ──────────────────────────
@compute @workgroup_size(256)
fn k_cstr(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x + params.base_inv;
    let nlen = params.needle_len;
    if (nlen == 0u || nlen > 16u || i + nlen > params.n) { return; }
    var needle: array<u32, 16>;
    let p0 = params.needle0; let p1 = params.needle1; let p2 = params.needle2; let p3 = params.needle3;
    needle[0] = p0 & 0xffu; needle[1] = (p0 >> 8u) & 0xffu; needle[2] = (p0 >> 16u) & 0xffu; needle[3] = (p0 >> 24u) & 0xffu;
    needle[4] = p1 & 0xffu; needle[5] = (p1 >> 8u) & 0xffu; needle[6] = (p1 >> 16u) & 0xffu; needle[7] = (p1 >> 24u) & 0xffu;
    needle[8] = p2 & 0xffu; needle[9] = (p2 >> 8u) & 0xffu; needle[10] = (p2 >> 16u) & 0xffu; needle[11] = (p2 >> 24u) & 0xffu;
    needle[12] = p3 & 0xffu; needle[13] = (p3 >> 8u) & 0xffu; needle[14] = (p3 >> 16u) & 0xffu; needle[15] = (p3 >> 24u) & 0xffu;
    for (var k: u32 = 0u; k < nlen; k = k + 1u) {
        if (load_b(i + k) != needle[k]) { return; }
    }
    push_hit(i);
}

@compute @workgroup_size(256)
fn k_sub_rsp(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x + params.base_inv;
    if (i + 2u < params.n && load_b(i) == 0x48u && load_b(i+1u) == 0x83u && load_b(i+2u) == 0xecu) {
        push_hit(i);
    }
}
