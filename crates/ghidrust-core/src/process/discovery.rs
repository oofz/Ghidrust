//! Live data discovery: scan, watch_expr, vtable_probe (bytes ≠ types).

use super::error::{ProcessError, ProcessErrorCode};
use super::types::{
    ModuleInfo, RegionInfo, ScanHit, ScanResult, VtableProbeResult, VtableSlot, WatchResult,
    WatchStep,
};
use super::win_observe::{self, HANDLE};

/// AOB pattern: hex bytes with `??` wildcards, space-separated.
pub fn parse_aob(pattern: &str) -> Result<Vec<Option<u8>>, ProcessError> {
    let mut out = Vec::new();
    for tok in pattern.split_whitespace() {
        if tok == "??" || tok == "?" {
            out.push(None);
        } else {
            let b = u8::from_str_radix(tok, 16).map_err(|_| {
                ProcessError::new(
                    ProcessErrorCode::InvalidArgument,
                    format!("bad AOB token '{tok}'"),
                )
            })?;
            out.push(Some(b));
        }
    }
    if out.is_empty() {
        return Err(ProcessError::new(
            ProcessErrorCode::InvalidArgument,
            "empty AOB pattern",
        ));
    }
    Ok(out)
}

pub fn find_aob(hay: &[u8], pat: &[Option<u8>]) -> Vec<usize> {
    let mut hits = Vec::new();
    if pat.is_empty() || hay.len() < pat.len() {
        return hits;
    }
    'outer: for i in 0..=(hay.len() - pat.len()) {
        for (j, p) in pat.iter().enumerate() {
            if let Some(b) = p {
                if hay[i + j] != *b {
                    continue 'outer;
                }
            }
        }
        hits.push(i);
    }
    hits
}

fn find_module<'a>(mods: &'a [ModuleInfo], va: u64) -> Option<&'a ModuleInfo> {
    mods.iter().find(|m| va >= m.base && va < m.base.wrapping_add(m.size))
}

pub struct ScanOpts {
    pub aob: Option<String>,
    pub string: Option<String>,
    pub utf16: bool,
    pub module_only: Option<String>,
    pub committed_private: bool,
    pub executable_only: bool,
    pub data_only: bool,
    pub max_hits: usize,
    pub max_bytes: u64,
    /// If set, rescan after this many ms and report addresses whose bytes changed.
    pub diff_wait_ms: Option<u64>,
}

impl Default for ScanOpts {
    fn default() -> Self {
        Self {
            aob: None,
            string: None,
            utf16: false,
            module_only: None,
            committed_private: true,
            executable_only: false,
            data_only: false,
            max_hits: 256,
            max_bytes: 64 * 1024 * 1024,
            diff_wait_ms: None,
        }
    }
}

pub fn process_scan(
    handle: HANDLE,
    pid: u32,
    opts: &ScanOpts,
) -> Result<ScanResult, ProcessError> {
    let mods = win_observe::modules(handle, pid)?;
    let regions = win_observe::regions(handle, 4096)?;
    let aob = opts
        .aob
        .as_deref()
        .map(parse_aob)
        .transpose()?;
    let string_bytes = opts.string.as_ref().map(|s| {
        if opts.utf16 {
            s.encode_utf16()
                .flat_map(|c| c.to_le_bytes())
                .collect::<Vec<u8>>()
        } else {
            s.as_bytes().to_vec()
        }
    });

    let mut hits = Vec::new();
    let mut bytes_scanned = 0u64;
    let mut regions_scanned = 0usize;
    let max_hits = opts.max_hits.clamp(1, 10_000);

    let filtered: Vec<&RegionInfo> = regions
        .iter()
        .filter(|r| r.state == "commit")
        .filter(|r| {
            if let Some(mod_name) = &opts.module_only {
                find_module(&mods, r.base)
                    .map(|m| {
                        m.name.eq_ignore_ascii_case(mod_name)
                            || m.path
                                .as_deref()
                                .map(|p| p.to_ascii_lowercase().ends_with(&mod_name.to_ascii_lowercase()))
                                .unwrap_or(false)
                    })
                    .unwrap_or(false)
            } else {
                true
            }
        })
        .filter(|r| {
            // protect is hex string; PAGE_EXECUTE* typically 0x10..0x80 range bits
            let p = u32::from_str_radix(r.protect.trim_start_matches("0x"), 16).unwrap_or(0);
            let exec = (p & 0xF0) != 0; // rough: execute bits in high nibble of low byte
            if opts.executable_only && !exec {
                return false;
            }
            if opts.data_only && exec {
                return false;
            }
            true
        })
        .collect();

    for r in filtered {
        if bytes_scanned >= opts.max_bytes || hits.len() >= max_hits {
            break;
        }
        let chunk = r.size.min(4 * 1024 * 1024) as usize;
        let data = win_observe::read_mem(handle, r.base, chunk);
        if data.bytes_read == 0 {
            continue;
        }
        regions_scanned += 1;
        bytes_scanned += data.bytes_read as u64;

        let mut offsets: Vec<usize> = Vec::new();
        if let Some(ref pat) = aob {
            offsets.extend(find_aob(&data.bytes, pat));
        }
        if let Some(ref sb) = string_bytes {
            let pat: Vec<Option<u8>> = sb.iter().map(|b| Some(*b)).collect();
            offsets.extend(find_aob(&data.bytes, &pat));
        }
        if aob.is_none() && string_bytes.is_none() {
            continue;
        }
        offsets.sort_unstable();
        offsets.dedup();
        for off in offsets {
            if hits.len() >= max_hits {
                break;
            }
            let va = r.base.wrapping_add(off as u64);
            let m = find_module(&mods, va);
            let preview = win_observe::read_mem(handle, va, 16);
            hits.push(ScanHit {
                va,
                module: m.map(|x| x.name.clone()),
                rva: m.map(|x| va.wrapping_sub(x.base)),
                preview_hex: if preview.bytes_read > 0 {
                    Some(preview.hex)
                } else {
                    None
                },
            });
        }
    }

    let mut diff_changed = None;
    if let Some(ms) = opts.diff_wait_ms {
        std::thread::sleep(std::time::Duration::from_millis(ms.min(30_000)));
        let mut changed = Vec::new();
        for h in &hits {
            let before = win_observe::read_mem(handle, h.va, 16);
            // re-read is "after"; we need before stored — store preview from first scan
            let after = win_observe::read_mem(handle, h.va, 16);
            // For true diff we should have stored first bytes; use a second full pattern scan
            // on hit addresses only: compare to preview_hex
            if let Some(ref prev) = h.preview_hex {
                if after.hex != *prev {
                    changed.push(h.va);
                }
            } else if before.hex != after.hex {
                changed.push(h.va);
            }
        }
        // Also re-scan same patterns for new hits that changed? Keep simple: changed among hits.
        let _ = before_placeholder();
        diff_changed = Some(changed);
    }

    let truncated = hits.len() >= max_hits || bytes_scanned >= opts.max_bytes;
    Ok(ScanResult {
        hits,
        truncated,
        regions_scanned,
        bytes_scanned,
        diff_changed,
    })
}

fn before_placeholder() {}

/// Watch DSL:
/// - `0xVA` or `VA` — read u64
/// - `module+rva` e.g. `game.exe+0x1234`
/// - chain: `0xVA->*+0x10->*+0x8`  (follow pointer, add offset)
/// - `u32@0xVA` / `u64@…` / `f32@…` / `f64@…`
pub fn eval_watch_expr(
    handle: HANDLE,
    pid: u32,
    expr: &str,
    want_matrix_heuristic: bool,
) -> Result<WatchResult, ProcessError> {
    let mods = win_observe::modules(handle, pid).unwrap_or_default();
    let mut steps = Vec::new();
    let mut parts: Vec<&str> = expr.split("->").map(str::trim).filter(|s| !s.is_empty()).collect();
    if parts.is_empty() {
        return Err(ProcessError::new(
            ProcessErrorCode::InvalidArgument,
            "empty watch expression",
        ));
    }

    // Optional type prefix on first token: u64@addr
    let mut read_size: usize = 8;
    let mut as_float = false;
    let mut as_f64 = false;
    let first = parts[0];
    let (first_addr_tok, typed) = if let Some(rest) = first.strip_prefix("u64@") {
        read_size = 8;
        (rest, true)
    } else if let Some(rest) = first.strip_prefix("u32@") {
        read_size = 4;
        (rest, true)
    } else if let Some(rest) = first.strip_prefix("f32@") {
        read_size = 4;
        as_float = true;
        (rest, true)
    } else if let Some(rest) = first.strip_prefix("f64@") {
        read_size = 8;
        as_f64 = true;
        (rest, true)
    } else {
        (first, false)
    };
    if typed {
        parts[0] = first_addr_tok;
    }

    let mut va = resolve_token(parts[0], &mods, None)?;
    steps.push(WatchStep {
        op: format!("base {}", parts[0]),
        va,
        value_u64: None,
    });

    for (i, part) in parts.iter().enumerate().skip(1) {
        // Read pointer at va
        let rr = win_observe::read_mem(handle, va, 8);
        if rr.bytes_read < 8 {
            return Ok(WatchResult {
                expr: expr.into(),
                steps,
                final_va: Some(va),
                value_hex: None,
                as_u64: None,
                as_f32: None,
                as_f64: None,
                heuristic_float4x4: None,
                heuristic: false,
                error: Some(format!("pointer read failed at {va:#x}")),
            });
        }
        let ptr = u64::from_le_bytes(rr.bytes[0..8].try_into().unwrap());
        steps.push(WatchStep {
            op: format!("deref[{}]", i - 1),
            va,
            value_u64: Some(ptr),
        });
        if ptr == 0 || ptr < 0x10000 {
            return Ok(WatchResult {
                expr: expr.into(),
                steps,
                final_va: Some(va),
                value_hex: None,
                as_u64: Some(ptr),
                as_f32: None,
                as_f64: None,
                heuristic_float4x4: None,
                heuristic: false,
                error: Some("null or low pointer in chain".into()),
            });
        }
        let off = parse_offset_token(part)?;
        va = ptr.wrapping_add(off);
        steps.push(WatchStep {
            op: format!("+{off:#x}"),
            va,
            value_u64: None,
        });
    }

    let rr = win_observe::read_mem(handle, va, read_size.max(64));
    if rr.bytes_read < read_size {
        return Ok(WatchResult {
            expr: expr.into(),
            steps,
            final_va: Some(va),
            value_hex: Some(rr.hex),
            as_u64: None,
            as_f32: None,
            as_f64: None,
            heuristic_float4x4: None,
            heuristic: false,
            error: Some(format!("short read at {va:#x}")),
        });
    }

    let as_u64 = if read_size >= 8 {
        Some(u64::from_le_bytes(rr.bytes[0..8].try_into().unwrap()))
    } else if read_size >= 4 {
        Some(u32::from_le_bytes(rr.bytes[0..4].try_into().unwrap()) as u64)
    } else {
        None
    };
    let as_f32 = if as_float && rr.bytes_read >= 4 {
        Some(f32::from_le_bytes(rr.bytes[0..4].try_into().unwrap()))
    } else {
        None
    };
    let as_f64 = if as_f64 && rr.bytes_read >= 8 {
        Some(f64::from_le_bytes(rr.bytes[0..8].try_into().unwrap()))
    } else {
        None
    };

    let mut heuristic = false;
    let mut matrix = None;
    if want_matrix_heuristic && rr.bytes_read >= 64 {
        let mut floats = Vec::with_capacity(16);
        for c in rr.bytes[..64].chunks_exact(4) {
            floats.push(f32::from_le_bytes(c.try_into().unwrap()));
        }
        // Heuristic: last row ~ [0,0,0,1] or many finite values
        if floats.iter().all(|f| f.is_finite()) {
            heuristic = true;
            matrix = Some(floats);
        }
    }

    Ok(WatchResult {
        expr: expr.into(),
        steps,
        final_va: Some(va),
        value_hex: Some(rr.hex),
        as_u64,
        as_f32,
        as_f64,
        heuristic_float4x4: matrix,
        heuristic,
        error: None,
    })
}

fn parse_offset_token(tok: &str) -> Result<u64, ProcessError> {
    let t = tok.trim().trim_start_matches('+');
    if let Some(rest) = t.strip_prefix("*+") {
        return parse_u64_flexible(rest);
    }
    if t == "*" {
        // bare * means +0 after deref (already deref'd)
        return Ok(0);
    }
    parse_u64_flexible(t.trim_start_matches('+'))
}

fn resolve_token(tok: &str, mods: &[ModuleInfo], _base: Option<u64>) -> Result<u64, ProcessError> {
    let tok = tok.trim();
    if let Some((mod_name, rva_s)) = tok.split_once('+') {
        if !mod_name.chars().all(|c| c.is_ascii_hexdigit() || c == 'x' || c == 'X')
            || mod_name.contains('.')
            || mod_name.chars().any(|c| c.is_alphabetic() && c != 'x' && c != 'X')
        {
            // module+rva form when left side looks like a name
            if mod_name.chars().any(|c| c.is_alphabetic()) {
                let rva = parse_u64_flexible(rva_s)?;
                let m = mods
                    .iter()
                    .find(|m| {
                        m.name.eq_ignore_ascii_case(mod_name)
                            || m.path
                                .as_deref()
                                .map(|p| {
                                    p.to_ascii_lowercase()
                                        .ends_with(&mod_name.to_ascii_lowercase())
                                })
                                .unwrap_or(false)
                    })
                    .ok_or_else(|| {
                        ProcessError::new(
                            ProcessErrorCode::ModuleNotFound,
                            format!("module not found: {mod_name}"),
                        )
                    })?;
                return Ok(m.base.wrapping_add(rva));
            }
        }
    }
    // bare hex VA
    if tok.contains('+') {
        // numeric base+off
        let (a, b) = tok.split_once('+').unwrap();
        let base = parse_u64_flexible(a)?;
        let off = parse_u64_flexible(b)?;
        return Ok(base.wrapping_add(off));
    }
    parse_u64_flexible(tok)
}

fn parse_u64_flexible(s: &str) -> Result<u64, ProcessError> {
    let s = s.trim().trim_start_matches('+');
    let (s, radix) = if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        (h, 16)
    } else if s.chars().any(|c| matches!(c, 'a'..='f' | 'A'..='F')) {
        (s, 16)
    } else {
        (s, 10)
    };
    u64::from_str_radix(s, radix).map_err(|_| {
        ProcessError::new(
            ProcessErrorCode::InvalidArgument,
            format!("bad integer '{s}'"),
        )
    })
}

pub fn vtable_probe(
    handle: HANDLE,
    pid: u32,
    object_va: u64,
    max_slots: usize,
) -> Result<VtableProbeResult, ProcessError> {
    let mods = win_observe::modules(handle, pid)?;
    let vt_read = win_observe::read_mem(handle, object_va, 8);
    if vt_read.bytes_read < 8 {
        return Err(ProcessError::new(
            ProcessErrorCode::AccessDenied,
            format!("cannot read object* at {object_va:#x}"),
        ));
    }
    let vtable_va = u64::from_le_bytes(vt_read.bytes[0..8].try_into().unwrap());
    let vt_mod = find_module(&mods, vtable_va);
    // Heuristic: vtable often in non-exec module image (.rdata) — we check it's inside a module.
    let in_module_rdata = vt_mod.is_some();
    let max_slots = max_slots.clamp(1, 256);
    let slot_bytes = win_observe::read_mem(handle, vtable_va, max_slots * 8);
    let mut slots = Vec::new();
    for i in 0..max_slots {
        let off = i * 8;
        if off + 8 > slot_bytes.bytes_read {
            break;
        }
        let target = u64::from_le_bytes(slot_bytes.bytes[off..off + 8].try_into().unwrap());
        if target == 0 {
            break;
        }
        let tm = find_module(&mods, target);
        slots.push(VtableSlot {
            index: i as u32,
            target_va: target,
            module: tm.map(|m| m.name.clone()),
            rva: tm.map(|m| target.wrapping_sub(m.base)),
        });
    }
    Ok(VtableProbeResult {
        object_va,
        vtable_va,
        in_module_rdata,
        module: vt_mod.map(|m| m.name.clone()),
        slots,
        rtti_hint: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aob_wildcard_match() {
        let pat = parse_aob("48 8b ?? 90").unwrap();
        let hay = [0x48, 0x8b, 0x05, 0x90, 0x00];
        assert_eq!(find_aob(&hay, &pat), vec![0]);
    }

    #[test]
    fn parse_offset_star_plus() {
        assert_eq!(parse_offset_token("*+0x10").unwrap(), 0x10);
        assert_eq!(parse_offset_token("+8").unwrap(), 8);
    }
}
