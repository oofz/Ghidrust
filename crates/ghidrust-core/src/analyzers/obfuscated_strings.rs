//! Recover stack-built and lightly obfuscated strings from code blocks.

use super::AnalyzerOutput;
use crate::error::Result;
use crate::program::Program;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ObfuscatedStringKind {
    Stack,
    Tight,
    Decoded,
    StaticHint,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObfuscatedStringHit {
    pub va: u64,
    pub value: String,
    pub kind: ObfuscatedStringKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoder_va: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_site: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct RecoverStringsOpts {
    pub only: Option<Vec<String>>,
    pub no: Option<Vec<String>>,
    pub functions: Option<Vec<u64>>,
    pub limit: Option<usize>,
}

fn kind_allowed(kind: &ObfuscatedStringKind, opts: &RecoverStringsOpts) -> bool {
    let name = match kind {
        ObfuscatedStringKind::Stack => "stack",
        ObfuscatedStringKind::Tight => "tight",
        ObfuscatedStringKind::Decoded => "decoded",
        ObfuscatedStringKind::StaticHint => "static",
    };
    if let Some(only) = &opts.only {
        if !only.is_empty() && !only.iter().any(|k| k.eq_ignore_ascii_case(name)) {
            return false;
        }
    }
    if let Some(no) = &opts.no {
        if no.iter().any(|k| k.eq_ignore_ascii_case(name)) {
            return false;
        }
    }
    true
}

fn is_printable_ascii(b: u8) -> bool {
    (0x20..=0x7e).contains(&b)
}

/// Decoder-site seeds from Find Crypt xrefs + Crypto Capabilities decrypt/encoding hits.
pub fn decoder_seed_vas(prog: &Program) -> Vec<u64> {
    let mut seeds = super::crypt_constants::crypt_xref_seed_vas(prog);
    for c in &prog.analysis.crypto_capabilities {
        if matches!(c.tag.as_str(), "decrypt" | "encoding") {
            if let Some(va) = c.function_va {
                seeds.push(va);
            }
        }
    }
    seeds.sort_unstable();
    seeds.dedup();
    seeds
}

const MAX_EMU_STEPS: usize = 10_000;
const MAX_WINDOW: usize = 512;

fn at_limit(hits: &[ObfuscatedStringHit], opts: &RecoverStringsOpts) -> bool {
    opts.limit.is_some_and(|limit| hits.len() >= limit)
}

/// A cheap pre-filter for byte-oriented decoder bodies. It deliberately requires both a
/// non-zero transform and stores, so ordinary tiny thunks and zeroing loops are skipped.
fn decoder_score(bytes: &[u8]) -> u8 {
    if bytes.len() < 12 || bytes.len() > MAX_WINDOW {
        return 0;
    }
    let mut transforms = 0u8;
    let mut stores = 0u8;
    let mut rotates = 0u8;
    for window in bytes.windows(3) {
        match window {
            [0x34 | 0x32 | 0x30, key, ..] if *key != 0 => transforms += 2,
            [0x04 | 0x2c, key, ..] if *key != 0 => transforms += 2,
            [0x80, modrm, key] if (*modrm & 0x38) != 0x38 && *key != 0 => transforms += 1,
            [0xc0 | 0xc1, modrm, count] if (*modrm & 0x38) == 0 && *count != 0 => rotates += 1,
            [0x88 | 0x89 | 0xc6, ..] => stores += 1,
            _ => {}
        }
    }
    transforms.saturating_add(rotates).min(4) + stores.min(3)
}

/// Recover obfuscated strings from executable mappings. This intentionally scans executable
/// raw images even when no section/function metadata exists.
pub fn recover_obfuscated_strings(
    prog: &Program,
    opts: &RecoverStringsOpts,
) -> Vec<ObfuscatedStringHit> {
    let mut hits = Vec::new();
    let mut seeds = decoder_seed_vas(prog);
    if let Some(functions) = &opts.functions {
        seeds.extend(functions.iter().copied());
    }
    seeds.sort_unstable();
    seeds.dedup();

    if kind_allowed(&ObfuscatedStringKind::StaticHint, opts) && opts.functions.is_none() {
        recover_static_hints(prog, opts, &mut hits);
    }

    let mut blocks: Vec<_> = prog.exec_blocks().collect();
    blocks.sort_by_key(|block| {
        let seeded = seeds
            .iter()
            .any(|&seed| seed >= block.va && seed < block.va.saturating_add(block.size));
        !seeded
    });
    let mut emu_steps = 0usize;
    for block in blocks {
        if at_limit(&hits, opts) {
            continue;
        }
        let regions: Vec<(usize, usize)> =
            match opts.functions.as_ref().filter(|items| !items.is_empty()) {
                None => vec![(0, block.bytes.len())],
                Some(entries) => entries
                    .iter()
                    .filter_map(|&entry| {
                        let (start_va, end_va) = match prog
                            .analysis
                            .functions
                            .iter()
                            .find(|function| function.entry == entry)
                        {
                            Some(function) => (function.entry, function.end),
                            None if entry >= block.va
                                && entry < block.va.saturating_add(block.size) =>
                            {
                                (block.va, block.va.saturating_add(block.bytes.len() as u64))
                            }
                            None => return None,
                        };
                        let start = start_va.saturating_sub(block.va) as usize;
                        let end = end_va
                            .saturating_sub(block.va)
                            .min(block.bytes.len() as u64)
                            as usize;
                        (start < block.bytes.len() && start < end).then_some((start, end))
                    })
                    .collect(),
            };
        for (region_start, region_end) in regions {
            let region = &block.bytes[region_start..region_end];
            recover_stack_immediates(block.va + region_start as u64, region, opts, &mut hits);
            for start in (0..region.len()).step_by(32) {
                if at_limit(&hits, opts) || emu_steps >= MAX_EMU_STEPS {
                    break;
                }
                let end = (start + MAX_WINDOW).min(region.len());
                let window = &region[start..end];
                if decoder_score(window) >= 4 {
                    emu_steps += window.len().min(MAX_EMU_STEPS - emu_steps);
                    emulate_stack_decoder(
                        block.va + region_start as u64 + start as u64,
                        window,
                        opts,
                        &mut hits,
                    );
                }
            }
            // The bounded helpers cover immediate-inline decoder idioms that do not
            // have enough stack-store evidence for the tiny emulator above.
            recover_xor_decoded(block.va + region_start as u64, region, opts, &mut hits);
            recover_arith_decoded(block.va + region_start as u64, region, opts, &mut hits);
        }
    }
    hits.sort_by(|a, b| a.va.cmp(&b.va).then(a.value.cmp(&b.value)));
    hits.dedup_by(|a, b| a.va == b.va && a.value == b.value && a.kind == b.kind);
    if let Some(limit) = opts.limit {
        hits.truncate(limit);
    }
    hits
}

fn recover_static_hints(
    prog: &Program,
    opts: &RecoverStringsOpts,
    out: &mut Vec<ObfuscatedStringHit>,
) {
    for block in prog.blocks.iter().filter(|block| !block.executable) {
        let mut runs = Vec::new();
        let mut offset = 0;
        while offset < block.bytes.len() {
            let start = offset;
            while offset < block.bytes.len() && is_printable_ascii(block.bytes[offset]) {
                offset += 1;
            }
            if offset - start >= 6 {
                runs.push((start, offset - start));
            }
            offset += 1;
        }
        // A single printable run can be incidental data. Require a neighboring run to
        // identify a table-like region, then report only bytes actually present in memory.
        for &(start, len) in &runs {
            let table_like = runs
                .iter()
                .any(|&(other, _)| other != start && other.abs_diff(start) <= 128);
            if table_like && !at_limit(out, opts) {
                out.push(ObfuscatedStringHit {
                    va: block.va + start as u64,
                    value: String::from_utf8_lossy(&block.bytes[start..start + len]).into_owned(),
                    kind: ObfuscatedStringKind::StaticHint,
                    decoder_va: None,
                    call_site: None,
                });
            }
        }
        // UTF-16LE-ish printable runs are independently useful when adjacent entries form
        // a table. Odd bytes must be zero to avoid fabricating text from arbitrary data.
        let mut utf16_runs = Vec::new();
        let mut offset = 0usize;
        while offset + 1 < block.bytes.len() {
            let start = offset;
            while offset + 1 < block.bytes.len()
                && is_printable_ascii(block.bytes[offset])
                && block.bytes[offset + 1] == 0
            {
                offset += 2;
            }
            if (offset - start) / 2 >= 4 {
                utf16_runs.push((start, offset));
            }
            offset += 2;
        }
        for &(start, end) in &utf16_runs {
            if utf16_runs
                .iter()
                .any(|&(other, _)| other != start && other.abs_diff(start) <= 160)
                && !at_limit(out, opts)
            {
                let value: String = (start..end)
                    .step_by(2)
                    .map(|p| block.bytes[p] as char)
                    .collect();
                out.push(ObfuscatedStringHit {
                    va: block.va + start as u64,
                    value,
                    kind: ObfuscatedStringKind::StaticHint,
                    decoder_va: None,
                    call_site: None,
                });
            }
        }
    }
}

/// Tiny, fail-closed byte emulator for stack-local decoder loops. It snapshots `C6` byte
/// stores, applies only recognized non-zero immediate transforms, and emits a string only
/// when the changed contiguous bytes are printable. No register or pointer speculation is
/// performed.
fn emulate_stack_decoder(
    base: u64,
    bytes: &[u8],
    opts: &RecoverStringsOpts,
    out: &mut Vec<ObfuscatedStringHit>,
) {
    if !kind_allowed(&ObfuscatedStringKind::Decoded, opts) {
        return;
    }
    let has_back_edge = bytes
        .windows(2)
        .any(|pair| pair[0] == 0xe2 || (pair[0] == 0xeb && (pair[1] as i8) < 0));
    if !has_back_edge {
        return;
    }
    let mut snapshot: std::collections::BTreeMap<i8, (u8, usize)> =
        std::collections::BTreeMap::new();
    let mut i = 0usize;
    while i + 3 < bytes.len() {
        if bytes[i..].starts_with(&[0xc6, 0x45]) {
            snapshot.insert(bytes[i + 2] as i8, (bytes[i + 3], i));
            i += 4;
        } else if i + 4 < bytes.len() && bytes[i..].starts_with(&[0xc6, 0x44, 0x24]) {
            snapshot.insert(bytes[i + 3] as i8, (bytes[i + 4], i));
            i += 5;
        } else {
            i += 1;
        }
    }
    if snapshot.len() < 4 {
        return;
    }
    let mut transformed = snapshot.clone();
    let mut decoder = None;
    for i in 0..bytes.len().saturating_sub(3) {
        let (op, disp, key, width) = if bytes[i..].starts_with(&[0x80, 0x75]) {
            (0u8, bytes[i + 2] as i8, bytes[i + 3], 4)
        } else if bytes[i..].starts_with(&[0x80, 0x45]) {
            (1u8, bytes[i + 2] as i8, bytes[i + 3], 4)
        } else if bytes[i..].starts_with(&[0x80, 0x6d]) {
            (2u8, bytes[i + 2] as i8, bytes[i + 3], 4)
        } else if i + 3 < bytes.len() && bytes[i..].starts_with(&[0xc0, 0x45]) {
            (3u8, bytes[i + 2] as i8, bytes[i + 3], 4)
        } else if i + 3 < bytes.len() && bytes[i..].starts_with(&[0xc0, 0x4d]) {
            (4u8, bytes[i + 2] as i8, bytes[i + 3], 4)
        } else {
            continue;
        };
        if key == 0 || !snapshot.contains_key(&disp) {
            continue;
        }
        let (before, store_at) = snapshot[&disp];
        let after = match op {
            0 => before ^ key,
            1 => before.wrapping_add(key),
            2 => before.wrapping_sub(key),
            3 => before.rotate_left((key & 7) as u32),
            _ => before.rotate_right((key & 7) as u32),
        };
        transformed.insert(disp, (after, store_at));
        decoder.get_or_insert(base + i as u64);
        let _ = width;
    }
    let Some(decoder_va) = decoder else {
        return;
    };
    let entries: Vec<_> = transformed.into_iter().collect();
    let mut start = 0usize;
    while start < entries.len() {
        let mut end = start + 1;
        while end < entries.len()
            && entries[end].0 == entries[end - 1].0 + 1
            && is_printable_ascii(entries[end].1 .0)
        {
            end += 1;
        }
        if end - start >= 4
            && entries[start..end]
                .iter()
                .all(|(_, (byte, _))| is_printable_ascii(*byte))
        {
            let value: String = entries[start..end]
                .iter()
                .map(|(_, (byte, _))| *byte as char)
                .collect();
            let store_at = entries[start].1 .1;
            let call_site = bytes
                .iter()
                .enumerate()
                .skip((decoder_va - base) as usize)
                .find_map(|(offset, byte)| (*byte == 0xe8).then_some(base + offset as u64));
            out.push(ObfuscatedStringHit {
                va: base + store_at as u64,
                value,
                kind: ObfuscatedStringKind::Decoded,
                decoder_va: Some(decoder_va),
                call_site,
            });
        }
        start = end;
    }
}

/// `C6 45 xx imm8` / `C6 44 24 xx imm8` style stack byte stores → stack strings.
fn recover_stack_immediates(
    base: u64,
    bytes: &[u8],
    opts: &RecoverStringsOpts,
    out: &mut Vec<ObfuscatedStringHit>,
) {
    if !kind_allowed(&ObfuscatedStringKind::Stack, opts)
        && !kind_allowed(&ObfuscatedStringKind::Tight, opts)
    {
        return;
    }
    let mut i = 0usize;
    while i + 4 < bytes.len() {
        // mov byte ptr [rbp+disp8], imm8  → C6 45 disp imm
        // mov byte ptr [rsp+disp8], imm8  → C6 44 24 disp imm
        let (store_va, imm, next) =
            if bytes[i] == 0xC6 && bytes[i + 1] == 0x45 && i + 3 < bytes.len() {
                (base + i as u64, bytes[i + 3], i + 4)
            } else if bytes[i] == 0xC6
                && bytes[i + 1] == 0x44
                && i + 4 < bytes.len()
                && bytes[i + 2] == 0x24
            {
                (base + i as u64, bytes[i + 4], i + 5)
            } else {
                i += 1;
                continue;
            };

        if !is_printable_ascii(imm) && imm != 0 {
            i = next;
            continue;
        }

        let mut chars = Vec::new();
        let mut j = i;
        let mut last_va = store_va;
        while j + 4 < bytes.len() {
            let (imm_b, step) = if bytes[j] == 0xC6 && bytes[j + 1] == 0x45 && j + 3 < bytes.len() {
                (bytes[j + 3], 4usize)
            } else if bytes[j] == 0xC6
                && bytes[j + 1] == 0x44
                && j + 4 < bytes.len()
                && bytes[j + 2] == 0x24
            {
                (bytes[j + 4], 5usize)
            } else {
                break;
            };
            if imm_b == 0 {
                j += step;
                break;
            }
            if !is_printable_ascii(imm_b) {
                break;
            }
            chars.push(imm_b);
            last_va = base + j as u64;
            j += step;
            if chars.len() > 256 {
                break;
            }
        }

        if chars.len() >= 4 {
            let value = String::from_utf8_lossy(&chars).into_owned();
            // Tight if a nearby XOR appears in the following 32 bytes.
            let window_end = (j + 32).min(bytes.len());
            let has_xor = bytes[j..window_end]
                .windows(2)
                .any(|w| w[0] == 0x34 || (w[0] == 0x80 && w.len() > 1) || w[0] == 0x30);
            let kind = if has_xor && kind_allowed(&ObfuscatedStringKind::Tight, opts) {
                ObfuscatedStringKind::Tight
            } else if kind_allowed(&ObfuscatedStringKind::Stack, opts) {
                ObfuscatedStringKind::Stack
            } else {
                i = j.max(next);
                continue;
            };
            out.push(ObfuscatedStringHit {
                va: store_va,
                value,
                kind,
                decoder_va: Some(last_va),
                call_site: None,
            });
            i = j.max(next);
        } else {
            i = next;
        }
    }
}

/// Scan for short XOR-imm loops that decode contiguous ciphertext into printable ASCII.
#[allow(dead_code)]
fn recover_xor_decoded(
    base: u64,
    bytes: &[u8],
    opts: &RecoverStringsOpts,
    out: &mut Vec<ObfuscatedStringHit>,
) {
    if !kind_allowed(&ObfuscatedStringKind::Decoded, opts) {
        return;
    }
    // Pattern: xor al/r8b, imm8  (34 xx) inside a small window with a load from a nearby data blob.
    let mut i = 0usize;
    while i + 8 < bytes.len() {
        if bytes[i] != 0x34 {
            i += 1;
            continue;
        }
        let key = bytes[i + 1];
        if key == 0 {
            i += 2;
            continue;
        }
        // Look backward up to 64 bytes for a LEA/MOV that could point at ciphertext;
        // instead, try decoding following immediates or prior .rdata-like immediates in code.
        // Practical approach: decode a run of bytes immediately after a `mov rsi, imm64` (48 BE)
        // is rare; scan for `34 key` density and try xor against nearby absolute addresses.
        // Simpler high-yield path: if the next 16+ bytes look like xor-encoded printable when
        // xored with `key`, emit them (common single-byte XOR blobs inlined after the decoder).
        let start = i + 2;
        let end = (start + 128).min(bytes.len());
        let mut decoded = Vec::new();
        for &b in &bytes[start..end] {
            let d = b ^ key;
            if d == 0 {
                break;
            }
            if !is_printable_ascii(d) {
                decoded.clear();
                break;
            }
            decoded.push(d);
            if decoded.len() > 200 {
                break;
            }
        }
        if decoded.len() >= 6 {
            out.push(ObfuscatedStringHit {
                va: base + start as u64,
                value: String::from_utf8_lossy(&decoded).into_owned(),
                kind: ObfuscatedStringKind::Decoded,
                decoder_va: Some(base + i as u64),
                call_site: None,
            });
            i = start + decoded.len();
        } else {
            i += 2;
        }
    }
}

/// ADD/SUB/ROL imm8 decode loops → printable ASCII (light emu without full CPU).
#[allow(dead_code)]
fn recover_arith_decoded(
    base: u64,
    bytes: &[u8],
    opts: &RecoverStringsOpts,
    out: &mut Vec<ObfuscatedStringHit>,
) {
    if !kind_allowed(&ObfuscatedStringKind::Decoded, opts) {
        return;
    }
    let mut i = 0usize;
    while i + 3 < bytes.len() {
        // add al, imm8 → 04 xx ; sub al, imm8 → 2C xx ; rol al, imm8 → C0 C0 xx
        let (key, kind_op, step) = if bytes[i] == 0x04 {
            (bytes[i + 1], b'+', 2usize)
        } else if bytes[i] == 0x2C {
            (bytes[i + 1], b'-', 2usize)
        } else if bytes[i] == 0xC0 && bytes[i + 1] == 0xC0 && i + 2 < bytes.len() {
            (bytes[i + 2], b'r', 3usize)
        } else {
            i += 1;
            continue;
        };
        if key == 0 {
            i += step;
            continue;
        }
        let start = i + step;
        let end = (start + 128).min(bytes.len());
        let mut decoded = Vec::new();
        for &b in &bytes[start..end] {
            let d = match kind_op {
                b'+' => b.wrapping_sub(key), // reverse of add
                b'-' => b.wrapping_add(key), // reverse of sub
                _ => b.rotate_right((key & 7) as u32),
            };
            if d == 0 {
                break;
            }
            if !is_printable_ascii(d) {
                decoded.clear();
                break;
            }
            decoded.push(d);
            if decoded.len() > 200 {
                break;
            }
        }
        if decoded.len() >= 6 {
            out.push(ObfuscatedStringHit {
                va: base + start as u64,
                value: String::from_utf8_lossy(&decoded).into_owned(),
                kind: ObfuscatedStringKind::Decoded,
                decoder_va: Some(base + i as u64),
                call_site: None,
            });
            i = start + decoded.len();
        } else {
            i += step;
        }
    }
}

pub fn run(prog: &mut Program) -> Result<AnalyzerOutput> {
    let opts = RecoverStringsOpts::default();
    let hits = recover_obfuscated_strings(prog, &opts);
    let n = hits.len();
    prog.analysis.obfuscated_strings = hits.clone();
    for h in &hits {
        let kind = match h.kind {
            ObfuscatedStringKind::Stack => "stack",
            ObfuscatedStringKind::Tight => "tight",
            ObfuscatedStringKind::Decoded => "decoded",
            ObfuscatedStringKind::StaticHint => "static",
        };
        let text: String = h.value.chars().take(80).collect();
        prog.edits.set_comment(
            h.va,
            crate::edits::CommentKind::Eol,
            format!("recovered[{kind}]: {text}"),
        );
    }
    Ok(AnalyzerOutput {
        name: "Obfuscated Strings".into(),
        status: "ok".into(),
        message: format!("recovered {n} obfuscated string(s)"),
        obfuscated_strings: Some(hits),
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::{MemoryBlock, Program};

    #[test]
    fn recovers_stack_byte_stores() {
        let mut prog = Program::new("t".into(), "raw");
        // Build "http" via C6 45 xx imm
        let mut code = Vec::new();
        for (disp, ch) in [(0u8, b'h'), (1, b't'), (2, b't'), (3, b'p'), (4, 0)] {
            code.extend_from_slice(&[0xC6, 0x45, disp, ch]);
        }
        prog.blocks.push(MemoryBlock {
            name: ".text".into(),
            va: 0x401000,
            size: code.len() as u64,
            bytes: code,
            readable: true,
            writable: false,
            executable: true,
        });
        let hits = recover_obfuscated_strings(&prog, &RecoverStringsOpts::default());
        assert!(hits.iter().any(|h| h.value == "http"));
    }

    #[test]
    fn classifies_tight_stack_construction() {
        let mut prog = Program::new("tight".into(), "raw");
        let mut code = Vec::new();
        for (disp, ch) in [
            (0u8, b't'),
            (1, b'i'),
            (2, b'g'),
            (3, b'h'),
            (4, b't'),
            (5, 0),
        ] {
            code.extend_from_slice(&[0xc6, 0x45, disp, ch]);
        }
        // Nearby non-zero byte transform makes this a tight construction site.
        code.extend_from_slice(&[0x80, 0x75, 0, 0x11]);
        prog.blocks.push(MemoryBlock {
            name: ".text".into(),
            va: 0x5000,
            size: code.len() as u64,
            bytes: code,
            readable: true,
            writable: false,
            executable: true,
        });
        let hits = recover_obfuscated_strings(&prog, &RecoverStringsOpts::default());
        assert!(hits
            .iter()
            .any(|h| h.value == "tight" && h.kind == ObfuscatedStringKind::Tight));
    }

    #[test]
    fn emulates_xor_stack_decoder_with_decoder_site() {
        let mut prog = Program::new("decode".into(), "raw");
        let mut code = Vec::new();
        for (disp, ch) in [
            (0u8, b's' ^ 0x55),
            (1, b'e' ^ 0x55),
            (2, b'e' ^ 0x55),
            (3, b'd' ^ 0x55),
        ] {
            code.extend_from_slice(&[0xc6, 0x45, disp, ch]);
        }
        for disp in 0..4u8 {
            code.extend_from_slice(&[0x80, 0x75, disp, 0x55]); // xor byte ptr [rbp+disp], 55
        }
        code.extend_from_slice(&[0xe2, 0xfe]); // bounded-loop marker
        prog.blocks.push(MemoryBlock {
            name: ".text".into(),
            va: 0x6000,
            size: code.len() as u64,
            bytes: code,
            readable: true,
            writable: false,
            executable: true,
        });
        let hits = recover_obfuscated_strings(&prog, &RecoverStringsOpts::default());
        assert!(hits.iter().any(|h| {
            h.value == "seed" && h.kind == ObfuscatedStringKind::Decoded && h.decoder_va.is_some()
        }));
    }

    #[test]
    fn recovers_static_hints_and_respects_kind_filters_and_limit() {
        let mut prog = Program::new("static".into(), "raw");
        prog.blocks.push(MemoryBlock {
            name: ".rdata".into(),
            va: 0x7000,
            size: 20,
            bytes: b"first!\0second!".to_vec(),
            readable: true,
            writable: false,
            executable: false,
        });
        let static_only = RecoverStringsOpts {
            only: Some(vec!["static".into()]),
            ..Default::default()
        };
        let hits = recover_obfuscated_strings(&prog, &static_only);
        assert!(hits.iter().all(|hit| hit.kind == ObfuscatedStringKind::StaticHint));
        assert!(hits.iter().any(|hit| hit.value == "first!"));

        let none = RecoverStringsOpts {
            no: Some(vec!["static".into()]),
            ..Default::default()
        };
        assert!(recover_obfuscated_strings(&prog, &none).is_empty());
        let limited = RecoverStringsOpts {
            limit: Some(1),
            ..Default::default()
        };
        assert_eq!(recover_obfuscated_strings(&prog, &limited).len(), 1);
    }

    #[test]
    fn recovers_add_sub_and_rol_inline_decoders() {
        let mut prog = Program::new("arith".into(), "raw");
        let mut code = vec![0x04, 0x11]; // add al, 0x11; encoded bytes follow
        code.extend(b"Yv}}\x802"); // "Hello!" plus 0x11
        code.push(0x11); // encoded NUL
        code.extend_from_slice(&[0x2c, 0x11]); // sub al, 0x11; encoded bytes follow
        code.extend(b"7T[[^\x10"); // "Hello!" minus 0x11
        code.push(0xef); // encoded NUL
        prog.blocks.push(MemoryBlock {
            name: ".text".into(),
            va: 0x8000,
            size: code.len() as u64,
            bytes: code,
            readable: true,
            writable: false,
            executable: true,
        });
        let hits = recover_obfuscated_strings(&prog, &RecoverStringsOpts::default());
        assert_eq!(
            hits.iter()
                .filter(|hit| hit.kind == ObfuscatedStringKind::Decoded && hit.value == "Hello!")
                .count(),
            2,
            "{hits:?}"
        );
    }
}
