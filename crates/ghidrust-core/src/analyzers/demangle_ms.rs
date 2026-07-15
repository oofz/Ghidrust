use super::AnalyzerOutput;
use crate::error::Result;
use crate::program::{Program, SymbolInfo};
use crate::rtti::demangle_msvc_simple;

pub fn run(prog: &mut Program) -> Result<AnalyzerOutput> {
    let mut out_syms = Vec::new();
    // Scan symbols
    for s in prog.analysis.symbols.iter_mut() {
        if let Some(d) = try_demangle(&s.name) {
            s.demangled = Some(d.clone());
            out_syms.push(SymbolInfo {
                va: s.va,
                name: s.name.clone(),
                demangled: Some(d),
            });
        }
    }
    // Scan memory for mangled / RTTI names
    for block in &prog.blocks {
        let b = &block.bytes;
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'?' || (b[i] == b'.' && b.get(i + 1) == Some(&b'?')) {
                if let Some(raw) = read_cstr(b, i) {
                    if let Some(d) = try_demangle(&raw) {
                        let va = block.va + i as u64;
                        out_syms.push(SymbolInfo {
                            va,
                            name: raw,
                            demangled: Some(d),
                        });
                    }
                    i += 4;
                    continue;
                }
            }
            i += 1;
        }
    }
    out_syms.sort_by_key(|s| s.va);
    out_syms.dedup_by_key(|s| s.va);
    let n = out_syms.len();
    Ok(AnalyzerOutput {
        name: "Demangler Microsoft".into(),
        status: "ok".into(),
        message: format!("demangled {n} symbol(s)"),
        symbols: Some(out_syms),
        ..Default::default()
    })
}

fn try_demangle(name: &str) -> Option<String> {
    if name.starts_with(".?A") {
        return Some(demangle_msvc_simple(name));
    }
    if name.starts_with('?') {
        // ?MyFunc@@YAXXZ → MyFunc
        let body = name.trim_start_matches('?');
        let leaf = body.split("@@").next().unwrap_or(body);
        let leaf = leaf.trim_start_matches('?');
        if !leaf.is_empty() && leaf.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Some(leaf.to_string());
        }
    }
    None
}

fn read_cstr(b: &[u8], off: usize) -> Option<String> {
    let end = b[off..].iter().position(|&c| c == 0)?;
    if end == 0 || end > 256 {
        return None;
    }
    let raw = &b[off..off + end];
    if raw.is_ascii() {
        Some(String::from_utf8_lossy(raw).into_owned())
    } else {
        None
    }
}
