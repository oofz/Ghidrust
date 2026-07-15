//! C++ RTTI recovery (Microsoft-style + string-scan fallback for Itanium-ish names).
//! Hand-rolled structure walk over the loaded program model.

use crate::error::Result;
use crate::program::Program;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RttiClass {
    pub name: String,
    /// VA of type_info / TypeDescriptor
    pub type_info_va: Option<u64>,
    /// VA of vtable (first function pointer slot) when recovered
    pub vtable_va: Option<u64>,
    /// VA of RTTICompleteObjectLocator when present
    pub col_va: Option<u64>,
    pub kind: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RttiReport {
    pub classes: Vec<RttiClass>,
    pub notes: Vec<String>,
}

/// Recover RTTI from a loaded program.
pub fn recover_rtti(prog: &Program) -> Result<RttiReport> {
    let mut report = RttiReport::default();

    // 1) Scan for MSVC decorated type names: .?AV...@@ or .?AU...@@
    let msvc_hits = scan_msvc_type_names(prog);
    for (va, name) in &msvc_hits {
        report.classes.push(RttiClass {
            name: demangle_msvc_simple(name),
            type_info_va: Some(*va),
            vtable_va: None,
            col_va: None,
            kind: "msvc_type_descriptor".into(),
        });
    }

    // 2) Link COL → type descriptor → vtable (PE image-relative, 32-bit fields)
    link_msvc_col(prog, &mut report);

    // 3) Itanium-style: _ZTS / _ZTV mangled fragments in rodata
    let itanium = scan_itanium_typeinfo_names(prog);
    for (va, name) in itanium {
        if report.classes.iter().any(|c| c.name == name) {
            continue;
        }
        report.classes.push(RttiClass {
            name,
            type_info_va: Some(va),
            vtable_va: None,
            col_va: None,
            kind: "itanium_typeinfo_name".into(),
        });
    }

    if report.classes.is_empty() {
        report
            .notes
            .push("no RTTI class names recovered".into());
    } else {
        report.notes.push(format!(
            "recovered {} class record(s)",
            report.classes.len()
        ));
    }
    Ok(report)
}

/// MSVC TypeDescriptor name field holds ".?AVFoo@@" etc.
fn scan_msvc_type_names(prog: &Program) -> Vec<(u64, String)> {
    let mut hits = Vec::new();
    for block in &prog.blocks {
        let b = &block.bytes;
        let mut i = 0;
        while i + 4 < b.len() {
            // look for ".?AV" or ".?AU" or ".?AE"
            if b[i] == b'.' && b[i + 1] == b'?' && b[i + 2] == b'A' {
                let tag = b[i + 3];
                if matches!(tag, b'V' | b'U' | b'E') {
                    if let Some(s) = read_cstr(b, i) {
                        if s.ends_with("@@") && s.len() > 5 && s.len() < 512 {
                            hits.push((block.va + i as u64, s));
                            i += 4;
                            continue;
                        }
                    }
                }
            }
            i += 1;
        }
    }
    hits
}

fn read_cstr(b: &[u8], off: usize) -> Option<String> {
    if off >= b.len() {
        return None;
    }
    let end = b[off..].iter().position(|&c| c == 0)?;
    if end == 0 || end > 512 {
        return None;
    }
    let raw = &b[off..off + end];
    if !raw.is_ascii() {
        return None;
    }
    Some(String::from_utf8_lossy(raw).into_owned())
}

/// ".?AVMyClass@@" → "MyClass" (simple undname subset)
pub fn demangle_msvc_simple(decorated: &str) -> String {
    let s = decorated
        .strip_prefix(".?AV")
        .or_else(|| decorated.strip_prefix(".?AU"))
        .or_else(|| decorated.strip_prefix(".?AE"))
        .unwrap_or(decorated);
    let s = s.strip_suffix("@@").unwrap_or(s);
    // Nested: may contain @ separators — keep last segment as leaf name if simple
    if s.contains('@') {
        // e.g. Foo@Bar@@ style — for MVP join with :: reverse
        let parts: Vec<&str> = s.split('@').filter(|p| !p.is_empty()).collect();
        if parts.len() > 1 {
            return parts.iter().rev().cloned().collect::<Vec<_>>().join("::");
        }
    }
    s.to_string()
}

/// Walk for Complete Object Locators: signature 1 (x64) or 0 (x86), pTypeDescriptor points at name-4-ish.
fn link_msvc_col(prog: &Program, report: &mut RttiReport) {
    let image_base = prog.image_base;
    // COL layout (x64):
    // u32 signature; u32 offset; u32 cdOffset; u32 pTypeDescriptor (RVA); u32 pClassDescriptor (RVA); u32 pSelf (RVA)
    for block in &prog.blocks {
        let b = &block.bytes;
        if b.len() < 24 {
            continue;
        }
        let mut i = 0;
        while i + 24 <= b.len() {
            let sig = u32::from_le_bytes(b[i..i + 4].try_into().unwrap());
            if sig > 1 {
                i += 4;
                continue;
            }
            let p_td = u32::from_le_bytes(b[i + 12..i + 16].try_into().unwrap()) as u64;
            let p_self = u32::from_le_bytes(b[i + 20..i + 24].try_into().unwrap()) as u64;
            let col_rva = (block.va + i as u64).wrapping_sub(image_base);
            // pSelf should equal COL RVA for x64 COL
            if sig == 1 && p_self != col_rva {
                i += 4;
                continue;
            }
            let td_va = image_base.wrapping_add(p_td);
            // TypeDescriptor: vfptr (8) + spare (8) + name on x64
            if let Some(name_bytes) = prog.read_va(td_va + 16, 64) {
                if name_bytes.starts_with(b".?A") {
                    if let Some(decorated) = read_cstr(&name_bytes, 0) {
                        let name = demangle_msvc_simple(&decorated);
                        let col_va = block.va + i as u64;
                        // vtable is often at COL_va + sizeof(COL) aligned, or pointer just after COL reference
                        // Heuristic: 8 bytes before a pointer to this COL is start of object; vtable at that ptr
                        let vtable_va = find_vtable_for_col(prog, col_va);

                        if let Some(cls) = report
                            .classes
                            .iter_mut()
                            .find(|c| c.type_info_va == Some(td_va) || c.name == name)
                        {
                            cls.col_va = Some(col_va);
                            cls.type_info_va = Some(td_va);
                            if cls.vtable_va.is_none() {
                                cls.vtable_va = vtable_va;
                            }
                            cls.kind = "msvc_col".into();
                        } else {
                            report.classes.push(RttiClass {
                                name,
                                type_info_va: Some(td_va),
                                vtable_va,
                                col_va: Some(col_va),
                                kind: "msvc_col".into(),
                            });
                        }
                    }
                }
            }
            i += 4;
        }
    }
}

fn find_vtable_for_col(prog: &Program, col_va: u64) -> Option<u64> {
    // Search for a pointer-sized value equal to col_va; vtable starts at that address.
    for block in &prog.blocks {
        let b = &block.bytes;
        let mut off = 0;
        while off + 8 <= b.len() {
            let val = u64::from_le_bytes(b[off..off + 8].try_into().unwrap());
            if val == col_va {
                // On MSVC x64, the COL pointer sits at vtable[-1]; first virtfn at this+8? 
                // Actually: object.vfptr -> vtable[0] which is first function; COL is at vfptr[-1].
                // So the pointer we found is at address A where *A == col; vtable starts at A+8.
                return Some(block.va + off as u64 + 8);
            }
            off += 8; // align scan
        }
    }
    None
}

fn scan_itanium_typeinfo_names(prog: &Program) -> Vec<(u64, String)> {
    let mut hits = Vec::new();
    for block in &prog.blocks {
        let b = &block.bytes;
        let mut i = 0;
        while i + 4 < b.len() {
            // _ZTS... null-terminated typeinfo name strings
            if b[i] == b'_' && b.get(i + 1) == Some(&b'Z') && b.get(i + 2) == Some(&b'T') && b.get(i + 3) == Some(&b'S')
            {
                if let Some(s) = read_cstr(b, i) {
                    if s.len() > 4 && s.len() < 256 {
                        let pretty = demangle_itanium_type_name(&s);
                        hits.push((block.va + i as u64, pretty));
                    }
                }
            }
            i += 1;
        }
    }
    hits
}

/// Minimal _ZTS length-name demangle: _ZTS3Foo → Foo; _ZTSN3Bar3BazE → Bar::Baz (best-effort)
pub fn demangle_itanium_type_name(s: &str) -> String {
    let body = s.strip_prefix("_ZTS").unwrap_or(s);
    parse_itanium_name(body).unwrap_or_else(|| s.to_string())
}

fn parse_itanium_name(mut body: &str) -> Option<String> {
    if body.starts_with('N') {
        body = &body[1..];
        let mut parts = Vec::new();
        while !body.is_empty() && !body.starts_with('E') {
            let (n, rest) = parse_len_id(body)?;
            parts.push(n);
            body = rest;
        }
        if parts.is_empty() {
            return None;
        }
        return Some(parts.join("::"));
    }
    let (n, _) = parse_len_id(body)?;
    Some(n)
}

fn parse_len_id(s: &str) -> Option<(String, &str)> {
    let mut i = 0;
    while i < s.len() && s.as_bytes()[i].is_ascii_digit() {
        i += 1;
    }
    if i == 0 {
        return None;
    }
    let len: usize = s[..i].parse().ok()?;
    if i + len > s.len() {
        return None;
    }
    Some((s[i..i + len].to_string(), &s[i + len..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demangle_msvc() {
        assert_eq!(demangle_msvc_simple(".?AVWidget@@"), "Widget");
        assert_eq!(demangle_msvc_simple(".?AUPod@@"), "Pod");
    }

    #[test]
    fn demangle_itanium() {
        assert_eq!(demangle_itanium_type_name("_ZTS3Foo"), "Foo");
    }
}
