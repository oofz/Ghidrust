//! Generic PE install inventory: VERSIONINFO + exe/dll catalog (hand-rolled).

use crate::error::{Error, Result};
use crate::pe;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct VersionInfo {
    pub file_version: Option<String>,
    pub product_version: Option<String>,
    pub product_name: Option<String>,
    pub file_description: Option<String>,
    pub company_name: Option<String>,
    pub original_filename: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeInventoryEntry {
    pub path: String,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default)]
    pub version: VersionInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeInventory {
    pub schema_version: u32,
    pub root: String,
    pub entries: Vec<PeInventoryEntry>,
    pub notes: Vec<String>,
}

pub const PE_INVENTORY_SCHEMA: u32 = 1;

/// Parse VS_VERSION_INFO string-file-info from PE bytes (best-effort).
pub fn parse_version_info(data: &[u8]) -> VersionInfo {
    let mut info = VersionInfo::default();
    if !pe::is_pe(data) {
        return info;
    }
    // Locate UTF-16LE "VS_VERSION_INFO"
    let needle = wide("VS_VERSION_INFO");
    let Some(pos) = find_bytes(data, &needle) else {
        return info;
    };
    // Search a window after the marker for StringFileInfo key/value pairs.
    let window_end = (pos + 0x4000).min(data.len());
    let window = &data[pos..window_end];
    info.file_version = find_version_string(window, "FileVersion");
    info.product_version = find_version_string(window, "ProductVersion");
    info.product_name = find_version_string(window, "ProductName");
    info.file_description = find_version_string(window, "FileDescription");
    info.company_name = find_version_string(window, "CompanyName");
    info.original_filename = find_version_string(window, "OriginalFilename");
    info
}

/// Read VERSIONINFO from a PE path.
pub fn version_info_path(path: impl AsRef<Path>) -> Result<VersionInfo> {
    let data = fs::read(path.as_ref()).map_err(|e| Error::Io(e.to_string()))?;
    Ok(parse_version_info(&data))
}

fn wide(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 2);
    for c in s.encode_utf16() {
        out.extend_from_slice(&c.to_le_bytes());
    }
    out
}

fn find_bytes(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

fn find_version_string(window: &[u8], key: &str) -> Option<String> {
    let key_w = wide(key);
    let mut search_from = 0;
    while let Some(rel) = find_bytes(&window[search_from..], &key_w) {
        let abs = search_from + rel;
        // Value typically follows key + NUL + padding to DWORD, as UTF-16LE.
        let after_key = abs + key_w.len();
        // Skip UTF-16 NUL
        let mut p = after_key;
        if p + 2 <= window.len() && window[p] == 0 && window[p + 1] == 0 {
            p += 2;
        }
        // Align to 4
        while p % 4 != 0 && p < window.len() {
            p += 1;
        }
        if let Some(val) = read_utf16_z(window, p) {
            if !val.is_empty() && val.len() < 512 {
                return Some(val);
            }
        }
        search_from = abs + 2;
    }
    None
}

fn read_utf16_z(data: &[u8], off: usize) -> Option<String> {
    if off >= data.len() {
        return None;
    }
    let mut units = Vec::new();
    let mut i = off;
    while i + 1 < data.len() {
        let u = u16::from_le_bytes([data[i], data[i + 1]]);
        i += 2;
        if u == 0 {
            break;
        }
        if units.len() > 512 {
            return None;
        }
        units.push(u);
    }
    if units.is_empty() {
        return None;
    }
    String::from_utf16(&units).ok()
}

fn is_pe_name(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| {
            let el = e.to_ascii_lowercase();
            el == "exe" || el == "dll" || el == "sys" || el == "scr"
        })
        .unwrap_or(false)
}

/// Walk `root` for exe/dll (and friends); attach VERSIONINFO when parseable.
/// Optional `hash` computes sha256 (slow on large trees — off by default).
pub fn inventory_pe_dir(
    root: impl AsRef<Path>,
    max_depth: usize,
    with_hash: bool,
) -> Result<PeInventory> {
    let root = root.as_ref();
    if !root.is_dir() {
        return Err(Error::Io(format!("not a directory: {}", root.display())));
    }
    let mut entries = Vec::new();
    let mut notes = Vec::new();
    walk_pe(
        root,
        root,
        0,
        max_depth,
        with_hash,
        &mut entries,
        &mut notes,
    );
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(PeInventory {
        schema_version: PE_INVENTORY_SCHEMA,
        root: root.display().to_string(),
        entries,
        notes,
    })
}

fn walk_pe(
    root: &Path,
    dir: &Path,
    depth: usize,
    max_depth: usize,
    with_hash: bool,
    out: &mut Vec<PeInventoryEntry>,
    notes: &mut Vec<String>,
) {
    if depth > max_depth {
        return;
    }
    let rd = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) => {
            notes.push(format!("skip {}: {e}", dir.display()));
            return;
        }
    };
    for ent in rd.flatten() {
        let path = ent.path();
        let meta = match ent.metadata() {
            Ok(m) => m,
            Err(e) => {
                notes.push(format!("stat {}: {e}", path.display()));
                continue;
            }
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            walk_pe(root, &path, depth + 1, max_depth, with_hash, out, notes);
            continue;
        }
        if !is_pe_name(&path) {
            continue;
        }
        let size = meta.len();
        let mut version = VersionInfo::default();
        let mut error = None;
        let mut sha256 = None;
        match fs::read(&path) {
            Ok(data) => {
                if pe::is_pe(&data) {
                    version = parse_version_info(&data);
                    if with_hash {
                        sha256 = Some(simple_sha256_hex(&data));
                    }
                } else {
                    error = Some("not_pe".into());
                }
            }
            Err(e) => error = Some(format!("io:{e}")),
        }
        out.push(PeInventoryEntry {
            path: path.display().to_string(),
            size,
            sha256,
            version,
            error,
        });
    }
}

/// Minimal FNV-independent hex digest without extra crates — use std only via a tiny hasher.
/// Prefer real sha2 when available from callers; here we ship a hand-rolled SHA-256.
fn simple_sha256_hex(data: &[u8]) -> String {
    sha256_hex(data)
}

// --- Hand-rolled SHA-256 (no external crate) ---

fn sha256_hex(data: &[u8]) -> String {
    let dig = sha256(data);
    let mut s = String::with_capacity(64);
    for b in dig {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn sha256(msg: &[u8]) -> [u8; 32] {
    // Standard SHA-256
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let bit_len = (msg.len() as u64).saturating_mul(8);
    let mut buf = msg.to_vec();
    buf.push(0x80);
    while (buf.len() % 64) != 56 {
        buf.push(0);
    }
    buf.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in buf.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

/// Helper for Unity inventory: VERSIONINFO for a single path (best-effort).
pub fn version_info_for_file(path: &Path) -> VersionInfo {
    version_info_path(path).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture_path;

    #[test]
    fn version_info_on_fixture_does_not_panic() {
        let path = fixture_path("tiny_x64.pe");
        let _ = version_info_path(&path).unwrap();
    }

    #[test]
    fn inventory_finds_pe_in_dir() {
        let dir = std::env::temp_dir().join(format!("ghidrust-inv-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let pe = fixture_path("tiny_x64.pe");
        let dest = dir.join("tiny.exe");
        fs::copy(&pe, &dest).unwrap();
        let inv = inventory_pe_dir(&dir, 2, false).unwrap();
        assert_eq!(inv.entries.len(), 1);
        assert!(inv.entries[0].path.ends_with("tiny.exe"));
        let _ = fs::remove_dir_all(&dir);
    }
}
