//! Hand-rolled capture file layout: magic + length-prefixed JSON frames.

use ghidrust_net_flow::Frame;
use std::path::Path;

pub const CAPTURE_MAGIC: &[u8; 8] = b"GRNCAP01";

pub fn write_frames(path: &Path, frames: &[Frame]) -> Result<(), String> {
    let mut out = Vec::new();
    out.extend_from_slice(CAPTURE_MAGIC);
    for f in frames {
        let blob = serde_json::to_vec(f).map_err(|e| e.to_string())?;
        out.extend_from_slice(&(blob.len() as u32).to_le_bytes());
        out.extend_from_slice(&blob);
    }
    std::fs::write(path, out).map_err(|e| e.to_string())
}

pub fn read_frames(path: &Path) -> Result<Vec<Frame>, String> {
    let data = std::fs::read(path).map_err(|e| e.to_string())?;
    if data.len() < 8 || &data[..8] != CAPTURE_MAGIC {
        return Err("not a ghidrust capture file".into());
    }
    let mut out = Vec::new();
    let mut i = 8;
    while i + 4 <= data.len() {
        let n = u32::from_le_bytes(data[i..i + 4].try_into().unwrap()) as usize;
        i += 4;
        if i + n > data.len() {
            break;
        }
        let f: Frame = serde_json::from_slice(&data[i..i + n]).map_err(|e| e.to_string())?;
        out.push(f);
        i += n;
    }
    Ok(out)
}
