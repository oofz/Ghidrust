//! Install a terminal-capable monospace font so Grok's logo / box-drawing
//! glyphs are not tofu (▯).
//!
//! egui's built-in ProggyClean covers little beyond ASCII. Grok Build's TUI
//! uses Unicode block elements, box drawing, and often braille half-tone art
//! — those need Cascadia / Consolas / a symbols fallback.

use eframe::egui::{FontData, FontDefinitions, FontFamily};
use std::path::PathBuf;

/// Prefer these system fonts (first existing file wins as primary monospace).
fn candidate_mono_paths() -> Vec<PathBuf> {
    let mut out = Vec::new();
    #[cfg(windows)]
    {
        if let Ok(windir) = std::env::var("WINDIR") {
            let fonts = PathBuf::from(windir).join("Fonts");
            for name in [
                "CascadiaMono.ttf",
                "cascadiamono.ttf",
                "CascadiaCode.ttf",
                "consola.ttf",
                "cour.ttf",
                "lucon.ttf", // Lucida Console
            ] {
                out.push(fonts.join(name));
            }
            // Symbol / emoji coverage for leftover glyphs.
            out.push(fonts.join("seguisym.ttf")); // Segoe UI Symbol
            out.push(fonts.join("seguiemj.ttf")); // Segoe UI Emoji
            out.push(fonts.join("msyh.ttc")); // Microsoft YaHei (CJK + some symbols)
        }
    }
    #[cfg(target_os = "macos")]
    {
        out.push(PathBuf::from("/System/Library/Fonts/Menlo.ttc"));
        out.push(PathBuf::from(
            "/System/Library/Fonts/Supplemental/Courier New.ttf",
        ));
        out.push(PathBuf::from("/System/Library/Fonts/Apple Symbols.ttf"));
    }
    #[cfg(target_os = "linux")]
    {
        for p in [
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
            "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
            "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
            "/usr/share/fonts/truetype/noto/NotoSansMono-Regular.ttf",
        ] {
            out.push(PathBuf::from(p));
        }
    }
    out
}

/// Replace egui's default monospace with a system terminal font + symbol fallbacks.
///
/// Safe to call once at app start. No-op (keeps defaults) if no candidate loads.
pub fn install_terminal_fonts(ctx: &eframe::egui::Context) {
    let mut fonts = FontDefinitions::default();
    let mut loaded: Vec<String> = Vec::new();

    for path in candidate_mono_paths() {
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        // Skip tiny/invalid reads.
        if bytes.len() < 1024 {
            continue;
        }
        let key = format!(
            "term_{}",
            path.file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("font")
                .to_ascii_lowercase()
        );
        if fonts.font_data.contains_key(&key) {
            continue;
        }
        fonts
            .font_data
            .insert(key.clone(), FontData::from_owned(bytes).into());
        loaded.push(key);
    }

    if loaded.is_empty() {
        return;
    }

    // Primary mono = first candidate; remaining act as fallbacks for missing glyphs.
    let mono = fonts.families.entry(FontFamily::Monospace).or_default();
    // Put our fonts first; keep egui defaults after as last resort.
    let mut rest = mono.clone();
    mono.clear();
    for k in &loaded {
        mono.push(k.clone());
    }
    for k in rest.drain(..) {
        if !mono.contains(&k) {
            mono.push(k);
        }
    }

    // Also prepend to Proportional so UI chrome can fall back if needed.
    let prop = fonts.families.entry(FontFamily::Proportional).or_default();
    for k in loaded.iter().rev() {
        if !prop.contains(k) {
            prop.insert(0, k.clone());
        }
    }

    ctx.set_fonts(fonts);
}
