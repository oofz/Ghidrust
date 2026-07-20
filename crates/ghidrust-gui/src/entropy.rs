//! Ghidrust GUI · Entropy strip + Overview banner.
//!
//! Renders the `` and `` header strips as
//! horizontal color bars sampled from executable memory blocks. Entropy is
//! computed via `ghidrust-core::bulk_scan::entropy_windows_seq` (Shannon
//! bits/byte, 0..8) so the strip is real, not fabricated.
//!
//! Extracted per internal modularization notes — new UI panes land here
//! instead of piling into `main.rs`.

use eframe::egui::{self, Color32, Rect, Sense, Stroke, StrokeKind, Ui, Vec2};
use ghidrust_core::{bulk_scan::entropy_windows_seq, Program};

/// A single sampled window used by the strip visualisations.
#[derive(Debug, Clone, Copy)]
pub struct Sample {
    pub va: u64,
    pub end_va: u64,
    /// Shannon entropy bits/byte in [0.0, 8.0].
    pub entropy: f64,
    /// Fraction of printable-ASCII bytes in the window ([0.0, 1.0]).
    pub ascii_ratio: f32,
}

/// Compute per-block entropy samples across every mapped memory block.
///
/// `window` is bytes per sample. Result is flat,
/// address-ordered, and honest: only mapped bytes are sampled.
pub fn entropy_samples(prog: &Program, window: usize) -> Vec<Sample> {
    let mut out = Vec::new();
    let w = window.max(16);
    for blk in &prog.blocks {
        let ents = entropy_windows_seq(&blk.bytes, w);
        for (i, e) in ents.iter().enumerate() {
            let base = blk.va + (i as u64) * (w as u64);
            let end = (base + w as u64).min(blk.va.saturating_add(blk.size));
            let start_off = (i * w).min(blk.bytes.len());
            let end_off = ((i + 1) * w).min(blk.bytes.len());
            let slice = &blk.bytes[start_off..end_off];
            let ascii = slice
                .iter()
                .filter(|b| (0x20u8..0x7Fu8).contains(*b) || matches!(**b, 0x09 | 0x0A | 0x0D))
                .count();
            let ratio = if slice.is_empty() {
                0.0
            } else {
                ascii as f32 / slice.len() as f32
            };
            out.push(Sample {
                va: base,
                end_va: end,
                entropy: *e,
                ascii_ratio: ratio,
            });
        }
    }
    out
}

/// Palette helper — map an entropy value to a color ramp.
pub fn entropy_color(e: f64) -> Color32 {
    // Cold (blue) → high entropy warm (red).
    let t = (e / 8.0).clamp(0.0, 1.0) as f32;
    let r = (t * 220.0) as u8;
    let g = ((1.0 - (t - 0.5).abs() * 2.0).max(0.0) * 180.0) as u8;
    let b = ((1.0 - t) * 220.0) as u8;
    Color32::from_rgb(r, g, b)
}

/// Overview banner palette — code (X) = green, data (RW) = cyan, RO = grey,
/// unmapped = dark. Uses per-block RWX flags plus ASCII ratio to pick a hue.
pub fn overview_color(prog: &Program, s: &Sample) -> Color32 {
    let blk = prog
        .blocks
        .iter()
        .find(|b| s.va >= b.va && s.va < b.va.saturating_add(b.size));
    match blk {
        Some(b) if b.executable => {
            if s.ascii_ratio > 0.9 {
                // Executable but almost all ASCII — likely misclassified data.
                Color32::from_rgb(0x03, 0xA9, 0xF4)
            } else {
                Color32::from_rgb(0x4C, 0xAF, 0x50)
            }
        }
        Some(b) if b.writable => Color32::from_rgb(0xFB, 0xC0, 0x2D),
        Some(_) => Color32::from_rgb(0x9E, 0x9E, 0x9E),
        None => Color32::from_gray(60),
    }
}

/// Render the entropy strip. Returns the clicked VA (start of the sample) or None.
pub fn render_entropy_strip(
    ui: &mut Ui,
    samples: &[Sample],
    muted: Color32,
    focused_va: Option<u64>,
    primary: Color32,
) -> Option<u64> {
    if samples.is_empty() {
        ui.label(
            egui::RichText::new("No mapped memory — load a program to see entropy.").color(muted),
        );
        return None;
    }
    let avail = ui.available_width();
    let strip_h = 24.0f32;
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(avail, strip_h), Sense::click());
    let painter = ui.painter();
    let per = (avail / samples.len() as f32).max(1.0);
    for (i, s) in samples.iter().enumerate() {
        let x = rect.min.x + i as f32 * per;
        let r = Rect::from_min_size(egui::pos2(x, rect.min.y), Vec2::new(per, strip_h));
        painter.rect_filled(r, 0.0, entropy_color(s.entropy));
    }
    // Focus cursor line.
    if let Some(va) = focused_va {
        if let Some((i, _)) = samples
            .iter()
            .enumerate()
            .find(|(_, s)| va >= s.va && va < s.end_va)
        {
            let x = rect.min.x + (i as f32 + 0.5) * per;
            painter.line_segment(
                [egui::pos2(x, rect.min.y), egui::pos2(x, rect.max.y)],
                Stroke::new(1.5, primary),
            );
        }
    }
    painter.rect(
        rect,
        0.0,
        Color32::TRANSPARENT,
        Stroke::new(1.0, muted),
        StrokeKind::Middle,
    );

    if let Some(pos) = resp.interact_pointer_pos() {
        let idx = ((pos.x - rect.min.x) / per).floor() as usize;
        return samples.get(idx).map(|s| s.va);
    }
    None
}

/// Render the Overview banner (memory-block colour map).
pub fn render_overview_strip(
    ui: &mut Ui,
    prog: &Program,
    samples: &[Sample],
    muted: Color32,
    focused_va: Option<u64>,
    primary: Color32,
) -> Option<u64> {
    if samples.is_empty() {
        return None;
    }
    let avail = ui.available_width();
    let strip_h = 16.0f32;
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(avail, strip_h), Sense::click());
    let painter = ui.painter();
    let per = (avail / samples.len() as f32).max(1.0);
    for (i, s) in samples.iter().enumerate() {
        let x = rect.min.x + i as f32 * per;
        let r = Rect::from_min_size(egui::pos2(x, rect.min.y), Vec2::new(per, strip_h));
        painter.rect_filled(r, 0.0, overview_color(prog, s));
    }
    if let Some(va) = focused_va {
        if let Some((i, _)) = samples
            .iter()
            .enumerate()
            .find(|(_, s)| va >= s.va && va < s.end_va)
        {
            let x = rect.min.x + (i as f32 + 0.5) * per;
            painter.line_segment(
                [egui::pos2(x, rect.min.y), egui::pos2(x, rect.max.y)],
                Stroke::new(1.5, primary),
            );
        }
    }
    painter.rect(
        rect,
        0.0,
        Color32::TRANSPARENT,
        Stroke::new(1.0, muted),
        StrokeKind::Middle,
    );
    if let Some(pos) = resp.interact_pointer_pos() {
        let idx = ((pos.x - rect.min.x) / per).floor() as usize;
        return samples.get(idx).map(|s| s.va);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidrust_core::{fixture_path, load_path};

    #[test]
    fn entropy_samples_are_bounded_and_ordered() {
        let prog = load_path(fixture_path("tiny_x64.pe")).unwrap();
        let s = entropy_samples(&prog, 256);
        assert!(!s.is_empty());
        for w in s.windows(2) {
            assert!(w[0].va <= w[1].va);
            assert!(w[0].entropy >= 0.0 && w[0].entropy <= 8.0001);
            assert!(w[0].ascii_ratio >= 0.0 && w[0].ascii_ratio <= 1.0);
        }
    }

    #[test]
    fn entropy_color_ramp_bounds() {
        let lo = entropy_color(0.0);
        let hi = entropy_color(8.0);
        assert!(lo != hi);
    }
}
