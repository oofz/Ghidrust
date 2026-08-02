//! Ghidrust brand assets (window icon + splash logo).

use eframe::egui::{self, ColorImage, IconData, TextureHandle, TextureOptions};

/// Embedded splash / window mark (same art as the Windows `.ico`).
const LOGO_PNG: &[u8] = include_bytes!("../assets/ghidrust.png");

fn decode_rgba() -> Option<(Vec<u8>, u32, u32)> {
    let img = image::load_from_memory(LOGO_PNG).ok()?.into_rgba8();
    let (w, h) = img.dimensions();
    Some((img.into_raw(), w, h))
}

/// Title-bar / taskbar icon for the native window.
pub fn window_icon() -> IconData {
    match decode_rgba() {
        Some((rgba, width, height)) => IconData {
            rgba,
            width,
            height,
        },
        None => IconData::default(),
    }
}

/// Upload the splash logo once into the egui texture atlas.
pub fn load_logo_texture(ctx: &egui::Context) -> Option<TextureHandle> {
    let (rgba, w, h) = decode_rgba()?;
    let color = ColorImage::from_rgba_unmultiplied([w as usize, h as usize], &rgba);
    Some(ctx.load_texture("ghidrust-logo", color, TextureOptions::LINEAR))
}
