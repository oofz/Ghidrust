//! Google Material Design / Material 3 icon SVGs (24×24 viewBox), painted with egui.
//! Source paths: https://github.com/google/material-design-icons (Apache-2.0).
//! No emoji. No extra icon crates — paths are inlined and stroked/filled via Painter.

use eframe::egui::{self, Color32, Pos2, Rect, Sense, Stroke, Ui, Vec2};

/// Material Icons 24dp viewBox.
const VB: f32 = 24.0;

#[derive(Clone, Copy)]
pub enum M3Icon {
    /// material: folder
    Folder,
    /// material: check_circle (filled check for "analyzed")
    CheckCircle,
    /// material: radio_button_unchecked (hollow for "not analyzed")
    RadioUnchecked,
    /// material: play_arrow (active / current file)
    PlayArrow,
}

/// Paint a Material 3 icon at the cursor; advances UI by `size`.
pub fn m3_icon(ui: &mut Ui, icon: M3Icon, size: f32, color: Color32) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    if ui.is_rect_visible(rect) {
        paint_icon(ui.painter(), rect, icon, color);
    }
    response
}

fn paint_icon(painter: &egui::Painter, rect: Rect, icon: M3Icon, color: Color32) {
    let s = rect.width().min(rect.height());
    let origin = rect.center() - Vec2::splat(s * 0.5);
    let map = |x: f32, y: f32| -> Pos2 {
        Pos2::new(origin.x + x / VB * s, origin.y + y / VB * s)
    };
    let stroke = Stroke::new((s / VB) * 1.75, color);

    match icon {
        M3Icon::Folder => {
            // Path: M10 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z
            let pts = [
                map(10.0, 4.0),
                map(4.0, 4.0),
                map(2.0, 6.0),
                map(2.0, 18.0),
                map(4.0, 20.0),
                map(20.0, 20.0),
                map(22.0, 18.0),
                map(22.0, 8.0),
                map(20.0, 6.0),
                map(12.0, 6.0),
                map(10.0, 4.0),
            ];
            painter.add(egui::Shape::convex_polygon(pts.to_vec(), color.gamma_multiply(0.35), stroke));
        }
        M3Icon::CheckCircle => {
            // Outer circle fill + check mark
            let c = map(12.0, 12.0);
            let r = (s / VB) * 9.0;
            painter.circle_filled(c, r, color);
            // check: (9,12) -> (11,14) -> (16,9)  — white on colored circle
            let ink = if color.r() as u16 + color.g() as u16 + color.b() as u16 > 400 {
                Color32::from_rgb(0x1C, 0x1B, 0x1F)
            } else {
                Color32::from_rgb(0xFF, 0xFB, 0xFE)
            };
            let check_stroke = Stroke::new((s / VB) * 2.0, ink);
            painter.line_segment([map(9.0, 12.0), map(11.0, 14.5)], check_stroke);
            painter.line_segment([map(11.0, 14.5), map(16.0, 9.0)], check_stroke);
        }
        M3Icon::RadioUnchecked => {
            let c = map(12.0, 12.0);
            let r = (s / VB) * 8.5;
            painter.circle_stroke(c, r, stroke);
        }
        M3Icon::PlayArrow => {
            // Triangle pointing right: (8,5) (8,19) (19,12)
            let pts = [map(8.0, 5.0), map(8.0, 19.0), map(19.0, 12.0)];
            painter.add(egui::Shape::convex_polygon(pts.to_vec(), color, Stroke::NONE));
        }
    }
}

/// Material 3 linear progress indicator (4dp track + primary fill).
pub fn m3_linear_progress(ui: &mut Ui, fraction: f32, primary: Color32, track: Color32) {
    let height = 4.0;
    let width = ui.available_width().max(40.0);
    let (rect, _) = ui.allocate_exact_size(Vec2::new(width, height), Sense::hover());
    ui.painter()
        .rect_filled(rect, egui::CornerRadius::same(2), track);
    let f = fraction.clamp(0.0, 1.0);
    if f > 0.0 {
        let mut fill = rect;
        fill.set_width((rect.width() * f).max(if f > 0.0 { 2.0 } else { 0.0 }));
        ui.painter()
            .rect_filled(fill, egui::CornerRadius::same(2), primary);
    }
}

/// Status row: Material check_circle or radio_button_unchecked + label text (no emoji).
pub fn status_badge(ui: &mut Ui, analyzed: bool, analyzed_color: Color32, muted: Color32) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 4.0;
        if analyzed {
            m3_icon(ui, M3Icon::CheckCircle, 14.0, analyzed_color);
            ui.label(egui::RichText::new("Analyzed").small().color(analyzed_color));
        } else {
            m3_icon(ui, M3Icon::RadioUnchecked, 14.0, muted);
            ui.label(egui::RichText::new("Not analyzed").small().color(muted));
        }
    });
}
