//! egui theme application for Ghidrust appearance + mode.

use eframe::egui::{self, Color32, Visuals};
use ghidrust_core::{theme_tokens, AppearanceTheme, ThemeMode};

/// Resolve color tokens for the given appearance + mode.
pub fn tokens(appearance: AppearanceTheme, theme: ThemeMode) -> ghidrust_core::M3Tokens {
    theme_tokens(appearance, theme)
}

/// Whether egui should start from dark visuals for this appearance + mode.
///
/// Future Console is always a dark CRT/neon panel (both gases).
pub fn prefers_dark_visuals(appearance: AppearanceTheme, theme: ThemeMode) -> bool {
    match (appearance, theme) {
        (AppearanceTheme::FutureConsole, _) => true,
        (_, ThemeMode::Dark) => true,
        (_, ThemeMode::Light) => false,
    }
}

/// Apply Material / console visuals and spacing to the egui context.
pub fn apply(ctx: &egui::Context, appearance: AppearanceTheme, theme: ThemeMode) {
    let t = tokens(appearance, theme);
    // Future Console is always a dark CRT/neon panel (both gases).
    let mut v = if prefers_dark_visuals(appearance, theme) {
        Visuals::dark()
    } else {
        Visuals::light()
    };
    let rgb = |c: [u8; 3]| Color32::from_rgb(c[0], c[1], c[2]);
    let corner = egui::CornerRadius::same(t.corner_radius);
    let stroke = egui::Stroke::new(t.stroke_width, rgb(t.outline));
    v.override_text_color = Some(rgb(t.on_surface));
    v.widgets.noninteractive.bg_fill = rgb(t.surface_container);
    v.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, rgb(t.on_surface));
    v.widgets.noninteractive.corner_radius = corner;
    v.widgets.inactive.bg_fill = rgb(t.surface_container);
    v.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, rgb(t.on_surface));
    v.widgets.inactive.bg_stroke = stroke;
    v.widgets.inactive.corner_radius = corner;
    v.widgets.hovered.bg_fill = match appearance {
        AppearanceTheme::FutureConsole => rgb(t.surface_bright),
        AppearanceTheme::Modern => rgb(t.primary_container).gamma_multiply(0.55),
        AppearanceTheme::ClassicGhidrust => rgb(t.primary).gamma_multiply(0.25),
    };
    v.widgets.hovered.bg_stroke = egui::Stroke::new(t.stroke_width, rgb(t.secondary));
    v.widgets.hovered.corner_radius = corner;
    v.widgets.active.bg_fill = match appearance {
        AppearanceTheme::FutureConsole => rgb(t.primary),
        AppearanceTheme::Modern => rgb(t.primary).gamma_multiply(0.45),
        AppearanceTheme::ClassicGhidrust => rgb(t.primary).gamma_multiply(0.35),
    };
    v.widgets.active.fg_stroke = egui::Stroke::new(
        1.0,
        match appearance {
            AppearanceTheme::FutureConsole => rgb(t.on_primary),
            _ => rgb(t.on_surface),
        },
    );
    v.widgets.active.corner_radius = corner;
    v.widgets.open.bg_fill = rgb(t.surface_container_high);
    v.widgets.open.corner_radius = corner;
    v.panel_fill = rgb(t.surface);
    v.window_fill = rgb(t.surface_container);
    v.extreme_bg_color = rgb(t.surface_dim);
    v.faint_bg_color = rgb(t.surface_container_low);
    v.selection.bg_fill = match appearance {
        AppearanceTheme::FutureConsole => rgb(t.primary).gamma_multiply(0.55),
        _ => rgb(t.primary).gamma_multiply(0.4),
    };
    v.hyperlink_color = rgb(t.primary);
    v.warn_fg_color = rgb(t.error);
    v.window_corner_radius = corner;
    v.menu_corner_radius = corner;
    v.popup_shadow = match appearance {
        AppearanceTheme::FutureConsole => egui::Shadow::NONE,
        AppearanceTheme::Modern => egui::Shadow {
            offset: [0, 2],
            blur: 8,
            spread: 0,
            color: Color32::from_black_alpha(40),
        },
        AppearanceTheme::ClassicGhidrust => v.popup_shadow,
    };
    ctx.set_visuals(v);
    // Wider side/top grab for resizable panels (bottom console drag).
    // Future Console: 4px half-cell spacing (Amber Console --space-1).
    ctx.style_mut(|s| {
        s.interaction.resize_grab_radius_side = 12.0;
        if appearance == AppearanceTheme::FutureConsole {
            s.spacing.item_spacing = egui::vec2(8.0, 8.0);
            s.spacing.button_padding = egui::vec2(22.0, 10.0);
        } else if appearance == AppearanceTheme::Modern {
            s.spacing.item_spacing = egui::vec2(8.0, 8.0);
            s.spacing.button_padding = egui::vec2(16.0, 8.0);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefers_dark_visuals_future_console_light() {
        assert!(prefers_dark_visuals(
            AppearanceTheme::FutureConsole,
            ThemeMode::Light
        ));
    }

    #[test]
    fn prefers_dark_visuals_future_console_dark() {
        assert!(prefers_dark_visuals(
            AppearanceTheme::FutureConsole,
            ThemeMode::Dark
        ));
    }

    #[test]
    fn prefers_dark_visuals_modern_dark() {
        assert!(prefers_dark_visuals(
            AppearanceTheme::Modern,
            ThemeMode::Dark
        ));
    }

    #[test]
    fn prefers_dark_visuals_modern_light() {
        assert!(!prefers_dark_visuals(
            AppearanceTheme::Modern,
            ThemeMode::Light
        ));
    }

    #[test]
    fn prefers_dark_visuals_classic_light() {
        assert!(!prefers_dark_visuals(
            AppearanceTheme::ClassicGhidrust,
            ThemeMode::Light
        ));
    }
}
