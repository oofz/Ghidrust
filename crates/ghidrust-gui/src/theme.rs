//! egui Style/Visuals compiler for [`ghidrust_core::ThemeSpec`] packs.
//!
//! One path for every appearance — swap designs by editing packs in
//! `ghidrust_core::theme_spec`, not by forking this file.

use eframe::egui::{self, Color32, Margin, Shadow, Visuals};
use ghidrust_core::{
    theme_spec, theme_tokens, ActiveFg, ActiveFill, AppearanceTheme, ElevationShadow, HoverFill,
    M3Tokens, ThemeMode, ThemeSpec,
};

/// Resolve color tokens for the given appearance + mode.
pub fn tokens(appearance: AppearanceTheme, theme: ThemeMode) -> M3Tokens {
    theme_tokens(appearance, theme)
}

/// Resolve the full theme pack (colors + density + state layers + elevation + motion).
pub fn spec(appearance: AppearanceTheme, theme: ThemeMode) -> ThemeSpec {
    theme_spec(appearance, theme)
}

/// Whether egui should start from dark visuals for this appearance + mode.
pub fn prefers_dark_visuals(appearance: AppearanceTheme, theme: ThemeMode) -> bool {
    theme_spec(appearance, theme).dark_base
}

fn margin_xy(xy: [f32; 2]) -> Margin {
    Margin::symmetric(xy[0] as i8, xy[1] as i8)
}

/// Compile a [`ThemeSpec`] into egui visuals + spacing (appearance-agnostic).
pub fn apply_spec(ctx: &egui::Context, spec: &ThemeSpec) {
    let t = &spec.colors;
    let d = &spec.density;
    let mut v = if spec.dark_base {
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

    v.widgets.hovered.bg_fill = match spec.state_layers.hover {
        HoverFill::PrimaryGamma(g) => rgb(t.primary).gamma_multiply(g),
        HoverFill::PrimaryContainerGamma(g) => rgb(t.primary_container).gamma_multiply(g),
        HoverFill::SurfaceBright => rgb(t.surface_bright),
    };
    v.widgets.hovered.bg_stroke = egui::Stroke::new(t.stroke_width, rgb(t.secondary));
    v.widgets.hovered.corner_radius = corner;

    v.widgets.active.bg_fill = match spec.state_layers.active {
        ActiveFill::Primary => rgb(t.primary),
        ActiveFill::PrimaryGamma(g) => rgb(t.primary).gamma_multiply(g),
    };
    v.widgets.active.fg_stroke = egui::Stroke::new(
        1.0,
        match spec.state_layers.active_fg {
            ActiveFg::OnPrimary => rgb(t.on_primary),
            ActiveFg::OnSurface => rgb(t.on_surface),
        },
    );
    v.widgets.active.corner_radius = corner;
    v.widgets.open.bg_fill = rgb(t.surface_container_high);
    v.widgets.open.corner_radius = corner;

    v.panel_fill = rgb(t.surface);
    v.window_fill = rgb(t.surface_container);
    v.window_stroke = egui::Stroke::new(t.stroke_width, rgb(t.outline_variant));
    v.extreme_bg_color = rgb(t.surface_dim);
    v.faint_bg_color = rgb(t.surface_container_low);
    v.code_bg_color = rgb(t.surface_container_lowest);
    v.selection.bg_fill = rgb(t.primary).gamma_multiply(spec.state_layers.selection_primary_gamma);
    v.hyperlink_color = rgb(t.primary);
    v.warn_fg_color = rgb(t.error);
    v.error_fg_color = rgb(t.error);
    v.window_corner_radius = corner;
    v.menu_corner_radius = corner;

    v.popup_shadow = match spec.elevation.popup_shadow {
        ElevationShadow::None => Shadow::NONE,
        ElevationShadow::Level2 => Shadow {
            offset: [0, 2],
            blur: 8,
            spread: 0,
            color: Color32::from_black_alpha(40),
        },
        ElevationShadow::Stock => v.popup_shadow,
    };

    ctx.set_visuals(v);
    ctx.style_mut(|s| {
        s.interaction.resize_grab_radius_side = d.resize_grab_radius;
        s.spacing.item_spacing = egui::vec2(d.item_spacing[0], d.item_spacing[1]);
        s.spacing.button_padding = egui::vec2(d.button_padding[0], d.button_padding[1]);
        s.spacing.window_margin = margin_xy(d.window_margin);
        s.spacing.menu_margin = margin_xy(d.menu_margin);
        s.spacing.indent = d.indent;
        s.spacing.interact_size.y = d.control_min_height;
        s.spacing.icon_width = d.icon_sm;
        s.spacing.icon_spacing = d.space_sm;
        s.animation_time = spec.motion.animation_time;
    });
}

/// Apply the theme pack for `appearance` + `theme` to the egui context.
pub fn apply(ctx: &egui::Context, appearance: AppearanceTheme, theme: ThemeMode) {
    apply_spec(ctx, &spec(appearance, theme));
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

    #[test]
    fn apply_spec_is_appearance_agnostic() {
        let _ = spec(AppearanceTheme::ClassicGhidrust, ThemeMode::Dark);
        let _ = spec(AppearanceTheme::Modern, ThemeMode::Light);
        let _ = spec(AppearanceTheme::FutureConsole, ThemeMode::Dark);
    }

    #[test]
    fn density_fib_values_wired() {
        let d = spec(AppearanceTheme::ClassicGhidrust, ThemeMode::Dark).density;
        assert_eq!(d.window_margin, [13.0, 13.0]);
        assert_eq!(d.menu_margin, [8.0, 5.0]);
        assert_eq!(d.indent, 13.0);
        assert_eq!(d.resize_grab_radius, 13.0);
    }
}
