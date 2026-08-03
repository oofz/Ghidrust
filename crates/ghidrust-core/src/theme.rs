//! Appearance themes + color tokens (shared for docs/tests; GUI applies via egui).
//!
//! Families:
//! - **Classic Ghidrust** — frozen historical Ghidrust palette (M3-inspired).
//! - **Modern** — Google Material 3 baseline roles (light + dark).
//! - **Future Console** — Amber Console design tokens ported 1:1 (see module notes).

use serde::{Deserialize, Serialize};

/// Light / dark (Classic + Modern). For Future Console: Neon gas / Amber CRT gas.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThemeMode {
    Dark,
    Light,
}

impl ThemeMode {
    pub fn toggle(self) -> Self {
        match self {
            ThemeMode::Dark => ThemeMode::Light,
            ThemeMode::Light => ThemeMode::Dark,
        }
    }
}

/// Selectable appearance family under File → Configure → Appearance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AppearanceTheme {
    /// Historical Ghidrust look (previous default tokens).
    #[default]
    ClassicGhidrust,
    /// Google Material 3 baseline (full role set, light + dark).
    Modern,
    /// Amber Console CRT / neon panel look ([Amber Console](https://dutchdiederik.github.io/AmberConsole/)).
    FutureConsole,
}

impl AppearanceTheme {
    pub const ALL: &[AppearanceTheme] = &[
        AppearanceTheme::ClassicGhidrust,
        AppearanceTheme::Modern,
        AppearanceTheme::FutureConsole,
    ];

    pub fn display_name(self) -> &'static str {
        match self {
            AppearanceTheme::ClassicGhidrust => "Classic Ghidrust",
            AppearanceTheme::Modern => "Modern",
            AppearanceTheme::FutureConsole => "Future Console",
        }
    }

    pub fn id(self) -> &'static str {
        match self {
            AppearanceTheme::ClassicGhidrust => "classic_ghidrust",
            AppearanceTheme::Modern => "modern",
            AppearanceTheme::FutureConsole => "future_console",
        }
    }

    pub fn from_id(s: &str) -> Self {
        match s {
            "modern" => AppearanceTheme::Modern,
            "future_console" | "amber" | "amber_console" => AppearanceTheme::FutureConsole,
            _ => AppearanceTheme::ClassicGhidrust,
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            AppearanceTheme::ClassicGhidrust => {
                "Original Ghidrust CodeBrowser palette (M3-inspired purple)."
            }
            AppearanceTheme::Modern => {
                "Google Material 3 baseline color roles with light and dark schemes."
            }
            AppearanceTheme::FutureConsole => {
                "Amber Console industrial CRT / neon plasma panel (ported design tokens)."
            }
        }
    }

    /// Label for the light/dark (or gas) toggle in the toolbar.
    pub fn mode_label(self, mode: ThemeMode) -> &'static str {
        match (self, mode) {
            (AppearanceTheme::FutureConsole, ThemeMode::Dark) => "Gas: Neon",
            (AppearanceTheme::FutureConsole, ThemeMode::Light) => "Gas: Amber",
            (_, ThemeMode::Dark) => "Theme: Dark",
            (_, ThemeMode::Light) => "Theme: Light",
        }
    }
}

/// Shared sRGB 0–255 tokens consumed by the GUI (`apply_theme` + pane accents).
///
/// Core roles always filled. Extended Material 3 roles are populated for Modern;
/// Classic / Future Console alias them onto the core set so callers stay uniform.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct M3Tokens {
    pub mode: ThemeMode,
    pub appearance: AppearanceTheme,
    pub primary: [u8; 3],
    pub on_primary: [u8; 3],
    pub primary_container: [u8; 3],
    pub on_primary_container: [u8; 3],
    pub secondary: [u8; 3],
    pub on_secondary: [u8; 3],
    pub secondary_container: [u8; 3],
    pub on_secondary_container: [u8; 3],
    pub tertiary: [u8; 3],
    pub on_tertiary: [u8; 3],
    pub tertiary_container: [u8; 3],
    pub on_tertiary_container: [u8; 3],
    pub surface: [u8; 3],
    pub surface_dim: [u8; 3],
    pub surface_bright: [u8; 3],
    pub surface_container_lowest: [u8; 3],
    pub surface_container_low: [u8; 3],
    pub surface_container: [u8; 3],
    pub surface_container_high: [u8; 3],
    pub surface_container_highest: [u8; 3],
    pub on_surface: [u8; 3],
    pub on_surface_variant: [u8; 3],
    pub outline: [u8; 3],
    pub outline_variant: [u8; 3],
    pub error: [u8; 3],
    pub on_error: [u8; 3],
    pub inverse_surface: [u8; 3],
    pub inverse_on_surface: [u8; 3],
    pub inverse_primary: [u8; 3],
    /// Corner radius hint for egui (Classic ≈ 4; Modern ≈ 12; Future Console = 8).
    pub corner_radius: u8,
    /// Stroke width hint (Future Console uses 2px soft-key borders).
    pub stroke_width: f32,
}

/// Resolve tokens for an appearance family + mode.
pub fn theme_tokens(appearance: AppearanceTheme, mode: ThemeMode) -> M3Tokens {
    match appearance {
        AppearanceTheme::ClassicGhidrust => classic_tokens(mode),
        AppearanceTheme::Modern => modern_tokens(mode),
        AppearanceTheme::FutureConsole => future_console_tokens(mode),
    }
}

/// Backward-compatible Classic Ghidrust tokens (mode only).
pub fn m3_tokens(mode: ThemeMode) -> M3Tokens {
    theme_tokens(AppearanceTheme::ClassicGhidrust, mode)
}

fn fill_aliases(
    mode: ThemeMode,
    appearance: AppearanceTheme,
    primary: [u8; 3],
    on_primary: [u8; 3],
    surface: [u8; 3],
    surface_container: [u8; 3],
    on_surface: [u8; 3],
    on_surface_variant: [u8; 3],
    outline: [u8; 3],
    error: [u8; 3],
    corner_radius: u8,
    stroke_width: f32,
) -> M3Tokens {
    M3Tokens {
        mode,
        appearance,
        primary,
        on_primary,
        primary_container: surface_container,
        on_primary_container: on_surface,
        secondary: on_surface_variant,
        on_secondary: surface,
        secondary_container: surface_container,
        on_secondary_container: on_surface,
        tertiary: primary,
        on_tertiary: on_primary,
        tertiary_container: surface_container,
        on_tertiary_container: on_surface,
        surface,
        surface_dim: surface,
        surface_bright: surface_container,
        surface_container_lowest: surface,
        surface_container_low: surface_container,
        surface_container,
        surface_container_high: surface_container,
        surface_container_highest: surface_container,
        on_surface,
        on_surface_variant,
        outline,
        outline_variant: outline,
        error,
        on_error: on_primary,
        inverse_surface: on_surface,
        inverse_on_surface: surface,
        inverse_primary: primary,
        corner_radius,
        stroke_width,
    }
}

/// Classic Ghidrust — exact historical values (do not retune).
fn classic_tokens(mode: ThemeMode) -> M3Tokens {
    match mode {
        ThemeMode::Dark => fill_aliases(
            mode,
            AppearanceTheme::ClassicGhidrust,
            [0xD0, 0xBC, 0xFF],
            [0x38, 0x1E, 0x72],
            [0x14, 0x14, 0x18],
            [0x1C, 0x1B, 0x1F],
            [0xE6, 0xE1, 0xE5],
            [0xCA, 0xC4, 0xD0],
            [0x93, 0x8F, 0x99],
            [0xF2, 0xB8, 0xB5],
            4,
            1.0,
        ),
        ThemeMode::Light => fill_aliases(
            mode,
            AppearanceTheme::ClassicGhidrust,
            [0x67, 0x50, 0xA4],
            [0xFF, 0xFF, 0xFF],
            [0xFF, 0xFB, 0xFE],
            [0xF3, 0xED, 0xF7],
            [0x1C, 0x1B, 0x1F],
            [0x49, 0x45, 0x4F],
            [0x79, 0x74, 0x7E],
            [0xB3, 0x26, 0x1E],
            4,
            1.0,
        ),
    }
}

/// Google Material 3 baseline scheme (seed / primary40 `#6750A4`).
/// Role hexes match Material Components Android baseline tonal assignments.
fn modern_tokens(mode: ThemeMode) -> M3Tokens {
    match mode {
        ThemeMode::Light => M3Tokens {
            mode,
            appearance: AppearanceTheme::Modern,
            primary: [0x67, 0x50, 0xA4],
            on_primary: [0xFF, 0xFF, 0xFF],
            primary_container: [0xEA, 0xDD, 0xFF],
            on_primary_container: [0x21, 0x00, 0x5D],
            secondary: [0x62, 0x5B, 0x71],
            on_secondary: [0xFF, 0xFF, 0xFF],
            secondary_container: [0xE8, 0xDE, 0xF8],
            on_secondary_container: [0x1D, 0x19, 0x2B],
            tertiary: [0x7D, 0x52, 0x60],
            on_tertiary: [0xFF, 0xFF, 0xFF],
            tertiary_container: [0xFF, 0xD8, 0xE4],
            on_tertiary_container: [0x31, 0x11, 0x1D],
            error: [0xB3, 0x26, 0x1E],
            on_error: [0xFF, 0xFF, 0xFF],
            surface: [0xFE, 0xF7, 0xFF],
            surface_dim: [0xDE, 0xD8, 0xE1],
            surface_bright: [0xFE, 0xF7, 0xFF],
            surface_container_lowest: [0xFF, 0xFF, 0xFF],
            surface_container_low: [0xF7, 0xF2, 0xFA],
            surface_container: [0xF3, 0xED, 0xF7],
            surface_container_high: [0xEC, 0xE6, 0xF0],
            surface_container_highest: [0xE6, 0xE0, 0xE9],
            on_surface: [0x1D, 0x1B, 0x20],
            on_surface_variant: [0x49, 0x45, 0x4F],
            outline: [0x79, 0x74, 0x7E],
            outline_variant: [0xCA, 0xC4, 0xD0],
            inverse_surface: [0x32, 0x2F, 0x35],
            inverse_on_surface: [0xF5, 0xEF, 0xF7],
            inverse_primary: [0xD0, 0xBC, 0xFF],
            corner_radius: 12,
            stroke_width: 1.0,
        },
        ThemeMode::Dark => M3Tokens {
            mode,
            appearance: AppearanceTheme::Modern,
            primary: [0xD0, 0xBC, 0xFF],
            on_primary: [0x38, 0x1E, 0x72],
            primary_container: [0x4F, 0x37, 0x8B],
            on_primary_container: [0xEA, 0xDD, 0xFF],
            secondary: [0xCC, 0xC2, 0xDC],
            on_secondary: [0x33, 0x2D, 0x41],
            secondary_container: [0x4A, 0x44, 0x58],
            on_secondary_container: [0xE8, 0xDE, 0xF8],
            tertiary: [0xEF, 0xB8, 0xC8],
            on_tertiary: [0x49, 0x25, 0x32],
            tertiary_container: [0x63, 0x3B, 0x48],
            on_tertiary_container: [0xFF, 0xD8, 0xE4],
            error: [0xF2, 0xB8, 0xB5],
            on_error: [0x60, 0x14, 0x10],
            surface: [0x14, 0x12, 0x18],
            surface_dim: [0x14, 0x12, 0x18],
            surface_bright: [0x3B, 0x38, 0x3E],
            surface_container_lowest: [0x0F, 0x0D, 0x13],
            surface_container_low: [0x1D, 0x1B, 0x20],
            surface_container: [0x21, 0x1F, 0x26],
            surface_container_high: [0x2B, 0x29, 0x30],
            surface_container_highest: [0x36, 0x34, 0x3B],
            on_surface: [0xE6, 0xE0, 0xE9],
            on_surface_variant: [0xCA, 0xC4, 0xD0],
            outline: [0x93, 0x8F, 0x99],
            outline_variant: [0x49, 0x45, 0x4F],
            inverse_surface: [0xE6, 0xE0, 0xE9],
            inverse_on_surface: [0x32, 0x2F, 0x35],
            inverse_primary: [0x67, 0x50, 0xA4],
            corner_radius: 12,
            stroke_width: 1.0,
        },
    }
}

/// Future Console — Amber Console tokens copied 1:1 from
/// `https://github.com/DutchDiederik/AmberConsole` `src/tokens/colors.css`.
///
/// Copyright (c) 2026, Diederik — https://diederik.blog
/// Licensed under the BSD 3-Clause License (see Amber Console LICENSE).
///
/// Mapping:
/// - `ThemeMode::Dark`  → `data-ac-gas="neon"`  (default pulsed neon panel)
/// - `ThemeMode::Light` → `data-ac-gas="amber"` (classic P3 amber CRT phosphor)
///
/// Not vendored as a git submodule; design tokens transcribed for egui.
fn future_console_tokens(mode: ThemeMode) -> M3Tokens {
    // Exact hex from colors.css — neon block / amber block.
    let (screen, screen_raised, screen_well, amber_100, amber_90, amber_70, amber_50, amber_30, on_fill) =
        match mode {
            // [data-ac-gas="neon"]
            ThemeMode::Dark => (
                [0x10, 0x06, 0x00], // --screen: #100600
                [0x1B, 0x0C, 0x02], // --screen-raised: #1b0c02
                [0x06, 0x02, 0x00], // --screen-well: #060200
                [0xFF, 0xA8, 0x6D], // --amber-100: #ffa86d
                [0xFF, 0x6B, 0x08], // --amber-90: #ff6b08
                [0xDD, 0x58, 0x00], // --amber-70: #dd5800
                [0xAB, 0x45, 0x00], // --amber-50: #ab4500
                [0x5B, 0x25, 0x00], // --amber-30: #5b2500
                [0x1E, 0x0C, 0x00], // --on-fill: #1e0c00
            ),
            // [data-ac-gas="amber"]
            ThemeMode::Light => (
                [0x0D, 0x07, 0x00], // --screen: #0d0700
                [0x17, 0x0E, 0x02], // --screen-raised: #170e02
                [0x06, 0x02, 0x00], // --screen-well: #060200
                [0xFF, 0xD0, 0x52], // --amber-100: #ffd052
                [0xFF, 0xAE, 0x1E], // --amber-90: #ffae1e
                [0xCD, 0x88, 0x17], // --amber-70: #cd8817
                [0x8D, 0x5B, 0x10], // --amber-50: #8d5b10
                [0x4A, 0x2F, 0x08], // --amber-30: #4a2f08
                [0x1A, 0x0E, 0x00], // --on-fill: #1a0e00
            ),
        };

    // Aliases from colors.css `:root` block:
    // --ink = amber-90, --ink-bright = amber-100, --ink-dim = amber-70,
    // --ink-faint = amber-50, --fill = amber-90, --stroke = amber-90.
    M3Tokens {
        mode,
        appearance: AppearanceTheme::FutureConsole,
        primary: amber_90,              // --ink / --fill / --stroke
        on_primary: on_fill,            // --on-fill
        primary_container: amber_70,    // --ink-dim
        on_primary_container: on_fill,
        secondary: amber_100,           // --ink-bright
        on_secondary: on_fill,
        secondary_container: amber_50,  // --ink-faint / --stroke-dim
        on_secondary_container: screen,
        tertiary: amber_30,             // --ink-trace
        on_tertiary: amber_100,
        tertiary_container: screen_well,
        on_tertiary_container: amber_70,
        surface: screen,                // --screen
        surface_dim: screen_well,       // --screen-well
        surface_bright: screen_raised,  // --screen-raised
        surface_container_lowest: screen_well,
        surface_container_low: screen,
        surface_container: screen_raised,
        surface_container_high: amber_30,
        surface_container_highest: amber_50,
        on_surface: amber_90,           // --ink
        on_surface_variant: amber_70,   // --ink-dim
        outline: amber_90,              // --stroke
        outline_variant: amber_50,      // --stroke-dim
        error: amber_100, // Amber Console: alarm = inverse/blink, never a new hue
        on_error: on_fill,
        inverse_surface: amber_90,
        inverse_on_surface: on_fill,
        inverse_primary: amber_100,
        corner_radius: 8, // --radius: 8px
        stroke_width: 2.0, // --border-w: 2px
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn theme_toggle_and_classic_tokens() {
        assert_eq!(ThemeMode::Dark.toggle(), ThemeMode::Light);
        let d = m3_tokens(ThemeMode::Dark);
        let l = m3_tokens(ThemeMode::Light);
        assert_ne!(d.surface, l.surface);
        assert_eq!(d.primary[0], 0xD0);
        assert_eq!(d.appearance, AppearanceTheme::ClassicGhidrust);
    }

    #[test]
    fn modern_differs_from_classic_surface_hierarchy() {
        let classic = theme_tokens(AppearanceTheme::ClassicGhidrust, ThemeMode::Dark);
        let modern = theme_tokens(AppearanceTheme::Modern, ThemeMode::Dark);
        assert_eq!(classic.primary, modern.primary);
        assert_ne!(classic.surface_container, modern.surface_container);
        assert_eq!(modern.primary_container, [0x4F, 0x37, 0x8B]);
        assert_eq!(modern.corner_radius, 12);
    }

    #[test]
    fn future_console_matches_amber_console_neon_and_amber_gas() {
        let neon = theme_tokens(AppearanceTheme::FutureConsole, ThemeMode::Dark);
        assert_eq!(neon.surface, [0x10, 0x06, 0x00]);
        assert_eq!(neon.primary, [0xFF, 0x6B, 0x08]);
        assert_eq!(neon.secondary, [0xFF, 0xA8, 0x6D]);
        assert_eq!(neon.corner_radius, 8);
        assert_eq!(neon.stroke_width, 2.0);

        let amber = theme_tokens(AppearanceTheme::FutureConsole, ThemeMode::Light);
        assert_eq!(amber.surface, [0x0D, 0x07, 0x00]);
        assert_eq!(amber.primary, [0xFF, 0xAE, 0x1E]);
        assert_eq!(amber.secondary, [0xFF, 0xD0, 0x52]);
    }

    #[test]
    fn appearance_id_round_trip() {
        for a in AppearanceTheme::ALL {
            assert_eq!(AppearanceTheme::from_id(a.id()), *a);
            assert!(!a.display_name().is_empty());
        }
    }
}
