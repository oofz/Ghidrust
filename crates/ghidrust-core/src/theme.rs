//! Appearance themes as swappable **ThemeSpec** packs (Material 3 structure).
//!
//! Families:
//! - **Classic Ghidrust** — historical purple seed + derived M3 surface ladder.
//! - **Modern** — Google Material 3 baseline color roles (light + dark).
//! - **Future Console** — Amber Console CRT / neon tokens (see module notes).
//!
//! Design model (industry-standard token layers):
//! 1. **Color scheme** — M3 roles (`M3Tokens`)
//! 2. **Shape** — corner radius + stroke (on color scheme for caller compat)
//! 3. **Density** — spacing / padding
//! 4. **State layers** — hover / pressed / selection (data, not GUI `match` arms)
//! 5. **Elevation** — popup shadow level
//! 6. **Motion** — animation duration
//! 7. **Semantics** — status + syntax accents for panes
//!
//! Swap a design by editing a pack in [`theme_spec`]; the GUI compiles any pack
//! through one Style/Visuals path.

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

/// Shared sRGB 0–255 Material 3 color roles (+ shape hints).
///
/// Core roles always filled. Extended M3 roles are fully populated for Modern;
/// Classic / Future Console fill the same fields so callers stay uniform.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
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
    /// M3 shape corner radius hint for egui (Classic = 5; Modern = 13; Future = 8).
    pub corner_radius: u8,
    /// Outline stroke width (Future Console uses 2px soft-key borders).
    pub stroke_width: f32,
}

/// Strict Fibonacci spacing scale (px). All chrome sizes resolve from these steps.
///
/// Sequence: 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 377, 610, 987.
pub struct FibScale;

impl FibScale {
    pub const HAIR: f32 = 1.0;
    pub const XXS: f32 = 2.0;
    pub const XS: f32 = 3.0;
    pub const SM: f32 = 5.0;
    pub const MD: f32 = 8.0;
    pub const LG: f32 = 13.0;
    pub const XL: f32 = 21.0;
    pub const XL2: f32 = 34.0;
    pub const XL3: f32 = 55.0;
    pub const XL4: f32 = 89.0;
    pub const XL5: f32 = 144.0;
    pub const XL6: f32 = 233.0;
    pub const XL7: f32 = 377.0;
    pub const XL8: f32 = 610.0;
    pub const XL9: f32 = 987.0;
}

/// Fibonacci-backed density pack (egui Spacing + chrome defaults + window tiers).
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct ThemeDensity {
    pub item_spacing: [f32; 2],
    pub button_padding: [f32; 2],
    pub window_margin: [f32; 2],
    pub menu_margin: [f32; 2],
    pub indent: f32,
    pub resize_grab_radius: f32,
    pub control_min_height: f32,
    pub icon_sm: f32,
    pub icon_md: f32,
    pub space_xs: f32,
    pub space_sm: f32,
    pub space_md: f32,
    pub space_lg: f32,
    pub space_xl: f32,
    pub panel_project: f32,
    pub panel_program: f32,
    pub panel_symbol: f32,
    pub panel_symbol_min: f32,
    pub console_default: f32,
    pub console_min: f32,
    pub console_grip: f32,
    pub console_handle_w: f32,
    pub scroll_sm: f32,
    pub scroll_md: f32,
    pub scroll_lg: f32,
    /// TextEdit / column field width tiers (Fibonacci).
    pub field_micro: f32,
    pub field_narrow: f32,
    pub field_compact: f32,
    pub field_std: f32,
    pub field_wide: f32,
    pub field_xwide: f32,
    /// Window default size tiers: `[width, height]`.
    pub win_xs: [f32; 2],
    pub win_sm: [f32; 2],
    pub win_md: [f32; 2],
    pub win_lg: [f32; 2],
    pub win_xl: [f32; 2],
}

impl ThemeDensity {
    const fn shared_chrome(button_padding: [f32; 2]) -> Self {
        Self {
            item_spacing: [FibScale::MD, FibScale::MD],
            button_padding,
            window_margin: [FibScale::LG, FibScale::LG],
            menu_margin: [FibScale::MD, FibScale::SM],
            indent: FibScale::LG,
            resize_grab_radius: FibScale::LG,
            control_min_height: FibScale::XL2,
            icon_sm: FibScale::LG,
            icon_md: FibScale::XL,
            space_xs: FibScale::XS,
            space_sm: FibScale::SM,
            space_md: FibScale::MD,
            space_lg: FibScale::LG,
            space_xl: FibScale::XL,
            panel_project: FibScale::XL6,
            panel_program: FibScale::XL6,
            panel_symbol: FibScale::XL6,
            panel_symbol_min: FibScale::XL5,
            console_default: FibScale::XL6,
            console_min: FibScale::XL5,
            console_grip: FibScale::LG,
            console_handle_w: FibScale::XL3,
            scroll_sm: FibScale::XL6,
            scroll_md: FibScale::XL7,
            scroll_lg: FibScale::XL8,
            field_micro: FibScale::XL3,
            field_narrow: FibScale::XL4,
            field_compact: FibScale::XL5,
            field_std: FibScale::XL6,
            field_wide: FibScale::XL7,
            field_xwide: FibScale::XL8,
            win_xs: [FibScale::XL7, FibScale::XL6],
            win_sm: [FibScale::XL7, FibScale::XL7],
            win_md: [FibScale::XL8, FibScale::XL7],
            win_lg: [FibScale::XL8, FibScale::XL8],
            win_xl: [FibScale::XL9, FibScale::XL8],
        }
    }

    /// Classic + Modern comfortable Fib desktop density.
    pub const FIB_DESKTOP: Self = Self::shared_chrome([FibScale::LG, FibScale::MD]);

    /// Future Console — same Fib ladder, larger soft-key padding.
    pub const FIB_CONSOLE: Self = Self::shared_chrome([FibScale::XL, FibScale::LG]);
}

/// Hover fill recipe (M3 state-layer approximation for egui fills).
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HoverFill {
    /// `primary` with egui `gamma_multiply`.
    PrimaryGamma(f32),
    /// `primary_container` with egui `gamma_multiply`.
    PrimaryContainerGamma(f32),
    /// Raised surface (console / tonal hover).
    SurfaceBright,
}

/// Pressed / active fill recipe.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActiveFill {
    Primary,
    PrimaryGamma(f32),
}

/// Ink on active controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActiveFg {
    OnPrimary,
    OnSurface,
}

/// Interactive state layers (Material state-layer model, pack-driven).
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct ThemeStateLayers {
    pub hover: HoverFill,
    pub active: ActiveFill,
    pub active_fg: ActiveFg,
    /// Selection highlight: `primary` × gamma.
    pub selection_primary_gamma: f32,
}

/// Popup / menu elevation (M3 elevation mapped to egui shadows).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ElevationShadow {
    /// No shadow (flat CRT / neon panel).
    None,
    /// Soft ambient (≈ M3 level 2): offset (0,2), blur 8, black α40.
    Level2,
    /// Keep egui `Visuals::dark/light` stock popup shadow.
    Stock,
}

/// Elevation tokens for floating surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ThemeElevation {
    pub popup_shadow: ElevationShadow,
}

/// Motion tokens (Material duration scale, seconds).
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct ThemeMotion {
    /// Typical UI animation length (`Style::animation_time`).
    pub animation_time: f32,
}

impl ThemeMotion {
    /// Material short-2 ≈ 150ms — standard control feedback.
    pub const SHORT2: Self = Self {
        animation_time: 0.15,
    };
    /// Material medium-1 ≈ 200ms — slightly softer chrome.
    pub const MEDIUM1: Self = Self {
        animation_time: 0.20,
    };
}

/// Semantic / syntax accents (not M3 core roles; app-specific extensions).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ThemeSemantics {
    pub ok: [u8; 3],
    pub warn: [u8; 3],
    pub muted: [u8; 3],
    pub syntax_keyword: [u8; 3],
    pub syntax_function: [u8; 3],
    pub syntax_label: [u8; 3],
    pub syntax_address: [u8; 3],
    pub syntax_constant: [u8; 3],
    pub syntax_comment: [u8; 3],
}

impl ThemeSemantics {
    /// Dark-scheme syntax (Material-ish accents used historically in the decompiler).
    pub const DARK_CODE: Self = Self {
        ok: [0x4C, 0xAF, 0x50],
        warn: [0xFB, 0xC0, 0x2D],
        muted: [0x9E, 0x9E, 0x9E],
        syntax_keyword: [0x64, 0xB5, 0xF6],
        syntax_function: [0xFF, 0xB7, 0x4D],
        syntax_label: [0xBA, 0x68, 0xC8],
        syntax_address: [0x4D, 0xD0, 0xE1],
        syntax_constant: [0x80, 0xDE, 0xEA],
        syntax_comment: [0x81, 0xC7, 0x84],
    };

    /// Light-scheme syntax — deeper chroma for contrast on pale surfaces.
    pub const LIGHT_CODE: Self = Self {
        ok: [0x2E, 0x7D, 0x32],
        warn: [0xF5, 0x7C, 0x00],
        muted: [0x75, 0x75, 0x75],
        syntax_keyword: [0x15, 0x65, 0xC0],
        syntax_function: [0xE6, 0x51, 0x00],
        syntax_label: [0x7B, 0x1F, 0xA2],
        syntax_address: [0x00, 0x83, 0x8F],
        syntax_constant: [0x00, 0x83, 0x8F],
        syntax_comment: [0x2E, 0x7D, 0x32],
    };

    /// Amber Console: keep hue family (no foreign greens/blues).
    pub const CONSOLE: Self = Self {
        ok: [0xFF, 0xAE, 0x1E],
        warn: [0xFF, 0xD0, 0x52],
        muted: [0xAB, 0x45, 0x00],
        syntax_keyword: [0xFF, 0xA8, 0x6D],
        syntax_function: [0xFF, 0x6B, 0x08],
        syntax_label: [0xFF, 0xD0, 0x52],
        syntax_address: [0xDD, 0x58, 0x00],
        syntax_constant: [0xFF, 0xA8, 0x6D],
        syntax_comment: [0xAB, 0x45, 0x00],
    };
}

/// Complete swappable theme pack — edit this (or add a pack) to change a design.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct ThemeSpec {
    pub colors: M3Tokens,
    /// Prefer egui dark Visuals base (Future Console is always dark CRT).
    pub dark_base: bool,
    pub density: ThemeDensity,
    pub state_layers: ThemeStateLayers,
    pub elevation: ThemeElevation,
    pub motion: ThemeMotion,
    pub semantics: ThemeSemantics,
}

/// Resolve a full theme pack for an appearance family + mode.
pub fn theme_spec(appearance: AppearanceTheme, mode: ThemeMode) -> ThemeSpec {
    match appearance {
        AppearanceTheme::ClassicGhidrust => classic_spec(mode),
        AppearanceTheme::Modern => modern_spec(mode),
        AppearanceTheme::FutureConsole => future_console_spec(mode),
    }
}

/// Resolve color tokens for an appearance family + mode.
pub fn theme_tokens(appearance: AppearanceTheme, mode: ThemeMode) -> M3Tokens {
    theme_spec(appearance, mode).colors
}

/// Backward-compatible Classic Ghidrust tokens (mode only).
pub fn m3_tokens(mode: ThemeMode) -> M3Tokens {
    theme_tokens(AppearanceTheme::ClassicGhidrust, mode)
}

// ---------------------------------------------------------------------------
// Packs
// ---------------------------------------------------------------------------

fn classic_spec(mode: ThemeMode) -> ThemeSpec {
    ThemeSpec {
        colors: classic_colors(mode),
        dark_base: matches!(mode, ThemeMode::Dark),
        density: ThemeDensity::FIB_DESKTOP,
        state_layers: ThemeStateLayers {
            hover: HoverFill::PrimaryGamma(0.25),
            active: ActiveFill::PrimaryGamma(0.35),
            active_fg: ActiveFg::OnSurface,
            selection_primary_gamma: 0.40,
        },
        elevation: ThemeElevation {
            popup_shadow: ElevationShadow::Level2,
        },
        motion: ThemeMotion::SHORT2,
        semantics: match mode {
            ThemeMode::Dark => ThemeSemantics::DARK_CODE,
            ThemeMode::Light => ThemeSemantics::LIGHT_CODE,
        },
    }
}

fn modern_spec(mode: ThemeMode) -> ThemeSpec {
    ThemeSpec {
        colors: modern_colors(mode),
        dark_base: matches!(mode, ThemeMode::Dark),
        density: ThemeDensity::FIB_DESKTOP,
        state_layers: ThemeStateLayers {
            hover: HoverFill::PrimaryContainerGamma(0.55),
            active: ActiveFill::PrimaryGamma(0.45),
            active_fg: ActiveFg::OnSurface,
            selection_primary_gamma: 0.40,
        },
        elevation: ThemeElevation {
            popup_shadow: ElevationShadow::Level2,
        },
        motion: ThemeMotion::MEDIUM1,
        semantics: match mode {
            ThemeMode::Dark => ThemeSemantics::DARK_CODE,
            ThemeMode::Light => ThemeSemantics::LIGHT_CODE,
        },
    }
}

fn future_console_spec(mode: ThemeMode) -> ThemeSpec {
    ThemeSpec {
        colors: future_console_colors(mode),
        // CRT / neon panel is always a dark egui base (both gases).
        dark_base: true,
        density: ThemeDensity::FIB_CONSOLE,
        state_layers: ThemeStateLayers {
            hover: HoverFill::SurfaceBright,
            active: ActiveFill::Primary,
            active_fg: ActiveFg::OnPrimary,
            selection_primary_gamma: 0.55,
        },
        elevation: ThemeElevation {
            popup_shadow: ElevationShadow::None,
        },
        motion: ThemeMotion::SHORT2,
        semantics: ThemeSemantics::CONSOLE,
    }
}

/// Lift/darken an sRGB triplet by a uniform channel delta (simple tonal step).
fn tonal_step(rgb: [u8; 3], delta: i16) -> [u8; 3] {
    [
        (i16::from(rgb[0]) + delta).clamp(0, 255) as u8,
        (i16::from(rgb[1]) + delta).clamp(0, 255) as u8,
        (i16::from(rgb[2]) + delta).clamp(0, 255) as u8,
    ]
}

/// Classic — frozen brand seeds with a derived M3 surface container ladder.
fn classic_colors(mode: ThemeMode) -> M3Tokens {
    match mode {
        ThemeMode::Dark => {
            let primary = [0xD0, 0xBC, 0xFF];
            let on_primary = [0x38, 0x1E, 0x72];
            let surface = [0x14, 0x14, 0x18];
            let surface_container = [0x1C, 0x1B, 0x1F];
            let on_surface = [0xE6, 0xE1, 0xE5];
            let on_surface_variant = [0xCA, 0xC4, 0xD0];
            let outline = [0x93, 0x8F, 0x99];
            let error = [0xF2, 0xB8, 0xB5];
            M3Tokens {
                mode,
                appearance: AppearanceTheme::ClassicGhidrust,
                primary,
                on_primary,
                primary_container: [0x4F, 0x37, 0x8B],
                on_primary_container: [0xEA, 0xDD, 0xFF],
                secondary: on_surface_variant,
                on_secondary: surface,
                secondary_container: tonal_step(surface_container, 6),
                on_secondary_container: on_surface,
                tertiary: primary,
                on_tertiary: on_primary,
                tertiary_container: tonal_step(surface_container, 10),
                on_tertiary_container: on_surface,
                surface,
                surface_dim: tonal_step(surface, -4),
                surface_bright: tonal_step(surface_container, 18),
                surface_container_lowest: tonal_step(surface, -5),
                surface_container_low: tonal_step(surface, 4),
                surface_container,
                surface_container_high: tonal_step(surface_container, 10),
                surface_container_highest: tonal_step(surface_container, 18),
                on_surface,
                on_surface_variant,
                outline,
                outline_variant: [0x49, 0x45, 0x4F],
                error,
                on_error: on_primary,
                inverse_surface: on_surface,
                inverse_on_surface: surface,
                inverse_primary: [0x67, 0x50, 0xA4],
                corner_radius: 5,
                stroke_width: 1.0,
            }
        }
        ThemeMode::Light => {
            let primary = [0x67, 0x50, 0xA4];
            let on_primary = [0xFF, 0xFF, 0xFF];
            let surface = [0xFF, 0xFB, 0xFE];
            let surface_container = [0xF3, 0xED, 0xF7];
            let on_surface = [0x1C, 0x1B, 0x1F];
            let on_surface_variant = [0x49, 0x45, 0x4F];
            let outline = [0x79, 0x74, 0x7E];
            let error = [0xB3, 0x26, 0x1E];
            M3Tokens {
                mode,
                appearance: AppearanceTheme::ClassicGhidrust,
                primary,
                on_primary,
                primary_container: [0xEA, 0xDD, 0xFF],
                on_primary_container: [0x21, 0x00, 0x5D],
                secondary: on_surface_variant,
                on_secondary: surface,
                secondary_container: tonal_step(surface_container, -6),
                on_secondary_container: on_surface,
                tertiary: primary,
                on_tertiary: on_primary,
                tertiary_container: tonal_step(surface_container, -10),
                on_tertiary_container: on_surface,
                surface,
                surface_dim: tonal_step(surface_container, -12),
                surface_bright: surface,
                surface_container_lowest: [0xFF, 0xFF, 0xFF],
                surface_container_low: tonal_step(surface_container, 4),
                surface_container,
                surface_container_high: tonal_step(surface_container, -6),
                surface_container_highest: tonal_step(surface_container, -12),
                on_surface,
                on_surface_variant,
                outline,
                outline_variant: [0xCA, 0xC4, 0xD0],
                error,
                on_error: on_primary,
                inverse_surface: on_surface,
                inverse_on_surface: surface,
                inverse_primary: [0xD0, 0xBC, 0xFF],
                corner_radius: 5,
                stroke_width: 1.0,
            }
        }
    }
}

/// Google Material 3 baseline scheme (seed / primary40 `#6750A4`).
fn modern_colors(mode: ThemeMode) -> M3Tokens {
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
            corner_radius: 13,
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
            corner_radius: 13,
            stroke_width: 1.0,
        },
    }
}

/// Future Console — Amber Console tokens from
/// `https://github.com/DutchDiederik/AmberConsole` `src/tokens/colors.css`.
///
/// Copyright (c) 2026, Diederik — https://diederik.blog
/// Licensed under the BSD 3-Clause License (see Amber Console LICENSE).
///
/// Mapping:
/// - `ThemeMode::Dark`  → `data-ac-gas="neon"`
/// - `ThemeMode::Light` → `data-ac-gas="amber"`
fn future_console_colors(mode: ThemeMode) -> M3Tokens {
    let (screen, screen_raised, screen_well, amber_100, amber_90, amber_70, amber_50, amber_30, on_fill) =
        match mode {
            ThemeMode::Dark => (
                [0x10, 0x06, 0x00],
                [0x1B, 0x0C, 0x02],
                [0x06, 0x02, 0x00],
                [0xFF, 0xA8, 0x6D],
                [0xFF, 0x6B, 0x08],
                [0xDD, 0x58, 0x00],
                [0xAB, 0x45, 0x00],
                [0x5B, 0x25, 0x00],
                [0x1E, 0x0C, 0x00],
            ),
            ThemeMode::Light => (
                [0x0D, 0x07, 0x00],
                [0x17, 0x0E, 0x02],
                [0x06, 0x02, 0x00],
                [0xFF, 0xD0, 0x52],
                [0xFF, 0xAE, 0x1E],
                [0xCD, 0x88, 0x17],
                [0x8D, 0x5B, 0x10],
                [0x4A, 0x2F, 0x08],
                [0x1A, 0x0E, 0x00],
            ),
        };

    M3Tokens {
        mode,
        appearance: AppearanceTheme::FutureConsole,
        primary: amber_90,
        on_primary: on_fill,
        primary_container: amber_70,
        on_primary_container: on_fill,
        secondary: amber_100,
        on_secondary: on_fill,
        secondary_container: amber_50,
        on_secondary_container: screen,
        tertiary: amber_30,
        on_tertiary: amber_100,
        tertiary_container: screen_well,
        on_tertiary_container: amber_70,
        surface: screen,
        surface_dim: screen_well,
        surface_bright: screen_raised,
        surface_container_lowest: screen_well,
        surface_container_low: screen,
        surface_container: screen_raised,
        surface_container_high: amber_30,
        surface_container_highest: amber_50,
        on_surface: amber_90,
        on_surface_variant: amber_70,
        outline: amber_90,
        outline_variant: amber_50,
        error: amber_100,
        on_error: on_fill,
        inverse_surface: amber_90,
        inverse_on_surface: on_fill,
        inverse_primary: amber_100,
        corner_radius: 8,
        stroke_width: 2.0,
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
        assert_eq!(modern.corner_radius, 13);
    }

    #[test]
    fn classic_has_surface_ladder() {
        let c = theme_tokens(AppearanceTheme::ClassicGhidrust, ThemeMode::Dark);
        assert_ne!(c.surface, c.surface_container_high);
        assert_ne!(c.surface_container, c.surface_container_highest);
        assert_ne!(c.surface_dim, c.surface_bright);
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

    #[test]
    fn theme_spec_packs_drive_chrome_without_gui_forks() {
        let classic = theme_spec(AppearanceTheme::ClassicGhidrust, ThemeMode::Dark);
        let modern = theme_spec(AppearanceTheme::Modern, ThemeMode::Dark);
        let future = theme_spec(AppearanceTheme::FutureConsole, ThemeMode::Light);

        assert!(classic.dark_base);
        assert!(!theme_spec(AppearanceTheme::Modern, ThemeMode::Light).dark_base);
        assert!(future.dark_base); // CRT always dark base

        assert_eq!(classic.density, ThemeDensity::FIB_DESKTOP);
        assert_eq!(modern.density, ThemeDensity::FIB_DESKTOP);
        assert_eq!(future.density, ThemeDensity::FIB_CONSOLE);
        assert_eq!(classic.density.button_padding, [FibScale::LG, FibScale::MD]);
        assert_eq!(future.density.button_padding, [FibScale::XL, FibScale::LG]);
        assert_eq!(classic.density.win_md, [FibScale::XL8, FibScale::XL7]);

        assert!(matches!(classic.state_layers.hover, HoverFill::PrimaryGamma(_)));
        assert!(matches!(
            modern.state_layers.hover,
            HoverFill::PrimaryContainerGamma(_)
        ));
        assert!(matches!(future.state_layers.hover, HoverFill::SurfaceBright));
        assert!(matches!(future.elevation.popup_shadow, ElevationShadow::None));
        assert!(matches!(
            classic.elevation.popup_shadow,
            ElevationShadow::Level2
        ));

        assert_eq!(theme_tokens(AppearanceTheme::Modern, ThemeMode::Dark), modern.colors);
    }

    #[test]
    fn semantics_follow_mode_for_classic() {
        let dark = theme_spec(AppearanceTheme::ClassicGhidrust, ThemeMode::Dark);
        let light = theme_spec(AppearanceTheme::ClassicGhidrust, ThemeMode::Light);
        assert_eq!(dark.semantics, ThemeSemantics::DARK_CODE);
        assert_eq!(light.semantics, ThemeSemantics::LIGHT_CODE);
    }
}
