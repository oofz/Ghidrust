//! Material 3–inspired color tokens (shared for docs/tests; GUI applies via egui).

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
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

/// sRGB 0–255 Material 3–inspired tokens.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct M3Tokens {
    pub mode: ThemeMode,
    pub primary: [u8; 3],
    pub on_primary: [u8; 3],
    pub surface: [u8; 3],
    pub surface_container: [u8; 3],
    pub on_surface: [u8; 3],
    pub on_surface_variant: [u8; 3],
    pub outline: [u8; 3],
    pub error: [u8; 3],
}

pub fn m3_tokens(mode: ThemeMode) -> M3Tokens {
    match mode {
        ThemeMode::Dark => M3Tokens {
            mode,
            primary: [0xD0, 0xBC, 0xFF],
            on_primary: [0x38, 0x1E, 0x72],
            surface: [0x14, 0x14, 0x18],
            surface_container: [0x1C, 0x1B, 0x1F],
            on_surface: [0xE6, 0xE1, 0xE5],
            on_surface_variant: [0xCA, 0xC4, 0xD0],
            outline: [0x93, 0x8F, 0x99],
            error: [0xF2, 0xB8, 0xB5],
        },
        ThemeMode::Light => M3Tokens {
            mode,
            primary: [0x67, 0x50, 0xA4],
            on_primary: [0xFF, 0xFF, 0xFF],
            surface: [0xFF, 0xFB, 0xFE],
            surface_container: [0xF3, 0xED, 0xF7],
            on_surface: [0x1C, 0x1B, 0x1F],
            on_surface_variant: [0x49, 0x45, 0x4F],
            outline: [0x79, 0x74, 0x7E],
            error: [0xB3, 0x26, 0x1E],
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn theme_toggle_and_tokens() {
        assert_eq!(ThemeMode::Dark.toggle(), ThemeMode::Light);
        let d = m3_tokens(ThemeMode::Dark);
        let l = m3_tokens(ThemeMode::Light);
        assert_ne!(d.surface, l.surface);
        assert_eq!(d.primary[0], 0xD0);
    }
}
