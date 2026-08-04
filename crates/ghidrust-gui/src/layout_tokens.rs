//! Fibonacci layout helpers over [`ThemeDensity`].
//!
//! Call sites pick a [`WinTier`], [`FieldWidth`], or scroll/space token — never raw chrome literals.

use eframe::egui::{self, Frame, Margin, Ui, Vec2};
use ghidrust_core::ThemeDensity;

/// Dialog / floating-window size tier (values from the active density pack).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WinTier {
    /// Tiny forms (rename, confirm).
    Xs,
    /// Search / goto / single-column edit.
    Sm,
    /// Options / layouts / medium tools.
    Md,
    /// Configure / debugger / default providers.
    Lg,
    /// Network host / large tool hosts.
    Xl,
}

impl WinTier {
    /// Default `[width, height]` for this tier.
    pub fn size(self, d: &ThemeDensity) -> Vec2 {
        let wh = match self {
            WinTier::Xs => d.win_xs,
            WinTier::Sm => d.win_sm,
            WinTier::Md => d.win_md,
            WinTier::Lg => d.win_lg,
            WinTier::Xl => d.win_xl,
        };
        Vec2::new(wh[0], wh[1])
    }

    /// Minimum size — one Fib window step down from the default tier.
    pub fn min_size(self, d: &ThemeDensity) -> Vec2 {
        match self {
            WinTier::Xs => Vec2::new(d.scroll_sm, d.panel_symbol_min),
            WinTier::Sm => WinTier::Xs.size(d),
            WinTier::Md => WinTier::Sm.size(d),
            WinTier::Lg => WinTier::Xs.size(d),
            WinTier::Xl => WinTier::Md.size(d),
        }
    }

    pub fn width(self, d: &ThemeDensity) -> f32 {
        self.size(d).x
    }

    #[allow(dead_code)]
    pub fn height(self, d: &ThemeDensity) -> f32 {
        self.size(d).y
    }
}

/// TextEdit / table column width tier (Fibonacci).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldWidth {
    /// 55 — tiny status / port columns.
    Micro,
    /// 89 — short codes / small numeric.
    Narrow,
    /// 144 — addresses / medium labels.
    Compact,
    /// 233 — paths / names.
    Std,
    /// 377 — long paths / filters.
    Wide,
    /// 610 — very wide editors.
    XWide,
}

impl FieldWidth {
    pub fn px(self, d: &ThemeDensity) -> f32 {
        match self {
            FieldWidth::Micro => d.field_micro,
            FieldWidth::Narrow => d.field_narrow,
            FieldWidth::Compact => d.field_compact,
            FieldWidth::Std => d.field_std,
            FieldWidth::Wide => d.field_wide,
            FieldWidth::XWide => d.field_xwide,
        }
    }
}

/// Card / group frame: Fib inner margin + style corner radius.
pub fn card_frame(ui: &Ui, d: &ThemeDensity) -> Frame {
    Frame::group(ui.style()).inner_margin(Margin::same(d.space_lg as i8))
}

/// Nested chip / inset frame.
pub fn chip_frame(_ui: &Ui, d: &ThemeDensity) -> Frame {
    Frame::NONE
        .inner_margin(Margin::same(d.space_xs as i8))
        .corner_radius(egui::CornerRadius::same(d.space_sm as u8))
}

/// Min height for explicitly sized buttons.
pub fn sized_button_height(d: &ThemeDensity) -> f32 {
    d.control_min_height
}

/// Convenience accessors matching density field names.
#[allow(dead_code)]
pub trait DensityExt {
    fn density(&self) -> &ThemeDensity;

    fn space_xs(&self) -> f32 {
        self.density().space_xs
    }
    fn space_sm(&self) -> f32 {
        self.density().space_sm
    }
    fn space_md(&self) -> f32 {
        self.density().space_md
    }
    fn space_lg(&self) -> f32 {
        self.density().space_lg
    }
    fn space_xl(&self) -> f32 {
        self.density().space_xl
    }
    fn scroll_sm(&self) -> f32 {
        self.density().scroll_sm
    }
    fn scroll_md(&self) -> f32 {
        self.density().scroll_md
    }
    fn scroll_lg(&self) -> f32 {
        self.density().scroll_lg
    }
    fn icon_sm(&self) -> f32 {
        self.density().icon_sm
    }
    fn icon_md(&self) -> f32 {
        self.density().icon_md
    }
    fn win(&self, tier: WinTier) -> Vec2 {
        tier.size(self.density())
    }
    fn field(&self, w: FieldWidth) -> f32 {
        w.px(self.density())
    }
}

impl DensityExt for ThemeDensity {
    fn density(&self) -> &ThemeDensity {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidrust_core::{FibScale, ThemeDensity};
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn win_tiers_are_fib() {
        let d = ThemeDensity::FIB_DESKTOP;
        assert_eq!(WinTier::Xs.size(&d), Vec2::new(377.0, 233.0));
        assert_eq!(WinTier::Sm.size(&d), Vec2::new(377.0, 377.0));
        assert_eq!(WinTier::Md.size(&d), Vec2::new(610.0, 377.0));
        assert_eq!(WinTier::Lg.size(&d), Vec2::new(610.0, 610.0));
        assert_eq!(WinTier::Xl.size(&d), Vec2::new(987.0, 610.0));
        assert_eq!(WinTier::Md.height(&d), 377.0);
        assert_eq!(d.scroll_md(), 377.0);
        assert_eq!(d.win(WinTier::Lg), Vec2::new(610.0, 610.0));
    }

    #[test]
    fn field_widths_are_fib() {
        let d = ThemeDensity::FIB_DESKTOP;
        assert_eq!(FieldWidth::Micro.px(&d), FibScale::XL3);
        assert_eq!(FieldWidth::Narrow.px(&d), FibScale::XL4);
        assert_eq!(FieldWidth::Compact.px(&d), FibScale::XL5);
        assert_eq!(FieldWidth::Std.px(&d), FibScale::XL6);
        assert_eq!(FieldWidth::Wide.px(&d), FibScale::XL7);
        assert_eq!(FieldWidth::XWide.px(&d), FibScale::XL8);
        assert_eq!(d.field(FieldWidth::Std), d.field_std);
        assert_eq!(sized_button_height(&d), FibScale::XL2);
    }

    #[test]
    fn no_raw_chrome_literals() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut violations = Vec::new();
        walk_rs(&root, &mut |path, src| {
            let rel = path
                .strip_prefix(&root)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");
            if is_allowlisted(&rel) {
                return;
            }
            for (line_no, line) in src.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.starts_with("//") || trimmed.starts_with("///") {
                    continue;
                }
                if let Some(reason) = chrome_literal_reason(trimmed) {
                    violations.push(format!("{rel}:{}: {reason}: {trimmed}", line_no + 1));
                }
            }
        });
        assert!(
            violations.is_empty(),
            "raw chrome numeric literals found (use ThemeDensity / FieldWidth / WinTier / FibScale):\n{}",
            violations.join("\n")
        );
    }

    fn is_allowlisted(rel: &str) -> bool {
        rel == "graphs.rs"
            || rel.starts_with("grok_term/")
            || rel.starts_with("app/tests.rs")
            || rel.ends_with("/tests.rs")
            || rel == "layout_tokens.rs" // this file's lint patterns are documentation
    }

    fn chrome_literal_reason(line: &str) -> Option<&'static str> {
        // icons.rs: allow path paint coords; forbid chrome helpers with numeric literals.
        let patterns: &[(&str, &str)] = &[
            (r"max_height(", "max_height numeric"),
            (r"min_height(", "min_height numeric"),
            (r"default_width(", "default_width numeric"),
            (r"default_size(egui::vec2(", "default_size numeric"),
            (r"min_size(egui::vec2(", "min_size numeric"),
            (r"min_width(", "min_width numeric"),
            (r"add_space(", "add_space numeric"),
            (r"desired_width(", "desired_width numeric"),
            (r"Margin::same(", "Margin::same numeric"),
            (r"CornerRadius::same(", "CornerRadius::same numeric"),
        ];
        for (needle, reason) in patterns {
            if let Some(idx) = line.find(needle) {
                let after = &line[idx + needle.len()..];
                let after = after.trim_start();
                if after.starts_with(|c: char| c.is_ascii_digit()) {
                    // Allow FibScale / density references — those don't start with a digit.
                    return Some(reason);
                }
            }
        }
        None
    }

    fn walk_rs(dir: &std::path::Path, f: &mut dyn FnMut(&std::path::Path, &str)) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk_rs(&path, f);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                if let Ok(src) = fs::read_to_string(&path) {
                    f(&path, &src);
                }
            }
        }
    }
}
