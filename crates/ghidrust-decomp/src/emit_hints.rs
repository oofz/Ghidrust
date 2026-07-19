//! Optional naming / OO hints for Stage-1 emit (R2 / R6).
//!
//! Built from a [`ghidrust_core::Program`] when available — imports, function
//! names, RTTI class names. Never invents callees that are not in the program.

use ghidrust_core::{rtti_catalog, Program};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Extra context Stage-1 uses when pretty-printing calls and methods.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EmitHints {
    /// Absolute call target VA → display name (import or function).
    pub call_names: BTreeMap<u64, String>,
    /// When true, first recovered param is rendered as `this`.
    pub method_this: bool,
    /// Optional class name for `this` (`ClassName *this`).
    pub this_class: Option<String>,
    /// Known vtable base VA → class name (for virtual-call comments).
    pub vtable_classes: BTreeMap<u64, String>,
}

impl EmitHints {
    /// Collect call-site names from functions + imports + RTTI on `prog`.
    pub fn from_program(prog: &Program) -> Self {
        let mut hints = EmitHints::default();
        for f in &prog.analysis.functions {
            if !f.name.is_empty() {
                hints.call_names.insert(f.entry, f.name.clone());
            }
        }
        // User renames win over analyzer names.
        for (entry, name) in &prog.edits.renames {
            hints.call_names.insert(*entry, name.clone());
        }
        for imp in &prog.imports {
            let sym = match &imp.name {
                Some(n) if !n.is_empty() => n.clone(),
                _ => match imp.ordinal {
                    Some(o) => format!("ord_{o}"),
                    None => continue,
                },
            };
            let name = if imp.dll.is_empty() {
                sym
            } else {
                format!("{}!{sym}", imp.dll)
            };
            if imp.iat_va != 0 {
                hints.call_names.insert(imp.iat_va, name);
            }
        }
        if let Ok((entries, _, _)) = rtti_catalog(prog) {
            for c in entries {
                if c.name.is_empty() {
                    continue;
                }
                for &va in &c.vtable_vas {
                    hints.vtable_classes.insert(va, c.name.clone());
                }
                if let Some(va) = c.vtable_va {
                    hints.vtable_classes.insert(va, c.name.clone());
                }
                // Heuristic: if function name matches class, mark method_this
                // when decompiling that class's methods (caller can override).
                let _ = c;
            }
        }
        hints
    }

    pub fn name_for_call(&self, target: u64) -> Option<&str> {
        self.call_names.get(&target).map(|s| s.as_str())
    }

    pub fn class_for_vtable(&self, va: u64) -> Option<&str> {
        self.vtable_classes.get(&va).map(|s| s.as_str())
    }

    /// Enable `this` rendering when `entry` looks like a method on `class`.
    pub fn with_method_this(mut self, class: impl Into<String>) -> Self {
        self.method_this = true;
        self.this_class = Some(class.into());
        self
    }
}
