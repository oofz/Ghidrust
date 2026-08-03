//! Program edits — rename/retype/comment/signature/types + dialog openers.
//!
//! Extracted per demonolith Wave 6.

use super::{NewTypeKind, GhidrustApp};
use crate::events::{GhidrustEvent, MutationKind};
use ghidrust_core::CommentKind;

impl GhidrustApp {

    /// Rename the symbol / function at `va` (persists into `Program::edits`).
    ///
    /// Also mirrors the rename into `Program::analysis.functions[i].name()` so
    /// every downstream pane (Symbol Tree, Functions Window, Symbol Table,
    /// Bookmarks label preview) sees the new name without a full re-analyze.
    /// Emits a `ProgramMutated::Rename` event which invalidates the Decompiler
    /// cache so the header string is rebuilt.
    pub(crate) fn rename_at(&mut self, va: u64, new_name: impl Into<String>) -> Result<(), String> {
        let new_name = new_name.into();
        if new_name.trim().is_empty() {
            return Err("empty name".into());
        }
        let prog = self
            .program
            .as_mut()
            .ok_or_else(|| "no program loaded".to_string())?;
        // Mirror into analysis so tables / listing / decomp header pick it up.
        if let Some(f) = prog.function_at_mut(va) {
            f.name = new_name.clone();
        } else if let Some(s) = prog.analysis.symbols.iter_mut().find(|s| s.va == va) {
            s.name = new_name.clone();
        }
        // Persist as an edit even if analysis had no matching entry.
        prog.edits.set_rename(va, &new_name);
        self.event_bus.publish(GhidrustEvent::ProgramMutated {
            kind: MutationKind::Rename {
                va,
                new_name: new_name.clone(),
            },
        });
        self.status = format!("Renamed {va:#x} → {new_name}");
        self.log(self.status.clone());
        Ok(())
    }

    /// Retype the variable / global at `va` (persists into `Program::edits`).
    pub(crate) fn retype_at(&mut self, va: u64, type_desc: impl Into<String>) -> Result<(), String> {
        let type_desc = type_desc.into();
        let prog = self
            .program
            .as_mut()
            .ok_or_else(|| "no program loaded".to_string())?;
        prog.edits.set_retype(va, &type_desc);
        self.event_bus.publish(GhidrustEvent::ProgramMutated {
            kind: MutationKind::Retype {
                va,
                type_desc: type_desc.clone(),
            },
        });
        self.status = format!("Retyped {va:#x} → {type_desc}");
        self.log(self.status.clone());
        Ok(())
    }

    /// Set (or clear) a comment at `va` (persists into `Program::edits`).
    pub(crate) fn set_comment_at(
        &mut self,
        va: u64,
        kind: CommentKind,
        text: impl Into<String>,
    ) -> Result<(), String> {
        let text = text.into();
        let prog = self
            .program
            .as_mut()
            .ok_or_else(|| "no program loaded".to_string())?;
        prog.edits.set_comment(va, kind, &text);
        self.event_bus.publish(GhidrustEvent::ProgramMutated {
            kind: MutationKind::CommentChanged { va },
        });
        self.status = if text.is_empty() {
            format!("Cleared {} comment at {va:#x}", kind.label())
        } else {
            format!("Set {} comment at {va:#x}", kind.label())
        };
        self.log(self.status.clone());
        Ok(())
    }

    /// Set / replace a function signature (Edit Function Signature dialog).
    pub(crate) fn set_function_signature(
        &mut self,
        entry: u64,
        signature: impl Into<String>,
    ) -> Result<(), String> {
        let signature = signature.into();
        let prog = self
            .program
            .as_mut()
            .ok_or_else(|| "no program loaded".to_string())?;
        let mut sig = prog
            .edits
            .function_signature(entry)
            .cloned()
            .unwrap_or_default();
        sig.signature = signature.clone();
        prog.edits.set_function_signature(entry, sig);
        self.event_bus.publish(GhidrustEvent::ProgramMutated {
            kind: MutationKind::Retype {
                va: entry,
                type_desc: signature.clone(),
            },
        });
        self.status = format!("Function signature @ {entry:#x} → {signature}");
        self.log(self.status.clone());
        Ok(())
    }

    /// Listing → Apply Data Type at `va` (drag from DTM, or `T` key).
    pub(crate) fn apply_type_at(&mut self, va: u64, type_name: impl Into<String>) -> Result<(), String> {
        let type_name = type_name.into();
        let prog = self
            .program
            .as_mut()
            .ok_or_else(|| "no program loaded".to_string())?;
        prog.edits.set_applied_type(va, &type_name);
        self.event_bus.publish(GhidrustEvent::ProgramMutated {
            kind: MutationKind::Retype {
                va,
                type_desc: type_name.clone(),
            },
        });
        self.status = format!("Applied type {type_name} @ {va:#x}");
        self.log(self.status.clone());
        Ok(())
    }

    /// DTM → Rename an existing user type (`Rename` on a Data Type
    /// leaf). Rewrites `applied_types` so Listing decorations stay in sync.
    #[cfg(test)]
    pub(crate) fn rename_user_type(
        &mut self,
        old: impl Into<String>,
        new: impl Into<String>,
    ) -> Result<(), String> {
        let old = old.into();
        let new = new.into();
        if new.trim().is_empty() {
            return Err("empty type name".into());
        }
        let prog = self
            .program
            .as_mut()
            .ok_or_else(|| "no program loaded".to_string())?;
        if !prog.edits.rename_user_type(&old, &new) {
            return Err(format!("no type named {old}"));
        }
        self.event_bus.publish(GhidrustEvent::ProgramMutated {
            kind: MutationKind::Retype {
                va: 0,
                type_desc: format!("rename type: {old} → {new}"),
            },
        });
        self.status = format!("Renamed type {old} → {new}");
        self.log(self.status.clone());
        Ok(())
    }

    /// DTM → Delete a user type (also unlinks any `Applied` decorations).
    pub(crate) fn delete_user_type(&mut self, name: &str) -> Result<(), String> {
        let prog = self
            .program
            .as_mut()
            .ok_or_else(|| "no program loaded".to_string())?;
        if !prog.edits.delete_user_type(name) {
            return Err(format!("no type named {name}"));
        }
        self.event_bus.publish(GhidrustEvent::ProgramMutated {
            kind: MutationKind::Retype {
                va: 0,
                type_desc: format!("deleted type: {name}"),
            },
        });
        self.status = format!("Deleted type {name}");
        self.log(self.status.clone());
        Ok(())
    }

    pub(crate) fn open_rename_dialog(&mut self, va: u64) {
        let old = self
            .program
            .as_ref()
            .and_then(|p| p.display_name_at(va))
            .map(|s| s.to_string())
            .unwrap_or_default();
        self.show_rename_dialog = true;
        self.rename_dialog_target_va = Some(va);
        self.rename_dialog_old_name = old.clone();
        self.rename_dialog_new_name = old;
    }

    pub(crate) fn open_retype_dialog(&mut self, va: u64) {
        let cur = self
            .program
            .as_ref()
            .and_then(|p| p.edits.retype_at(va))
            .unwrap_or_default()
            .to_string();
        self.show_retype_dialog = true;
        self.retype_dialog_target_va = Some(va);
        self.retype_dialog_type = cur;
    }

    pub(crate) fn open_comment_dialog(&mut self, va: u64, kind: CommentKind) {
        let text = self
            .program
            .as_ref()
            .and_then(|p| p.edits.comment_at(va, kind))
            .unwrap_or_default()
            .to_string();
        self.show_comment_dialog = true;
        self.comment_dialog_target_va = Some(va);
        self.comment_dialog_kind = kind;
        self.comment_dialog_text = text;
    }

    pub(crate) fn open_signature_dialog(&mut self, entry: u64) {
        let existing = self
            .program
            .as_ref()
            .and_then(|p| p.edits.function_signature(entry))
            .map(|s| s.signature.clone())
            .unwrap_or_else(|| {
                self.program
                    .as_ref()
                    .and_then(|p| p.function_at(entry))
                    .map(|f| {
                        format!(
                            "undefined {}({})",
                            f.name,
                            if f.parameters.is_empty() {
                                "void".to_string()
                            } else {
                                f.parameters.join(", ")
                            }
                        )
                    })
                    .unwrap_or_default()
            });
        self.show_fn_signature_dialog = true;
        self.fn_signature_dialog_entry = Some(entry);
        self.fn_signature_dialog_text = existing;
    }

    pub(crate) fn open_new_type_dialog(&mut self, kind: NewTypeKind) {
        self.show_new_type_dialog = true;
        self.new_type_dialog_kind = kind;
        self.new_type_dialog_name.clear();
        self.new_type_dialog_body = kind.template().to_string();
    }

    pub(crate) fn open_edit_type_dialog(&mut self, name: &str) {
        let body = self
            .program
            .as_ref()
            .and_then(|p| p.edits.user_type(name))
            .unwrap_or_default()
            .to_string();
        self.show_edit_type_dialog = true;
        self.edit_type_dialog_orig_name = name.to_string();
        self.edit_type_dialog_name = name.to_string();
        self.edit_type_dialog_body = body;
    }

    pub(crate) fn open_type_chooser(&mut self, va: Option<u64>) {
        self.show_type_chooser_dialog = true;
        self.type_chooser_target_va = va;
        self.type_chooser_filter.clear();
    }
}
