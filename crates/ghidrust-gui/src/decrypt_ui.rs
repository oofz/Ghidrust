//! Decrypt / crypto-result pane helpers for egui.

use eframe::egui::{self, Color32, Ui};
use ghidrust_core::{
    bake, extract_iocs, magic, suggest_recipe_for_hint, BakeOp, CryptConstantHit,
    CryptoCapabilityHit, ObfuscatedStringHit, Program,
};
use std::cell::RefCell;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecryptTab {
    Bake,
    Constants,
    Strings,
    Capabilities,
}

impl DecryptTab {
    fn label(self) -> &'static str {
        match self {
            Self::Bake => "Bake",
            Self::Constants => "Constants",
            Self::Strings => "Strings",
            Self::Capabilities => "Capabilities",
        }
    }
}

/// Action requested by the Decrypt pane (host applies to program edits).
#[derive(Debug, Clone)]
pub enum DecryptPaneAction {
    ApplyComment { va: u64, text: String },
    ApplyBookmark { va: u64, text: String },
    SendToListing { va: u64 },
    LoadVa { va: u64, len: usize },
    Goto { va: u64 },
    DecryptNearby { va: u64, hint: String },
    BakeRemnant { va: u64 },
    FocusFunction { va: u64 },
}

#[derive(Debug, Clone)]
pub struct DecryptPaneState {
    pub input_hex: String,
    pub key_hex: String,
    pub iv_hex: String,
    pub output: String,
    pub output_bytes: Vec<u8>,
    pub message: String,
    pub source_va: Option<u64>,
    pub input_source: String,
    pub algo_hint: Option<String>,
    pub tab: DecryptTab,
    pub va_input: String,
    pub va_len: usize,
    pub file_path: String,
    pub selected_preset: String,
    pub mode: String,
    pub nonce_hex: String,
    pub counter: String,
    pub crib: String,
}

impl Default for DecryptPaneState {
    fn default() -> Self {
        Self {
            input_hex: String::new(),
            key_hex: String::new(),
            iv_hex: String::new(),
            output: String::new(),
            output_bytes: Vec::new(),
            message: String::new(),
            source_va: None,
            input_source: "Paste hex or Base64 text".into(),
            algo_hint: None,
            tab: DecryptTab::Bake,
            va_input: String::new(),
            va_len: 256,
            file_path: String::new(),
            selected_preset: "magic".into(),
            mode: "cbc".into(),
            nonce_hex: String::new(),
            counter: "0".into(),
            crib: String::new(),
        }
    }
}

impl DecryptPaneState {
    pub fn focus(&mut self, tab: DecryptTab) {
        self.tab = tab;
    }

    pub fn load_bytes(&mut self, va: Option<u64>, bytes: &[u8], hint: Option<String>) {
        self.input_hex = bytes.iter().map(|b| format!("{b:02x}")).collect();
        self.source_va = va;
        self.input_source = if va.is_some() {
            "Listing selection (hex bytes)".into()
        } else {
            "Paste hex or Base64 text".into()
        };
        self.algo_hint = hint;
        self.output.clear();
        self.output_bytes.clear();
        self.message.clear();
    }

    pub fn load_text(&mut self, va: Option<u64>, text: String, source: &str) {
        self.input_hex = text;
        self.source_va = va;
        self.input_source = source.into();
        self.algo_hint = None;
        self.output.clear();
        self.output_bytes.clear();
        self.message.clear();
    }

    fn input_bytes(&self, preset: &str) -> Vec<u8> {
        if matches!(
            preset,
            "from_b64"
                | "b64_utf16"
                | "b64_gunzip"
                | "from_hex"
                | "charcode"
                | "url"
                | "html"
                | "rot13"
                | "reverse"
                | "utf16"
                | "inflate"
        ) {
            return self.input_hex.trim().as_bytes().to_vec();
        }
        let clean: String = self
            .input_hex
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        (0..clean.len())
            .step_by(2)
            .filter_map(|i| {
                clean
                    .get(i..i + 2)
                    .and_then(|s| u8::from_str_radix(s, 16).ok())
            })
            .collect()
    }

    pub fn bake_preset(&mut self, preset: &str) {
        let input = self.input_bytes(preset);
        let ops: Vec<BakeOp> = match preset {
            "xor_brute" => vec![BakeOp {
                op: "XORBrute".into(),
                args: serde_json::json!({}),
            }],
            "from_b64" => vec![BakeOp {
                op: "FromBase64".into(),
                args: serde_json::json!({}),
            }],
            "b64_utf16" => vec![
                BakeOp {
                    op: "FromBase64".into(),
                    args: serde_json::json!({}),
                },
                BakeOp {
                    op: "DecodeUTF16LE".into(),
                    args: serde_json::json!({}),
                },
            ],
            "xor_key" => vec![BakeOp {
                op: "XOR".into(),
                args: serde_json::json!({"key_hex": self.key_hex}),
            }],
            "rc4" => vec![BakeOp {
                op: "RC4".into(),
                args: serde_json::json!({"key_hex": self.key_hex}),
            }],
            "aes_cbc" => vec![BakeOp {
                op: "AESDecrypt".into(),
                args: serde_json::json!({
                    "key_hex": self.key_hex,
                    "iv_hex": self.iv_hex,
                    "mode": self.mode
                }),
            }],
            "des" => vec![BakeOp {
                op: "DESDecrypt".into(),
                args: serde_json::json!({"key_hex": self.key_hex, "iv_hex": self.iv_hex, "mode": self.mode}),
            }],
            "triple_des" => vec![BakeOp {
                op: "TripleDESDecrypt".into(),
                args: serde_json::json!({"key_hex": self.key_hex, "iv_hex": self.iv_hex, "mode": self.mode}),
            }],
            "blowfish" => vec![BakeOp {
                op: "BlowfishDecrypt".into(),
                args: serde_json::json!({"key_hex": self.key_hex, "iv_hex": self.iv_hex, "mode": self.mode}),
            }],
            "chacha" => vec![BakeOp {
                op: "ChaCha20Decrypt".into(),
                args: serde_json::json!({
                    "key_hex": self.key_hex,
                    "nonce_hex": self.nonce_hex,
                    "counter": self.counter.parse::<u32>().unwrap_or(0),
                }),
            }],
            "gunzip" => vec![BakeOp {
                op: "Gunzip".into(),
                args: serde_json::json!({}),
            }],
            "inflate" => vec![BakeOp {
                op: "Inflate".into(),
                args: serde_json::json!({}),
            }],
            "from_hex" => vec![BakeOp {
                op: "FromHex".into(),
                args: serde_json::json!({}),
            }],
            "charcode" => vec![BakeOp {
                op: "FromCharcode".into(),
                args: serde_json::json!({}),
            }],
            "url" => vec![BakeOp {
                op: "UrlDecode".into(),
                args: serde_json::json!({}),
            }],
            "html" => vec![BakeOp {
                op: "HtmlEntityDecode".into(),
                args: serde_json::json!({}),
            }],
            "rot13" => vec![BakeOp {
                op: "ROT13".into(),
                args: serde_json::json!({}),
            }],
            "reverse" => vec![BakeOp {
                op: "Reverse".into(),
                args: serde_json::json!({}),
            }],
            "utf16" => vec![BakeOp {
                op: "DecodeUTF16LE".into(),
                args: serde_json::json!({}),
            }],
            "b64_gunzip" => vec![
                BakeOp {
                    op: "FromBase64".into(),
                    args: serde_json::json!({}),
                },
                BakeOp {
                    op: "Gunzip".into(),
                    args: serde_json::json!({}),
                },
            ],
            "hint" => {
                if let Some(h) = &self.algo_hint {
                    let mut ops = suggest_recipe_for_hint(h);
                    for op in &mut ops {
                        if op.op.eq_ignore_ascii_case("AESDecrypt")
                            || op.op.eq_ignore_ascii_case("RC4")
                            || op.op.eq_ignore_ascii_case("XOR")
                        {
                            if let Some(obj) = op.args.as_object_mut() {
                                if !self.key_hex.is_empty() {
                                    obj.insert(
                                        "key_hex".into(),
                                        serde_json::Value::String(self.key_hex.clone()),
                                    );
                                }
                                if !self.iv_hex.is_empty() {
                                    obj.insert(
                                        "iv_hex".into(),
                                        serde_json::Value::String(self.iv_hex.clone()),
                                    );
                                }
                            }
                        }
                    }
                    ops
                } else {
                    self.message = "no algo hint".into();
                    return;
                }
            }
            "magic" => {
                let r = if self.crib.trim().is_empty() {
                    magic(&input, 3)
                } else {
                    ghidrust_core::magic_with_crib(&input, 3, Some(&self.crib))
                };
                self.message = format!("{} {:?}", r.message, r.recipe_applied);
                self.output_bytes = (0..r.output_hex.len())
                    .step_by(2)
                    .filter_map(|i| u8::from_str_radix(&r.output_hex[i..i + 2], 16).ok())
                    .collect();
                self.output = r.output_utf8.unwrap_or(r.output_hex);
                return;
            }
            _ => {
                self.message = format!("unknown preset {preset}");
                return;
            }
        };
        let r = bake(&input, &ops);
        self.message = r.message;
        if r.ok {
            let bytes: Vec<u8> = (0..r.output_hex.len())
                .step_by(2)
                .filter_map(|i| u8::from_str_radix(&r.output_hex[i..i + 2], 16).ok())
                .collect();
            let iocs = extract_iocs(&bytes);
            self.output_bytes = bytes;
            self.output = r.output_utf8.unwrap_or(r.output_hex);
            if !iocs.is_empty() {
                self.message = format!("{} | iocs={}", self.message, iocs.join(", "));
            }
        } else {
            self.output.clear();
            self.output_bytes.clear();
        }
    }
}

pub fn ui_crypto_constants(
    ui: &mut Ui,
    muted: Color32,
    hits: &[CryptConstantHit],
    mut on_goto: impl FnMut(u64),
    mut on_decrypt: impl FnMut(u64, &str),
) {
    ui.heading("Crypto Constants");
    ui.small(egui::RichText::new("Find Crypt analyzer hits").color(muted));
    ui.separator();
    if hits.is_empty() {
        ui.weak("No hits — run Find Crypt analyzer.");
        return;
    }
    egui::ScrollArea::vertical()
        .max_height(420.0)
        .show(ui, |ui| {
            egui::Grid::new("crypt_const_grid")
                .num_columns(4)
                .striped(true)
                .show(ui, |ui| {
                    ui.strong("Address");
                    ui.strong("Algorithm");
                    ui.strong("Constant");
                    ui.strong("");
                    ui.end_row();
                    for h in hits {
                        if ui
                            .link(egui::RichText::new(format!("{:#x}", h.va)).monospace())
                            .clicked()
                        {
                            on_goto(h.va);
                        }
                        ui.monospace(&h.algorithm);
                        ui.label(&h.constant);
                        if ui.button("Decrypt nearby…").clicked() {
                            on_decrypt(h.va, &h.algorithm);
                        }
                        ui.end_row();
                    }
                });
        });
}

pub fn ui_recovered_strings(
    ui: &mut Ui,
    muted: Color32,
    hits: &[ObfuscatedStringHit],
    mut on_goto: impl FnMut(u64),
    mut on_bake: impl FnMut(u64),
    mut on_decoder: impl FnMut(u64),
) {
    ui.heading("Recovered Strings");
    ui.small(egui::RichText::new("Obfuscated Strings analyzer").color(muted));
    ui.separator();
    if hits.is_empty() {
        ui.weak("No hits — run Obfuscated Strings analyzer.");
        return;
    }
    egui::ScrollArea::vertical()
        .max_height(420.0)
        .show(ui, |ui| {
            egui::Grid::new("recovered_str_grid")
                .num_columns(5)
                .striped(true)
                .show(ui, |ui| {
                    ui.strong("Address");
                    ui.strong("Kind");
                    ui.strong("String");
                    ui.strong("");
                    ui.strong("");
                    ui.end_row();
                    for h in hits {
                        if ui
                            .link(egui::RichText::new(format!("{:#x}", h.va)).monospace())
                            .clicked()
                        {
                            on_goto(h.va);
                        }
                        ui.label(format!("{:?}", h.kind));
                        let val: String = h.value.chars().take(80).collect();
                        ui.monospace(val);
                        if ui.small_button("Bake remnant…").clicked() {
                            on_bake(h.va);
                        }
                        if let Some(decoder_va) = h.decoder_va {
                            if ui.small_button("Decoder").clicked() {
                                on_decoder(decoder_va);
                            }
                        } else {
                            ui.label("");
                        }
                        ui.end_row();
                    }
                });
        });
}

pub fn ui_crypto_capabilities(
    ui: &mut Ui,
    muted: Color32,
    hits: &[CryptoCapabilityHit],
    mut on_goto: impl FnMut(u64),
    mut on_decrypt: impl FnMut(u64, String),
) {
    ui.heading("Crypto Capabilities");
    ui.small(egui::RichText::new("Crypto Capabilities analyzer").color(muted));
    ui.separator();
    if hits.is_empty() {
        ui.weak("No hits — run Crypto Capabilities analyzer.");
        return;
    }
    egui::ScrollArea::vertical()
        .max_height(420.0)
        .show(ui, |ui| {
            egui::Grid::new("crypto_cap_grid")
                .num_columns(4)
                .striped(true)
                .show(ui, |ui| {
                    ui.strong("VA");
                    ui.strong("Tag");
                    ui.strong("Capability");
                    ui.strong("");
                    ui.end_row();
                    for h in hits {
                        let va_s = h
                            .function_va
                            .map(|v| format!("{v:#x}"))
                            .unwrap_or_else(|| "-".into());
                        if let Some(va) = h.function_va {
                            if ui.link(egui::RichText::new(va_s).monospace()).clicked() {
                                on_goto(va);
                            }
                        } else {
                            ui.monospace(va_s);
                        }
                        ui.label(&h.tag);
                        ui.label(format!("{} ({})", h.capability, h.evidence));
                        if let Some(va) = h.function_va {
                            if ui.small_button("Decrypt at function…").clicked() {
                                on_decrypt(va, h.capability.clone());
                            }
                        } else {
                            ui.label("");
                        }
                        ui.end_row();
                    }
                });
        });
}

const PRESETS: &[(&str, &str)] = &[
    ("xor_brute", "XOR brute"),
    ("xor_key", "XOR key"),
    ("from_b64", "Base64"),
    ("from_hex", "Hex text"),
    ("b64_utf16", "Base64 → UTF-16LE"),
    ("b64_gunzip", "Base64 → Gunzip"),
    ("gunzip", "Gunzip"),
    ("inflate", "Inflate"),
    ("charcode", "Charcode"),
    ("url", "URL decode"),
    ("html", "HTML entities"),
    ("rot13", "ROT13"),
    ("reverse", "Reverse"),
    ("utf16", "UTF-16LE"),
    ("rc4", "RC4"),
    ("aes_cbc", "AES"),
    ("des", "DES"),
    ("triple_des", "Triple-DES"),
    ("blowfish", "Blowfish"),
    ("chacha", "ChaCha20"),
    ("magic", "Magic"),
];

fn preset_label(preset: &str) -> &'static str {
    PRESETS
        .iter()
        .find_map(|(value, label)| (*value == preset).then_some(*label))
        .unwrap_or("Magic")
}

pub fn ui_decrypt_window(
    ui: &mut Ui,
    muted: Color32,
    state: &mut DecryptPaneState,
    constants: &[CryptConstantHit],
    strings: &[ObfuscatedStringHit],
    capabilities: &[CryptoCapabilityHit],
) -> Option<DecryptPaneAction> {
    ui.heading("Decrypt");
    ui.small(
        egui::RichText::new("Bake input and crypto discovery results in one window.").color(muted),
    );
    ui.separator();
    ui.horizontal_wrapped(|ui| {
        for tab in [
            DecryptTab::Bake,
            DecryptTab::Constants,
            DecryptTab::Strings,
            DecryptTab::Capabilities,
        ] {
            ui.selectable_value(&mut state.tab, tab, tab.label());
        }
    });
    ui.separator();

    match state.tab {
        DecryptTab::Bake => ui_bake_tab(ui, muted, state),
        DecryptTab::Constants => {
            let action = RefCell::new(None);
            ui_crypto_constants(
                ui,
                muted,
                constants,
                |va| *action.borrow_mut() = Some(DecryptPaneAction::Goto { va }),
                |va, hint| {
                    *action.borrow_mut() = Some(DecryptPaneAction::DecryptNearby {
                        va,
                        hint: hint.to_owned(),
                    })
                },
            );
            action.into_inner()
        }
        DecryptTab::Strings => {
            let action = RefCell::new(None);
            ui_recovered_strings(
                ui,
                muted,
                strings,
                |va| *action.borrow_mut() = Some(DecryptPaneAction::Goto { va }),
                |va| *action.borrow_mut() = Some(DecryptPaneAction::BakeRemnant { va }),
                |va| *action.borrow_mut() = Some(DecryptPaneAction::FocusFunction { va }),
            );
            action.into_inner()
        }
        DecryptTab::Capabilities => {
            let action = RefCell::new(None);
            ui_crypto_capabilities(
                ui,
                muted,
                capabilities,
                |va| *action.borrow_mut() = Some(DecryptPaneAction::Goto { va }),
                |va, hint| {
                    *action.borrow_mut() = Some(DecryptPaneAction::DecryptNearby { va, hint })
                },
            );
            action.into_inner()
        }
    }
}

fn ui_bake_tab(
    ui: &mut Ui,
    muted: Color32,
    state: &mut DecryptPaneState,
) -> Option<DecryptPaneAction> {
    let mut action = None;
    ui.small(egui::RichText::new("Select input, choose an operation, then Bake.").color(muted));
    ui.separator();
    if let Some(hint) = &state.algo_hint {
        ui.label(format!("Hint: {hint}"));
        if hint.to_ascii_uppercase().contains("AES") && ui.button("Apply AES-CBC").clicked() {
            state.bake_preset("aes_cbc");
        }
        if ui.button("Bake from hint").clicked() {
            state.bake_preset("hint");
        }
    }
    if let Some(va) = state.source_va {
        ui.small(format!("Source VA: {va:#x}"));
    }
    ui.small(format!("Input source: {}", state.input_source));
    ui.horizontal(|ui| {
        ui.label("VA:");
        ui.add(egui::TextEdit::singleline(&mut state.va_input).desired_width(120.0));
        ui.label("Length:");
        ui.add(egui::DragValue::new(&mut state.va_len).range(1..=0x10000));
        if ui.button("Load VA").clicked() {
            let raw = state.va_input.trim().trim_start_matches("0x");
            match u64::from_str_radix(raw, 16) {
                Ok(va) => {
                    action = Some(DecryptPaneAction::LoadVa {
                        va,
                        len: state.va_len,
                    })
                }
                Err(_) => state.message = "VA must be hexadecimal, e.g. 401000".into(),
            }
        }
    });
    ui.horizontal(|ui| {
        ui.label("File:");
        ui.add(egui::TextEdit::singleline(&mut state.file_path).desired_width(280.0));
        if ui.button("Load file").clicked() {
            match std::fs::read(&state.file_path) {
                Ok(bytes) => {
                    state.load_bytes(None, &bytes, None);
                    state.input_source = format!("File: {}", state.file_path);
                }
                Err(e) => state.message = format!("file read failed: {e}"),
            }
        }
    });
    ui.label("Input (hex by default; text operations accept pasted text):");
    ui.add(
        egui::TextEdit::multiline(&mut state.input_hex)
            .desired_width(f32::INFINITY)
            .desired_rows(4)
            .font(egui::TextStyle::Monospace),
    );
    ui.horizontal(|ui| {
        ui.label("Key hex:");
        ui.add(egui::TextEdit::singleline(&mut state.key_hex).desired_width(180.0));
        ui.label("IV hex:");
        ui.add(egui::TextEdit::singleline(&mut state.iv_hex).desired_width(180.0));
    });
    ui.horizontal(|ui| {
        ui.label("Mode:");
        egui::ComboBox::from_id_salt("decrypt_mode")
            .selected_text(&state.mode)
            .show_ui(ui, |ui| {
                for mode in ["cbc", "ecb", "ctr", "cfb", "ofb", "gcm"] {
                    ui.selectable_value(&mut state.mode, mode.into(), mode);
                }
            });
        ui.label("Nonce:");
        ui.add(egui::TextEdit::singleline(&mut state.nonce_hex).desired_width(130.0));
        ui.label("Counter:");
        ui.add(egui::TextEdit::singleline(&mut state.counter).desired_width(55.0));
    });
    ui.horizontal(|ui| {
        ui.label("Operation:");
        egui::ComboBox::from_id_salt("decrypt_preset")
            .selected_text(preset_label(&state.selected_preset))
            .show_ui(ui, |ui| {
                for (preset, label) in PRESETS {
                    ui.selectable_value(&mut state.selected_preset, (*preset).into(), *label);
                }
            });
        if ui.button("Bake operation").clicked() {
            let preset = state.selected_preset.clone();
            state.bake_preset(&preset);
        }
        if ui.button("Bake from hint").clicked() {
            state.bake_preset("hint");
        }
    });
    ui.horizontal(|ui| {
        ui.label("Magic crib:");
        ui.add(egui::TextEdit::singleline(&mut state.crib).desired_width(180.0));
        if ui.button("Magic").clicked() {
            state.bake_preset("magic");
        }
        for (label, preset) in [
            ("XOR brute", "xor_brute"),
            ("Base64", "from_b64"),
            ("Gunzip", "gunzip"),
        ] {
            if ui.small_button(label).clicked() {
                state.bake_preset(preset);
            }
        }
    });
    ui.horizontal(|ui| {
        let can_apply = state.source_va.is_some() && !state.output.is_empty();
        if ui
            .add_enabled(can_apply, egui::Button::new("Apply as comment"))
            .on_hover_text("Write bake output as an EOL comment at the source VA")
            .clicked()
        {
            if let Some(va) = state.source_va {
                let text: String = state.output.chars().take(200).collect();
                action = Some(DecryptPaneAction::ApplyComment {
                    va,
                    text: format!("decrypted: {text}"),
                });
            }
        }
        if ui
            .add_enabled(can_apply, egui::Button::new("Apply as bookmark"))
            .clicked()
        {
            if let Some(va) = state.source_va {
                action = Some(DecryptPaneAction::ApplyBookmark {
                    va,
                    text: state.output.chars().take(120).collect(),
                });
            }
        }
        if ui.button("Extract IOCs").clicked() {
            let iocs = extract_iocs(&state.output_bytes);
            state.message = if iocs.is_empty() {
                "No IOCs found in Bake output.".into()
            } else {
                format!("IOCs: {}", iocs.join(", "))
            };
        }
        if ui
            .add_enabled(can_apply, egui::Button::new("Send to Listing"))
            .on_hover_text("Focuses the input VA; output is not written as code.")
            .clicked()
        {
            if let Some(va) = state.source_va {
                action = Some(DecryptPaneAction::SendToListing { va });
            }
        }
    });
    if !state.message.is_empty() {
        ui.small(&state.message);
    }
    ui.label("Output:");
    ui.add(
        egui::TextEdit::multiline(&mut state.output)
            .desired_width(f32::INFINITY)
            .desired_rows(6)
            .font(egui::TextStyle::Monospace),
    );
    action
}

pub fn bytes_at(prog: &Program, va: u64, count: usize) -> Option<Vec<u8>> {
    prog.read_va(va, count)
}
