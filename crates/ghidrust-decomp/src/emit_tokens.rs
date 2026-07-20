//! R5 — Emit-time token / source-map for Stage-1 pseudo-C.
//!
//! Tokens are produced alongside the text so the GUI can navigate without
//! brittle regex over the finished string.

use serde::{Deserialize, Serialize};

/// kinds used by the GUI highlighter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmitTokenKind {
    Keyword,
    Type,
    Function,
    Variable,
    Number,
    String,
    Comment,
    Operator,
    Punct,
    Label,
    Address,
    Text,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmitToken {
    pub kind: EmitTokenKind,
    pub text: String,
    /// Optional code VA associated with this token (call target, label, …).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub va: Option<u64>,
}

/// Simple builder that mirrors text into a token stream.
#[derive(Debug, Default)]
pub struct TokenSink {
    pub tokens: Vec<EmitToken>,
}

impl TokenSink {
    pub fn push(&mut self, kind: EmitTokenKind, text: impl Into<String>, va: Option<u64>) {
        let text = text.into();
        if text.is_empty() {
            return;
        }
        self.tokens.push(EmitToken { kind, text, va });
    }

    pub fn comment_line(&mut self, line: &str) {
        self.push(EmitTokenKind::Comment, line, None);
        self.push(EmitTokenKind::Text, "\n", None);
    }

    pub fn keyword(&mut self, s: &str) {
        self.push(EmitTokenKind::Keyword, s, None);
    }

    pub fn text(&mut self, s: &str) {
        self.push(EmitTokenKind::Text, s, None);
    }

    pub fn ident(&mut self, s: &str, va: Option<u64>) {
        self.push(EmitTokenKind::Variable, s, va);
    }

    pub fn function(&mut self, s: &str, va: Option<u64>) {
        self.push(EmitTokenKind::Function, s, va);
    }

    pub fn number(&mut self, s: &str) {
        self.push(EmitTokenKind::Number, s, None);
    }
}
