//! Decompiler token model — Ghidra `ClangToken` analog for cross-highlight and nav.
//!
//! **Design note.** The Stage-0 (or Stage-0.5) pseudo-C is produced by
//! [`ghidrust_decomp`] and may be swapped out later for a real IR/SSA emitter.
//! To avoid fighting with the decompiler crate over SSA internals, this module
//! tokenises the **existing pseudo-C string** into a `Vec<Token>` with kinds
//! and (optionally) a machine address so the GUI can:
//!
//! * cross-highlight the Listing line when a token is clicked;
//! * navigate to a function/label on double-click;
//! * middle-click a variable to highlight every occurrence in the pane.
//!
//! When the decompiler eventually emits real token spans, replace [`tokenize`]
//! with a shim that just adopts those spans — the GUI consumer surface stays
//! the same.

/// One rendered token in the decompiler pane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub kind: TokenKind,
    pub text: String,
    /// Machine address this token maps to, when known.
    pub va: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    /// Keyword — `if`, `else`, `goto`, `return`, `void`, primitive types, …
    Keyword,
    /// Function name (declaration or call).
    Function,
    /// Local variable / parameter / register name.
    Variable,
    /// Block label — `block_3:` on the left; `block_3` in `goto block_3`.
    Label,
    /// Numeric literal — either a scalar or an address (`0x140001000`).
    Constant,
    /// Hex address literal (subclass of Constant with a resolved VA).
    Address,
    /// Comment (`// …` or `/* … */`).
    Comment,
    /// Punctuation / operator / whitespace glue.
    Syntax,
    /// Whitespace-only chunk (preserved so we can round-trip render).
    Whitespace,
    /// Newline sentinel (reserved for future non-`\n`-split renderers).
    #[allow(dead_code)]
    Newline,
}

/// One decompiler line, with its (optional) source instruction address and its tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecompLine {
    /// 0-based line index in the pseudo-C output.
    pub line: usize,
    /// Machine address the line maps to (first address token found on the line, if any).
    pub machine_addr: Option<u64>,
    /// Block label this line lives in, when detectable.
    pub block_label: Option<String>,
    pub tokens: Vec<Token>,
}

/// C-ish keywords used by the Stage-0 / Stage-0.5 emitter.
const C_KEYWORDS: &[&str] = &[
    "if", "else", "goto", "return", "while", "for", "do", "switch", "case",
    "break", "continue", "default", "void", "int", "char", "short", "long",
    "unsigned", "signed", "float", "double", "bool", "true", "false", "null",
    "sizeof", "struct", "union", "enum",
];

/// Register names we always classify as `Variable` (x86-64 GPRs + segment/xmm subset).
const REGISTER_NAMES: &[&str] = &[
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
    "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
    "al", "bl", "cl", "dl", "ah", "bh", "ch", "dh",
    "sil", "dil", "bpl", "spl",
    "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
    "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",
    "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
    "rip", "eip", "ip", "cs", "ds", "es", "fs", "gs", "ss",
];

/// Tokenise a full pseudo-C source blob into per-line spans.
pub fn tokenize(source: &str) -> Vec<DecompLine> {
    let mut out = Vec::new();
    let mut current_block: Option<String> = None;
    for (idx, raw) in source.split('\n').enumerate() {
        let mut tokens = Vec::new();
        let mut machine_addr = None;
        tokenize_line(raw, &mut tokens);
        // Resolve line-level machine addr: first Address token wins, else scrape a
        // hex literal out of any comment on the line.
        for t in &tokens {
            if matches!(t.kind, TokenKind::Address) {
                if let Some(v) = t.va {
                    machine_addr = Some(v);
                    break;
                }
            }
        }
        if machine_addr.is_none() {
            for t in &tokens {
                if matches!(t.kind, TokenKind::Comment) {
                    if let Some(v) = t.va {
                        machine_addr = Some(v);
                        break;
                    }
                }
            }
        }
        // Track "block_N:" label state so downstream renderers can group.
        if let Some(label) = block_label_from_line(raw) {
            current_block = Some(label);
        }
        out.push(DecompLine {
            line: idx,
            machine_addr,
            block_label: current_block.clone(),
            tokens,
        });
    }
    out
}

/// Parse a `block_N:` label at the start of a stripped line, else `None`.
fn block_label_from_line(line: &str) -> Option<String> {
    let t = line.trim_start();
    if !t.starts_with("block_") {
        return None;
    }
    let end = t.find(':')?;
    let label = &t[..end];
    if !label
        .strip_prefix("block_")
        .map(|rest| rest.chars().all(|c| c.is_ascii_digit()))
        .unwrap_or(false)
    {
        return None;
    }
    Some(label.to_string())
}

fn tokenize_line(line: &str, out: &mut Vec<Token>) {
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        // Line comment: consume rest of line.
        if c == '/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            let text = &line[i..];
            let va = first_hex_in(text);
            out.push(Token {
                kind: TokenKind::Comment,
                text: text.to_string(),
                va,
            });
            return;
        }
        // Block comment: consume to `*/` or end.
        if c == '/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            let mut j = i + 2;
            while j + 1 < bytes.len() && !(bytes[j] == b'*' && bytes[j + 1] == b'/') {
                j += 1;
            }
            let end = (j + 2).min(bytes.len());
            // Scrape any 0x… addresses from inside the comment.
            let text = &line[i..end];
            let addr_va = first_hex_in(text);
            out.push(Token {
                kind: TokenKind::Comment,
                text: text.to_string(),
                va: addr_va,
            });
            i = end;
            continue;
        }
        // Whitespace run.
        if c.is_ascii_whitespace() {
            let start = i;
            while i < bytes.len() && (bytes[i] as char).is_ascii_whitespace() {
                i += 1;
            }
            out.push(Token {
                kind: TokenKind::Whitespace,
                text: line[start..i].to_string(),
                va: None,
            });
            continue;
        }
        // Hex / numeric literal.
        if c == '0'
            && i + 1 < bytes.len()
            && (bytes[i + 1] == b'x' || bytes[i + 1] == b'X')
        {
            let start = i;
            i += 2;
            while i < bytes.len() && (bytes[i] as char).is_ascii_hexdigit() {
                i += 1;
            }
            let text = line[start..i].to_string();
            let va = u64::from_str_radix(&text[2..], 16).ok();
            out.push(Token {
                kind: TokenKind::Address,
                text,
                va,
            });
            continue;
        }
        if c.is_ascii_digit() {
            let start = i;
            while i < bytes.len() && (bytes[i] as char).is_ascii_digit() {
                i += 1;
            }
            let text = line[start..i].to_string();
            let va = text.parse::<u64>().ok();
            out.push(Token {
                kind: TokenKind::Constant,
                text,
                va,
            });
            continue;
        }
        // Identifier / keyword.
        if is_ident_start(c) {
            let start = i;
            while i < bytes.len() && is_ident_part(bytes[i] as char) {
                i += 1;
            }
            let text = &line[start..i];
            let kind = classify_ident(text, &line[i..]);
            let va = if text.starts_with("FUN_") {
                u64::from_str_radix(&text[4..], 16).ok()
            } else if let Some(rest) = text.strip_prefix("block_") {
                // block_N is a label, not an address, but keep the id as VA-ish so
                // consumers can uniquely key on it.
                rest.parse::<u64>().ok()
            } else {
                None
            };
            out.push(Token {
                kind,
                text: text.to_string(),
                va,
            });
            continue;
        }
        // Fallback: single punctuation/operator character.
        let start = i;
        // Group common multi-char operators.
        let two = if i + 1 < bytes.len() {
            &line[i..i + 2]
        } else {
            ""
        };
        let n = match two {
            "==" | "!=" | "<=" | ">=" | "&&" | "||" | "->" | "::" | "<<" | ">>" | "+=" | "-="
            | "*=" | "/=" => 2,
            _ => 1,
        };
        i += n;
        out.push(Token {
            kind: TokenKind::Syntax,
            text: line[start..i].to_string(),
            va: None,
        });
    }
}

fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

fn is_ident_part(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn classify_ident(text: &str, rest_of_line: &str) -> TokenKind {
    if C_KEYWORDS.contains(&text) {
        return TokenKind::Keyword;
    }
    if REGISTER_NAMES.contains(&text) {
        return TokenKind::Variable;
    }
    if text.starts_with("block_") {
        return TokenKind::Label;
    }
    if text.starts_with("FUN_") {
        return TokenKind::Function;
    }
    // Heuristic: if the identifier is followed by `(`, treat as function call/decl.
    if rest_of_line.trim_start().starts_with('(') {
        return TokenKind::Function;
    }
    // Everything else: variable-ish.
    TokenKind::Variable
}

/// First `0x…` in a slice, parsed as u64.
fn first_hex_in(s: &str) -> Option<u64> {
    let idx = s.find("0x")?;
    let rest = &s[idx + 2..];
    let end = rest
        .find(|c: char| !c.is_ascii_hexdigit())
        .unwrap_or(rest.len());
    u64::from_str_radix(&rest[..end], 16).ok()
}

/// Return every distinct occurrence of `text` in the given line set (for middle-click highlight).
#[allow(dead_code)] // reserved for future "count occurrences" hover UI
pub fn occurrences_of<'a>(lines: &'a [DecompLine], text: &str) -> Vec<(usize, usize)> {
    let mut hits = Vec::new();
    for line in lines {
        for (ti, tok) in line.tokens.iter().enumerate() {
            if tok.text == text
                && !matches!(
                    tok.kind,
                    TokenKind::Whitespace | TokenKind::Syntax | TokenKind::Newline
                )
            {
                hits.push((line.line, ti));
            }
        }
    }
    hits
}

/// Return the line index (if any) whose `machine_addr == Some(va)` — used to
/// cross-highlight the decompiler when the Listing cursor moves.
pub fn line_for_va(lines: &[DecompLine], va: u64) -> Option<usize> {
    // Prefer exact match, else nearest prior.
    let mut best = None;
    for line in lines {
        if let Some(a) = line.machine_addr {
            if a == va {
                return Some(line.line);
            }
            if a < va {
                best = Some(line.line);
            }
            if a > va {
                break;
            }
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keywords_functions_addresses_and_registers() {
        let src = "// hi 0x1000\nvoid FUN_140001000(void) {\n  block_0:\n    if (eax == 0) {\n      goto block_1;\n    }\n    return;\n}\n";
        let lines = tokenize(src);
        assert_eq!(lines.len(), 9, "expected 9 split-by-newline lines");
        // Line 0: comment with a hex inside.
        assert!(lines[0]
            .tokens
            .iter()
            .any(|t| matches!(t.kind, TokenKind::Comment)));
        assert_eq!(lines[0].machine_addr, Some(0x1000));
        // Line 1: keyword `void`, function `FUN_…`.
        let kinds: Vec<TokenKind> = lines[1].tokens.iter().map(|t| t.kind).collect();
        assert!(kinds.contains(&TokenKind::Keyword), "void keyword missing");
        assert!(kinds.contains(&TokenKind::Function), "FUN_ missing");
        // Line 2: block_0: label.
        assert_eq!(lines[2].block_label.as_deref(), Some("block_0"));
        assert!(lines[2]
            .tokens
            .iter()
            .any(|t| matches!(t.kind, TokenKind::Label)));
        // Line 3: keyword if + register eax.
        assert!(lines[3]
            .tokens
            .iter()
            .any(|t| matches!(t.kind, TokenKind::Keyword) && t.text == "if"));
        assert!(lines[3]
            .tokens
            .iter()
            .any(|t| matches!(t.kind, TokenKind::Variable) && t.text == "eax"));
    }

    #[test]
    fn line_for_va_finds_exact_and_nearest() {
        let src = "// 0x1000\n// 0x1010\n// 0x1020\n";
        let lines = tokenize(src);
        assert_eq!(line_for_va(&lines, 0x1010), Some(1));
        assert_eq!(line_for_va(&lines, 0x1015), Some(1)); // nearest prior
        assert_eq!(line_for_va(&lines, 0x0FFF), None);
    }

    #[test]
    fn occurrences_of_matches_only_meaningful_tokens() {
        let src = "eax + eax; // eax\n";
        let lines = tokenize(src);
        let hits = occurrences_of(&lines, "eax");
        // Two Variable hits — the "eax" inside the comment must NOT count.
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn ida_style_fun_extract_va() {
        let src = "void FUN_140001000(void) {}\n";
        let lines = tokenize(src);
        let f = lines[0]
            .tokens
            .iter()
            .find(|t| t.text == "FUN_140001000")
            .unwrap();
        assert_eq!(f.va, Some(0x140001000));
        assert_eq!(f.kind, TokenKind::Function);
    }
}
