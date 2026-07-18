//! Minimal fenced-code-block extractor for the Grok pane renderer.
//!
//! The pane needs to render streamed assistant output as Markdown *with* the
//! ability to hand fenced code blocks (`` ``` ``) to specialised renderers:
//!
//! - Pseudo-C / C blocks go through the existing `decomp_tokens` highlighter
//!   in the GUI, so agent-produced pseudo-C looks exactly like the Decompiler
//!   pane's output.
//! - JSON blocks (tool call results) get a monospace box with a "Copy" button.
//! - Everything else falls back to plain monospace.
//!
//! We deliberately don't pull `pulldown-cmark` in P1; a fenced-block splitter
//! is enough for the pane, keeps the dep footprint minimal, and doesn't drag
//! CommonMark tables into the airgap build. Full Markdown rendering is a
//! Phase-2 stretch (behind a `markdown-full` feature) when the pane needs
//! bulleted lists / headings / links.

use serde::{Deserialize, Serialize};

/// One parsed segment of streamed assistant text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MarkdownBlock {
    /// Prose (no fence). Rendered as wrapping label text.
    Prose(String),
    /// Fenced code block; `lang` may be empty. Common langs we treat specially
    /// in the GUI: `c`, `cpp`, `pseudo-c`, `pseudoc`, `json`, `rust`, `sh`.
    Code { lang: String, body: String },
}

impl MarkdownBlock {
    /// True if the block is a code fence whose language should be highlighted
    /// with the Decompiler pane's `decomp_tokens` highlighter.
    pub fn is_pseudo_c(&self) -> bool {
        match self {
            MarkdownBlock::Code { lang, .. } => {
                matches!(
                    lang.to_ascii_lowercase().as_str(),
                    "c" | "cpp" | "c++" | "pseudo-c" | "pseudoc" | "pseudo_c"
                )
            }
            _ => false,
        }
    }

    /// True if the block is a code fence with `json` — GUI renders with a
    /// monospace box + copy button.
    pub fn is_json(&self) -> bool {
        matches!(
            self,
            MarkdownBlock::Code { lang, .. } if lang.eq_ignore_ascii_case("json")
        )
    }
}

/// Split streamed Markdown into alternating prose / code blocks.
///
/// Rules:
///
/// - A line whose *stripped* content begins with ` ``` ` opens or closes a
///   fence; the tail after the backticks (up to whitespace) is the language.
/// - Unterminated fences are still emitted as a code block (truncated
///   streaming input renders sensibly).
/// - Empty inputs return an empty vec.
/// - Consecutive prose lines coalesce into a single [`MarkdownBlock::Prose`].
pub fn parse_markdown(input: &str) -> Vec<MarkdownBlock> {
    let mut out: Vec<MarkdownBlock> = Vec::new();
    let mut prose_buf = String::new();
    let mut code_buf = String::new();
    let mut code_lang = String::new();
    let mut in_code = false;

    for line in input.split_inclusive('\n') {
        let stripped = line.trim_end_matches('\n').trim_end_matches('\r');
        let s = stripped.trim_start();
        if s.starts_with("```") {
            if in_code {
                push_code(&mut out, std::mem::take(&mut code_lang), std::mem::take(&mut code_buf));
                in_code = false;
            } else {
                push_prose(&mut out, std::mem::take(&mut prose_buf));
                let after = s.trim_start_matches('`').trim();
                let lang: String = after
                    .split(|c: char| c.is_whitespace())
                    .next()
                    .unwrap_or("")
                    .to_string();
                code_lang = lang;
                in_code = true;
            }
            continue;
        }
        if in_code {
            code_buf.push_str(line);
        } else {
            prose_buf.push_str(line);
        }
    }
    if in_code {
        // Streaming truncation: flush the partial code block so the pane still
        // renders something monospace instead of eating half the stream.
        push_code(&mut out, code_lang, code_buf);
    } else {
        push_prose(&mut out, prose_buf);
    }
    out
}

fn push_prose(out: &mut Vec<MarkdownBlock>, buf: String) {
    if buf.is_empty() {
        return;
    }
    if let Some(MarkdownBlock::Prose(last)) = out.last_mut() {
        last.push_str(&buf);
        return;
    }
    out.push(MarkdownBlock::Prose(buf));
}

fn push_code(out: &mut Vec<MarkdownBlock>, lang: String, body: String) {
    out.push(MarkdownBlock::Code { lang, body });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input() {
        assert!(parse_markdown("").is_empty());
    }

    #[test]
    fn plain_prose_is_single_block() {
        let bs = parse_markdown("hello\nworld\n");
        assert_eq!(bs.len(), 1);
        assert!(matches!(bs[0], MarkdownBlock::Prose(_)));
    }

    #[test]
    fn splits_fenced_code_with_language() {
        let src = "before\n```c\nint x = 0;\n```\nafter\n";
        let bs = parse_markdown(src);
        assert_eq!(bs.len(), 3);
        assert!(matches!(&bs[0], MarkdownBlock::Prose(p) if p.trim() == "before"));
        match &bs[1] {
            MarkdownBlock::Code { lang, body } => {
                assert_eq!(lang, "c");
                assert!(body.contains("int x = 0;"));
            }
            _ => panic!("expected code"),
        }
        assert!(matches!(&bs[2], MarkdownBlock::Prose(p) if p.trim() == "after"));
    }

    #[test]
    fn unterminated_fence_still_flushes() {
        let src = "prose\n```json\n{\"a\":1}\n";
        let bs = parse_markdown(src);
        assert_eq!(bs.len(), 2);
        match &bs[1] {
            MarkdownBlock::Code { lang, body } => {
                assert_eq!(lang, "json");
                assert!(body.contains("\"a\":1"));
            }
            _ => panic!("expected code fallback"),
        }
    }

    #[test]
    fn language_variants_map_to_pseudo_c() {
        for l in ["c", "C", "cpp", "c++", "pseudo-c", "pseudoc", "PSEUDO_C"] {
            let b = MarkdownBlock::Code {
                lang: l.into(),
                body: "x;".into(),
            };
            assert!(b.is_pseudo_c(), "{l} should be pseudo-c");
        }
        assert!(!MarkdownBlock::Code {
            lang: "rust".into(),
            body: "x;".into()
        }
        .is_pseudo_c());
    }

    #[test]
    fn json_language_flag() {
        let b = MarkdownBlock::Code {
            lang: "JSON".into(),
            body: "{}".into(),
        };
        assert!(b.is_json());
    }

    #[test]
    fn indented_fence_still_matches() {
        let src = "  ```c\nint a;\n  ```\n";
        let bs = parse_markdown(src);
        assert_eq!(bs.len(), 1);
        match &bs[0] {
            MarkdownBlock::Code { lang, body } => {
                assert_eq!(lang, "c");
                assert!(body.contains("int a;"));
            }
            _ => panic!("expected code"),
        }
    }
}
