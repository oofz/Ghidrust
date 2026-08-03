//! Ghidrust Net Rule (GNR) dialect — parse and compile.

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub action: String,
    pub proto: String,
    pub src: String,
    pub src_port: String,
    pub direction: String,
    pub dst: String,
    pub dst_port: String,
    pub sid: u32,
    pub msg: String,
    pub severity: u8,
    pub contents: Vec<ContentOpt>,
    #[serde(default)]
    pub skipped_options: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentOpt {
    pub pattern: Vec<u8>,
    pub nocase: bool,
    pub offset: Option<usize>,
    pub depth: Option<usize>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CompiledRuleset {
    pub rules: Vec<Rule>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleError {
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for RuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}
impl std::error::Error for RuleError {}

/// Load and compile a rules file.
pub fn load_rule_pack(path: &Path) -> Result<CompiledRuleset, RuleError> {
    let text = std::fs::read_to_string(path).map_err(|e| RuleError {
        code: "io".into(),
        message: e.to_string(),
    })?;
    compile_rules(&text)
}

/// Compile GNR text (one rule per line; `#` comments).
pub fn compile_rules(text: &str) -> Result<CompiledRuleset, RuleError> {
    let mut rules = Vec::new();
    let mut warnings = Vec::new();
    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match parse_rule_line(line) {
            Ok(r) => {
                for s in &r.skipped_options {
                    warnings.push(format!("line {}: skipped option '{s}'", lineno + 1));
                }
                rules.push(r);
            }
            Err(e) => {
                return Err(RuleError {
                    code: "parse".into(),
                    message: format!("line {}: {}", lineno + 1, e.message),
                });
            }
        }
    }
    Ok(CompiledRuleset { rules, warnings })
}

fn parse_rule_line(line: &str) -> Result<Rule, RuleError> {
    // header (options)
    let (header, opts) = if let Some(i) = line.find('(') {
        let end = line.rfind(')').ok_or_else(|| RuleError {
            code: "parse".into(),
            message: "missing closing ')'".into(),
        })?;
        (&line[..i], &line[i + 1..end])
    } else {
        return Err(RuleError {
            code: "parse".into(),
            message: "missing options block".into(),
        });
    };
    let parts: Vec<_> = header.split_whitespace().collect();
    if parts.len() < 7 {
        return Err(RuleError {
            code: "parse".into(),
            message: "expected: action proto src sport dir dst dport".into(),
        });
    }
    let mut sid = 0u32;
    let mut msg = String::new();
    let mut severity = 2u8;
    let mut contents = Vec::new();
    let mut skipped = Vec::new();
    for opt in opts.split(';') {
        let opt = opt.trim();
        if opt.is_empty() {
            continue;
        }
        if let Some(rest) = opt.strip_prefix("msg:") {
            msg = unquote(rest.trim());
        } else if let Some(rest) = opt.strip_prefix("sid:") {
            sid = rest.trim().parse().unwrap_or(0);
        } else if let Some(rest) = opt.strip_prefix("severity:") {
            severity = rest.trim().parse().unwrap_or(2);
        } else if let Some(rest) = opt.strip_prefix("content:") {
            let (pat, flags) = split_content(rest.trim());
            let mut c = ContentOpt {
                pattern: unescape_content(&unquote(&pat)),
                nocase: false,
                offset: None,
                depth: None,
            };
            for f in flags {
                match f {
                    "nocase" => c.nocase = true,
                    other if other.starts_with("offset:") => {
                        c.offset = other["offset:".len()..].parse().ok();
                    }
                    other if other.starts_with("depth:") => {
                        c.depth = other["depth:".len()..].parse().ok();
                    }
                    other => skipped.push(other.to_string()),
                }
            }
            contents.push(c);
        } else if opt == "nocase" {
            if let Some(c) = contents.last_mut() {
                c.nocase = true;
            }
        } else if let Some(rest) = opt.strip_prefix("offset:") {
            if let Some(c) = contents.last_mut() {
                c.offset = rest.trim().parse().ok();
            }
        } else if let Some(rest) = opt.strip_prefix("depth:") {
            if let Some(c) = contents.last_mut() {
                c.depth = rest.trim().parse().ok();
            }
        } else if opt.starts_with("classtype:")
            || opt.starts_with("rev:")
            || opt.starts_with("reference:")
            || opt == "flow:to_server"
            || opt == "flow:established"
        {
            // recognized no-ops for Wave 3
        } else {
            skipped.push(opt.to_string());
        }
    }
    if sid == 0 {
        return Err(RuleError {
            code: "parse".into(),
            message: "sid required".into(),
        });
    }
    Ok(Rule {
        action: parts[0].into(),
        proto: parts[1].into(),
        src: parts[2].into(),
        src_port: parts[3].into(),
        direction: parts[4].into(),
        dst: parts[5].into(),
        dst_port: parts[6].into(),
        sid,
        msg,
        severity,
        contents,
        skipped_options: skipped,
    })
}

fn unquote(s: &str) -> String {
    let s = s.trim();
    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

fn split_content(s: &str) -> (String, Vec<&str>) {
    // "pattern"[,flags...]
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('"') {
        if let Some(end) = rest.find('"') {
            let pat = format!("\"{}\"", &rest[..end]);
            let after = rest[end + 1..].trim().trim_start_matches(',').trim();
            let flags: Vec<_> = if after.is_empty() {
                Vec::new()
            } else {
                after.split(',').map(|x| x.trim()).filter(|x| !x.is_empty()).collect()
            };
            return (pat, flags);
        }
    }
    (s.to_string(), Vec::new())
}

fn unescape_content(s: &str) -> Vec<u8> {
    // Support |HH HH| hex runs mixed with text.
    let mut out = Vec::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '|' {
            let mut hex = String::new();
            while let Some(&n) = chars.peek() {
                if n == '|' {
                    chars.next();
                    break;
                }
                hex.push(n);
                chars.next();
            }
            for part in hex.split_whitespace() {
                if let Ok(b) = u8::from_str_radix(part, 16) {
                    out.push(b);
                }
            }
        } else {
            out.push(c as u8);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_content_rule() {
        let text = r#"alert tcp any any -> any any (msg:"probe"; content:"EVIL"; nocase; sid:1000001; severity:2;)"#;
        let set = compile_rules(text).unwrap();
        assert_eq!(set.rules.len(), 1);
        assert_eq!(set.rules[0].sid, 1000001);
        assert_eq!(set.rules[0].contents[0].pattern, b"EVIL");
        assert!(set.rules[0].contents[0].nocase);
    }

    #[test]
    fn malformed_missing_sid() {
        let text = r#"alert tcp any any -> any any (msg:"x"; content:"EVIL";)"#;
        assert!(compile_rules(text).is_err());
    }
}
