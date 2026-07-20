pub mod att;
pub mod noregname;

/// Rewrite immediates that look negative hex into unsigned hex when possible.
pub fn unsigned_imm(operands: &str) -> String {
    operands
 .split(", ")
        .map(|part| {
            let p = part.trim();
 if let Some(rest) = p.strip_prefix("-0x") {
                if let Ok(v) = u64::from_str_radix(rest, 16) {
 return format!("{:#x}", (!v).wrapping_add(1));
                }
            }
            p.to_string()
        })
        .collect::<Vec<_>>()
 .join(", ")
}
