//! AT&T operand reformatter (Intel text → AT&T-ish).

pub fn reformat_operands(mnemonic: &str, operands: &str) -> String {
    if operands.is_empty() {
        return String::new();
    }
    let parts: Vec<&str> = operands.split(", ").collect();
    let mapped: Vec<String> = parts
        .iter()
        .map(|p| {
            let p = p.trim();
            if p.starts_with('[') || p.contains(" ptr ") {
                format!("*{p}")
            } else if p.starts_with("0x") || p.starts_with("-0x") || p.parse::<i64>().is_ok() {
                format!("${p}")
            } else {
                format!("%{p}")
            }
        })
        .collect();
    // AT&T reverses src,dst for most two-operand forms.
    if mapped.len() == 2 && mnemonic != "bound" {
        format!("{}, {}", mapped[1], mapped[0])
    } else {
        mapped.join(", ")
    }
}
