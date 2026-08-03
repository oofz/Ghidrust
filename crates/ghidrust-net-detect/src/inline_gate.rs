//! Optional inline block policy (Wave 6 stretch) — off by default.

/// Inline packet block is refused unless explicitly enabled.
pub fn inline_block_allowed() -> bool {
    std::env::var("GHIDRUST_NET_INLINE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inline_refused_by_default() {
        std::env::remove_var("GHIDRUST_NET_INLINE");
        assert!(!inline_block_allowed());
    }
}
