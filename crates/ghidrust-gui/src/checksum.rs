//! Pure checksum math for the Checksum Generator pane.
//!
//! Extracted from `app.rs` (Wave 1 demonolith). UI + program I/O stay on
//! `GhidrustApp`; this module owns report types and hash helpers only.

/// Checksum Generator report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChecksumReport {
    pub target: String,
    pub len: usize,
    pub crc32: u32,
    pub sum8: u32,
    pub sum16: u32,
    pub sum32: u64,
    pub adler32: u32,
    pub fletcher16: u32,
    pub fletcher32: u64,
}

/// Checksum Generator scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChecksumMode {
    /// Concatenation of every loaded memory block.
    WholeImage,
    /// A single memory block chosen by name.
    Section(String),
}

/// CRC-32/ISO-HDLC (polynomial `0xEDB88320`) — matches default.
pub fn crc32_ieee(data: &[u8]) -> u32 {
    let mut c: u32 = 0xFFFF_FFFF;
    for &b in data {
        c ^= b as u32;
        for _ in 0..8 {
            let mask = (c & 1).wrapping_neg();
            c = (c >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !c
}

pub fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &byte in data {
        a = (a + byte as u32) % MOD;
        b = (b + a) % MOD;
    }
    (b << 16) | a
}

pub fn fletcher_pair(data: &[u8]) -> (u32, u64) {
    let (mut a16, mut b16): (u16, u16) = (0, 0);
    for &byte in data {
        a16 = a16.wrapping_add(byte as u16);
        b16 = b16.wrapping_add(a16);
    }
    let f16 = ((b16 as u32) << 16) | a16 as u32;

    let (mut a32, mut b32): (u32, u32) = (0, 0);
    for chunk in data.chunks_exact(2) {
        let w = u16::from_le_bytes([chunk[0], chunk[1]]) as u32;
        a32 = a32.wrapping_add(w);
        b32 = b32.wrapping_add(a32);
    }
    let f32 = ((b32 as u64) << 32) | a32 as u64;
    (f16, f32)
}

/// Compute every field of a [`ChecksumReport`] for `data` labeled `target`.
pub fn report_for(target: String, data: &[u8]) -> ChecksumReport {
    let len = data.len();
    let crc32 = crc32_ieee(data);
    let sum8: u32 = data.iter().map(|&b| b as u32).sum();
    let sum16: u32 = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]) as u32)
        .sum::<u32>();
    let sum32: u64 = data
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]) as u64)
        .sum::<u64>();
    let adler32 = adler32(data);
    let (fletcher16, fletcher32) = fletcher_pair(data);
    ChecksumReport {
        target,
        len,
        crc32,
        sum8,
        sum16,
        sum32,
        adler32,
        fletcher16,
        fletcher32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_ieee_empty_and_check_vector() {
        assert_eq!(crc32_ieee(b""), 0x0000_0000);
        // Well-known ISO-HDLC / IEEE check value for "123456789".
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn adler32_empty_and_check_vector() {
        // Adler-32 of empty input is 1 (a=1, b=0).
        assert_eq!(adler32(b""), 0x0000_0001);
        // Adler-32 of "123456789" (RFC 1950 check vector).
        assert_eq!(adler32(b"123456789"), 0x091E_01DE);
    }

    #[test]
    fn fletcher_pair_empty_and_short() {
        assert_eq!(fletcher_pair(b""), (0, 0));
        // Single byte: a16=0x41, b16=0x41; no complete u16 for f32 → 0.
        assert_eq!(fletcher_pair(b"A"), (0x0041_0041, 0));
        // Two bytes: f16 from running sums; f32 from one LE u16 word.
        let (f16, f32) = fletcher_pair(b"AB");
        let mut a16: u16 = 0;
        let mut b16: u16 = 0;
        for &byte in b"AB" {
            a16 = a16.wrapping_add(byte as u16);
            b16 = b16.wrapping_add(a16);
        }
        assert_eq!(f16, ((b16 as u32) << 16) | a16 as u32);
        let w = u16::from_le_bytes([b'A', b'B']) as u32;
        assert_eq!(f32, ((w as u64) << 32) | w as u64);
    }

    #[test]
    fn report_for_aggregates_known_vector() {
        let data = b"123456789";
        let r = report_for("t".into(), data);
        assert_eq!(r.target, "t");
        assert_eq!(r.len, 9);
        assert_eq!(r.crc32, 0xCBF4_3926);
        assert_eq!(r.adler32, 0x091E_01DE);
        assert_eq!(r.sum8, data.iter().map(|&b| b as u32).sum::<u32>());
        // 4 complete LE u16 pairs from 8 bytes; last byte dropped by chunks_exact(2).
        let sum16: u32 = data
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]) as u32)
            .sum();
        assert_eq!(r.sum16, sum16);
        // 2 complete LE u32 words; last byte dropped.
        let sum32: u64 = data
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]) as u64)
            .sum();
        assert_eq!(r.sum32, sum32);
        let (f16, f32) = fletcher_pair(data);
        assert_eq!(r.fletcher16, f16);
        assert_eq!(r.fletcher32, f32);
    }
}
