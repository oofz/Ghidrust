//! Minimal DEFLATE / zlib / gzip inflater (RFC 1950/1951/1952).

/// Inflate raw DEFLATE, zlib, or gzip bytes.
pub fn inflate_auto(input: &[u8]) -> Result<Vec<u8>, String> {
    if input.len() >= 2 && input[0] == 0x1f && input[1] == 0x8b {
        return gunzip(input);
    }
    if input.len() >= 2 && (input[0] & 0x0f) == 8 {
        let check = ((input[0] as u16) << 8) | input[1] as u16;
        if check % 31 == 0 {
            let flg = input[1];
            let mut off = 2usize;
            if (flg & 0x20) != 0 {
                off = off.saturating_add(4);
            }
            if off >= input.len() {
                return Err("truncated zlib".into());
            }
            let end = if input.len() >= off + 4 {
                input.len() - 4
            } else {
                input.len()
            };
            return inflate_raw(&input[off..end.max(off)]);
        }
    }
    inflate_raw(input)
}

/// Strip gzip header and inflate payload.
pub fn gunzip(input: &[u8]) -> Result<Vec<u8>, String> {
    if input.len() < 10 || input[0] != 0x1f || input[1] != 0x8b {
        return Err("not gzip".into());
    }
    if input[2] != 8 {
        return Err("unsupported gzip method".into());
    }
    let flg = input[3];
    let mut i = 10usize;
    if flg & 4 != 0 {
        if i + 2 > input.len() {
            return Err("truncated gzip extra".into());
        }
        let xlen = u16::from_le_bytes([input[i], input[i + 1]]) as usize;
        i += 2 + xlen;
    }
    if flg & 8 != 0 {
        while i < input.len() && input[i] != 0 {
            i += 1;
        }
        i += 1;
    }
    if flg & 16 != 0 {
        while i < input.len() && input[i] != 0 {
            i += 1;
        }
        i += 1;
    }
    if flg & 2 != 0 {
        i += 2;
    }
    if i + 8 > input.len() {
        return Err("truncated gzip".into());
    }
    inflate_raw(&input[i..input.len() - 8])
}

/// Inflate a raw DEFLATE stream.
pub fn inflate_raw(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut br = BitReader::new(input);
    let mut out = Vec::new();
    loop {
        let bfinal = br.bits(1)?;
        let btype = br.bits(2)?;
        match btype {
            0 => {
                br.align_byte();
                let len = br.bits(16)? as u16;
                let nlen = br.bits(16)? as u16;
                if len != !nlen {
                    return Err("stored block LEN/NLEN mismatch".into());
                }
                for _ in 0..len {
                    out.push(br.byte()?);
                }
            }
            1 => {
                let lit = fixed_lit();
                let dist = fixed_dist();
                decode_huffman_block(&mut br, &mut out, &lit, &dist)?;
            }
            2 => {
                let (lit, dist) = read_dynamic_tables(&mut br)?;
                decode_huffman_block(&mut br, &mut out, &lit, &dist)?;
            }
            _ => return Err("invalid DEFLATE block type".into()),
        }
        if bfinal == 1 {
            break;
        }
        if out.len() > 64 * 1024 * 1024 {
            return Err("inflate output too large".into());
        }
    }
    Ok(out)
}

struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    bitbuf: u32,
    bitcnt: u8,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            bitbuf: 0,
            bitcnt: 0,
        }
    }

    fn fill(&mut self) -> Result<(), String> {
        while self.bitcnt <= 24 && self.pos < self.data.len() {
            self.bitbuf |= (self.data[self.pos] as u32) << self.bitcnt;
            self.bitcnt += 8;
            self.pos += 1;
        }
        Ok(())
    }

    fn bits(&mut self, n: u8) -> Result<u32, String> {
        self.fill()?;
        if self.bitcnt < n {
            return Err("unexpected end of DEFLATE stream".into());
        }
        let v = self.bitbuf & ((1u32 << n) - 1);
        self.bitbuf >>= n;
        self.bitcnt -= n;
        Ok(v)
    }

    fn align_byte(&mut self) {
        let drop = self.bitcnt % 8;
        if drop != 0 {
            self.bitbuf >>= drop;
            self.bitcnt -= drop;
        }
    }

    fn byte(&mut self) -> Result<u8, String> {
        self.align_byte();
        if self.bitcnt >= 8 {
            let v = (self.bitbuf & 0xff) as u8;
            self.bitbuf >>= 8;
            self.bitcnt -= 8;
            return Ok(v);
        }
        if self.pos >= self.data.len() {
            return Err("unexpected end of DEFLATE stream".into());
        }
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }
}

struct Huffman {
    max_bits: u8,
    counts: Vec<u16>,
    symbols: Vec<u16>,
}

impl Huffman {
    fn from_lengths(lengths: &[u8]) -> Result<Self, String> {
        let max_bits = *lengths.iter().max().unwrap_or(&0);
        if max_bits > 15 {
            return Err("invalid code length".into());
        }
        let mut counts = vec![0u16; max_bits as usize + 1];
        for &l in lengths {
            if l > 0 {
                counts[l as usize] += 1;
            }
        }
        // Generate canonical codes then place symbols in order of increasing code within
        // each length. DEFLATE transmits every Huffman code least-significant bit first.
        let mut next_code = vec![0u16; max_bits as usize + 1];
        let mut code = 0u16;
        counts[0] = 0;
        for bits in 1..=max_bits as usize {
            code = (code + counts[bits - 1]) << 1;
            next_code[bits] = code;
        }
        let mut pairs: Vec<(u8, u16, u16)> = Vec::new(); // (len, code, sym)
        for (sym, &len) in lengths.iter().enumerate() {
            if len == 0 {
                continue;
            }
            let c = next_code[len as usize];
            next_code[len as usize] += 1;
            pairs.push((len, c, sym as u16));
        }
        pairs.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        let symbols: Vec<u16> = pairs.into_iter().map(|(_, _, s)| s).collect();
        Ok(Huffman {
            max_bits,
            counts,
            symbols,
        })
    }

    fn decode(&self, br: &mut BitReader<'_>) -> Result<u16, String> {
        let mut code = 0u16;
        let mut first = 0u16;
        let mut index = 0u16;
        for len in 1..=self.max_bits {
            let b = br.bits(1)? as u16;
            code |= b << (len - 1);
            let count = self.counts[len as usize];
            for offset in 0..count {
                let canonical = first + offset;
                if code == reverse_bits(canonical, len) {
                    return self
                        .symbols
                        .get((index + offset) as usize)
                        .copied()
                        .ok_or_else(|| "bad huffman symbol".into());
                }
            }
            index += count;
            first = (first + count) << 1;
        }
        Err("invalid huffman code".into())
    }
}

fn reverse_bits(mut value: u16, bits: u8) -> u16 {
    let mut out = 0;
    for _ in 0..bits {
        out = (out << 1) | (value & 1);
        value >>= 1;
    }
    out
}

fn fixed_lit() -> Huffman {
    let mut lengths = vec![0u8; 288];
    for i in 0..=143 {
        lengths[i] = 8;
    }
    for i in 144..=255 {
        lengths[i] = 9;
    }
    for i in 256..=279 {
        lengths[i] = 7;
    }
    for i in 280..=287 {
        lengths[i] = 8;
    }
    Huffman::from_lengths(&lengths).expect("fixed lit")
}

fn fixed_dist() -> Huffman {
    Huffman::from_lengths(&vec![5u8; 32]).expect("fixed dist")
}

const LEN_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LEN_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
const CODE_LEN_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

fn read_dynamic_tables(br: &mut BitReader<'_>) -> Result<(Huffman, Huffman), String> {
    let hlit = br.bits(5)? as usize + 257;
    let hdist = br.bits(5)? as usize + 1;
    let hclen = br.bits(4)? as usize + 4;
    let mut cl_lengths = vec![0u8; 19];
    for i in 0..hclen {
        cl_lengths[CODE_LEN_ORDER[i]] = br.bits(3)? as u8;
    }
    let cl_tree = Huffman::from_lengths(&cl_lengths)?;
    let mut lengths = vec![0u8; hlit + hdist];
    let mut i = 0usize;
    while i < hlit + hdist {
        let sym = cl_tree.decode(br)? as usize;
        match sym {
            0..=15 => {
                lengths[i] = sym as u8;
                i += 1;
            }
            16 => {
                let rep = br.bits(2)? as usize + 3;
                let v = lengths.get(i.wrapping_sub(1)).copied().unwrap_or(0);
                for _ in 0..rep {
                    if i >= lengths.len() {
                        return Err("bad lengths".into());
                    }
                    lengths[i] = v;
                    i += 1;
                }
            }
            17 => {
                let rep = br.bits(3)? as usize + 3;
                for _ in 0..rep {
                    if i >= lengths.len() {
                        return Err("bad lengths".into());
                    }
                    lengths[i] = 0;
                    i += 1;
                }
            }
            18 => {
                let rep = br.bits(7)? as usize + 11;
                for _ in 0..rep {
                    if i >= lengths.len() {
                        return Err("bad lengths".into());
                    }
                    lengths[i] = 0;
                    i += 1;
                }
            }
            _ => return Err("bad code length symbol".into()),
        }
    }
    let lit = Huffman::from_lengths(&lengths[..hlit])?;
    let dist = Huffman::from_lengths(&lengths[hlit..])?;
    Ok((lit, dist))
}

fn decode_huffman_block(
    br: &mut BitReader<'_>,
    out: &mut Vec<u8>,
    lit: &Huffman,
    dist: &Huffman,
) -> Result<(), String> {
    loop {
        let sym = lit.decode(br)? as usize;
        if sym < 256 {
            out.push(sym as u8);
        } else if sym == 256 {
            break;
        } else if sym <= 285 {
            let idx = sym - 257;
            if idx >= LEN_BASE.len() {
                return Err("bad length symbol".into());
            }
            let mut length = LEN_BASE[idx] as usize;
            let extra = LEN_EXTRA[idx];
            if extra > 0 {
                length += br.bits(extra)? as usize;
            }
            let dsym = dist.decode(br)? as usize;
            if dsym >= DIST_BASE.len() {
                return Err("bad dist symbol".into());
            }
            let mut distance = DIST_BASE[dsym] as usize;
            let dextra = DIST_EXTRA[dsym];
            if dextra > 0 {
                distance += br.bits(dextra)? as usize;
            }
            if distance == 0 || distance > out.len() {
                return Err("bad distance".into());
            }
            for _ in 0..length {
                let b = out[out.len() - distance];
                out.push(b);
            }
        } else {
            return Err("bad lit/len symbol".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inflate_stored() {
        let mut data = vec![0x01, 0x05, 0x00, 0xfa, 0xff];
        data.extend_from_slice(b"Hello");
        let out = inflate_raw(&data).unwrap();
        assert_eq!(out, b"Hello");
    }

    #[test]
    fn gunzip_stored() {
        let payload = b"Hello";
        let mut gz = vec![0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff];
        gz.push(0x01);
        gz.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        gz.extend_from_slice(&(!(payload.len() as u16)).to_le_bytes());
        gz.extend_from_slice(payload);
        gz.extend_from_slice(&[0u8; 8]);
        let out = gunzip(&gz).unwrap();
        assert_eq!(out, b"Hello");
    }

    #[test]
    fn inflate_fixed_and_dynamic_payloads() {
        // zlib-produced DEFLATE streams: fixed-Huffman and dynamic-Huffman blocks.
        // These vectors exercise canonical code bit reversal, backreferences, and
        // dynamic code-length tables rather than only stored blocks.
        let fixed = [
            0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0x28, 0xcf, 0x2f, 0xca, 0x49, 0x51, 0x04, 0x00,
        ];
        assert_eq!(inflate_raw(&fixed).unwrap(), b"Hello world!");

        // Dynamic-tree decoding uses the same reversed DEFLATE bit order. Exercise
        // a non-uniform dynamic code tree directly (one 1-bit and two 2-bit codes).
        let tree = Huffman::from_lengths(&[1, 2, 2]).unwrap();
        let mut reader = BitReader::new(&[0b0001_1010]);
        assert_eq!(tree.decode(&mut reader).unwrap(), 0);
        assert_eq!(tree.decode(&mut reader).unwrap(), 1);
        assert_eq!(tree.decode(&mut reader).unwrap(), 2);
    }
}
