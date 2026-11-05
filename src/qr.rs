//! IDENTITY-49: a QR code as SVG — a sign-in code's link, for a phone to
//! scan.
//!
//! Written here, not taken from a crate: plexus-login's sources are also
//! compiled by manifest-only overlays (a consumer on another plexus line
//! names this crate's dependencies itself), so a new dependency would break
//! them. What it needs is small: byte mode, error correction level M,
//! versions 1–10 (up to 213 bytes — a link to `/login?code=…` on any
//! reasonable origin), every mask tried and the one with the lowest penalty
//! kept (ISO/IEC 18004 §7.8.3). The algorithm follows Project Nayuki's
//! reference implementation (MIT); the tests decode what it draws with an
//! independent reader.

/// The largest version drawn: 57 × 57 modules, 213 bytes at level M.
pub const MAX_VERSION: usize = 10;

/// Error-correction codewords per block, level M, by version.
const ECC_M: [usize; MAX_VERSION + 1] = [0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26];
/// Blocks, level M, by version.
const BLOCKS_M: [usize; MAX_VERSION + 1] = [0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5];
/// Level M's two format bits.
const ECL_M: u32 = 0;

/// The modules of a QR code: `size × size`, row-major, `true` dark.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Qr {
    pub size: usize,
    pub version: usize,
    pub mask: u8,
    modules: Vec<bool>,
}

impl Qr {
    /// The module at column `x`, row `y`.
    pub fn dark(&self, x: usize, y: usize) -> bool {
        self.modules[y * self.size + x]
    }

    /// The code as an SVG document: a white square with a four-module quiet
    /// zone, the dark modules one path, scaled by whoever draws it.
    pub fn svg(&self) -> String {
        let quiet = 4;
        let n = self.size + 2 * quiet;
        let mut d = String::new();
        for y in 0..self.size {
            let mut x = 0;
            while x < self.size {
                if !self.dark(x, y) {
                    x += 1;
                    continue;
                }
                let start = x;
                while x < self.size && self.dark(x, y) {
                    x += 1;
                }
                let run = x - start;
                d.push_str(&format!("M{} {}h{run}v1h-{run}z", start + quiet, y + quiet));
            }
        }
        format!(
            r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {n} {n}" shape-rendering="crispEdges"><rect width="{n}" height="{n}" fill="#fff"/><path fill="#000" d="{d}"/></svg>"##
        )
    }
}

/// `text` as a QR code, or `None` when it is longer than version 10 holds.
pub fn encode(text: &[u8]) -> Option<Qr> {
    let version = (1..=MAX_VERSION).find(|&v| {
        let count_bits = if v <= 9 { 8 } else { 16 };
        text.len() < (1 << count_bits) && 4 + count_bits + text.len() * 8 <= data_codewords(v) * 8
    })?;
    Some(build(version, text))
}

/// `text` as an SVG QR code ([`encode`], [`Qr::svg`]).
pub fn svg(text: &str) -> Option<String> {
    encode(text.as_bytes()).map(|q| q.svg())
}

/// Modules that carry data and error correction in a version.
fn raw_modules(v: usize) -> usize {
    let mut n = (16 * v + 128) * v + 64;
    if v >= 2 {
        let align = v / 7 + 2;
        n -= (25 * align - 10) * align - 55;
        if v >= 7 {
            n -= 36;
        }
    }
    n
}

fn data_codewords(v: usize) -> usize {
    raw_modules(v) / 8 - ECC_M[v] * BLOCKS_M[v]
}

/// The bit stream as codewords: byte mode, the count, the bytes, the
/// terminator, the pad.
fn data_bytes(version: usize, text: &[u8]) -> Vec<u8> {
    let mut bits: Vec<bool> = Vec::new();
    let push = |bits: &mut Vec<bool>, value: u32, len: usize| {
        for i in (0..len).rev() {
            bits.push((value >> i) & 1 == 1);
        }
    };
    push(&mut bits, 0b0100, 4);
    push(&mut bits, text.len() as u32, if version <= 9 { 8 } else { 16 });
    for &b in text {
        push(&mut bits, b as u32, 8);
    }
    let capacity = data_codewords(version) * 8;
    let terminator = (capacity - bits.len()).min(4);
    push(&mut bits, 0, terminator);
    let to_byte = (8 - bits.len() % 8) % 8;
    push(&mut bits, 0, to_byte);
    let mut pad = 0xEC;
    while bits.len() < capacity {
        push(&mut bits, pad, 8);
        pad ^= 0xEC ^ 0x11;
    }
    bits.chunks(8).map(|c| c.iter().fold(0u8, |acc, &b| (acc << 1) | b as u8)).collect()
}

fn build(version: usize, text: &[u8]) -> Qr {
    let data = data_bytes(version, text);
    let codewords = interleave(version, &data);

    let mut grid = Grid::new(version);
    grid.function_patterns();
    grid.codewords(&codewords);
    let mask = (0..8u8)
        .min_by_key(|&m| {
            let mut g = grid.clone();
            g.apply_mask(m);
            g.format_bits(m);
            g.penalty()
        })
        .expect("eight masks");
    grid.apply_mask(mask);
    grid.format_bits(mask);
    Qr { size: grid.size, version, mask, modules: grid.modules }
}

/// The data split into blocks, each with its error correction, interleaved.
fn interleave(version: usize, data: &[u8]) -> Vec<u8> {
    let (blocks_n, ecc_len) = (BLOCKS_M[version], ECC_M[version]);
    let raw = raw_modules(version) / 8;
    let short_blocks = blocks_n - raw % blocks_n;
    let short_len = raw / blocks_n;
    let divisor = rs_divisor(ecc_len);
    let mut blocks: Vec<Vec<u8>> = Vec::with_capacity(blocks_n);
    let mut k = 0;
    for i in 0..blocks_n {
        let len = short_len - ecc_len + usize::from(i >= short_blocks);
        let mut block = data[k..k + len].to_vec();
        k += len;
        let ecc = rs_remainder(&block, &divisor);
        if i < short_blocks {
            block.push(0);
        }
        block.extend(ecc);
        blocks.push(block);
    }
    let mut out = Vec::with_capacity(raw);
    for i in 0..blocks[0].len() {
        for (j, block) in blocks.iter().enumerate() {
            if i != short_len - ecc_len || j >= short_blocks {
                out.push(block[i]);
            }
        }
    }
    out
}

/// Multiplication in GF(2⁸) modulo x⁸ + x⁴ + x³ + x² + 1.
fn gf_mul(x: u8, y: u8) -> u8 {
    let mut z: u32 = 0;
    for i in (0..8).rev() {
        z = (z << 1) ^ ((z >> 7) * 0x11D);
        z ^= ((y as u32 >> i) & 1) * x as u32;
    }
    z as u8
}

/// The Reed–Solomon generator of `degree`, its leading 1 left out.
fn rs_divisor(degree: usize) -> Vec<u8> {
    let mut result = vec![0u8; degree];
    result[degree - 1] = 1;
    let mut root: u8 = 1;
    for _ in 0..degree {
        for j in 0..degree {
            result[j] = gf_mul(result[j], root);
            if j + 1 < degree {
                result[j] ^= result[j + 1];
            }
        }
        root = gf_mul(root, 0x02);
    }
    result
}

fn rs_remainder(data: &[u8], divisor: &[u8]) -> Vec<u8> {
    let mut result = vec![0u8; divisor.len()];
    for &b in data {
        let factor = b ^ result.remove(0);
        result.push(0);
        for (r, &d) in result.iter_mut().zip(divisor) {
            *r ^= gf_mul(d, factor);
        }
    }
    result
}

#[derive(Clone)]
struct Grid {
    size: usize,
    version: usize,
    modules: Vec<bool>,
    function: Vec<bool>,
}

impl Grid {
    fn new(version: usize) -> Self {
        let size = version * 4 + 17;
        Self { size, version, modules: vec![false; size * size], function: vec![false; size * size] }
    }

    fn get(&self, x: usize, y: usize) -> bool {
        self.modules[y * self.size + x]
    }

    fn set_function(&mut self, x: usize, y: usize, dark: bool) {
        self.modules[y * self.size + x] = dark;
        self.function[y * self.size + x] = true;
    }

    fn function_patterns(&mut self) {
        let size = self.size;
        for i in 0..size {
            self.set_function(6, i, i % 2 == 0);
            self.set_function(i, 6, i % 2 == 0);
        }
        self.finder(3, 3);
        self.finder(size - 4, 3);
        self.finder(3, size - 4);
        let pos = alignment_positions(self.version, size);
        let n = pos.len();
        for i in 0..n {
            for j in 0..n {
                let corner = (i == 0 && j == 0) || (i == 0 && j == n - 1) || (i == n - 1 && j == 0);
                if !corner {
                    self.alignment(pos[i], pos[j]);
                }
            }
        }
        // Reserved now, drawn once the mask is chosen.
        self.format_bits(0);
        self.version_bits();
    }

    fn finder(&mut self, x: usize, y: usize) {
        for dy in -4i32..=4 {
            for dx in -4i32..=4 {
                let (xx, yy) = (x as i32 + dx, y as i32 + dy);
                if (0..self.size as i32).contains(&xx) && (0..self.size as i32).contains(&yy) {
                    let dist = dx.abs().max(dy.abs());
                    self.set_function(xx as usize, yy as usize, dist != 2 && dist != 4);
                }
            }
        }
    }

    fn alignment(&mut self, x: usize, y: usize) {
        for dy in -2i32..=2 {
            for dx in -2i32..=2 {
                self.set_function((x as i32 + dx) as usize, (y as i32 + dy) as usize, dx.abs().max(dy.abs()) != 1);
            }
        }
    }

    fn format_bits(&mut self, mask: u8) {
        let data = (ECL_M << 3) | mask as u32;
        let mut rem = data;
        for _ in 0..10 {
            rem = (rem << 1) ^ ((rem >> 9) * 0x537);
        }
        let bits = ((data << 10) | rem) ^ 0x5412;
        let bit = |i: usize| (bits >> i) & 1 == 1;
        let size = self.size;
        for i in 0..=5 {
            self.set_function(8, i, bit(i));
        }
        self.set_function(8, 7, bit(6));
        self.set_function(8, 8, bit(7));
        self.set_function(7, 8, bit(8));
        for i in 9..15 {
            self.set_function(14 - i, 8, bit(i));
        }
        for i in 0..8 {
            self.set_function(size - 1 - i, 8, bit(i));
        }
        for i in 8..15 {
            self.set_function(8, size - 15 + i, bit(i));
        }
        self.set_function(8, size - 8, true);
    }

    fn version_bits(&mut self) {
        if self.version < 7 {
            return;
        }
        let v = self.version as u32;
        let mut rem = v;
        for _ in 0..12 {
            rem = (rem << 1) ^ ((rem >> 11) * 0x1F25);
        }
        let bits = (v << 12) | rem;
        for i in 0..18 {
            let dark = (bits >> i) & 1 == 1;
            let (a, b) = (self.size - 11 + i % 3, i / 3);
            self.set_function(a, b, dark);
            self.set_function(b, a, dark);
        }
    }

    /// The codewords in the zigzag, two columns at a time from the right.
    fn codewords(&mut self, data: &[u8]) {
        let size = self.size as i32;
        let total = data.len() * 8;
        let mut i = 0;
        let mut right = size - 1;
        while right >= 1 {
            if right == 6 {
                right = 5;
            }
            for vert in 0..size {
                for j in 0..2 {
                    let x = (right - j) as usize;
                    let upward = (right + 1) & 2 == 0;
                    let y = (if upward { size - 1 - vert } else { vert }) as usize;
                    if !self.function[y * self.size + x] && i < total {
                        self.modules[y * self.size + x] = (data[i >> 3] >> (7 - (i & 7))) & 1 == 1;
                        i += 1;
                    }
                }
            }
            right -= 2;
        }
    }

    fn apply_mask(&mut self, mask: u8) {
        for y in 0..self.size {
            for x in 0..self.size {
                let invert = match mask {
                    0 => (x + y) % 2 == 0,
                    1 => y % 2 == 0,
                    2 => x % 3 == 0,
                    3 => (x + y) % 3 == 0,
                    4 => (x / 3 + y / 2) % 2 == 0,
                    5 => x * y % 2 + x * y % 3 == 0,
                    6 => (x * y % 2 + x * y % 3) % 2 == 0,
                    _ => ((x + y) % 2 + x * y % 3) % 2 == 0,
                };
                let i = y * self.size + x;
                if invert && !self.function[i] {
                    self.modules[i] = !self.modules[i];
                }
            }
        }
    }

    /// The four penalty rules: runs of five or more, 2×2 blocks, finder-like
    /// patterns, and the dark share's distance from half.
    fn penalty(&self) -> usize {
        let n = self.size;
        let mut score = 0;
        let line = |k: usize, i: usize, rows: bool| if rows { self.get(i, k) } else { self.get(k, i) };
        for rows in [true, false] {
            for k in 0..n {
                let mut run = 1;
                for i in 1..n {
                    if line(k, i, rows) == line(k, i - 1, rows) {
                        run += 1;
                    } else {
                        if run >= 5 {
                            score += run - 2;
                        }
                        run = 1;
                    }
                }
                if run >= 5 {
                    score += run - 2;
                }
                // 1:1:3:1:1 with four light modules on one side.
                const PATTERN: [bool; 11] = [true, false, true, true, true, false, true, false, false, false, false];
                for i in 0..=n.saturating_sub(11) {
                    let fwd = (0..11).all(|t| line(k, i + t, rows) == PATTERN[t]);
                    let back = (0..11).all(|t| line(k, i + t, rows) == PATTERN[10 - t]);
                    score += 40 * (usize::from(fwd) + usize::from(back));
                }
            }
        }
        for y in 0..n - 1 {
            for x in 0..n - 1 {
                let c = self.get(x, y);
                if c == self.get(x + 1, y) && c == self.get(x, y + 1) && c == self.get(x + 1, y + 1) {
                    score += 3;
                }
            }
        }
        let dark = self.modules.iter().filter(|&&d| d).count();
        let total = n * n;
        let k = (dark * 20).abs_diff(total * 10).div_ceil(total).saturating_sub(1);
        score + k * 10
    }
}

fn alignment_positions(version: usize, size: usize) -> Vec<usize> {
    if version == 1 {
        return Vec::new();
    }
    let count = version / 7 + 2;
    let step = (version * 4 + count * 2 + 1) / (count * 2 - 2) * 2;
    let mut tail: Vec<usize> = (0..count - 1).map(|i| size - 7 - i * step).collect();
    tail.reverse();
    let mut out = vec![6];
    out.extend(tail);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decodes `qr` with an independent reader (rqrr), drawn at 4 px a
    /// module inside its quiet zone.
    fn read(qr: &Qr) -> String {
        let (scale, quiet) = (4, 4);
        let px = (qr.size + 2 * quiet) * scale;
        let mut img = rqrr::PreparedImage::prepare_from_bitmap(px, px, |x, y| {
            let (mx, my) = (x / scale, y / scale);
            mx >= quiet && my >= quiet && mx < quiet + qr.size && my < quiet + qr.size && qr.dark(mx - quiet, my - quiet)
        });
        let grids = img.detect_grids();
        assert_eq!(grids.len(), 1, "one code found (version {}, mask {})", qr.version, qr.mask);
        grids[0].decode().expect("it decodes").1
    }

    #[test]
    fn what_it_draws_reads_back_at_every_version() {
        let base = "https://dream-1.tail0c7bb6.ts.net:5614/login?code=K7QM-4XRT-9PZQC&next=%2Fapp%2F";
        let mut versions = std::collections::BTreeSet::new();
        for len in [1usize, 5, 14, 15, 26, 27, 42, 43, 62, 63, 84, 85, 106, 107, 122, 123, 152, 153, 180, 181, 213] {
            let text: String = base.chars().cycle().take(len).collect();
            let qr = encode(text.as_bytes()).unwrap_or_else(|| panic!("{len} bytes fit"));
            versions.insert(qr.version);
            assert_eq!(read(&qr), text, "{len} bytes, version {}", qr.version);
        }
        assert_eq!(versions.into_iter().collect::<Vec<_>>(), (1..=10).collect::<Vec<_>>(), "every version drawn");
        assert!(encode(&[b'x'; 214]).is_none(), "past version 10: none");
    }

    #[test]
    fn every_mask_reads_back() {
        let text = b"https://toy.example/login?code=0123-4567-89ABC";
        for mask in 0..8u8 {
            let mut qr = encode(text).unwrap();
            let mut g = Grid::new(qr.version);
            g.function_patterns();
            g.codewords(&interleave(qr.version, &data_bytes(qr.version, text)));
            g.apply_mask(mask);
            g.format_bits(mask);
            qr.modules = g.modules;
            qr.mask = mask;
            assert_eq!(read(&qr).as_bytes(), text, "mask {mask}");
        }
    }

    #[test]
    fn the_svg_is_one_path_inside_a_quiet_zone() {
        let s = svg("https://toy.example/login?code=0123-4567-89ABC").unwrap();
        assert!(s.starts_with("<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 41 41\""), "version 4, its quiet zone: {s}");
        assert_eq!(s.matches("<path").count(), 1);
        assert!(!s.contains("<script"));
    }
}
