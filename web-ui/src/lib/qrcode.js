// Zero-dependency ISO/IEC 18004 QR Code encoder (Byte mode, ECC Level L, Versions 1-12)
// Produces crisp SVG QR codes locally for TOTP otpauth:// provisioning URIs.

const GF_EXP = new Uint8Array(512);
const GF_LOG = new Uint8Array(256);
{
  let x = 1;
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x;
    GF_LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255];
}

function gfMul(a, b) {
  if (a === 0 || b === 0) return 0;
  return GF_EXP[GF_LOG[a] + GF_LOG[b]];
}

function rsPoly(ecCount) {
  let g = [1];
  for (let i = 0; i < ecCount; i++) {
    const next = new Array(g.length + 1).fill(0);
    const root = GF_EXP[i];
    for (let j = 0; j < g.length; j++) {
      next[j] ^= g[j];
      next[j + 1] ^= gfMul(g[j], root);
    }
    g = next;
  }
  return g;
}

function rsEncode(data, ecCount) {
  const gen = rsPoly(ecCount);
  const rem = new Uint8Array(data.length + ecCount);
  rem.set(data);
  for (let i = 0; i < data.length; i++) {
    const coef = rem[i];
    if (coef !== 0) {
      for (let j = 0; j < gen.length; j++) {
        rem[i + j] ^= gfMul(gen[j], coef);
      }
    }
  }
  return rem.slice(data.length);
}

// [version, dataCodewords, ecPerBlock, blocksGroup1, dataCwGroup1, blocksGroup2, dataCwGroup2] for ECC Level L
const VERSION_SPECS_L = [
  [1, 19, 7, 1, 19, 0, 0],
  [2, 34, 10, 1, 34, 0, 0],
  [3, 55, 15, 1, 55, 0, 0],
  [4, 80, 20, 1, 80, 0, 0],
  [5, 108, 26, 1, 108, 0, 0],
  [6, 136, 18, 2, 68, 0, 0],
  [7, 156, 20, 2, 78, 0, 0],
  [8, 194, 24, 2, 97, 0, 0],
  [9, 232, 30, 2, 116, 0, 0],
  [10, 274, 18, 2, 68, 2, 69],
  [11, 324, 20, 4, 81, 0, 0],
  [12, 370, 24, 2, 92, 2, 93],
];

const ALIGN_CENTERS = {
  1: [],
  2: [6, 18],
  3: [6, 22],
  4: [6, 26],
  5: [6, 30],
  6: [6, 34],
  7: [6, 22, 38],
  8: [6, 24, 42],
  9: [6, 26, 46],
  10: [6, 28, 50],
  11: [6, 30, 54],
  12: [6, 32, 58],
};

function chooseSpec(byteLen) {
  for (const spec of VERSION_SPECS_L) {
    const ccBits = spec[0] >= 10 ? 16 : 8;
    const availBits = spec[1] * 8;
    if (4 + ccBits + byteLen * 8 <= availBits) return spec;
  }
  throw new Error('QR payload too long');
}

function buildCodewords(bytes, spec) {
  const [ver, totalData, ecPerBlock, b1, d1, b2, d2] = spec;
  const bits = [];
  const pushBits = (val, len) => {
    for (let i = len - 1; i >= 0; i--) bits.push((val >> i) & 1);
  };
  pushBits(0b0100, 4); // Byte mode
  pushBits(bytes.length, ver >= 10 ? 16 : 8);
  for (const b of bytes) pushBits(b, 8);
  const capBits = totalData * 8;
  pushBits(0, Math.min(4, capBits - bits.length));
  while (bits.length % 8 !== 0) bits.push(0);
  const data = new Uint8Array(totalData);
  for (let i = 0; i < bits.length; i += 8) {
    let v = 0;
    for (let k = 0; k < 8; k++) v = (v << 1) | bits[i + k];
    data[i / 8] = v;
  }
  const padBytes = [0xec, 0x11];
  for (let i = bits.length / 8, p = 0; i < totalData; i++, p ^= 1) data[i] = padBytes[p];

  const dataBlocks = [];
  const ecBlocks = [];
  let offset = 0;
  for (let i = 0; i < b1; i++) {
    const slice = data.slice(offset, offset + d1);
    offset += d1;
    dataBlocks.push(slice);
    ecBlocks.push(rsEncode(slice, ecPerBlock));
  }
  for (let i = 0; i < b2; i++) {
    const slice = data.slice(offset, offset + d2);
    offset += d2;
    dataBlocks.push(slice);
    ecBlocks.push(rsEncode(slice, ecPerBlock));
  }

  const out = [];
  const maxD = Math.max(d1, d2);
  for (let i = 0; i < maxD; i++) {
    for (const blk of dataBlocks) if (i < blk.length) out.push(blk[i]);
  }
  for (let i = 0; i < ecPerBlock; i++) {
    for (const blk of ecBlocks) out.push(blk[i]);
  }
  return out;
}

function bchFormat(bits5) {
  let d = bits5 << 10;
  const poly = 0b10100110111;
  for (let i = 14; i >= 10; i--) {
    if ((d >> i) & 1) d ^= poly << (i - 10);
  }
  return ((bits5 << 10) | d) ^ 0b101010000010010;
}

function bchVersion(ver) {
  let d = ver << 12;
  const poly = 0b1111100100101;
  for (let i = 17; i >= 12; i--) {
    if ((d >> i) & 1) d ^= poly << (i - 12);
  }
  return (ver << 12) | d;
}

function createMatrix(ver) {
  const n = ver * 4 + 17;
  const mod = Array.from({ length: n }, () => new Int8Array(n).fill(-1));
  const fn = Array.from({ length: n }, () => new Uint8Array(n));

  const setFn = (r, c, v) => {
    if (r >= 0 && r < n && c >= 0 && c < n) {
      mod[r][c] = v ? 1 : 0;
      fn[r][c] = 1;
    }
  };

  const finder = (tr, tc) => {
    for (let dr = -1; dr <= 7; dr++) {
      for (let dc = -1; dc <= 7; dc++) {
        const dark =
          dr >= 0 &&
          dr <= 6 &&
          dc >= 0 &&
          dc <= 6 &&
          (dr === 0 || dr === 6 || dc === 0 || dc === 6 || (dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4));
        setFn(tr + dr, tc + dc, dark);
      }
    }
  };
  finder(0, 0);
  finder(0, n - 7);
  finder(n - 7, 0);

  for (let i = 8; i < n - 8; i++) {
    setFn(6, i, i % 2 === 0);
    setFn(i, 6, i % 2 === 0);
  }

  const centers = ALIGN_CENTERS[ver] || [];
  for (const r of centers) {
    for (const c of centers) {
      if ((r === 6 && c === 6) || (r === 6 && c === n - 7) || (r === n - 7 && c === 6)) continue;
      for (let dr = -2; dr <= 2; dr++) {
        for (let dc = -2; dc <= 2; dc++) {
          setFn(r + dr, c + dc, Math.max(Math.abs(dr), Math.abs(dc)) !== 1);
        }
      }
    }
  }

  setFn(4 * ver + 9, 8, true);

  // Reserve format & version info areas
  for (let i = 0; i < 9; i++) {
    if (i !== 6) {
      setFn(8, i, false);
      setFn(i, 8, false);
    }
  }
  for (let i = n - 8; i < n; i++) setFn(8, i, false);
  for (let i = n - 7; i < n; i++) setFn(i, 8, false);
  if (ver >= 7) {
    const vbits = bchVersion(ver);
    for (let i = 0; i < 18; i++) {
      const bit = Boolean((vbits >> i) & 1);
      const a = Math.floor(i / 3);
      const b = n - 11 + (i % 3);
      setFn(a, b, bit);
      setFn(b, a, bit);
    }
  }
  return { n, mod, fn };
}

function applyMaskAndFormat(baseMod, fn, n, maskId) {
  const m = baseMod.map((row) => Int8Array.from(row));
  const maskFn = (r, c) => {
    switch (maskId) {
      case 0: return (r + c) % 2 === 0;
      case 1: return r % 2 === 0;
      case 2: return c % 3 === 0;
      case 3: return (r + c) % 3 === 0;
      case 4: return (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0;
      case 5: return ((r * c) % 2) + ((r * c) % 3) === 0;
      case 6: return (((r * c) % 2) + ((r * c) % 3)) % 2 === 0;
      default: return (((r + c) % 2) + ((r * c) % 3)) % 2 === 0;
    }
  };
  for (let r = 0; r < n; r++) {
    for (let c = 0; c < n; c++) {
      if (!fn[r][c] && maskFn(r, c)) m[r][c] ^= 1;
    }
  }
  const fmt = bchFormat((0b01 << 3) | maskId); // ECC L = 01
  for (let i = 0; i < 15; i++) {
    const bit = (fmt >> i) & 1;
    // Top-right horizontal (bits 0..7 at cols n-1..n-8) and bottom-left vertical (bits 8..14 at rows n-7..n-1)
    if (i < 8) {
      m[8][n - 1 - i] = bit;
    } else {
      m[n - 15 + i][8] = bit;
    }
    // Top-left vertical (bits 0..5 at rows 0..5, bit 6 at row 7) and top-left horizontal (bit 7 at col 8, bit 8 at col 7, bits 9..14 at cols 5..0)
    if (i < 6) {
      m[i][8] = bit;
    } else if (i === 6) {
      m[7][8] = bit;
    } else if (i === 7) {
      m[8][8] = bit;
    } else if (i === 8) {
      m[8][7] = bit;
    } else {
      m[8][14 - i] = bit;
    }
  }
  return m;
}

function penaltyScore(m, n) {
  let score = 0;
  for (let r = 0; r < n; r++) {
    let run = 1;
    for (let c = 1; c < n; c++) {
      if (m[r][c] === m[r][c - 1]) run++;
      else {
        if (run >= 5) score += run - 2;
        run = 1;
      }
    }
    if (run >= 5) score += run - 2;
  }
  for (let c = 0; c < n; c++) {
    let run = 1;
    for (let r = 1; r < n; r++) {
      if (m[r][c] === m[r - 1][c]) run++;
      else {
        if (run >= 5) score += run - 2;
        run = 1;
      }
    }
    if (run >= 5) score += run - 2;
  }
  for (let r = 0; r < n - 1; r++) {
    for (let c = 0; c < n - 1; c++) {
      const v = m[r][c];
      if (v === m[r][c + 1] && v === m[r + 1][c] && v === m[r + 1][c + 1]) score += 3;
    }
  }
  return score;
}

export function encodeQrMatrix(text) {
  const bytes = new TextEncoder().encode(String(text));
  const spec = chooseSpec(bytes.length);
  const codewords = buildCodewords(bytes, spec);
  const { n, mod, fn } = createMatrix(spec[0]);

  let bitIdx = 0;
  const totalBits = codewords.length * 8;
  let dir = -1;
  for (let col = n - 1; col > 0; col -= 2) {
    if (col === 6) col--;
    for (let step = 0; step < n; step++) {
      const r = dir === -1 ? n - 1 - step : step;
      for (let dx = 0; dx < 2; dx++) {
        const c = col - dx;
        if (!fn[r][c]) {
          let bit = 0;
          if (bitIdx < totalBits) {
            bit = (codewords[bitIdx >> 3] >> (7 - (bitIdx & 7))) & 1;
            bitIdx++;
          }
          mod[r][c] = bit;
        }
      }
    }
    dir = -dir;
  }

  let best = null;
  let bestScore = Infinity;
  for (let maskId = 0; maskId < 8; maskId++) {
    const candidate = applyMaskAndFormat(mod, fn, n, maskId);
    const s = penaltyScore(candidate, n);
    if (s < bestScore) {
      bestScore = s;
      best = candidate;
    }
  }
  return { size: n, matrix: best };
}

export function renderQrSvgDataUri(text) {
  const { size, matrix } = encodeQrMatrix(text);
  const q = 2; // quiet zone modules
  const dim = size + q * 2;
  let path = '';
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (matrix[r][c]) path += `M${c + q},${r + q}h1v1h-1z`;
    }
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${dim} ${dim}" shape-rendering="crispEdges"><rect width="${dim}" height="${dim}" fill="#ffffff"/><path d="${path}" fill="#0f172a"/></svg>`;
}
