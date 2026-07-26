import { describe, expect, it } from 'vitest';

import {
  encodeQrCode,
  QR_MAX_BYTES,
  QR_QUIET_ZONE,
  qrByteCapacity,
  renderQrCodeSvg,
} from './qr-code';

/**
 * The encoder's failure mode is silent: a symbol built from a mistyped block
 * table encodes without complaint and scans nowhere. Nothing in this file
 * therefore asserts against the encoder's own view of itself.
 *
 * Two independent checks carry the suite:
 *
 *  1. **Published capacities.** ISO/IEC 18004's byte-mode capacity figures for
 *     level M are external data. They are a function of BOTH block tables, so a
 *     single wrong entry moves at least one of them.
 *  2. **A decoder written from the specification, not from the encoder.** It
 *     re-derives the function-module map, reads the mask out of the format bits,
 *     un-masks, walks the zig-zag, de-interleaves, checks the Reed-Solomon
 *     syndromes are zero and parses the byte-mode segment back out. Anything the
 *     encoder gets wrong about placement, masking, padding or error correction
 *     shows up as a decode failure rather than as a matching mistake on both
 *     sides.
 */

/* --------------------------------------------------------------------------
 * A minimal QR reader, written against ISO/IEC 18004 for this test only.
 * ------------------------------------------------------------------------ */

/** Level M block structure, transcribed from the standard's tables. */
const ECC_PER_BLOCK_M: readonly number[] = [
  -1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28,
  28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
];
const BLOCKS_M: readonly number[] = [
  -1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25,
  26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49,
];

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

function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return GF_EXP[GF_LOG[a] + GF_LOG[b]];
}

function rawDataModules(version: number): number {
  let result = (16 * version + 128) * version + 64;
  if (version >= 2) {
    const numAlign = Math.floor(version / 7) + 2;
    result -= (25 * numAlign - 10) * numAlign - 55;
    if (version >= 7) result -= 36;
  }
  return result;
}

function alignmentPositions(version: number): number[] {
  if (version === 1) return [];
  const numAlign = Math.floor(version / 7) + 2;
  const step = version === 32 ? 26 : Math.ceil((version * 4 + 4) / (numAlign * 2 - 2) / 2) * 2;
  const result = [6];
  for (let pos = version * 4 + 17 - 7; result.length < numAlign; pos -= step) {
    result.splice(1, 0, pos);
  }
  return result;
}

/** Modules a decoder must skip: everything that is not payload. */
function functionMap(version: number): boolean[][] {
  const size = version * 4 + 17;
  const reserved = Array.from({ length: size }, () => new Array<boolean>(size).fill(false));
  const mark = (x: number, y: number) => {
    if (x >= 0 && x < size && y >= 0 && y < size) reserved[y][x] = true;
  };

  for (let i = 0; i < size; i++) {
    mark(6, i);
    mark(i, 6);
  }
  for (let y = 0; y < 9; y++) {
    for (let x = 0; x < 9; x++) {
      mark(x, y); // top-left finder + format
      if (x < 8) mark(size - 1 - x, y); // top-right finder + format
      if (y < 8) mark(x, size - 1 - y); // bottom-left finder + format
    }
  }
  if (version >= 7) {
    for (let i = 0; i < 18; i++) {
      const a = size - 11 + (i % 3);
      const b = Math.floor(i / 3);
      mark(a, b);
      mark(b, a);
    }
  }
  const positions = alignmentPositions(version);
  for (let i = 0; i < positions.length; i++) {
    for (let j = 0; j < positions.length; j++) {
      const corner =
        (i === 0 && j === 0) ||
        (i === 0 && j === positions.length - 1) ||
        (i === positions.length - 1 && j === 0);
      if (corner) continue;
      for (let dy = -2; dy <= 2; dy++) {
        for (let dx = -2; dx <= 2; dx++) mark(positions[i] + dx, positions[j] + dy);
      }
    }
  }
  return reserved;
}

/** Read the 15 format bits from the primary copy and validate the BCH code. */
function readFormat(modules: readonly (readonly boolean[])[]): { ecc: number; mask: number } {
  const size = modules.length;
  const bits: boolean[] = [];
  for (let i = 0; i <= 5; i++) bits.push(modules[i][8]);
  bits.push(modules[7][8], modules[8][8], modules[8][7]);
  for (let i = 9; i < 15; i++) bits.push(modules[8][14 - i]);

  let value = 0;
  for (let i = 0; i < 15; i++) if (bits[i]) value |= 1 << i;

  // Brute-force against every valid format codeword: this validates the BCH
  // parity and the 0x5412 mask without reimplementing either.
  for (let data = 0; data < 32; data++) {
    let rem = data;
    for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
    const candidate = (((data << 10) | rem) ^ 0x5412) & 0x7fff;
    if (candidate === value) return { ecc: data >> 3, mask: data & 0b111 };
  }
  throw new Error('format information is not a valid BCH(15,5) codeword');
}

function maskBit(mask: number, x: number, y: number): boolean {
  switch (mask) {
    case 0:
      return (x + y) % 2 === 0;
    case 1:
      return y % 2 === 0;
    case 2:
      return x % 3 === 0;
    case 3:
      return (x + y) % 3 === 0;
    case 4:
      return (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0;
    case 5:
      return ((x * y) % 2) + ((x * y) % 3) === 0;
    case 6:
      return (((x * y) % 2) + ((x * y) % 3)) % 2 === 0;
    default:
      return (((x + y) % 2) + ((x * y) % 3)) % 2 === 0;
  }
}

/** Decode a symbol back to its payload string, or throw explaining why not. */
function decodeQr(qr: { size: number; version: number; modules: readonly (readonly boolean[])[] }) {
  const { size, version, modules } = qr;
  expect(size).toBe(version * 4 + 17);

  const { ecc, mask } = readFormat(modules);
  if (ecc !== 0b00) throw new Error(`expected error-correction level M, read ${ecc}`);

  const reserved = functionMap(version);

  // Un-mask, then walk the zig-zag to recover the interleaved codewords.
  const bits: number[] = [];
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert++) {
      for (let j = 0; j < 2; j++) {
        const x = right - j;
        const upward = ((right + 1) & 2) === 0;
        const y = upward ? size - 1 - vert : vert;
        if (reserved[y][x]) continue;
        const dark = modules[y][x] !== maskBit(mask, x, y);
        bits.push(dark ? 1 : 0);
      }
    }
  }

  const total = Math.floor(rawDataModules(version) / 8);
  const interleaved: number[] = [];
  for (let i = 0; i + 8 <= bits.length && interleaved.length < total; i += 8) {
    let byte = 0;
    for (let j = 0; j < 8; j++) byte = (byte << 1) | bits[i + j];
    interleaved.push(byte);
  }
  expect(interleaved.length).toBe(total);

  // De-interleave into blocks.
  const numBlocks = BLOCKS_M[version];
  const eccLen = ECC_PER_BLOCK_M[version];
  const shortLen = Math.floor(total / numBlocks);
  const numShort = numBlocks - (total % numBlocks);
  const blocks: number[][] = Array.from({ length: numBlocks }, () => []);

  let cursor = 0;
  const dataLenOf = (b: number) => shortLen - eccLen + (b < numShort ? 0 : 1);
  const maxDataLen = shortLen - eccLen + 1;
  for (let i = 0; i < maxDataLen; i++) {
    for (let b = 0; b < numBlocks; b++) {
      if (i < dataLenOf(b)) blocks[b].push(interleaved[cursor++]);
    }
  }
  for (let i = 0; i < eccLen; i++) {
    for (let b = 0; b < numBlocks; b++) blocks[b].push(interleaved[cursor++]);
  }
  expect(cursor).toBe(total);

  // Every block must be a valid Reed-Solomon codeword: all syndromes zero.
  for (const block of blocks) {
    for (let s = 0; s < eccLen; s++) {
      let acc = 0;
      for (const coefficient of block) acc = gfMul(acc, GF_EXP[s]) ^ coefficient;
      expect(acc).toBe(0);
    }
  }

  const data: number[] = [];
  for (let b = 0; b < numBlocks; b++) data.push(...blocks[b].slice(0, dataLenOf(b)));

  // Parse the byte-mode segment.
  const dataBits: number[] = [];
  for (const byte of data) for (let i = 7; i >= 0; i--) dataBits.push((byte >>> i) & 1);
  const take = (n: number) => {
    let v = 0;
    for (let i = 0; i < n; i++) v = (v << 1) | (dataBits.shift() as number);
    return v;
  };
  expect(take(4)).toBe(0b0100);
  const length = take(version <= 9 ? 8 : 16);
  const payload = new Uint8Array(length);
  for (let i = 0; i < length; i++) payload[i] = take(8);
  return new TextDecoder().decode(payload);
}

/* --------------------------------------------------------------------------
 * Tests
 * ------------------------------------------------------------------------ */

describe('qrByteCapacity — cross-checked against ISO/IEC 18004 level M', () => {
  // Published byte-mode capacities. External data: a wrong entry in either
  // block table changes at least one of these.
  const PUBLISHED: ReadonlyArray<readonly [version: number, capacity: number]> = [
    [1, 14],
    [2, 26],
    [3, 42],
    [4, 62],
    [5, 84],
    [10, 213],
    [20, 666],
    [30, 1370],
    [40, 2331],
  ];

  it.each(PUBLISHED)('version %i holds %i bytes', (version, capacity) => {
    expect(qrByteCapacity(version)).toBe(capacity);
  });

  it('capacity increases monotonically across every version', () => {
    for (let version = 2; version <= 40; version++) {
      expect(qrByteCapacity(version)).toBeGreaterThan(qrByteCapacity(version - 1));
    }
  });

  it('QR_MAX_BYTES is the version-40 capacity', () => {
    expect(QR_MAX_BYTES).toBe(2331);
  });
});

describe('encodeQrCode — round-trips through an independent reader', () => {
  const PAYLOADS: ReadonlyArray<readonly [label: string, text: string]> = [
    ['a short URI', 'openid4vp://?x=1'],
    ['a version-boundary payload', 'a'.repeat(14)],
    ['a one-byte-larger payload', 'a'.repeat(15)],
    ['a medium invocation URI', `openid4vp://?request=${'A'.repeat(180)}`],
    ['a large invocation URI', `openid4vp://?request=${'A'.repeat(900)}`],
    ['a maximum-size payload', 'z'.repeat(2331)],
    ['a non-ASCII payload', 'wallet — Ünïcödé ✓ präsentation'],
  ];

  it.each(PAYLOADS)('decodes %s back to the original text', (_label, text) => {
    const qr = encodeQrCode(text);
    expect(qr).toBeDefined();
    expect(decodeQr(qr!)).toBe(text);
  });

  it('selects the smallest version that fits', () => {
    expect(encodeQrCode('a'.repeat(14))?.version).toBe(1);
    expect(encodeQrCode('a'.repeat(15))?.version).toBe(2);
    expect(encodeQrCode('a'.repeat(26))?.version).toBe(2);
    expect(encodeQrCode('a'.repeat(27))?.version).toBe(3);
  });

  it('returns undefined rather than throwing when the payload cannot fit', () => {
    expect(encodeQrCode('z'.repeat(QR_MAX_BYTES + 1))).toBeUndefined();
  });

  it('counts UTF-8 bytes, not characters, when choosing a version', () => {
    // 15 three-byte characters is 45 bytes: past version 3's 42-byte capacity
    // even though 15 CHARACTERS would fit version 2.
    const qr = encodeQrCode('✓'.repeat(15));
    expect(qr?.version).toBe(4);
    expect(decodeQr(qr!)).toBe('✓'.repeat(15));
  });

  it('places the three finder patterns and the always-dark module', () => {
    const qr = encodeQrCode('https://auth.example.com')!;
    const { modules, size } = qr;
    for (const [ox, oy] of [
      [0, 0],
      [size - 7, 0],
      [0, size - 7],
    ]) {
      // Dark 7x7 border, light ring inside it, dark 3x3 core.
      expect(modules[oy][ox]).toBe(true);
      expect(modules[oy + 1][ox + 1]).toBe(false);
      expect(modules[oy + 3][ox + 3]).toBe(true);
      expect(modules[oy + 6][ox + 6]).toBe(true);
    }
    expect(modules[size - 8][8]).toBe(true);
  });

  it('draws alternating timing patterns', () => {
    const qr = encodeQrCode('https://auth.example.com')!;
    for (let i = 8; i < qr.size - 8; i++) {
      expect(qr.modules[6][i]).toBe(i % 2 === 0);
      expect(qr.modules[i][6]).toBe(i % 2 === 0);
    }
  });
});

describe('renderQrCodeSvg', () => {
  it('renders a self-contained SVG with a quiet zone and no inline style', () => {
    const qr = encodeQrCode('openid4vp://?x=1')!;
    const svg = renderQrCodeSvg(qr, 'Scan with your wallet');
    const dimension = qr.size + QR_QUIET_ZONE * 2;

    expect(svg.startsWith('<svg ')).toBe(true);
    expect(svg).toContain(`viewBox="0 0 ${dimension} ${dimension}"`);
    expect(svg).toContain('role="img"');
    expect(svg).toContain('aria-label="Scan with your wallet"');
    expect(svg).not.toContain('style=');
    expect(svg).not.toContain('<script');
  });

  it('escapes the accessible label', () => {
    const qr = encodeQrCode('openid4vp://?x=1')!;
    const svg = renderQrCodeSvg(qr, '<img src=x onerror="alert(1)">');
    expect(svg).not.toContain('<img');
    expect(svg).toContain('&lt;img');
  });
});
