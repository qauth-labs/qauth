/**
 * QR Code encoder — byte mode, error-correction level M (issue #239).
 *
 * The wallet-login screen has to put an OID4VP invocation URI on the desktop
 * screen so a phone can pick it up (OID4VP 1.0 §5: the request is delivered to
 * the wallet's Authorization Endpoint, either as a custom scheme or a universal
 * link). That is a QR code, and a QR code is the one thing on that page we
 * cannot render with HTML.
 *
 * ## Why this is hand-written rather than a dependency
 *
 * It is ~300 lines of pure, dependency-free arithmetic over `GF(256)` with no
 * I/O, no clock and no configuration. Against that, a new npm dependency on the
 * auth server — the process that holds the signing keys and the session store —
 * is a permanent supply-chain surface for a function that is fully specified by
 * ISO/IEC 18004 and never changes. The workspace's standing rule is to prefer an
 * existing dependency; there is no existing one for this, so the smaller
 * long-term liability wins.
 *
 * ## Scope, deliberately narrow
 *
 * - **Byte mode only.** A URI is bytes. Alphanumeric mode would encode a small
 *   subset of URIs more densely and every other one not at all.
 * - **Error-correction level M only.** ~15% recovery: the level the QR ecosystem
 *   treats as the default for screen-displayed codes. One level means ONE row of
 *   each block table, and every row is cross-checked against the published
 *   capacity figures in the tests — a mistyped table entry is the failure mode
 *   here, and it is silent (a code that encodes fine and scans nowhere).
 * - **No Kanji/ECI/structured-append.** Nothing on this page needs them.
 *
 * The encoder is total: it returns `undefined` rather than throwing when the
 * payload does not fit version 40 (see {@link QR_MAX_BYTES}), because the caller
 * — a login screen — must degrade to the deep-link button rather than 500.
 *
 * @see ISO/IEC 18004 (QR Code bar code symbology specification)
 */

/** The one error-correction level this module emits (~15% recovery). */
const ECC_LEVEL_FORMAT_BITS = 0b00;

/**
 * Error-correction codewords per block, indexed by version (1–40), for level M.
 * Index 0 is unused. Cross-checked against published byte capacities in the
 * tests — see the module note on silent table typos.
 */
const ECC_CODEWORDS_PER_BLOCK: readonly number[] = [
  -1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28,
  28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
];

/** Number of error-correction blocks, indexed by version (1–40), for level M. */
const NUM_ERROR_CORRECTION_BLOCKS: readonly number[] = [
  -1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25,
  26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49,
];

/** Lowest QR version (21×21 modules). */
export const QR_MIN_VERSION = 1;
/** Highest QR version (177×177 modules). */
export const QR_MAX_VERSION = 40;

/** Byte-mode padding codewords, alternated after the terminator (§8.4.9). */
const PAD_CODEWORDS = [0xec, 0x11] as const;

/**
 * A rendered symbol: a square grid of light/dark modules, quiet zone excluded.
 */
export interface QrCode {
  /** Modules per side (21 + 4 × (version − 1)). */
  readonly size: number;
  /** Version 1–40, exposed for diagnostics and tests. */
  readonly version: number;
  /** `modules[y][x]` — `true` is a dark module. */
  readonly modules: readonly (readonly boolean[])[];
}

/** Raw data modules available in a version, before error correction (§7.4). */
function numRawDataModules(version: number): number {
  let result = (16 * version + 128) * version + 64;
  if (version >= 2) {
    const numAlign = Math.floor(version / 7) + 2;
    result -= (25 * numAlign - 10) * numAlign - 55;
    if (version >= 7) result -= 36;
  }
  return result;
}

/** Total codewords (data + error correction) a version holds. */
function numTotalCodewords(version: number): number {
  return Math.floor(numRawDataModules(version) / 8);
}

/** Data codewords a version holds at level M. */
function numDataCodewords(version: number): number {
  return (
    numTotalCodewords(version) -
    ECC_CODEWORDS_PER_BLOCK[version] * NUM_ERROR_CORRECTION_BLOCKS[version]
  );
}

/** Bits the byte-mode character count field occupies at this version (§8.4). */
function charCountBits(version: number): number {
  return version <= 9 ? 8 : 16;
}

/**
 * Payload bytes a version can carry in byte mode at level M.
 *
 * Exported because it is the value the tests pin against the published capacity
 * table — the only independent check available on the block tables above.
 */
export function qrByteCapacity(version: number): number {
  const availableBits = numDataCodewords(version) * 8 - 4 - charCountBits(version);
  return Math.floor(availableBits / 8);
}

/** Largest payload this encoder can represent (version 40, level M). */
export const QR_MAX_BYTES = qrByteCapacity(QR_MAX_VERSION);

/* ---------------------------------------------------------------------------
 * Reed–Solomon over GF(256), the field ISO/IEC 18004 §7.5.2 specifies
 * (primitive polynomial x^8 + x^4 + x^3 + x^2 + 1 = 0x11D).
 * ------------------------------------------------------------------------- */

/** Multiply two field elements (Russian-peasant, branch-free on the data). */
function fieldMultiply(x: number, y: number): number {
  let z = 0;
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d);
    z ^= ((y >>> i) & 1) * x;
  }
  return z & 0xff;
}

/** Coefficients of the degree-`degree` generator polynomial, highest term omitted. */
function generatorPolynomial(degree: number): number[] {
  const result = new Array<number>(degree).fill(0);
  result[degree - 1] = 1;

  // Multiply by (x - r^i) for i = 0 .. degree-1, tracking r^i as `root`.
  let root = 1;
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < degree; j++) {
      result[j] = fieldMultiply(result[j], root);
      if (j + 1 < degree) result[j] ^= result[j + 1];
    }
    root = fieldMultiply(root, 0x02);
  }
  return result;
}

/** Error-correction codewords for one block. */
function remainder(data: readonly number[], divisor: readonly number[]): number[] {
  const result = new Array<number>(divisor.length).fill(0);
  for (const byte of data) {
    const factor = byte ^ (result.shift() as number);
    result.push(0);
    for (let i = 0; i < divisor.length; i++) {
      result[i] ^= fieldMultiply(divisor[i], factor);
    }
  }
  return result;
}

/* ---------------------------------------------------------------------------
 * Encoding
 * ------------------------------------------------------------------------- */

/** Append the low `count` bits of `value`, most-significant first. */
function appendBits(bits: number[], value: number, count: number): void {
  for (let i = count - 1; i >= 0; i--) {
    bits.push((value >>> i) & 1);
  }
}

/** Smallest version that fits `byteLength` payload bytes, or undefined. */
function selectVersion(byteLength: number): number | undefined {
  for (let version = QR_MIN_VERSION; version <= QR_MAX_VERSION; version++) {
    if (byteLength <= qrByteCapacity(version)) return version;
  }
  return undefined;
}

/** Build the padded data-codeword sequence for one version (§8.4.9). */
function buildDataCodewords(bytes: Uint8Array, version: number): number[] {
  const bits: number[] = [];
  appendBits(bits, 0b0100, 4); // byte mode
  appendBits(bits, bytes.length, charCountBits(version));
  for (const byte of bytes) appendBits(bits, byte, 8);

  const capacityBits = numDataCodewords(version) * 8;
  // Terminator, then pad to a byte boundary, then alternating pad codewords.
  appendBits(bits, 0, Math.min(4, capacityBits - bits.length));
  appendBits(bits, 0, (8 - (bits.length % 8)) % 8);

  const codewords: number[] = [];
  for (let i = 0; i < bits.length; i += 8) {
    let byte = 0;
    for (let j = 0; j < 8; j++) byte = (byte << 1) | bits[i + j];
    codewords.push(byte);
  }
  for (let i = 0; codewords.length * 8 < capacityBits; i++) {
    codewords.push(PAD_CODEWORDS[i % PAD_CODEWORDS.length]);
  }
  return codewords;
}

/** Split into blocks, add error correction, and interleave (§8.6). */
function addEccAndInterleave(data: readonly number[], version: number): number[] {
  const numBlocks = NUM_ERROR_CORRECTION_BLOCKS[version];
  const blockEccLen = ECC_CODEWORDS_PER_BLOCK[version];
  const rawCodewords = numTotalCodewords(version);
  const numShortBlocks = numBlocks - (rawCodewords % numBlocks);
  const shortBlockLen = Math.floor(rawCodewords / numBlocks);

  const divisor = generatorPolynomial(blockEccLen);
  const blocks: number[][] = [];
  for (let i = 0, k = 0; i < numBlocks; i++) {
    const dataLen = shortBlockLen - blockEccLen + (i < numShortBlocks ? 0 : 1);
    const dat = data.slice(k, k + dataLen);
    k += dataLen;
    const ecc = remainder(dat, divisor);
    // Short blocks carry one fewer data codeword. A placeholder keeps every
    // block the same length so the interleave loop below is a plain transpose;
    // the placeholder index is the one the loop skips, so it is never emitted.
    if (i < numShortBlocks) dat.push(0);
    blocks.push(dat.concat(ecc));
  }

  const result: number[] = [];
  for (let i = 0; i < blocks[0].length; i++) {
    for (let j = 0; j < blocks.length; j++) {
      if (i !== shortBlockLen - blockEccLen || j >= numShortBlocks) {
        result.push(blocks[j][i]);
      }
    }
  }
  return result;
}

/* ---------------------------------------------------------------------------
 * Symbol construction
 * ------------------------------------------------------------------------- */

/** Centre coordinates of the alignment patterns for a version (§7.3.5). */
function alignmentPatternPositions(version: number): number[] {
  if (version === 1) return [];
  const numAlign = Math.floor(version / 7) + 2;
  const step = version === 32 ? 26 : Math.ceil((version * 4 + 4) / (numAlign * 2 - 2) / 2) * 2;
  const result = [6];
  for (let pos = version * 4 + 17 - 7; result.length < numAlign; pos -= step) {
    result.splice(1, 0, pos);
  }
  return result;
}

/** Mutable drawing surface; `isFunction` marks modules masking must not touch. */
interface Canvas {
  readonly size: number;
  readonly version: number;
  readonly modules: boolean[][];
  readonly isFunction: boolean[][];
}

function setFunctionModule(canvas: Canvas, x: number, y: number, isDark: boolean): void {
  canvas.modules[y][x] = isDark;
  canvas.isFunction[y][x] = true;
}

function getBit(value: number, index: number): boolean {
  return ((value >>> index) & 1) !== 0;
}

/** Format information: 5 data bits + BCH(15,5), masked with 0x5412 (§8.9). */
function drawFormatBits(canvas: Canvas, mask: number): void {
  const data = (ECC_LEVEL_FORMAT_BITS << 3) | mask;
  let rem = data;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  const bits = ((data << 10) | rem) ^ 0x5412;

  // First copy, around the top-left finder pattern.
  for (let i = 0; i <= 5; i++) setFunctionModule(canvas, 8, i, getBit(bits, i));
  setFunctionModule(canvas, 8, 7, getBit(bits, 6));
  setFunctionModule(canvas, 8, 8, getBit(bits, 7));
  setFunctionModule(canvas, 7, 8, getBit(bits, 8));
  for (let i = 9; i < 15; i++) setFunctionModule(canvas, 14 - i, 8, getBit(bits, i));

  // Second copy, split across the other two finder patterns.
  const size = canvas.size;
  for (let i = 0; i < 8; i++) setFunctionModule(canvas, size - 1 - i, 8, getBit(bits, i));
  for (let i = 8; i < 15; i++) setFunctionModule(canvas, 8, size - 15 + i, getBit(bits, i));
  setFunctionModule(canvas, 8, size - 8, true); // always-dark module
}

/** Version information: 6 data bits + BCH(18,6), versions 7+ only (§8.10). */
function drawVersionBits(canvas: Canvas): void {
  if (canvas.version < 7) return;
  let rem = canvas.version;
  for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
  const bits = (canvas.version << 12) | rem;

  for (let i = 0; i < 18; i++) {
    const bit = getBit(bits, i);
    const a = canvas.size - 11 + (i % 3);
    const b = Math.floor(i / 3);
    setFunctionModule(canvas, a, b, bit);
    setFunctionModule(canvas, b, a, bit);
  }
}

/** Finder pattern plus its separator, centred on (x, y). */
function drawFinderPattern(canvas: Canvas, x: number, y: number): void {
  for (let dy = -4; dy <= 4; dy++) {
    for (let dx = -4; dx <= 4; dx++) {
      const dist = Math.max(Math.abs(dx), Math.abs(dy));
      const xx = x + dx;
      const yy = y + dy;
      if (xx >= 0 && xx < canvas.size && yy >= 0 && yy < canvas.size) {
        setFunctionModule(canvas, xx, yy, dist !== 2 && dist !== 4);
      }
    }
  }
}

/** Alignment pattern centred on (x, y). */
function drawAlignmentPattern(canvas: Canvas, x: number, y: number): void {
  for (let dy = -2; dy <= 2; dy++) {
    for (let dx = -2; dx <= 2; dx++) {
      setFunctionModule(canvas, x + dx, y + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
    }
  }
}

function drawFunctionPatterns(canvas: Canvas): void {
  const size = canvas.size;

  // Timing patterns.
  for (let i = 0; i < size; i++) {
    setFunctionModule(canvas, 6, i, i % 2 === 0);
    setFunctionModule(canvas, i, 6, i % 2 === 0);
  }

  drawFinderPattern(canvas, 3, 3);
  drawFinderPattern(canvas, size - 4, 3);
  drawFinderPattern(canvas, 3, size - 4);

  const positions = alignmentPatternPositions(canvas.version);
  for (let i = 0; i < positions.length; i++) {
    for (let j = 0; j < positions.length; j++) {
      // The three finder-pattern corners have no alignment pattern.
      const isCorner =
        (i === 0 && j === 0) ||
        (i === 0 && j === positions.length - 1) ||
        (i === positions.length - 1 && j === 0);
      if (!isCorner) drawAlignmentPattern(canvas, positions[i], positions[j]);
    }
  }

  // Drawn with a placeholder mask; rewritten once the mask is chosen.
  drawFormatBits(canvas, 0);
  drawVersionBits(canvas);
}

/** Lay the interleaved codewords into the symbol, zig-zagging upward (§8.7.3). */
function drawCodewords(canvas: Canvas, data: readonly number[]): void {
  const size = canvas.size;
  let i = 0;
  for (let right = size - 1; right >= 1; right -= 2) {
    // Column 6 is the vertical timing pattern; the pair skips over it.
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert++) {
      for (let j = 0; j < 2; j++) {
        const x = right - j;
        const upward = ((right + 1) & 2) === 0;
        const y = upward ? size - 1 - vert : vert;
        if (!canvas.isFunction[y][x] && i < data.length * 8) {
          canvas.modules[y][x] = getBit(data[i >>> 3], 7 - (i & 7));
          i++;
        }
      }
    }
  }
}

/** The eight data-mask conditions (§8.8.1). */
function maskCondition(mask: number, x: number, y: number): boolean {
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

/** XOR the mask over every non-function module. Self-inverse. */
function applyMask(canvas: Canvas, mask: number): void {
  for (let y = 0; y < canvas.size; y++) {
    for (let x = 0; x < canvas.size; x++) {
      if (!canvas.isFunction[y][x] && maskCondition(mask, x, y)) {
        canvas.modules[y][x] = !canvas.modules[y][x];
      }
    }
  }
}

const PENALTY_N1 = 3;
const PENALTY_N2 = 3;
const PENALTY_N3 = 40;
const PENALTY_N4 = 10;

/** Total penalty score for the current module grid (§8.8.2). */
function penaltyScore(canvas: Canvas): number {
  const size = canvas.size;
  const modules = canvas.modules;
  let result = 0;

  // Rule 1 — adjacent modules of the same colour in a row/column.
  for (let y = 0; y < size; y++) {
    let runColor = modules[y][0];
    let runLength = 1;
    for (let x = 1; x < size; x++) {
      if (modules[y][x] === runColor) {
        runLength++;
      } else {
        if (runLength >= 5) result += PENALTY_N1 + (runLength - 5);
        runColor = modules[y][x];
        runLength = 1;
      }
    }
    if (runLength >= 5) result += PENALTY_N1 + (runLength - 5);
  }
  for (let x = 0; x < size; x++) {
    let runColor = modules[0][x];
    let runLength = 1;
    for (let y = 1; y < size; y++) {
      if (modules[y][x] === runColor) {
        runLength++;
      } else {
        if (runLength >= 5) result += PENALTY_N1 + (runLength - 5);
        runColor = modules[y][x];
        runLength = 1;
      }
    }
    if (runLength >= 5) result += PENALTY_N1 + (runLength - 5);
  }

  // Rule 2 — 2×2 blocks of one colour.
  for (let y = 0; y < size - 1; y++) {
    for (let x = 0; x < size - 1; x++) {
      const c = modules[y][x];
      if (c === modules[y][x + 1] && c === modules[y + 1][x] && c === modules[y + 1][x + 1]) {
        result += PENALTY_N2;
      }
    }
  }

  // Rule 3 — 1:1:3:1:1 finder-like patterns, in rows and columns.
  for (let y = 0; y < size; y++) {
    for (let x = 0; x <= size - 7; x++) {
      if (isFinderLike(modules[y], x)) result += PENALTY_N3;
    }
  }
  for (let x = 0; x < size; x++) {
    const column: boolean[] = [];
    for (let y = 0; y < size; y++) column.push(modules[y][x]);
    for (let y = 0; y <= size - 7; y++) {
      if (isFinderLike(column, y)) result += PENALTY_N3;
    }
  }

  // Rule 4 — deviation of the dark-module proportion from 50%.
  let dark = 0;
  for (const row of modules) for (const cell of row) if (cell) dark++;
  const total = size * size;
  const k = Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1;
  result += Math.max(k, 0) * PENALTY_N4;

  return result;
}

/**
 * Does the 7-module window at `offset` hold the 1:1:3:1:1 finder-like pattern
 * bounded by four light modules on at least one side?
 *
 * Only mask SELECTION depends on this, so an imprecise answer costs a slightly
 * worse mask, never a wrong symbol.
 */
function isFinderLike(line: readonly boolean[], offset: number): boolean {
  const w = line;
  const core =
    w[offset] &&
    !w[offset + 1] &&
    w[offset + 2] &&
    w[offset + 3] &&
    w[offset + 4] &&
    !w[offset + 5] &&
    w[offset + 6];
  if (!core) return false;

  const lightBefore =
    offset >= 4 && !w[offset - 1] && !w[offset - 2] && !w[offset - 3] && !w[offset - 4];
  const lightAfter =
    offset + 10 < line.length &&
    !w[offset + 7] &&
    !w[offset + 8] &&
    !w[offset + 9] &&
    !w[offset + 10];
  return lightBefore || lightAfter;
}

/**
 * Encode `text` as a QR symbol (byte mode, level M).
 *
 * @param text - the payload; UTF-8 encoded before framing.
 * @returns the symbol, or `undefined` when the payload exceeds
 * {@link QR_MAX_BYTES}. Callers MUST handle `undefined` by degrading rather than
 * failing the page — an over-long invocation URI is a configuration outcome, not
 * a server fault.
 */
export function encodeQrCode(text: string): QrCode | undefined {
  const bytes = new TextEncoder().encode(text);
  const version = selectVersion(bytes.length);
  if (version === undefined) return undefined;

  const size = version * 4 + 17;
  const canvas: Canvas = {
    size,
    version,
    modules: Array.from({ length: size }, () => new Array<boolean>(size).fill(false)),
    isFunction: Array.from({ length: size }, () => new Array<boolean>(size).fill(false)),
  };

  drawFunctionPatterns(canvas);
  drawCodewords(canvas, addEccAndInterleave(buildDataCodewords(bytes, version), version));

  // Choose the mask with the lowest penalty, as the specification requires;
  // each candidate is applied, scored and undone (masking is self-inverse).
  let bestMask = 0;
  let bestPenalty = Number.POSITIVE_INFINITY;
  for (let mask = 0; mask < 8; mask++) {
    applyMask(canvas, mask);
    drawFormatBits(canvas, mask);
    const penalty = penaltyScore(canvas);
    if (penalty < bestPenalty) {
      bestPenalty = penalty;
      bestMask = mask;
    }
    applyMask(canvas, mask);
  }
  applyMask(canvas, bestMask);
  drawFormatBits(canvas, bestMask);

  return { size, version, modules: canvas.modules };
}

/** Quiet zone required around a symbol, in modules (§9.1). */
export const QR_QUIET_ZONE = 4;

/**
 * Render a symbol as a standalone SVG element.
 *
 * The output carries no `style` attribute and no script: colours are set with
 * presentation attributes, so the page's nonce-based CSP (`style-src 'self'`
 * plus a per-request nonce) needs no relaxation. Everything interpolated is
 * derived from module booleans and the caller's `label`, which is escaped.
 *
 * @param qr - the symbol to render.
 * @param label - accessible name announced by screen readers.
 */
export function renderQrCodeSvg(qr: QrCode, label: string): string {
  const dimension = qr.size + QR_QUIET_ZONE * 2;
  const parts: string[] = [];
  for (let y = 0; y < qr.size; y++) {
    for (let x = 0; x < qr.size; x++) {
      if (qr.modules[y][x]) {
        parts.push(`M${x + QR_QUIET_ZONE},${y + QR_QUIET_ZONE}h1v1h-1z`);
      }
    }
  }

  const escapedLabel = label
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');

  return (
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${dimension} ${dimension}" ` +
    `width="100%" height="100%" shape-rendering="crispEdges" role="img" ` +
    `aria-label="${escapedLabel}">` +
    `<rect width="${dimension}" height="${dimension}" fill="#ffffff"/>` +
    `<path d="${parts.join('')}" fill="#111111"/>` +
    `</svg>`
  );
}
