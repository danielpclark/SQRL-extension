// Minimal QR Code encoder (ISO/IEC 18004), byte mode, all versions, automatic mask selection.
// Used to show an identity as a QR code for transfer to another SQRL client (the data is the
// binary `sqrldata` file, exactly like GRC's client encodes it).

const ECC = { L: 1, M: 0, Q: 3, H: 2 };
const ECC_CODEWORDS_PER_BLOCK = [
  // L
  [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  // M
  [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28],
  // Q
  [-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  // H
  [-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30]
];
const NUM_ERROR_CORRECTION_BLOCKS = [
  [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
  [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49],
  [-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68],
  [-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81]
];
const TABLE_INDEX = { L: 0, M: 1, Q: 2, H: 3 };

function numRawDataModules(ver) {
  let result = (16 * ver + 128) * ver + 64;
  if (ver >= 2) {
    const numAlign = Math.floor(ver / 7) + 2;
    result -= (25 * numAlign - 10) * numAlign - 55;
    if (ver >= 7) result -= 36;
  }
  return result;
}

function numDataCodewords(ver, ecl) {
  const i = TABLE_INDEX[ecl];
  return Math.floor(numRawDataModules(ver) / 8) - ECC_CODEWORDS_PER_BLOCK[i][ver] * NUM_ERROR_CORRECTION_BLOCKS[i][ver];
}

// --- Reed-Solomon over GF(2^8) with the QR primitive polynomial 0x11D ---------------------
function rsMultiply(x, y) {
  let z = 0;
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d);
    z ^= ((y >>> i) & 1) * x;
  }
  return z;
}
function rsDivisor(degree) {
  const result = new Uint8Array(degree);
  result[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < result.length; j++) {
      result[j] = rsMultiply(result[j], root);
      if (j + 1 < result.length) result[j] ^= result[j + 1];
    }
    root = rsMultiply(root, 0x02);
  }
  return result;
}
function rsRemainder(data, divisor) {
  const result = new Uint8Array(divisor.length);
  for (const b of data) {
    const factor = b ^ result[0];
    result.copyWithin(0, 1);
    result[result.length - 1] = 0;
    for (let i = 0; i < result.length; i++) result[i] ^= rsMultiply(divisor[i], factor);
  }
  return result;
}

// --- bit buffer -------------------------------------------------------------------------
class BitBuffer {
  constructor() {
    this.bits = [];
  }
  append(val, len) {
    for (let i = len - 1; i >= 0; i--) this.bits.push((val >>> i) & 1);
  }
  get length() {
    return this.bits.length;
  }
}

/**
 * Encode `data` (Uint8Array) and return { size, modules: Array<Array<boolean>>, version }.
 * `forceMask` (0-7) overrides the automatic mask selection; used by the tests.
 */
export function encodeBytes(data, ecl = 'L', minVersion = 1, forceMask = null) {
  // pick the smallest version that fits
  let version = -1;
  for (let v = Math.max(1, minVersion); v <= 40; v++) {
    const capacityBits = numDataCodewords(v, ecl) * 8;
    const countBits = v <= 9 ? 8 : 16;
    if (4 + countBits + data.length * 8 <= capacityBits) {
      version = v;
      break;
    }
  }
  if (version < 0) throw new Error('data too long for a QR code');
  const capacityBits = numDataCodewords(version, ecl) * 8;

  const bb = new BitBuffer();
  bb.append(0x4, 4); // byte mode
  bb.append(data.length, version <= 9 ? 8 : 16);
  for (const b of data) bb.append(b, 8);
  bb.append(0, Math.min(4, capacityBits - bb.length)); // terminator
  bb.append(0, (8 - (bb.length % 8)) % 8);
  for (let pad = 0xec; bb.length < capacityBits; pad ^= 0xec ^ 0x11) bb.append(pad, 8);
  const dataCodewords = new Uint8Array(bb.length / 8);
  bb.bits.forEach((bit, i) => (dataCodewords[i >>> 3] |= bit << (7 - (i & 7))));

  const allCodewords = addEccAndInterleave(dataCodewords, version, ecl);
  const qr = new QrMatrix(version, ecl);
  qr.drawFunctionPatterns();
  qr.drawCodewords(allCodewords);
  if (forceMask === null) {
    qr.applyBestMask();
  } else {
    qr.applyMask(forceMask);
    qr.drawFormatBits(forceMask);
  }
  return { size: qr.size, modules: qr.modules, version };
}

function addEccAndInterleave(data, version, ecl) {
  const i = TABLE_INDEX[ecl];
  const numBlocks = NUM_ERROR_CORRECTION_BLOCKS[i][version];
  const blockEccLen = ECC_CODEWORDS_PER_BLOCK[i][version];
  const rawCodewords = Math.floor(numRawDataModules(version) / 8);
  const numShortBlocks = numBlocks - (rawCodewords % numBlocks);
  const shortBlockLen = Math.floor(rawCodewords / numBlocks);
  const blocks = [];
  const divisor = rsDivisor(blockEccLen);
  for (let b = 0, k = 0; b < numBlocks; b++) {
    const datLen = shortBlockLen - blockEccLen + (b < numShortBlocks ? 0 : 1);
    const dat = data.slice(k, k + datLen);
    k += datLen;
    const ecc = rsRemainder(dat, divisor);
    const block = new Uint8Array(shortBlockLen + 1);
    block.set(dat, 0);
    block.set(ecc, shortBlockLen + 1 - blockEccLen);
    blocks.push({ block, datLen });
  }
  const result = [];
  for (let col = 0; col < shortBlockLen + 1; col++) {
    blocks.forEach(({ block }, b) => {
      if (col !== shortBlockLen - blockEccLen || b >= numShortBlocks) result.push(block[col]);
    });
  }
  return Uint8Array.from(result);
}

class QrMatrix {
  constructor(version, ecl) {
    this.version = version;
    this.ecl = ecl;
    this.size = version * 4 + 17;
    this.modules = Array.from({ length: this.size }, () => new Array(this.size).fill(false));
    this.isFunction = Array.from({ length: this.size }, () => new Array(this.size).fill(false));
  }
  set(x, y, dark) {
    this.modules[y][x] = dark;
    this.isFunction[y][x] = true;
  }
  drawFunctionPatterns() {
    const n = this.size;
    for (let i = 0; i < n; i++) {
      this.set(6, i, i % 2 === 0);
      this.set(i, 6, i % 2 === 0);
    }
    this.drawFinder(3, 3);
    this.drawFinder(n - 4, 3);
    this.drawFinder(3, n - 4);
    const align = this.alignmentPositions();
    for (let i = 0; i < align.length; i++) {
      for (let j = 0; j < align.length; j++) {
        if ((i === 0 && j === 0) || (i === 0 && j === align.length - 1) || (i === align.length - 1 && j === 0)) continue;
        this.drawAlignment(align[i], align[j]);
      }
    }
    this.drawFormatBits(0);
    this.drawVersion();
  }
  drawFinder(cx, cy) {
    for (let dy = -4; dy <= 4; dy++) {
      for (let dx = -4; dx <= 4; dx++) {
        const dist = Math.max(Math.abs(dx), Math.abs(dy));
        const x = cx + dx;
        const y = cy + dy;
        if (x >= 0 && x < this.size && y >= 0 && y < this.size) this.set(x, y, dist !== 2 && dist !== 4);
      }
    }
  }
  drawAlignment(cx, cy) {
    for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) this.set(cx + dx, cy + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
  }
  alignmentPositions() {
    if (this.version === 1) return [];
    const numAlign = Math.floor(this.version / 7) + 2;
    const step = this.version === 32 ? 26 : Math.ceil((this.version * 4 + 4) / (numAlign * 2 - 2)) * 2;
    const result = [6];
    for (let pos = this.size - 7; result.length < numAlign; pos -= step) result.splice(1, 0, pos);
    return result;
  }
  drawFormatBits(mask) {
    const data = (ECC[this.ecl] << 3) | mask;
    let rem = data;
    for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
    const bits = ((data << 10) | rem) ^ 0x5412;
    const n = this.size;
    for (let i = 0; i <= 5; i++) this.set(8, i, ((bits >>> i) & 1) !== 0);
    this.set(8, 7, ((bits >>> 6) & 1) !== 0);
    this.set(8, 8, ((bits >>> 7) & 1) !== 0);
    this.set(7, 8, ((bits >>> 8) & 1) !== 0);
    for (let i = 9; i < 15; i++) this.set(14 - i, 8, ((bits >>> i) & 1) !== 0);
    for (let i = 0; i < 8; i++) this.set(n - 1 - i, 8, ((bits >>> i) & 1) !== 0);
    for (let i = 8; i < 15; i++) this.set(8, n - 15 + i, ((bits >>> i) & 1) !== 0);
    this.set(8, n - 8, true);
  }
  drawVersion() {
    if (this.version < 7) return;
    let rem = this.version;
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
    const bits = (this.version << 12) | rem;
    const n = this.size;
    for (let i = 0; i < 18; i++) {
      const bit = ((bits >>> i) & 1) !== 0;
      const a = n - 11 + (i % 3);
      const b = Math.floor(i / 3);
      this.set(a, b, bit);
      this.set(b, a, bit);
    }
  }
  drawCodewords(codewords) {
    const n = this.size;
    let i = 0;
    for (let right = n - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5;
      for (let vert = 0; vert < n; vert++) {
        for (let j = 0; j < 2; j++) {
          const x = right - j;
          const upward = ((right + 1) & 2) === 0;
          const y = upward ? n - 1 - vert : vert;
          if (!this.isFunction[y][x] && i < codewords.length * 8) {
            this.modules[y][x] = ((codewords[i >>> 3] >>> (7 - (i & 7))) & 1) !== 0;
            i++;
          }
        }
      }
    }
  }
  applyMask(mask) {
    const n = this.size;
    for (let y = 0; y < n; y++) {
      for (let x = 0; x < n; x++) {
        let invert;
        switch (mask) {
          case 0: invert = (x + y) % 2 === 0; break;
          case 1: invert = y % 2 === 0; break;
          case 2: invert = x % 3 === 0; break;
          case 3: invert = (x + y) % 3 === 0; break;
          case 4: invert = (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0; break;
          case 5: invert = ((x * y) % 2) + ((x * y) % 3) === 0; break;
          case 6: invert = (((x * y) % 2) + ((x * y) % 3)) % 2 === 0; break;
          default: invert = (((x + y) % 2) + ((x * y) % 3)) % 2 === 0; break;
        }
        if (!this.isFunction[y][x] && invert) this.modules[y][x] = !this.modules[y][x];
      }
    }
  }
  applyBestMask() {
    let best = 0;
    let bestPenalty = Infinity;
    for (let m = 0; m < 8; m++) {
      this.applyMask(m);
      this.drawFormatBits(m);
      const p = this.penalty();
      if (p < bestPenalty) {
        bestPenalty = p;
        best = m;
      }
      this.applyMask(m); // undo
    }
    this.applyMask(best);
    this.drawFormatBits(best);
  }
  penalty() {
    const n = this.size;
    const mod = this.modules;
    let result = 0;
    // adjacent runs in rows and columns
    for (let y = 0; y < n; y++) {
      let runColor = false;
      let runX = 0;
      const history = [0, 0, 0, 0, 0, 0, 0];
      for (let x = 0; x < n; x++) {
        if (mod[y][x] === runColor) {
          runX++;
          if (runX === 5) result += 3;
          else if (runX > 5) result++;
        } else {
          finderPenaltyAddHistory(runX, history, n);
          if (!runColor) result += finderPenaltyCount(history, n) * 40;
          runColor = mod[y][x];
          runX = 1;
        }
      }
      result += finderPenaltyTerminate(runColor, runX, history, n) * 40;
    }
    for (let x = 0; x < n; x++) {
      let runColor = false;
      let runY = 0;
      const history = [0, 0, 0, 0, 0, 0, 0];
      for (let y = 0; y < n; y++) {
        if (mod[y][x] === runColor) {
          runY++;
          if (runY === 5) result += 3;
          else if (runY > 5) result++;
        } else {
          finderPenaltyAddHistory(runY, history, n);
          if (!runColor) result += finderPenaltyCount(history, n) * 40;
          runColor = mod[y][x];
          runY = 1;
        }
      }
      result += finderPenaltyTerminate(runColor, runY, history, n) * 40;
    }
    // 2x2 blocks
    for (let y = 0; y < n - 1; y++) {
      for (let x = 0; x < n - 1; x++) {
        const c = mod[y][x];
        if (c === mod[y][x + 1] && c === mod[y + 1][x] && c === mod[y + 1][x + 1]) result += 3;
      }
    }
    // dark proportion
    let dark = 0;
    for (const row of mod) for (const c of row) if (c) dark++;
    const total = n * n;
    const k = Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1;
    result += k * 10;
    return result;
  }
}

function finderPenaltyCount(history, n) {
  const core = history[1] > 0 && history[2] === history[1] && history[3] === history[1] * 3 && history[4] === history[1] && history[5] === history[1];
  return (core && history[0] >= history[1] * 4 && history[6] >= history[1] ? 1 : 0) + (core && history[6] >= history[1] * 4 && history[0] >= history[1] ? 1 : 0);
}
function finderPenaltyAddHistory(currentRunLength, history, n) {
  if (history[0] === 0) currentRunLength += n;
  history.pop();
  history.unshift(currentRunLength);
}
function finderPenaltyTerminate(currentRunColor, currentRunLength, history, n) {
  if (currentRunColor) {
    finderPenaltyAddHistory(currentRunLength, history, n);
    currentRunLength = 0;
  }
  currentRunLength += n;
  finderPenaltyAddHistory(currentRunLength, history, n);
  return finderPenaltyCount(history, n);
}

/** Draw a QR code onto a canvas. */
export function drawToCanvas(canvas, data, { scale = 4, border = 4, ecl = 'L' } = {}) {
  const { size, modules } = encodeBytes(data, ecl);
  const px = (size + border * 2) * scale;
  canvas.width = px;
  canvas.height = px;
  const ctx = canvas.getContext('2d');
  ctx.fillStyle = '#fff';
  ctx.fillRect(0, 0, px, px);
  ctx.fillStyle = '#000';
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      if (modules[y][x]) ctx.fillRect((x + border) * scale, (y + border) * scale, scale, scale);
    }
  }
  return { size };
}
