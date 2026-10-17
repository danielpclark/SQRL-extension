// Verifies extension/js/qr.js by decoding its output with an independent decoder (zxing-cpp)
// for many payload sizes, error-correction levels and masks.
//
//   python3 -m pip install zxing-cpp numpy
//   node tests/qr-check.mjs
import { encodeBytes } from '../extension/js/qr.js';
import { spawnSync } from 'node:child_process';

const py = `
import sys, json, numpy as np, zxingcpp
cases = json.loads(sys.stdin.read())
out = []
for m in cases:
    n = len(m); scale = 4; border = 4
    img = np.full(((n + 2 * border) * scale, (n + 2 * border) * scale), 255, dtype=np.uint8)
    for y in range(n):
        row = m[y]
        for x in range(n):
            if row[x]:
                img[(y + border) * scale:(y + border + 1) * scale, (x + border) * scale:(x + border + 1) * scale] = 0
    res = zxingcpp.read_barcodes(img)
    out.append(list(res[0].bytes) if res else None)
print(json.dumps(out))
`;

let seed = 12345;
const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) & 0xff;
const cases = [];
for (const len of [1, 17, 18, 60, 206, 334, 640, 1200]) {
  for (const ecl of ['L', 'M', 'Q', 'H']) {
    for (const mask of [null, 0, 5]) {
      const data = Array.from({ length: len }, rnd);
      const { modules } = encodeBytes(Uint8Array.from(data), ecl, 1, mask);
      cases.push({ data, ecl, mask, modules: modules.map((r) => r.map((v) => (v ? 1 : 0))) });
    }
  }
}
const res = spawnSync('python3', ['-c', py], { input: JSON.stringify(cases.map((c) => c.modules)), maxBuffer: 1 << 28 });
if (res.status !== 0) {
  console.error(res.stderr.toString());
  process.exit(1);
}
const decoded = JSON.parse(res.stdout.toString());
let failures = 0;
cases.forEach((c, i) => {
  const ok = decoded[i] && decoded[i].length === c.data.length && decoded[i].every((b, k) => b === c.data[k]);
  if (!ok) {
    failures++;
    console.log(`FAIL len=${c.data.length} ecl=${c.ecl} mask=${c.mask === null ? 'auto' : c.mask}: ${decoded[i] ? 'decoded to different bytes' : 'not decodable'}`);
  }
});
console.log(failures ? `${failures} failures` : `qr.js: all ${cases.length} codes decode correctly`);
process.exit(failures ? 1 : 0);
