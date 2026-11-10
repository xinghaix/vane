import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';

const distDir = path.resolve('dist');
const exts = new Set(['.html', '.js', '.css', '.svg', '.json', '.webmanifest']);

function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(full);
    } else if (exts.has(path.extname(entry.name))) {
      const raw = fs.readFileSync(full);
      const br = zlib.brotliCompressSync(raw, {
        params: { [zlib.constants.BROTLI_PARAM_QUALITY]: 11 }
      });
      const gz = zlib.gzipSync(raw, { level: 9 });
      fs.writeFileSync(full + '.br', br);
      fs.writeFileSync(full + '.gz', gz);
    }
  }
}

walk(distDir);
console.log('Pre-compressed dist assets (.br and .gz) successfully.');
