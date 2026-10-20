// SPDX-License-Identifier: AGPL-3.0-only
// Independent Node.js RFC 8785 JCS implementation for WTP/0.1 RC2.
// Supports both default strict ASCII-key mode and `--unicode-keys` full RFC 8785 UTF-16 code-unit sorting.
const fs = require('node:fs');
const allowUnicodeKeys = process.argv.includes('--unicode-keys');

function cmpUtf16CodeUnits(a, b) {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const ca = a.charCodeAt(i);
    const cb = b.charCodeAt(i);
    if (ca !== cb) return ca - cb;
  }
  return a.length - b.length;
}

function hasUnpairedSurrogate(s) {
  return /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(s);
}

function canonical(o, depth = 0) {
  if (depth > 40) throw Error('nesting limit');
  if (o === null || typeof o === 'boolean') return JSON.stringify(o);
  if (typeof o === 'string') {
    if (hasUnpairedSurrogate(o)) throw Error('surrogate');
    return JSON.stringify(o);
  }
  if (typeof o === 'number') {
    if (!Number.isSafeInteger(o)) throw Error('non-safe integer');
    return JSON.stringify(o);
  }
  if (Array.isArray(o)) {
    return '[' + o.map(x => canonical(x, depth + 1)).join(',') + ']';
  }
  if (typeof o === 'object') {
    const ks = Object.keys(o).sort(cmpUtf16CodeUnits);
    for (const k of ks) {
      if (hasUnpairedSurrogate(k)) throw Error('surrogate in key');
      if (!allowUnicodeKeys && !/^[\x21-\x7e]+$/.test(k)) throw Error('non-ASCII key');
    }
    return '{' + ks.map(k => JSON.stringify(k) + ':' + canonical(o[k], depth + 1)).join(',') + '}';
  }
  throw Error('unsupported value');
}

process.stdout.write(canonical(JSON.parse(fs.readFileSync(0, 'utf8'))));
