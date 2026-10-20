// SPDX-License-Identifier: AGPL-3.0-only
// Independent Node.js RFC 8949 §4.2.1 Deterministic CBOR (dCBOR) encoder & Ed25519 verifier for Wutong Protocol v0.1.0.
const fs = require('node:fs');
const crypto = require('node:crypto');

function encodeHead(major, arg) {
  const mt = major << 5;
  if (arg < 24) return Buffer.from([mt | arg]);
  if (arg <= 0xff) return Buffer.from([mt | 24, arg]);
  if (arg <= 0xffff) {
    const b = Buffer.alloc(3);
    b[0] = mt | 25;
    b.writeUInt16BE(arg, 1);
    return b;
  }
  if (arg <= 0xffffffff) {
    const b = Buffer.alloc(5);
    b[0] = mt | 26;
    b.writeUInt32BE(arg >>> 0, 1);
    return b;
  }
  const b = Buffer.alloc(9);
  b[0] = mt | 27;
  b.writeBigUInt64BE(BigInt(arg), 1);
  return b;
}

function encodeDcbor(o, depth = 0) {
  if (depth > 40) throw Error('nesting limit');
  if (o === null) return Buffer.from([0xf6]);
  if (o === false) return Buffer.from([0xf4]);
  if (o === true) return Buffer.from([0xf5]);
  if (typeof o === 'number') {
    if (!Number.isSafeInteger(o)) throw Error('non-safe integer');
    if (o >= 0) return encodeHead(0, o);
    return encodeHead(1, -1 - o);
  }
  if (typeof o === 'string') {
    const raw = Buffer.from(o, 'utf8');
    return Buffer.concat([encodeHead(3, raw.length), raw]);
  }
  if (Array.isArray(o)) {
    return Buffer.concat([encodeHead(4, o.length), ...o.map(x => encodeDcbor(x, depth + 1))]);
  }
  if (typeof o === 'object') {
    const pairs = Object.keys(o).map(k => ({
      ek: encodeDcbor(k, depth + 1),
      ev: encodeDcbor(o[k], depth + 1),
    }));
    pairs.sort((a, b) => Buffer.compare(a.ek, b.ek));
    const chunks = [encodeHead(5, pairs.length)];
    for (const p of pairs) {
      chunks.push(p.ek, p.ev);
    }
    return Buffer.concat(chunks);
  }
  throw Error('unsupported value');
}

const input = JSON.parse(fs.readFileSync(0, 'utf8'));
if (process.argv.includes('--verify-seed0')) {
  const sig = Buffer.from(input.proof.sig, 'base64url');
  const copy = { ...input };
  delete copy.proof;
  const seed = Buffer.from([...Array(32).keys()]);
  const priv = crypto.createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]),
    format: 'der',
    type: 'pkcs8',
  });
  const ok = crypto.verify(
    null,
    Buffer.concat([Buffer.from('WUTONG-CBOR-SIG-V0.1\0'), encodeDcbor(copy)]),
    crypto.createPublicKey(priv),
    sig
  );
  process.stdout.write(ok ? 'OK' : 'FAIL');
} else {
  process.stdout.write(encodeDcbor(input).toString('hex'));
}
