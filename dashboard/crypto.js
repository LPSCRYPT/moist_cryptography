import { permute } from "https://esm.sh/@zkpassport/poseidon2@0.6.2";

export const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export const GRUMPKIN_ORDER = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
export const G = [1n, 17631683881184975370165255887551781615748388533673675138860n];
export const KDF_DOMAIN_V2 = 0x4d4f495354_4b44465632n;
export const KDF_ROLE_PLAINTEXT = 1n;
export const PLAINTEXT_FIELDS = 39;

export function hexToBigInt(v) {
  if (typeof v === "bigint") return v;
  if (!v) return 0n;
  return BigInt(v.startsWith("0x") ? v : `0x${v}`);
}

export function bigIntToHex(v) {
  return `0x${(v % P).toString(16).padStart(64, "0")}`;
}

function mod(v, m = P) {
  const r = v % m;
  return r >= 0n ? r : r + m;
}

function inv(a) {
  return modPow(mod(a), P - 2n, P);
}

function modPow(base, exp, m) {
  let b = mod(base, m);
  let e = exp;
  let out = 1n;
  while (e > 0n) {
    if (e & 1n) out = (out * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return out;
}

export function isOnGrumpkin(point) {
  if (!point) return false;
  const [x, y] = point;
  if (x === 0n && y === 0n) return false;
  if (x >= P || y >= P || x < 0n || y < 0n) return false;
  return mod(y * y) === mod(x * x * x - 17n);
}

export function ecAdd(p1, p2) {
  if (p1 == null) return p2;
  if (p2 == null) return p1;
  const [x1, y1] = p1;
  const [x2, y2] = p2;
  let lambda;
  if (x1 === x2) {
    if (y1 !== y2) return null;
    lambda = mod(3n * x1 * x1 * inv(2n * y1));
  } else {
    lambda = mod((y2 - y1) * inv(x2 - x1));
  }
  const x3 = mod(lambda * lambda - x1 - x2);
  const y3 = mod(lambda * (x1 - x3) - y1);
  return [x3, y3];
}

export function ecMul(point, scalar) {
  let result = null;
  let addend = point;
  let s = mod(scalar, GRUMPKIN_ORDER);
  while (s > 0n) {
    if (s & 1n) result = ecAdd(result, addend);
    addend = ecAdd(addend, addend);
    s >>= 1n;
  }
  return result;
}

export function poseidon2Perm(a, b, c, d) {
  const out = permute([mod(a), mod(b), mod(c), mod(d)]);
  if (!Array.isArray(out) || out.length !== 4) throw new Error("Poseidon2 permute returned an unexpected shape");
  return out.map((v) => mod(BigInt(v)));
}

export function kdf(role, sharedX, sharedY) {
  return poseidon2Perm(KDF_DOMAIN_V2, role, sharedX, sharedY)[0];
}

export function keystream39(k) {
  const out = new Array(PLAINTEXT_FIELDS);
  for (let b = 0; b < 13; b++) {
    const block = poseidon2Perm(k, BigInt(b), 0n, 0n);
    out[b * 3] = block[0];
    out[b * 3 + 1] = block[1];
    out[b * 3 + 2] = block[2];
  }
  return out;
}

export function decryptSlot(c1X, c1Y, c2Fields, ownerSk) {
  const c1 = [hexToBigInt(c1X), hexToBigInt(c1Y)];
  if (!isOnGrumpkin(c1)) throw new Error("c1 is not a Grumpkin point");
  const shared = ecMul(c1, hexToBigInt(ownerSk));
  if (!shared) throw new Error("sk*c1 yielded identity");
  const key = kdf(KDF_ROLE_PLAINTEXT, shared[0], shared[1]);
  const ks = keystream39(key);
  const fields = c2Fields.map((c, i) => mod(hexToBigInt(c) - ks[i]));
  return { fields, key };
}

export function bytesHexToFields(hex) {
  const raw = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (raw.length % 64 !== 0) throw new Error(`field byte length is not multiple of 32: ${raw.length / 2}`);
  const fields = [];
  for (let i = 0; i < raw.length; i += 64) fields.push(`0x${raw.slice(i, i + 64)}`);
  return fields;
}

export function decodePlaintext(fields) {
  if (fields.length !== PLAINTEXT_FIELDS) throw new Error(`expected ${PLAINTEXT_FIELDS} fields`);
  const bytes = new Uint8Array(PLAINTEXT_FIELDS * 31);
  fields.forEach((field, fieldIdx) => {
    let v = typeof field === "bigint" ? field : hexToBigInt(field);
    for (let i = 0; i < 31; i++) {
      bytes[fieldIdx * 31 + i] = Number(v & 0xffn);
      v >>= 8n;
    }
  });
  const pose = readLe(bytes, 0, 8);
  const w = bytes[8];
  const h = bytes[9];
  const indices = [];
  for (let i = 0; i < w * h; i++) {
    const b = bytes[10 + Math.floor(i / 2)];
    indices.push(i & 1 ? (b >> 4) & 0xf : b & 0xf);
  }
  return { pose, ...decodePose(pose), w, h, indices };
}

function readLe(bytes, offset, len) {
  let out = 0n;
  for (let i = len - 1; i >= 0; i--) out = (out << 8n) + BigInt(bytes[offset + i]);
  return out;
}

export function decodePose(pose) {
  const p = typeof pose === "bigint" ? pose : BigInt(pose);
  if (p >> 30n) throw new Error(`pose reserved bits set: 0x${p.toString(16)}`);
  return {
    x: Number(p & 0x3fn),
    y: Number((p >> 6n) & 0x3fn),
    scaleQ88: Number((p >> 12n) & 0xffffn),
    quarterTurns: Number((p >> 28n) & 0x03n),
  };
}
