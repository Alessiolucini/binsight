/**
 * Clean-room TLSH (Trend Micro Locality Sensitive Hash) over a whole buffer,
 * reconstructed from the published whitepaper and the documented reference
 * algorithm (sliding 5-byte window, Pearson bucket mapping, quartile coding).
 * No third-party TLSH code is used. The output matches the reference "T1"
 * 72-character digest, or null when the input is too short or too uniform to
 * produce a defined hash (the reference "TNULL" case).
 */

/** Fixed Pearson permutation table used by the TLSH bucket mapping. */
// prettier-ignore
const V_TABLE = Uint8Array.from([
  1, 87, 49, 12, 176, 178, 102, 166, 121, 193, 6, 84, 249, 230, 44, 163,
  14, 197, 213, 181, 161, 85, 218, 80, 64, 239, 24, 226, 236, 142, 38, 200,
  110, 177, 104, 103, 141, 253, 255, 50, 77, 101, 81, 18, 45, 96, 31, 222,
  25, 107, 190, 70, 86, 237, 240, 34, 72, 242, 20, 214, 244, 227, 149, 235,
  97, 234, 57, 22, 60, 250, 82, 175, 208, 5, 127, 199, 111, 62, 135, 248,
  174, 169, 211, 58, 66, 154, 106, 195, 245, 171, 17, 187, 182, 179, 0, 243,
  132, 56, 148, 75, 128, 133, 158, 100, 130, 126, 91, 13, 153, 246, 216, 219,
  119, 68, 223, 78, 83, 88, 201, 99, 122, 11, 92, 32, 136, 114, 52, 10,
  138, 30, 48, 183, 156, 35, 61, 26, 143, 74, 251, 94, 129, 162, 63, 152,
  170, 7, 115, 167, 241, 206, 3, 150, 55, 59, 151, 220, 90, 53, 23, 131,
  125, 173, 15, 238, 79, 95, 89, 16, 105, 137, 225, 224, 217, 160, 37, 123,
  118, 73, 2, 157, 46, 116, 9, 145, 134, 228, 207, 212, 202, 215, 69, 229,
  27, 188, 67, 124, 168, 252, 42, 4, 29, 108, 21, 247, 19, 205, 39, 203,
  233, 40, 186, 147, 198, 192, 155, 33, 164, 191, 98, 204, 165, 180, 117, 76,
  140, 36, 210, 172, 41, 54, 159, 8, 185, 232, 113, 196, 231, 47, 146, 120,
  51, 65, 28, 144, 254, 221, 93, 189, 194, 139, 112, 43, 71, 109, 184, 209,
]);

/** Smallest input the reference algorithm accepts before returning a digest. */
export const TLSH_MIN_DATA_LENGTH = 50;

const EFF_BUCKETS = 128;
const CODE_SIZE = 32;
const WINDOW = 5;

const LOG_1_5 = Math.log(1.5);
const LOG_1_3 = Math.log(1.3);
const LOG_1_1 = Math.log(1.1);

const bMapping = (salt: number, a: number, b: number, c: number): number => {
  let h = V_TABLE[salt] as number;
  h = V_TABLE[h ^ a] as number;
  h = V_TABLE[h ^ b] as number;
  h = V_TABLE[h ^ c] as number;
  return h;
};

/** Reference length bucket: a logarithmic encoding capped at one byte. */
const lCapturing = (length: number): number => {
  let value: number;
  if (length <= 656) value = Math.floor(Math.log(length) / LOG_1_5);
  else if (length <= 3199)
    value = Math.floor(Math.log(length) / LOG_1_3 - 8.727_77);
  else value = Math.floor(Math.log(length) / LOG_1_1 - 62.547_2);
  return value > 255 ? 255 : value & 0xff;
};

const swapNibbles = (byte: number): number =>
  ((byte & 0x0f) << 4) | ((byte & 0xf0) >> 4);

const hex2 = (byte: number): string =>
  byte.toString(16).padStart(2, "0").toUpperCase();

interface Digest {
  readonly checksum: number;
  readonly length: number;
  readonly q1: number;
  readonly q2: number;
  readonly q3: number;
  readonly code: Uint8Array;
}

const populateBuckets = (
  bytes: Buffer,
): { readonly buckets: Uint32Array; readonly checksum: number } => {
  const buckets = new Uint32Array(256);
  const window = new Uint8Array(WINDOW);
  const bump = (index: number): void => {
    buckets[index] = (buckets[index] as number) + 1;
  };
  let checksum = 0;
  let position = 0;
  for (let index = 0; index < bytes.length; index += 1) {
    window[position] = bytes[index] as number;
    if (index >= WINDOW - 1) {
      const w0 = window[position] as number;
      const w1 = window[(position + 4) % WINDOW] as number;
      const w2 = window[(position + 3) % WINDOW] as number;
      const w3 = window[(position + 2) % WINDOW] as number;
      const w4 = window[(position + 1) % WINDOW] as number;
      checksum = bMapping(0, w0, w1, checksum);
      bump(bMapping(2, w0, w1, w2));
      bump(bMapping(3, w0, w1, w3));
      bump(bMapping(5, w0, w2, w3));
      bump(bMapping(7, w0, w2, w4));
      bump(bMapping(11, w0, w1, w4));
      bump(bMapping(13, w0, w3, w4));
    }
    position = (position + 1) % WINDOW;
  }
  return { buckets, checksum };
};

const quartiles = (
  buckets: Uint32Array,
): { readonly q1: number; readonly q2: number; readonly q3: number } => {
  const sorted = Array.from(buckets.subarray(0, EFF_BUCKETS)).sort(
    (left, right) => left - right,
  );
  return {
    q1: sorted[EFF_BUCKETS / 4 - 1] as number,
    q2: sorted[EFF_BUCKETS / 2 - 1] as number,
    q3: sorted[EFF_BUCKETS - EFF_BUCKETS / 4 - 1] as number,
  };
};

const encodeBody = (
  buckets: Uint32Array,
  q1: number,
  q2: number,
  q3: number,
): Uint8Array => {
  const code = new Uint8Array(CODE_SIZE);
  for (let i = 0; i < CODE_SIZE; i += 1) {
    let byte = 0;
    for (let k = 0; k < 4; k += 1) {
      const count = buckets[4 * i + k] as number;
      if (q3 < count) byte += 3 << (k * 2);
      else if (q2 < count) byte += 2 << (k * 2);
      else if (q1 < count) byte += 1 << (k * 2);
    }
    code[i] = byte;
  }
  return code;
};

const computeDigest = (bytes: Buffer): Digest | null => {
  if (bytes.length < TLSH_MIN_DATA_LENGTH) return null;
  const { buckets, checksum } = populateBuckets(bytes);
  const { q1, q2, q3 } = quartiles(buckets);
  if (q3 === 0) return null;
  return {
    checksum,
    length: lCapturing(bytes.length),
    q1,
    q2,
    q3,
    code: encodeBody(buckets, q1, q2, q3),
  };
};

const serialize = (digest: Digest): string => {
  const q1ratio = Math.trunc((digest.q1 * 100) / digest.q3) % 16;
  const q2ratio = Math.trunc((digest.q2 * 100) / digest.q3) % 16;
  const q = (q2ratio << 4) | q1ratio;
  let out = "T1";
  out += hex2(swapNibbles(digest.checksum));
  out += hex2(swapNibbles(digest.length));
  out += hex2(swapNibbles(q));
  for (let i = 0; i < CODE_SIZE; i += 1)
    out += hex2(digest.code[CODE_SIZE - 1 - i] as number);
  return out;
};

/** TLSH digest of the whole buffer, or null for too-short or too-uniform data. */
export const tlshHash = (bytes: Buffer): string | null => {
  const digest = computeDigest(bytes);
  return digest === null ? null : serialize(digest);
};
