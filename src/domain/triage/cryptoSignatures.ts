/**
 * Byte-level signatures for well-known cryptographic and hashing constants,
 * authored from public specifications. Each signature is a set of exact byte
 * sequences to search for in a file; a match is observed bytes, and the
 * attribution to an algorithm is an inference (constants are often shared and
 * their presence does not prove the algorithm is reachable or used).
 *
 * Specifications cited inline:
 * - AES S-box / inverse S-box / Rcon: FIPS 197.
 * - AES Te0/Td0 fast-implementation tables: Daemen & Rijmen, derived here from
 *   the S-box and the MixColumns matrix (Te0[0]=0xc66363a5, Td0[0]=0x51f4a750).
 * - MD5 T table and A/B/C/D init: RFC 1321 (T[i]=floor(2^32*|sin(i+1)|)).
 * - SHA-1 H and K: FIPS 180-4 section 5.3.1 / 6.1.
 * - SHA-256 H and K, SHA-512 H and K: FIPS 180-4 sections 5.3 / 4.2.
 * - CRC-32 reflected table and polynomials 0x04C11DB7 / 0xEDB88320: ITU-T V.42
 *   / zlib (reflected form used by zlib, PNG, gzip).
 * - DES S-boxes S1..S8: FIPS 46-3 appendix.
 * - Blowfish P-array (hex digits of pi): Schneier, "Description of a New
 *   Variable-Length Key, 64-Bit Block Cipher (Blowfish)".
 * - ChaCha/Salsa20 sigma/tau constants: Bernstein, "ChaCha, a variant of
 *   Salsa20" / "Salsa20 specification".
 * - TEA/XTEA delta 0x9E3779B9 and XXTEA 0x61C88647: Wheeler & Needham.
 * - FNV-1 primes and offset bases: IETF draft-eastlake-fnv.
 * - MurmurHash3 constants: Appleby, public domain reference.
 * - xxHash primes: Collet, public domain reference.
 * - DEFLATE length/distance base tables: RFC 1951.
 * - Base64 alphabet: RFC 4648 (standard and URL-safe).
 * - P-256 (secp256r1) and secp256k1 parameters: SEC 2 / NIST SP 800-186.
 * - Curve25519 field prime 2^255-19 and a24 constant 121665: RFC 7748.
 */

/** Family of constant a match belongs to. */
export type CryptoFindingKind =
  | "sbox"
  | "iv"
  | "round_constant"
  | "table"
  | "magic"
  | "curve_param";

/** One exact byte sequence to search for, tagged with its word byte order. */
export interface CryptoSignatureVariant {
  readonly byteOrder: "le" | "be" | "any";
  readonly bytes: Uint8Array;
}

/** A named constant with one or more byte encodings to look for. */
export interface CryptoSignature {
  readonly algorithm: string;
  readonly kind: CryptoFindingKind;
  readonly variants: readonly CryptoSignatureVariant[];
}

/** GF(2^8) multiply with the AES reduction polynomial 0x11b. */
const gmul = (a: number, b: number): number => {
  let product = 0;
  let left = a;
  let right = b;
  for (let bit = 0; bit < 8; bit += 1) {
    if ((right & 1) !== 0) product ^= left;
    const high = left & 0x80;
    left = (left << 1) & 0xff;
    if (high !== 0) left ^= 0x1b;
    right >>= 1;
  }
  return product;
};

/** AES forward S-box (FIPS 197, figure 7). */
// prettier-ignore
export const AES_SBOX: readonly number[] = [
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
];

const aesInverseSbox = (): number[] => {
  const inverse: number[] = Array.from({ length: 256 }, () => 0);
  for (let index = 0; index < 256; index += 1)
    inverse[AES_SBOX[index] as number] = index;
  return inverse;
};

/** AES round-key schedule constants Rcon[1..10] (FIPS 197). */
const AES_RCON: readonly number[] = [
  0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
];

const aesTe0 = (): number[] =>
  AES_SBOX.map(
    (value) =>
      ((gmul(value, 2) << 24) |
        (value << 16) |
        (value << 8) |
        gmul(value, 3)) >>>
      0,
  );

const aesTd0 = (): number[] => {
  const inverse = aesInverseSbox();
  return inverse.map(
    (value) =>
      ((gmul(value, 0x0e) << 24) |
        (gmul(value, 0x09) << 16) |
        (gmul(value, 0x0d) << 8) |
        gmul(value, 0x0b)) >>>
      0,
  );
};

const md5Table = (): number[] => {
  const table: number[] = Array.from({ length: 64 }, () => 0);
  for (let index = 0; index < 64; index += 1)
    table[index] = Math.floor(Math.abs(Math.sin(index + 1)) * 2 ** 32) >>> 0;
  return table;
};

const crc32ReflectedTable = (): number[] => {
  const table: number[] = Array.from({ length: 256 }, () => 0);
  for (let index = 0; index < 256; index += 1) {
    let crc = index;
    for (let bit = 0; bit < 8; bit += 1)
      crc = (crc & 1) !== 0 ? (crc >>> 1) ^ 0xedb88320 : crc >>> 1;
    table[index] = crc >>> 0;
  }
  return table;
};

/** DES S-boxes S1..S8 as the 4-bit outputs in row-major order (FIPS 46-3). */
// prettier-ignore
const DES_SBOXES: readonly number[] = [
  14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
  4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13,
  15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
  0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9,
  10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
  13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12,
  7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
  10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14,
  2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
  4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3,
  12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
  9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13,
  4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
  1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12,
  13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
  7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11,
];

/** Blowfish P-array: first 18 fractional hex digits of pi (Schneier). */
const BLOWFISH_P: readonly number[] = [
  0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093822, 0x299f31d0,
  0x082efa98, 0xec4e6c89, 0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
  0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917, 0x9216d5d9, 0x8979fb1b,
];

/** DEFLATE length base values (RFC 1951, 3.2.5), 257..285. */
const DEFLATE_LENGTH_BASE: readonly number[] = [
  3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67,
  83, 99, 115, 131, 163, 195, 227, 258,
];

/** DEFLATE distance base values (RFC 1951, 3.2.5). */
const DEFLATE_DISTANCE_BASE: readonly number[] = [
  1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769,
  1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];

/** Standard Base64 alphabet (RFC 4648 §4). Exported for the custom-alphabet heuristic. */
export const BASE64_STD_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
/** URL- and filename-safe Base64 alphabet (RFC 4648 §5). */
export const BASE64_URL_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

const pack32 = (words: readonly number[], little: boolean): Uint8Array => {
  const bytes = Buffer.alloc(words.length * 4);
  words.forEach((word, index) =>
    little
      ? bytes.writeUInt32LE(word >>> 0, index * 4)
      : bytes.writeUInt32BE(word >>> 0, index * 4),
  );
  return bytes;
};

const pack16 = (words: readonly number[], little: boolean): Uint8Array => {
  const bytes = Buffer.alloc(words.length * 2);
  words.forEach((word, index) =>
    little
      ? bytes.writeUInt16LE(word & 0xffff, index * 2)
      : bytes.writeUInt16BE(word & 0xffff, index * 2),
  );
  return bytes;
};

const pack64 = (words: readonly bigint[], little: boolean): Uint8Array => {
  const bytes = Buffer.alloc(words.length * 8);
  words.forEach((word, index) =>
    little
      ? bytes.writeBigUInt64LE(word, index * 8)
      : bytes.writeBigUInt64BE(word, index * 8),
  );
  return bytes;
};

const wordVariants = (words: readonly number[]): CryptoSignatureVariant[] => [
  { byteOrder: "le", bytes: pack32(words, true) },
  { byteOrder: "be", bytes: pack32(words, false) },
];

const halfWordVariants = (
  words: readonly number[],
): CryptoSignatureVariant[] => [
  { byteOrder: "le", bytes: pack16(words, true) },
  { byteOrder: "be", bytes: pack16(words, false) },
];

const quadWordVariants = (
  words: readonly bigint[],
): CryptoSignatureVariant[] => [
  { byteOrder: "le", bytes: pack64(words, true) },
  { byteOrder: "be", bytes: pack64(words, false) },
];

const byteVariant = (bytes: Uint8Array): CryptoSignatureVariant[] => [
  { byteOrder: "any", bytes },
];

const asciiVariant = (text: string): CryptoSignatureVariant[] =>
  byteVariant(Buffer.from(text, "latin1"));

/** Big-endian hex integer, searched in both byte orders. */
const bigIntVariants = (hex: string): CryptoSignatureVariant[] => {
  const be = Buffer.from(hex, "hex");
  const le = Buffer.from(be).reverse();
  return [
    { byteOrder: "be", bytes: be },
    { byteOrder: "le", bytes: le },
  ];
};

const SHA1_H: readonly number[] = [
  0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0,
];
const SHA1_K: readonly number[] = [
  0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6,
];
const SHA256_H: readonly number[] = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
  0x1f83d9ab, 0x5be0cd19,
];
/** First eight SHA-256 round constants; a prefix anchor matches the full 64. */
const SHA256_K8: readonly number[] = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
  0x923f82a4, 0xab1c5ed5,
];
const SHA512_H: readonly bigint[] = [
  0x6a09e667f3bcc908n,
  0xbb67ae8584caa73bn,
  0x3c6ef372fe94f82bn,
  0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n,
  0x9b05688c2b3e6c1fn,
  0x1f83d9abfb41bd6bn,
  0x5be0cd19137e2179n,
];
/** First eight SHA-512 round constants; a prefix anchor matches the full 80. */
const SHA512_K8: readonly bigint[] = [
  0x428a2f98d728ae22n,
  0x7137449123ef65cdn,
  0xb5c0fbcfec4d3b2fn,
  0xe9b5dba58189dbbcn,
  0x3956c25bf348b538n,
  0x59f111f1b605d019n,
  0x923f82a4af194f9bn,
  0xab1c5ed5da6d8118n,
];
const MD5_INIT: readonly number[] = [
  0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476,
];

/** Complete signature set, built once at module load from the constants above. */
export const CRYPTO_SIGNATURES: readonly CryptoSignature[] = [
  {
    algorithm: "AES",
    kind: "sbox",
    variants: byteVariant(Buffer.from(AES_SBOX)),
  },
  {
    algorithm: "AES (inverse S-box)",
    kind: "sbox",
    variants: byteVariant(Buffer.from(aesInverseSbox())),
  },
  {
    algorithm: "AES (Te0 table)",
    kind: "table",
    variants: wordVariants(aesTe0()),
  },
  {
    algorithm: "AES (Td0 table)",
    kind: "table",
    variants: wordVariants(aesTd0()),
  },
  {
    algorithm: "AES (Rcon)",
    kind: "round_constant",
    variants: byteVariant(Buffer.from(AES_RCON)),
  },
  {
    algorithm: "MD5 (T table)",
    kind: "table",
    variants: wordVariants(md5Table()),
  },
  { algorithm: "MD5 (init)", kind: "iv", variants: wordVariants(MD5_INIT) },
  { algorithm: "SHA-1 (init)", kind: "iv", variants: wordVariants(SHA1_H) },
  {
    algorithm: "SHA-1 (round constants)",
    kind: "round_constant",
    variants: wordVariants(SHA1_K),
  },
  { algorithm: "SHA-256 (init)", kind: "iv", variants: wordVariants(SHA256_H) },
  {
    algorithm: "SHA-256 (round constants K)",
    kind: "round_constant",
    variants: wordVariants(SHA256_K8),
  },
  {
    algorithm: "SHA-512/384 (init)",
    kind: "iv",
    variants: quadWordVariants(SHA512_H),
  },
  {
    algorithm: "SHA-512/384 (round constants K)",
    kind: "round_constant",
    variants: quadWordVariants(SHA512_K8),
  },
  {
    algorithm: "CRC-32 (reflected table)",
    kind: "table",
    variants: wordVariants(crc32ReflectedTable()),
  },
  {
    algorithm: "CRC-32 (polynomial 0xEDB88320)",
    kind: "magic",
    variants: wordVariants([0xedb88320]),
  },
  {
    algorithm: "CRC-32 (polynomial 0x04C11DB7)",
    kind: "magic",
    variants: wordVariants([0x04c11db7]),
  },
  {
    algorithm: "DES (S-boxes)",
    kind: "sbox",
    variants: byteVariant(Buffer.from(DES_SBOXES)),
  },
  {
    algorithm: "Blowfish (P-array)",
    kind: "table",
    variants: wordVariants(BLOWFISH_P),
  },
  {
    algorithm: "ChaCha/Salsa20 (sigma)",
    kind: "magic",
    variants: asciiVariant("expand 32-byte k"),
  },
  {
    algorithm: "ChaCha/Salsa20 (tau)",
    kind: "magic",
    variants: asciiVariant("expand 16-byte k"),
  },
  {
    algorithm: "TEA/XTEA (delta 0x9E3779B9)",
    kind: "magic",
    variants: wordVariants([0x9e3779b9]),
  },
  {
    algorithm: "XXTEA (0x61C88647)",
    kind: "magic",
    variants: wordVariants([0x61c88647]),
  },
  {
    algorithm: "FNV-1 32-bit (prime/offset)",
    kind: "magic",
    variants: wordVariants([0x01000193, 0x811c9dc5]),
  },
  {
    algorithm: "FNV-1 64-bit (prime)",
    kind: "magic",
    variants: quadWordVariants([0x00000100000001b3n]),
  },
  {
    algorithm: "FNV-1 64-bit (offset basis)",
    kind: "magic",
    variants: quadWordVariants([0xcbf29ce484222325n]),
  },
  {
    algorithm: "MurmurHash3 (c1/c2)",
    kind: "magic",
    variants: wordVariants([0xcc9e2d51, 0x1b873593]),
  },
  {
    algorithm: "xxHash (PRIME64_1)",
    kind: "magic",
    variants: quadWordVariants([0x9e3779b185ebca87n]),
  },
  {
    algorithm: "xxHash (PRIME64_2)",
    kind: "magic",
    variants: quadWordVariants([0xc2b2ae3d27d4eb4fn]),
  },
  {
    algorithm: "DEFLATE (length base table)",
    kind: "table",
    variants: halfWordVariants(DEFLATE_LENGTH_BASE),
  },
  {
    algorithm: "DEFLATE (distance base table)",
    kind: "table",
    variants: halfWordVariants(DEFLATE_DISTANCE_BASE),
  },
  {
    algorithm: "Base64 (standard alphabet)",
    kind: "table",
    variants: asciiVariant(BASE64_STD_ALPHABET),
  },
  {
    algorithm: "Base64 (URL-safe alphabet)",
    kind: "table",
    variants: asciiVariant(BASE64_URL_ALPHABET),
  },
  {
    algorithm: "NIST P-256 (field prime)",
    kind: "curve_param",
    variants: bigIntVariants(
      "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    ),
  },
  {
    algorithm: "NIST P-256 (coefficient b)",
    kind: "curve_param",
    variants: bigIntVariants(
      "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
    ),
  },
  {
    algorithm: "NIST P-256 (base point Gx)",
    kind: "curve_param",
    variants: bigIntVariants(
      "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    ),
  },
  {
    algorithm: "secp256k1 (field prime)",
    kind: "curve_param",
    variants: bigIntVariants(
      "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
    ),
  },
  {
    algorithm: "secp256k1 (base point Gx)",
    kind: "curve_param",
    variants: bigIntVariants(
      "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    ),
  },
  {
    algorithm: "secp256k1 (group order n)",
    kind: "curve_param",
    variants: bigIntVariants(
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
    ),
  },
  {
    algorithm: "Curve25519 (field prime 2^255-19)",
    kind: "curve_param",
    variants: bigIntVariants(
      "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed",
    ),
  },
  {
    algorithm: "Curve25519 (a24 constant 121665)",
    kind: "curve_param",
    variants: wordVariants([0x0001db41]),
  },
];
