import type { StringEncoding } from "../domain/triage/extractBinaryStrings.js";

/**
 * Printable-run recovery over raw bytes, one encoding at a time. Each scanner
 * is a synchronous generator so the caller can interleave cooperative yields
 * and stop early; nothing is retained across runs.
 */

/** Longest text emitted for a single run; longer runs keep their true length but capped text. */
export const MAX_STRING_CHARS = 8192;

/** One recovered printable run and where it begins in the file. */
export interface RawRun {
  readonly encoding: StringEncoding;
  readonly file_offset: number;
  readonly text: string;
  /** Printable character count, which may exceed `text.length` when the text was capped. */
  readonly length: number;
}

// Printable set matches the de facto `strings` convention: graphic ASCII,
// space, and the horizontal tab (0x09). Other control bytes break a run.
const isPrintableByte = (byte: number): boolean =>
  byte === 0x09 || (byte >= 0x20 && byte <= 0x7e);

/** Single-byte printable runs (0x20..0x7e). */
export function* scanAscii(
  bytes: Buffer,
  minLength: number,
): Generator<RawRun> {
  let start = -1;
  let count = 0;
  for (let index = 0; index <= bytes.length; index += 1) {
    const printable = index < bytes.length && isPrintableByte(bytes[index]!);
    if (printable) {
      if (start < 0) {
        start = index;
        count = 0;
      }
      count += 1;
    } else if (start >= 0) {
      if (count >= minLength) {
        const end = start + Math.min(count, MAX_STRING_CHARS);
        yield {
          encoding: "ascii",
          file_offset: start,
          text: bytes.toString("latin1", start, end),
          length: count,
        };
      }
      start = -1;
      count = 0;
    }
  }
}

/** UTF-16LE printable runs: each unit is a printable byte followed by 0x00. */
export function* scanUtf16le(
  bytes: Buffer,
  minLength: number,
): Generator<RawRun> {
  let start = -1;
  let count = 0;
  let index = 0;
  const flush = (): RawRun | null => {
    if (start >= 0 && count >= minLength) {
      const end = start + 2 * Math.min(count, MAX_STRING_CHARS);
      return {
        encoding: "utf16le",
        file_offset: start,
        text: bytes.toString("utf16le", start, end),
        length: count,
      };
    }
    return null;
  };
  while (index + 1 < bytes.length) {
    if (bytes[index + 1] === 0 && isPrintableByte(bytes[index]!)) {
      if (start < 0) {
        start = index;
        count = 0;
      }
      count += 1;
      index += 2;
    } else {
      const run = flush();
      if (run !== null) yield run;
      start = -1;
      count = 0;
      index += 1;
    }
  }
  const tail = flush();
  if (tail !== null) yield tail;
}

interface DecodedCodePoint {
  readonly cp: number;
  readonly size: number;
}

/** A trailing continuation byte (0x80..0xbf), or null when absent or out of range. */
const continuationByte = (bytes: Buffer, at: number): number | null => {
  const value = bytes[at];
  return value !== undefined && value >= 0x80 && value <= 0xbf ? value : null;
};

const decodeTwoByte = (
  bytes: Buffer,
  index: number,
  b0: number,
): DecodedCodePoint | null => {
  const c1 = continuationByte(bytes, index + 1);
  return c1 === null ? null : { cp: ((b0 & 0x1f) << 6) | (c1 & 0x3f), size: 2 };
};

const decodeThreeByte = (
  bytes: Buffer,
  index: number,
  b0: number,
): DecodedCodePoint | null => {
  const c1 = continuationByte(bytes, index + 1);
  const c2 = continuationByte(bytes, index + 2);
  if (c1 === null || c2 === null) return null;
  if ((b0 === 0xe0 && c1 < 0xa0) || (b0 === 0xed && c1 > 0x9f)) return null;
  return {
    cp: ((b0 & 0x0f) << 12) | ((c1 & 0x3f) << 6) | (c2 & 0x3f),
    size: 3,
  };
};

const decodeFourByte = (
  bytes: Buffer,
  index: number,
  b0: number,
): DecodedCodePoint | null => {
  const c1 = continuationByte(bytes, index + 1);
  const c2 = continuationByte(bytes, index + 2);
  const c3 = continuationByte(bytes, index + 3);
  if (c1 === null || c2 === null || c3 === null) return null;
  if ((b0 === 0xf0 && c1 < 0x90) || (b0 === 0xf4 && c1 > 0x8f)) return null;
  return {
    cp:
      ((b0 & 0x07) << 18) |
      ((c1 & 0x3f) << 12) |
      ((c2 & 0x3f) << 6) |
      (c3 & 0x3f),
    size: 4,
  };
};

/** Decoded code point and its byte width, or null for an invalid or overlong sequence. */
const decodeUtf8 = (bytes: Buffer, index: number): DecodedCodePoint | null => {
  const b0 = bytes[index]!;
  if (b0 < 0x80) return { cp: b0, size: 1 };
  if (b0 >= 0xc2 && b0 <= 0xdf) return decodeTwoByte(bytes, index, b0);
  if (b0 >= 0xe0 && b0 <= 0xef) return decodeThreeByte(bytes, index, b0);
  if (b0 >= 0xf0 && b0 <= 0xf4) return decodeFourByte(bytes, index, b0);
  return null;
};

const isPrintableCodePoint = (cp: number): boolean =>
  cp === 0x09 || (cp >= 0x20 && cp !== 0x7f && !(cp >= 0x80 && cp <= 0x9f));

/**
 * Multi-byte UTF-8 runs. A run is emitted only when it carries at least one
 * non-ASCII code point, so pure-ASCII text remains the ascii encoding's domain.
 */
export function* scanUtf8(bytes: Buffer, minLength: number): Generator<RawRun> {
  let start = -1;
  let count = 0;
  let hasMultibyte = false;
  let capByte = -1;
  let index = 0;
  while (index < bytes.length) {
    const decoded = decodeUtf8(bytes, index);
    if (decoded !== null && isPrintableCodePoint(decoded.cp)) {
      if (start < 0) {
        start = index;
        count = 0;
        hasMultibyte = false;
        capByte = -1;
      }
      count += 1;
      if (decoded.size > 1) hasMultibyte = true;
      index += decoded.size;
      if (count === MAX_STRING_CHARS) capByte = index;
    } else {
      if (start >= 0 && count >= minLength && hasMultibyte) {
        const end = capByte >= 0 ? capByte : index;
        yield {
          encoding: "utf8",
          file_offset: start,
          text: bytes.toString("utf8", start, end),
          length: count,
        };
      }
      start = -1;
      count = 0;
      hasMultibyte = false;
      capByte = -1;
      index += 1;
    }
  }
  if (start >= 0 && count >= minLength && hasMultibyte)
    yield {
      encoding: "utf8",
      file_offset: start,
      text: bytes.toString("utf8", start, capByte >= 0 ? capByte : index),
      length: count,
    };
}

/** The scanner generator for one encoding. */
export const scannerFor = (
  encoding: StringEncoding,
): ((bytes: Buffer, minLength: number) => Generator<RawRun>) =>
  encoding === "ascii"
    ? scanAscii
    : encoding === "utf16le"
      ? scanUtf16le
      : scanUtf8;
