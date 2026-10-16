import * as zlib from "node:zlib";
import type { CarvingValidatorKey } from "../domain/triage/carvingSignatures.js";
import type { FormatValidator } from "./ScanEmbeddedContentReaders.js";
import {
  has,
  probeDeflate,
  result,
  safe,
  u16be,
  u16le,
  u32be,
  u32le,
  u64be,
  u64le,
} from "./ScanEmbeddedContentReaders.js";
import { EXECUTABLE_VALIDATORS } from "./ScanEmbeddedContentExecutables.js";

export type { FormatValidator } from "./ScanEmbeddedContentReaders.js";

/**
 * Structural validators for archive, compression, image, document, database,
 * filesystem, certificate and firmware containers, plus the registry that maps
 * every signature's validator key to its implementation. Validators read only
 * headers and bounded tables; `derCertificate`/`pkcs12` share a DER `SEQUENCE`
 * prefix and are written to be mutually exclusive.
 */

const ZIP_METHODS = new Set([0, 8, 9, 12, 14, 93, 94, 95, 96, 97, 98, 99]);

const zipLocal: FormatValidator = (b, s) => {
  if (!has(b, s, 30)) return null;
  const method = u16le(b, s + 8);
  const nameLen = u16le(b, s + 26);
  const extraLen = u16le(b, s + 28);
  if (!ZIP_METHODS.has(method) || nameLen > 0x1000 || extraLen > 0x1000)
    return null;
  return result(null, "medium", `method ${method}`);
};

const zipCentral: FormatValidator = (b, s) => {
  if (!has(b, s, 46)) return null;
  const method = u16le(b, s + 10);
  const nameLen = u16le(b, s + 28);
  if (!ZIP_METHODS.has(method) || nameLen > 0x1000) return null;
  return result(null, "medium", `method ${method}`);
};

const zipEocd: FormatValidator = (b, s) => {
  if (!has(b, s, 22)) return null;
  const commentLen = u16le(b, s + 20);
  if (!has(b, s + 22, commentLen)) return null;
  const entries = u16le(b, s + 10);
  return result(
    22 + commentLen,
    "medium",
    `${entries} entr${entries === 1 ? "y" : "ies"}`,
  );
};

/** Advance past a NUL-terminated string, returning -1 when unterminated. */
const skipCString = (b: Buffer, o: number): number => {
  const nul = b.indexOf(0, o);
  return nul === -1 ? -1 : nul + 1;
};

const gzip: FormatValidator = (b, s) => {
  if (!has(b, s, 10) || (b.readUInt8(s + 3) & 0xe0) !== 0) return null;
  const flg = b.readUInt8(s + 3);
  let cursor = s + 10;
  if (flg & 0x04) {
    if (!has(b, cursor, 2)) return null;
    cursor += 2 + u16le(b, cursor);
  }
  if (flg & 0x08) cursor = skipCString(b, cursor);
  if (flg & 0x10) cursor = skipCString(b, cursor);
  if (flg & 0x02) cursor += 2;
  if (cursor < 0 || cursor > b.length)
    return result(null, "medium", "gzip header");
  const deflate = probeDeflate(
    b.subarray(cursor, Math.min(b.length, cursor + 0x10000)),
  );
  return result(null, deflate ? "high" : "medium", "gzip header");
};

const zlibStream: FormatValidator = (b, s) => {
  if (!has(b, s, 2)) return null;
  const cmf = b.readUInt8(s);
  const flg = b.readUInt8(s + 1);
  if ((cmf & 0x0f) !== 8 || cmf >> 4 > 7 || ((cmf << 8) | flg) % 31 !== 0)
    return null;
  const headerLen = flg & 0x20 ? 6 : 2;
  const deflate = probeDeflate(
    b.subarray(s + headerLen, Math.min(b.length, s + headerLen + 0x10000)),
  );
  return deflate ? result(null, "medium", "zlib stream") : null;
};

const xz: FormatValidator = (b, s) => {
  if (!has(b, s, 12)) return null;
  const flags = b.subarray(s + 6, s + 8);
  if (zlib.crc32(flags) >>> 0 !== u32le(b, s + 8)) return null;
  return result(null, "high", "stream header CRC32 valid");
};

const zstd: FormatValidator = (b, s) => {
  if (!has(b, s, 5)) return null;
  if ((b.readUInt8(s + 4) & 0x08) !== 0) return null;
  return result(null, "high", "frame header");
};

const bzip2: FormatValidator = (b, s) => {
  if (!has(b, s, 10)) return null;
  const level = b.readUInt8(s + 3);
  if (level < 0x31 || level > 0x39) return null;
  const block = b.subarray(s + 4, s + 10);
  if (!block.equals(Buffer.from([0x31, 0x41, 0x59, 0x26, 0x53, 0x59])))
    return null;
  return result(null, "high", `block size ${level - 0x30}00k`);
};

const sevenZip: FormatValidator = (b, s) => {
  if (!has(b, s, 32)) return null;
  const major = b.readUInt8(s + 6);
  if (major !== 0) return null;
  const nextOff = safe(u64le(b, s + 12));
  const nextSize = safe(u64le(b, s + 20));
  if (nextOff === null || nextSize === null)
    return result(null, "high", "7z header");
  return result(32 + nextOff + nextSize, "high", "7z header");
};

const cab: FormatValidator = (b, s) => {
  if (!has(b, s, 36) || u32le(b, s + 4) !== 0 || u32le(b, s + 12) !== 0)
    return null;
  const total = u32le(b, s + 8);
  if (b.readUInt8(s + 25) !== 1) return null;
  return result(total > 0 ? total : null, "high", "cabinet header");
};

const png: FormatValidator = (b, s) => {
  if (!has(b, s, 16) || b.toString("latin1", s + 12, s + 16) !== "IHDR")
    return null;
  let cursor = s + 8;
  for (let i = 0; i < 0x1_0000; i += 1) {
    if (!has(b, cursor, 8)) break;
    const len = u32be(b, cursor);
    const type = b.toString("latin1", cursor + 4, cursor + 8);
    cursor += 12 + len;
    if (type === "IEND")
      return result(
        cursor - s <= b.length ? cursor - s : null,
        "high",
        "PNG image",
      );
    if (cursor <= s || cursor > b.length) break;
  }
  return result(null, "high", "PNG image");
};

const jpeg: FormatValidator = (b, s) => {
  const marker = has(b, s, 4) ? b.readUInt8(s + 3) : 0;
  if (marker < 0xc0 || marker === 0xff) return null;
  let cursor = s + 2;
  for (let i = 0; i < 0x4000; i += 1) {
    if (!has(b, cursor, 2) || b.readUInt8(cursor) !== 0xff) break;
    const code = b.readUInt8(cursor + 1);
    if (code === 0xd9) return result(cursor + 2 - s, "high", "JPEG image");
    if (code === 0xda) {
      const eoi = b.indexOf(Buffer.from([0xff, 0xd9]), cursor);
      return result(eoi === -1 ? null : eoi + 2 - s, "high", "JPEG image");
    }
    if (code >= 0xd0 && code <= 0xd7) {
      cursor += 2;
      continue;
    }
    if (!has(b, cursor + 2, 2)) break;
    cursor += 2 + u16be(b, cursor + 2);
  }
  return result(null, "high", "JPEG image");
};

const pdf: FormatValidator = (b, s) => {
  const window = b.subarray(s, Math.min(b.length, s + 0x400_0000));
  const marker = Buffer.from("%%EOF");
  const last = window.lastIndexOf(marker);
  const size = last === -1 ? null : last + marker.length;
  return result(size, "high", `PDF ${b.toString("latin1", s + 5, s + 8)}`);
};

const sqlite: FormatValidator = (b, s) => {
  if (!has(b, s, 32)) return null;
  const raw = u16be(b, s + 16);
  const pageSize = raw === 1 ? 65536 : raw;
  if (pageSize < 512 || (pageSize & (pageSize - 1)) !== 0) return null;
  const pages = u32be(b, s + 28);
  const bytes = pages * pageSize;
  return result(
    bytes > 0 && bytes <= b.length ? bytes : null,
    "high",
    `page size ${pageSize}`,
  );
};

const derLength = (
  b: Buffer,
  s: number,
): { length: number; headerLen: number } | null => {
  if (!has(b, s, 2)) return null;
  const first = b.readUInt8(s + 1);
  if (first === 0x82)
    return has(b, s, 4) ? { length: u16be(b, s + 2), headerLen: 4 } : null;
  if (first === 0x83)
    return has(b, s, 5)
      ? { length: (b.readUInt8(s + 2) << 16) | u16be(b, s + 3), headerLen: 5 }
      : null;
  return null;
};

const derCertificate: FormatValidator = (b, s) => {
  const outer = derLength(b, s);
  if (outer === null || b.readUInt8(s + outer.headerLen) !== 0x30) return null;
  const end = s + outer.headerLen + outer.length;
  if (end > b.length) return result(null, "low", "truncated DER sequence");
  return result(
    outer.headerLen + outer.length,
    "medium",
    "nested DER sequences",
  );
};

const pkcs12: FormatValidator = (b, s) => {
  const outer = derLength(b, s);
  if (outer === null || !has(b, s + outer.headerLen, 3)) return null;
  if (
    b.readUInt8(s + outer.headerLen) !== 0x02 ||
    b.readUInt8(s + outer.headerLen + 1) !== 0x01 ||
    b.readUInt8(s + outer.headerLen + 2) !== 0x03
  )
    return null;
  const end = s + outer.headerLen + outer.length;
  return result(
    end <= b.length ? outer.headerLen + outer.length : null,
    "medium",
    "PKCS#12 version 3",
  );
};

const squashfs: FormatValidator = (b, s) => {
  if (!has(b, s, 48)) return null;
  const le = b.toString("latin1", s, s + 4) === "hsqs";
  const r16 = (o: number): number => (le ? u16le(b, s + o) : u16be(b, s + o));
  const major = r16(28);
  const compression = r16(20);
  if (major < 1 || major > 4 || compression < 1 || compression > 6) return null;
  const used = le ? safe(u64le(b, s + 40)) : safe(u64be(b, s + 40));
  return result(
    used !== null && used > 0 && used <= b.length ? used : null,
    "high",
    `v${major}.${r16(30)} ${le ? "le" : "be"}`,
  );
};

const cpio: FormatValidator = (b, s) => {
  if (!has(b, s, 14)) return null;
  const magic = b.toString("latin1", s, s + 6);
  if (magic === "070701" || magic === "070702") {
    for (let i = 6; i < 14; i += 1) {
      const c = b.readUInt8(s + i);
      const hex =
        (c >= 0x30 && c <= 0x39) ||
        (c >= 0x41 && c <= 0x46) ||
        (c >= 0x61 && c <= 0x66);
      if (!hex) return null;
    }
  }
  return result(null, "medium", `cpio ${magic}`);
};

/** Validate the octal header checksum of a single 512-byte tar block. */
const tarChecksumValid = (b: Buffer, s: number): boolean => {
  let sum = 0;
  for (let i = 0; i < 512; i += 1)
    sum += i >= 148 && i < 156 ? 0x20 : b.readUInt8(s + i);
  const field = b
    .toString("latin1", s + 148, s + 156)
    .replace(/\0.*$/u, "")
    .trim();
  const stored = Number.parseInt(field, 8);
  return Number.isFinite(stored) && stored === sum;
};

/** Walk tar block headers to the two-zero-block terminator, bounded. */
const tarArchiveSize = (b: Buffer, s: number): number | null => {
  let cursor = s;
  for (let i = 0; i < 0x10_0000; i += 1) {
    if (!has(b, cursor, 512)) return null;
    if (b.subarray(cursor, cursor + 512).every((v) => v === 0))
      return cursor + 512 - s;
    if (!tarChecksumValid(b, cursor)) return cursor > s ? cursor - s : null;
    const sizeField = b
      .toString("latin1", cursor + 124, cursor + 136)
      .replace(/\0.*$/u, "")
      .trim();
    const fileSize = Number.parseInt(sizeField, 8);
    if (!Number.isFinite(fileSize)) return cursor - s;
    cursor += 512 + Math.ceil(fileSize / 512) * 512;
  }
  return null;
};

const tar: FormatValidator = (b, s) => {
  if (!has(b, s, 512)) return null;
  if (!tarChecksumValid(b, s)) return null;
  return result(tarArchiveSize(b, s), "high", "ustar header");
};

const uimage: FormatValidator = (b, s) => {
  if (!has(b, s, 64)) return null;
  const headerCrc = u32be(b, s + 4);
  const header = Buffer.from(b.subarray(s, s + 64));
  header.writeUInt32BE(0, 4);
  if (zlib.crc32(header) >>> 0 !== headerCrc) return null;
  const dataSize = u32be(b, s + 12);
  const name = b.toString("latin1", s + 32, s + 64).replace(/\0.*$/u, "");
  return result(
    64 + dataSize,
    "high",
    name === "" ? "uImage" : `uImage "${name}"`,
  );
};

const dtb: FormatValidator = (b, s) => {
  if (!has(b, s, 28)) return null;
  const total = u32be(b, s + 4);
  const version = u32be(b, s + 20);
  const lastComp = u32be(b, s + 24);
  if (version < 16 || version > 17 || lastComp > version || total < 40)
    return null;
  return result(total <= b.length ? total : null, "high", `version ${version}`);
};

/** Registry mapping each signature's validator key to its implementation. */
export const CARVING_VALIDATORS: Readonly<
  Record<CarvingValidatorKey, FormatValidator>
> = {
  ...EXECUTABLE_VALIDATORS,
  zipLocal,
  zipCentral,
  zipEocd,
  gzip,
  zlib: zlibStream,
  xz,
  zstd,
  bzip2,
  sevenZip,
  cab,
  png,
  jpeg,
  pdf,
  sqlite,
  derCertificate,
  pkcs12,
  squashfs,
  cpio,
  tar,
  uimage,
  dtb,
};
