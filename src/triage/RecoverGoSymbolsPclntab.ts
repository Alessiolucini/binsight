import type { GoBinaryContainer } from "../go/GoBinaryContainer.js";

/** Published header-magic revisions this decoder recognizes. */
export type GoPclntabVersion = "1.2" | "1.16" | "1.18" | "1.20";

interface VersionMagic {
  readonly magic: number;
  readonly version: GoPclntabVersion;
}

/** Header magic to format revision, in discovery order. */
const VERSION_MAGICS: readonly VersionMagic[] = [
  { magic: 0xffff_fffb, version: "1.2" },
  { magic: 0xffff_fffa, version: "1.16" },
  { magic: 0xffff_fff0, version: "1.18" },
  { magic: 0xffff_fff1, version: "1.20" },
];

/** Upper bound on one decoded symbol name, guarding malformed length fields. */
const MAX_NAME_BYTES = 4096;
/** Upper bound on candidate magic positions examined before giving up. */
const MAX_CANDIDATES = 4096;

/** One recovered function: its embedded name and absolute entry address. */
export interface DecodedFunction {
  readonly name: string;
  readonly entry: bigint;
}

/** A located and decoded `pclntab`; offsets are relative to the decoded buffer. */
export interface DecodedPclntab {
  readonly fileOffset: number;
  readonly version: GoPclntabVersion;
  readonly magic: number;
  readonly pointerSize: 4 | 8;
  readonly functionCount: number;
  readonly functions: readonly DecodedFunction[];
}

/** Rejection of one candidate position; never escapes decode attempts. */
class DecodeReject extends Error {}

/**
 * Locate the first decodable `pclntab` in the container's read-only sections
 * and recover its function names and entry addresses. Returns null when no
 * candidate validates. Pure and bounded; `maxFunctions` caps returned entries.
 */
export const findPclntab = (
  bytes: Buffer,
  container: GoBinaryContainer,
  maxFunctions: number,
  signal?: AbortSignal,
): DecodedPclntab | null => {
  const little = container.byte_order === "little";
  let examined = 0;
  for (const section of container.sections) {
    if (!section.read_only || section.size < 8) continue;
    const region = bytes.subarray(
      section.offset,
      section.offset + section.size,
    );
    for (const { magic, version } of VERSION_MAGICS) {
      const needle = magicNeedle(magic, little);
      let search = 0;
      for (;;) {
        const hit = region.indexOf(needle, search);
        if (hit < 0) break;
        search = hit + 1;
        if (examined >= MAX_CANDIDATES) return null;
        examined += 1;
        const decoded = tryDecode({
          bytes,
          base: section.offset + hit,
          version,
          magic,
          little,
          maxFunctions,
          signal,
        });
        if (decoded !== null) return decoded;
      }
    }
  }
  return null;
};

/** Little- or big-endian byte image of a header magic for substring search. */
const magicNeedle = (magic: number, little: boolean): Buffer => {
  const needle = Buffer.alloc(4);
  if (little) needle.writeUInt32LE(magic >>> 0);
  else needle.writeUInt32BE(magic >>> 0);
  return needle;
};

/** One magic hit to validate and decode in place. */
interface Candidate {
  readonly bytes: Buffer;
  readonly base: number;
  readonly version: GoPclntabVersion;
  readonly magic: number;
  readonly little: boolean;
  readonly maxFunctions: number;
  readonly signal?: AbortSignal | undefined;
}

const tryDecode = (candidate: Candidate): DecodedPclntab | null => {
  try {
    return decodeHeader(candidate);
  } catch (cause) {
    if (cause instanceof DecodeReject || cause instanceof RangeError)
      return null;
    throw cause;
  }
};

/** Shared guarded little/big-endian field reader over the decoded buffer. */
class PclntabReader {
  constructor(
    readonly bytes: Buffer,
    readonly little: boolean,
    readonly pointerSize: 4 | 8,
  ) {}

  private guard(offset: number, width: number): number {
    if (offset < 0 || offset + width > this.bytes.length)
      throw new DecodeReject(`field at ${offset} leaves the decoded buffer`);
    return offset;
  }

  u8(offset: number): number {
    return this.bytes[this.guard(offset, 1)] as number;
  }

  u32(offset: number): number {
    const at = this.guard(offset, 4);
    return this.little
      ? this.bytes.readUInt32LE(at)
      : this.bytes.readUInt32BE(at);
  }

  i32(offset: number): number {
    const at = this.guard(offset, 4);
    return this.little
      ? this.bytes.readInt32LE(at)
      : this.bytes.readInt32BE(at);
  }

  uptr(offset: number): bigint {
    if (this.pointerSize === 4) return BigInt(this.u32(offset));
    const at = this.guard(offset, 8);
    return this.little
      ? this.bytes.readBigUInt64LE(at)
      : this.bytes.readBigUInt64BE(at);
  }

  /** NUL-terminated name, rejecting control bytes and overlong spans. */
  name(offset: number): string {
    if (offset < 0 || offset >= this.bytes.length)
      throw new DecodeReject("name offset leaves the decoded buffer");
    const limit = Math.min(offset + MAX_NAME_BYTES, this.bytes.length);
    const end = this.bytes.indexOf(0, offset);
    const stop = end < 0 || end > limit ? limit : end;
    const span = this.bytes.subarray(offset, stop);
    if (span.length === 0) throw new DecodeReject("empty name");
    for (const byte of span)
      if (byte < 0x20) throw new DecodeReject("control byte in name");
    return new TextDecoder("utf-8", { fatal: false }).decode(span);
  }
}

interface HeaderLayout {
  readonly functionCount: number;
  readonly nameBase: number;
  readonly functabStart: number;
  /** Buffer offset the `_func` struct offsets are measured from. */
  readonly funcStructBase: number;
  readonly textStart: bigint;
  readonly wideFunctab: boolean;
}

const decodeHeader = (candidate: Candidate): DecodedPclntab => {
  const { bytes, base, version, magic, little, maxFunctions, signal } =
    candidate;
  if (bytes[base + 4] !== 0 || bytes[base + 5] !== 0)
    throw new DecodeReject("header padding is not zero");
  const minLineCost = bytes[base + 6] ?? 0;
  if (![1, 2, 4].includes(minLineCost))
    throw new DecodeReject("unexpected minimum line-table quantum");
  const pointerSize = bytes[base + 7];
  if (pointerSize !== 4 && pointerSize !== 8)
    throw new DecodeReject("unexpected pointer size");
  const reader = new PclntabReader(bytes, little, pointerSize);
  const layout =
    version === "1.2"
      ? legacyLayout(reader, base)
      : modernLayout(reader, base, version);
  if (layout.functionCount <= 0)
    throw new DecodeReject("non-positive function count");
  const stride = layout.wideFunctab ? pointerSize * 2 : 8;
  // Validate the whole functab (nfunc + 1 sentinel entries) fits before work.
  reader.u8(layout.functabStart);
  const functabEnd = layout.functabStart + (layout.functionCount + 1) * stride;
  if (functabEnd > bytes.length)
    throw new DecodeReject("function table leaves the decoded buffer");
  const functions = recoverFunctions(reader, layout, maxFunctions, signal);
  if (functions.length === 0) throw new DecodeReject("no function decoded");
  return {
    fileOffset: base,
    version,
    magic,
    pointerSize,
    functionCount: layout.functionCount,
    functions,
  };
};

/** Go 1.2 header: names are offsets into the table itself. */
const legacyLayout = (reader: PclntabReader, base: number): HeaderLayout => {
  const functionCount = Number(reader.uptr(base + 8));
  // In Go 1.2 both func-struct and name offsets are relative to the table start.
  return {
    functionCount,
    nameBase: base,
    functabStart: base + 8 + reader.pointerSize,
    funcStructBase: base,
    textStart: 0n,
    wideFunctab: true,
  };
};

/** Go 1.16 (and 1.18/1.20 with an added textStart field) header layout. */
const modernLayout = (
  reader: PclntabReader,
  base: number,
  version: GoPclntabVersion,
): HeaderLayout => {
  const ptr = reader.pointerSize;
  let cursor = base + 8;
  const functionCount = Number(reader.uptr(cursor));
  cursor += ptr; // nfunc
  cursor += ptr; // nfiles
  let textStart = 0n;
  const hasTextStart = version !== "1.16";
  if (hasTextStart) {
    textStart = reader.uptr(cursor);
    cursor += ptr;
  }
  const funcnameOffset = Number(reader.uptr(cursor));
  cursor += ptr; // funcnametab
  cursor += ptr; // cutab
  cursor += ptr; // filetab
  cursor += ptr; // pctab
  const pclnOffset = Number(reader.uptr(cursor));
  // From Go 1.16 the func-struct offsets index the pcln region (pclnOffset).
  return {
    functionCount,
    nameBase: base + funcnameOffset,
    functabStart: base + pclnOffset,
    funcStructBase: base + pclnOffset,
    textStart,
    wideFunctab: version === "1.16",
  };
};

const recoverFunctions = (
  reader: PclntabReader,
  layout: HeaderLayout,
  maxFunctions: number,
  signal?: AbortSignal,
): DecodedFunction[] => {
  const limit = Math.min(layout.functionCount, maxFunctions);
  const stride = layout.wideFunctab ? reader.pointerSize * 2 : 8;
  const nameFieldOffset = layout.wideFunctab ? reader.pointerSize : 4;
  const functions: DecodedFunction[] = [];
  for (let index = 0; index < limit; index += 1) {
    if ((index & 0x1fff) === 0) signal?.throwIfAborted();
    const slot = layout.functabStart + index * stride;
    const { entry, funcOffset } = readFunctabEntry(reader, layout, slot);
    const funcStruct = layout.funcStructBase + funcOffset;
    const nameOffset = reader.i32(funcStruct + nameFieldOffset);
    if (nameOffset < 0) continue;
    const named = tryName(reader, layout.nameBase + nameOffset);
    if (named !== null) functions.push({ name: named, entry });
  }
  return functions;
};

/** One functab slot: an absolute entry address and the `_func` struct offset. */
const readFunctabEntry = (
  reader: PclntabReader,
  layout: HeaderLayout,
  slot: number,
): { entry: bigint; funcOffset: number } => {
  if (layout.wideFunctab) {
    const entry = reader.uptr(slot);
    return {
      entry,
      funcOffset: Number(reader.uptr(slot + reader.pointerSize)),
    };
  }
  const entryOffset = reader.u32(slot);
  return {
    entry: layout.textStart + BigInt(entryOffset),
    funcOffset: reader.u32(slot + 4),
  };
};

/** Decode one name, treating an out-of-range or malformed span as absent. */
const tryName = (reader: PclntabReader, offset: number): string | null => {
  try {
    return reader.name(offset);
  } catch (cause) {
    if (cause instanceof DecodeReject || cause instanceof RangeError)
      return null;
    throw cause;
  }
};
