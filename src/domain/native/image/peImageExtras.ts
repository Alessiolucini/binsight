import {
  IMAGE_PARSE_LIMITS,
  type ImageSymbol,
  type ImageSymbolBinding,
  type ImageSymbolType,
  type PeCodeView,
  type PeDataDirectory,
  type PeLoadConfig,
  type PeRichEntry,
  type PeRichHeader,
} from "./executableImage.js";
import type { ImageReader } from "./imageReader.js";
import type { PeImageContext } from "./peImage.js";

const DANS = 0x536e_6144;
const RICH = Buffer.from("Rich", "latin1");
const RICH_START = 0x80;
const DIR_LOAD_CONFIG = 10;
const DIR_DEBUG = 6;
const DIR_TLS = 9;
const DEBUG_ENTRY_BYTES = 28;
const DEBUG_TYPE_CODEVIEW = 2;
const DEBUG_TYPE_EX_DLL_CHARACTERISTICS = 20;

/** The 16 PE data-directory slots in their canonical order. */
export const DATA_DIRECTORY_NAMES: readonly string[] = [
  "EXPORT",
  "IMPORT",
  "RESOURCE",
  "EXCEPTION",
  "SECURITY",
  "BASERELOC",
  "DEBUG",
  "ARCHITECTURE",
  "GLOBALPTR",
  "TLS",
  "LOAD_CONFIG",
  "BOUND_IMPORT",
  "IAT",
  "DELAY_IMPORT",
  "CLR",
  "RESERVED",
];

const rol32 = (value: number, rotate: number): number => {
  const bits = rotate & 31;
  const unsigned = value >>> 0;
  if (bits === 0) return unsigned;
  return ((unsigned << bits) | (unsigned >>> (32 - bits))) >>> 0;
};

/** PE image checksum recomputed with the pefile `generate_checksum` algorithm. */
export const computePeChecksum = (
  reader: ImageReader,
  peOffset: number,
): number => {
  const data = reader.bytes;
  const length = data.length;
  const checksumIndex = Math.floor((peOffset + 88) / 4);
  const remainder = length % 4;
  const words = Math.floor(length / 4) + (remainder === 0 ? 0 : 1);
  let checksum = 0;
  for (let index = 0; index < words; index += 1) {
    if (index === checksumIndex) continue;
    const dword = wordAt(data, index, remainder, words);
    checksum += dword;
    if (checksum >= 0x1_0000_0000)
      checksum =
        (checksum % 0x1_0000_0000) + Math.floor(checksum / 0x1_0000_0000);
  }
  checksum = (checksum % 0x1_0000) + Math.floor(checksum / 0x1_0000);
  checksum = checksum + Math.floor(checksum / 0x1_0000);
  return (checksum % 0x1_0000) + length;
};

const wordAt = (
  data: Buffer,
  index: number,
  remainder: number,
  words: number,
): number => {
  const start = index * 4;
  if (index + 1 === words && remainder !== 0) {
    let value = 0;
    for (let byte = 0; byte < remainder; byte += 1)
      value += (data[start + byte] ?? 0) * 2 ** (8 * byte);
    return value;
  }
  return data.readUInt32LE(start);
};

/** Parse the `DanS`..`Rich` XOR-masked stream that precedes the PE header. */
export const parseRichHeader = (
  reader: ImageReader,
  peOffset: number,
): PeRichHeader | null => {
  const data = reader.bytes;
  const limit = Math.min(peOffset, data.length);
  if (limit <= RICH_START + 8) return null;
  const richIndex = data.indexOf(RICH, RICH_START);
  if (richIndex === -1 || richIndex + 8 > limit) return null;
  const xorKey = data.readUInt32LE(richIndex + 4);
  const dansOffset = findDans(data, richIndex, xorKey);
  if (dansOffset === null) return null;
  const entries = richEntries(data, dansOffset + 16, richIndex, xorKey);
  const clear = Buffer.alloc(richIndex - dansOffset);
  for (let index = 0; index < clear.length; index += 1)
    clear[index] =
      (data[dansOffset + index] ?? 0) ^ ((xorKey >>> (8 * (index % 4))) & 0xff);
  return {
    offset: dansOffset,
    end_offset: richIndex + 8,
    xor_key: xorKey,
    entries,
    checksum_valid: richChecksum(data, dansOffset, entries) === xorKey,
    clear_bytes: clear,
  };
};

const findDans = (
  data: Buffer,
  richIndex: number,
  key: number,
): number | null => {
  for (let offset = RICH_START; offset + 4 <= richIndex; offset += 4)
    if ((data.readUInt32LE(offset) ^ key) >>> 0 === DANS) return offset;
  return null;
};

const richEntries = (
  data: Buffer,
  start: number,
  richIndex: number,
  key: number,
): PeRichEntry[] => {
  const entries: PeRichEntry[] = [];
  for (let offset = start; offset + 8 <= richIndex; offset += 8) {
    const compid = (data.readUInt32LE(offset) ^ key) >>> 0;
    const count = (data.readUInt32LE(offset + 4) ^ key) >>> 0;
    entries.push({ product_id: compid >>> 16, build: compid & 0xffff, count });
  }
  return entries;
};

const richChecksum = (
  data: Buffer,
  dansOffset: number,
  entries: readonly PeRichEntry[],
): number => {
  let checksum = dansOffset;
  for (let index = 0; index < dansOffset; index += 1) {
    if (index >= 0x3c && index < 0x40) continue;
    checksum = (checksum + rol32(data[index] ?? 0, index)) >>> 0;
  }
  for (const entry of entries) {
    const compid = ((entry.product_id << 16) | (entry.build & 0xffff)) >>> 0;
    checksum = (checksum + rol32(compid, entry.count)) >>> 0;
  }
  return checksum >>> 0;
};

const LOAD_CONFIG_LAYOUT = {
  64: {
    cookie: 88,
    sehTable: 96,
    sehCount: 104,
    guard: 112,
    guardCount: 136,
    flags: 144,
    ptr: 8,
  },
  32: {
    cookie: 60,
    sehTable: 64,
    sehCount: 68,
    guard: 72,
    guardCount: 84,
    flags: 88,
    ptr: 4,
  },
} as const;

/** Read the load-configuration directory, honoring its declared `Size`. */
export const parseLoadConfig = (ctx: PeImageContext): PeLoadConfig | null => {
  const directory = ctx.directories[DIR_LOAD_CONFIG];
  if (directory === undefined || directory.rva === 0) return null;
  const base = ctx.rvaToOffset(directory.rva, 4);
  if (base === null) return null;
  const reader = ctx.reader;
  const size = reader.u32(base, "PE load config size");
  const layout = LOAD_CONFIG_LAYOUT[ctx.bits];
  const ptr = (field: number): bigint | null =>
    field + layout.ptr <= size
      ? reader.word(base + field, ctx.bits, "PE load config field")
      : null;
  return {
    size,
    security_cookie: ptr(layout.cookie),
    se_handler_table: ptr(layout.sehTable),
    se_handler_count: ptr(layout.sehCount),
    guard_cf_check_function: ptr(layout.guard),
    guard_cf_function_count: ptr(layout.guardCount),
    guard_flags:
      layout.flags + 4 <= size
        ? reader.u32(base + layout.flags, "PE guard flags")
        : null,
  };
};

/** The virtual addresses of TLS callbacks, or null when there is no TLS directory. */
export const parseTlsCallbacks = (
  ctx: PeImageContext,
): readonly bigint[] | null => {
  const directory = ctx.directories[DIR_TLS];
  if (directory === undefined || directory.rva === 0) return null;
  const base = ctx.rvaToOffset(directory.rva, ctx.bits === 64 ? 40 : 24);
  if (base === null) return null;
  const callbacksField = ctx.bits === 64 ? 24 : 12;
  const callbacksVa = ctx.reader.word(
    base + callbacksField,
    ctx.bits,
    "PE TLS callbacks",
  );
  if (callbacksVa === 0n) return [];
  return readCallbackArray(ctx, callbacksVa - ctx.imageBase);
};

const readCallbackArray = (ctx: PeImageContext, firstRva: bigint): bigint[] => {
  const callbacks: bigint[] = [];
  const width = ctx.bits / 8;
  if (firstRva < 0n || firstRva > BigInt(Number.MAX_SAFE_INTEGER))
    return callbacks;
  for (let index = 0; index < IMAGE_PARSE_LIMITS.tlsCallbacks; index += 1) {
    const offset = ctx.rvaToOffset(Number(firstRva) + index * width, width);
    if (offset === null) break;
    const value = ctx.reader.word(offset, ctx.bits, "PE TLS callback");
    if (value === 0n) break;
    callbacks.push(value);
  }
  return callbacks;
};

/** Decoded debug directory: every entry type, CodeView record and EX flags. */
export interface PeDebugInfo {
  readonly debug_types: readonly number[];
  readonly codeview: PeCodeView | null;
  readonly ex_dll_characteristics: number | null;
}

export const parseDebugInfo = (ctx: PeImageContext): PeDebugInfo => {
  const directory = ctx.directories[DIR_DEBUG];
  const empty: PeDebugInfo = {
    debug_types: [],
    codeview: null,
    ex_dll_characteristics: null,
  };
  if (directory === undefined || directory.rva === 0 || directory.size === 0)
    return empty;
  const base = ctx.rvaToOffset(directory.rva, directory.size);
  if (base === null) return empty;
  const count = Math.min(Math.floor(directory.size / DEBUG_ENTRY_BYTES), 4096);
  const types: number[] = [];
  let codeview: PeCodeView | null = null;
  let exDllCharacteristics: number | null = null;
  for (let index = 0; index < count; index += 1) {
    const entry = base + index * DEBUG_ENTRY_BYTES;
    const type = ctx.reader.u32(entry + 12, "PE debug type");
    types.push(type);
    const rawPointer = debugDataOffset(ctx, entry);
    if (
      type === DEBUG_TYPE_CODEVIEW &&
      codeview === null &&
      rawPointer !== null
    )
      codeview = parseCodeView(ctx.reader, rawPointer);
    if (type === DEBUG_TYPE_EX_DLL_CHARACTERISTICS && rawPointer !== null)
      exDllCharacteristics = ctx.reader.u16(
        rawPointer,
        "PE ex dll characteristics",
      );
  }
  return {
    debug_types: types,
    codeview,
    ex_dll_characteristics: exDllCharacteristics,
  };
};

const debugDataOffset = (ctx: PeImageContext, entry: number): number | null => {
  const pointer = ctx.reader.u32(entry + 24, "PE debug pointer to raw data");
  if (pointer !== 0) return pointer;
  const rva = ctx.reader.u32(entry + 20, "PE debug address of raw data");
  return rva === 0 ? null : ctx.rvaToOffset(rva, 1);
};

const parseCodeView = (
  reader: ImageReader,
  offset: number,
): PeCodeView | null => {
  const signature = reader
    .slice(offset, 4, "PE CodeView signature")
    .toString("latin1");
  if (signature === "RSDS") {
    const guid = formatGuid(reader.slice(offset + 4, 16, "PE CodeView GUID"));
    return {
      signature: "RSDS",
      identifier: guid,
      age: reader.u32(offset + 20, "PE CodeView age"),
      pdb_path:
        reader.cString(offset + 24, IMAGE_PARSE_LIMITS.stringBytes, "latin1") ??
        "",
    };
  }
  if (signature === "NB10")
    return {
      signature: "NB10",
      identifier: reader.u32(offset + 8, "PE NB10 timestamp").toString(16),
      age: reader.u32(offset + 12, "PE NB10 age"),
      pdb_path:
        reader.cString(offset + 16, IMAGE_PARSE_LIMITS.stringBytes, "latin1") ??
        "",
    };
  return null;
};

const formatGuid = (bytes: Buffer): string => {
  const hex = (start: number, end: number): string =>
    bytes.subarray(start, end).toString("hex").toUpperCase();
  const part1 = bytes
    .readUInt32LE(0)
    .toString(16)
    .toUpperCase()
    .padStart(8, "0");
  const part2 = bytes
    .readUInt16LE(4)
    .toString(16)
    .toUpperCase()
    .padStart(4, "0");
  const part3 = bytes
    .readUInt16LE(6)
    .toString(16)
    .toUpperCase()
    .padStart(4, "0");
  return `${part1}-${part2}-${part3}-${hex(8, 10)}-${hex(10, 16)}`;
};

const SYMBOL_RECORD_BYTES = 18;

const symbolType = (type: number, storageClass: number): ImageSymbolType => {
  if ((type & 0x30) === 0x20) return "function";
  if (storageClass === 103) return "file";
  if (storageClass === 3) return "section";
  return "object";
};

const symbolBinding = (storageClass: number): ImageSymbolBinding => {
  if (storageClass === 2) return "global";
  if (storageClass === 105) return "weak";
  if (storageClass === 3 || storageClass === 6 || storageClass === 103)
    return "local";
  return "other";
};

/** COFF symbols and the honest coverage for the symbol list. */
export interface PeSymbols {
  readonly symbols: readonly ImageSymbol[];
  readonly coverage: "complete" | "truncated" | "unavailable";
}

/** Parse the COFF symbol table when the file header points at one. */
export const parseCoffSymbols = (ctx: PeImageContext): PeSymbols => {
  if (ctx.pointerToSymbolTable === 0 || ctx.numberOfSymbols === 0)
    return { symbols: [], coverage: "unavailable" };
  const stringBase =
    ctx.pointerToSymbolTable + ctx.numberOfSymbols * SYMBOL_RECORD_BYTES;
  if (
    !ctx.reader.contains(
      ctx.pointerToSymbolTable,
      ctx.numberOfSymbols * SYMBOL_RECORD_BYTES,
    )
  ) {
    ctx.diagnostics.add("PE COFF symbol table lies outside the image");
    return { symbols: [], coverage: "unavailable" };
  }
  const symbols: ImageSymbol[] = [];
  let index = 0;
  while (index < ctx.numberOfSymbols) {
    if (symbols.length >= IMAGE_PARSE_LIMITS.symbols)
      return { symbols, coverage: "truncated" };
    const record = ctx.pointerToSymbolTable + index * SYMBOL_RECORD_BYTES;
    symbols.push(readCoffSymbol(ctx.reader, record, stringBase));
    index += 1 + ctx.reader.u8(record + 17, "PE COFF aux count");
  }
  return { symbols, coverage: "complete" };
};

const readCoffSymbol = (
  reader: ImageReader,
  record: number,
  stringBase: number,
): ImageSymbol => {
  const inlineZero = reader.u32(record, "PE COFF symbol name") === 0;
  const name = inlineZero
    ? (reader.cString(
        stringBase + reader.u32(record + 4, "PE COFF name offset"),
        IMAGE_PARSE_LIMITS.stringBytes,
        "latin1",
      ) ?? "")
    : reader.fixedString(record, 8, "PE COFF symbol name");
  const value = reader.u32(record + 8, "PE COFF symbol value");
  const sectionNumber = reader.bytes.readInt16LE(record + 12);
  const type = reader.u16(record + 14, "PE COFF symbol type");
  const storageClass = reader.u8(record + 16, "PE COFF storage class");
  return {
    name,
    value: BigInt(value),
    size: 0n,
    type: symbolType(type, storageClass),
    binding: symbolBinding(storageClass),
    defined: sectionNumber > 0,
    table: "coff",
  };
};

/** Project the optional-header data directories into named model entries. */
export const buildDataDirectories = (
  entries: readonly { readonly rva: number; readonly size: number }[],
): readonly PeDataDirectory[] =>
  DATA_DIRECTORY_NAMES.map((name, index) => ({
    index,
    name,
    rva: entries[index]?.rva ?? 0,
    size: entries[index]?.size ?? 0,
  }));
