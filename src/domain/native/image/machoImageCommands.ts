/**
 * Mach-O load-command walking: one bounded pass over LC_SEGMENT(_64) and the
 * metadata commands, projecting segments, sections and the facts the image
 * model and the nlist reader need. All file offsets are absolute in the whole
 * analyzed file (slice offset + in-slice offset).
 */

import { IMAGE_PARSE_LIMITS } from "./executableImage.js";
import type {
  ImageLibrary,
  ImageLibraryKind,
  ImageRange,
  ImageSection,
  ImageSegment,
  MachoBuildVersion,
  MachoDylib,
  MachoEncryptionInfo,
} from "./executableImage.js";
import {
  malformed,
  type ImageDiagnostics,
  type ImageReader,
} from "./imageReader.js";

// Combined LC_REQ_DYLD (0x80000000) commands are written as full unsigned hex
// literals: the JS `|` operator truncates to signed int32, which would make
// these negative and never equal the unsigned value read from the file.
export const LC_SEGMENT = 0x1;
export const LC_SYMTAB = 0x2;
export const LC_UNIXTHREAD = 0x5;
export const LC_LOAD_DYLIB = 0xc;
export const LC_ID_DYLIB = 0xd;
export const LC_LOAD_WEAK_DYLIB = 0x8000_0018;
export const LC_SEGMENT_64 = 0x19;
export const LC_UUID = 0x1b;
export const LC_RPATH = 0x8000_001c;
export const LC_CODE_SIGNATURE = 0x1d;
export const LC_LAZY_LOAD_DYLIB = 0x20;
export const LC_ENCRYPTION_INFO = 0x21;
export const LC_REEXPORT_DYLIB = 0x8000_001f;
export const LC_LOAD_UPWARD_DYLIB = 0x8000_0023;
export const LC_VERSION_MIN_MACOSX = 0x24;
export const LC_VERSION_MIN_IPHONEOS = 0x25;
export const LC_MAIN = 0x8000_0028;
export const LC_SOURCE_VERSION = 0x2a;
export const LC_ENCRYPTION_INFO_64 = 0x2c;
export const LC_VERSION_MIN_TVOS = 0x2f;
export const LC_VERSION_MIN_WATCHOS = 0x30;
export const LC_BUILD_VERSION = 0x32;
export const LC_DYLD_EXPORTS_TRIE = 0x8000_0033;
export const LC_DYLD_CHAINED_FIXUPS = 0x8000_0034;

const COMMAND_NAMES = new Map<number, string>([
  [LC_SEGMENT, "LC_SEGMENT"],
  [LC_SYMTAB, "LC_SYMTAB"],
  [0x3, "LC_SYMSEG"],
  [0x4, "LC_THREAD"],
  [LC_UNIXTHREAD, "LC_UNIXTHREAD"],
  [0xb, "LC_DYSYMTAB"],
  [LC_LOAD_DYLIB, "LC_LOAD_DYLIB"],
  [LC_ID_DYLIB, "LC_ID_DYLIB"],
  [0xe, "LC_LOAD_DYLINKER"],
  [0xf, "LC_ID_DYLINKER"],
  [0x16, "LC_TWOLEVEL_HINTS"],
  [LC_LOAD_WEAK_DYLIB, "LC_LOAD_WEAK_DYLIB"],
  [LC_SEGMENT_64, "LC_SEGMENT_64"],
  [0x1a, "LC_ROUTINES_64"],
  [LC_UUID, "LC_UUID"],
  [LC_RPATH, "LC_RPATH"],
  [LC_CODE_SIGNATURE, "LC_CODE_SIGNATURE"],
  [0x1e, "LC_SEGMENT_SPLIT_INFO"],
  [LC_REEXPORT_DYLIB, "LC_REEXPORT_DYLIB"],
  [LC_LAZY_LOAD_DYLIB, "LC_LAZY_LOAD_DYLIB"],
  [LC_ENCRYPTION_INFO, "LC_ENCRYPTION_INFO"],
  [0x22, "LC_DYLD_INFO"],
  [0x8000_0022, "LC_DYLD_INFO_ONLY"],
  [LC_LOAD_UPWARD_DYLIB, "LC_LOAD_UPWARD_DYLIB"],
  [LC_VERSION_MIN_MACOSX, "LC_VERSION_MIN_MACOSX"],
  [LC_VERSION_MIN_IPHONEOS, "LC_VERSION_MIN_IPHONEOS"],
  [0x26, "LC_FUNCTION_STARTS"],
  [0x27, "LC_DYLD_ENVIRONMENT"],
  [LC_MAIN, "LC_MAIN"],
  [0x29, "LC_DATA_IN_CODE"],
  [LC_SOURCE_VERSION, "LC_SOURCE_VERSION"],
  [0x2b, "LC_DYLIB_CODE_SIGN_DRS"],
  [LC_ENCRYPTION_INFO_64, "LC_ENCRYPTION_INFO_64"],
  [0x2d, "LC_LINKER_OPTION"],
  [0x2e, "LC_LINKER_OPTIMIZATION_HINT"],
  [LC_VERSION_MIN_TVOS, "LC_VERSION_MIN_TVOS"],
  [LC_VERSION_MIN_WATCHOS, "LC_VERSION_MIN_WATCHOS"],
  [0x31, "LC_NOTE"],
  [LC_BUILD_VERSION, "LC_BUILD_VERSION"],
  [LC_DYLD_EXPORTS_TRIE, "LC_DYLD_EXPORTS_TRIE"],
  [LC_DYLD_CHAINED_FIXUPS, "LC_DYLD_CHAINED_FIXUPS"],
  [0x8000_0035, "LC_FILESET_ENTRY"],
]);

/** Readable name for a load command, falling back to its hex value. */
export const commandName = (command: number): string =>
  COMMAND_NAMES.get(command) ?? `LC_(0x${command.toString(16)})`;

const DYLIB_KINDS = new Map<number, ImageLibraryKind>([
  [LC_LOAD_DYLIB, "needed"],
  [LC_LOAD_WEAK_DYLIB, "weak"],
  [LC_REEXPORT_DYLIB, "reexport"],
  [LC_LOAD_UPWARD_DYLIB, "upward"],
  [LC_LAZY_LOAD_DYLIB, "lazy"],
]);

const VERSION_MIN_PLATFORMS = new Map<number, number>([
  [LC_VERSION_MIN_MACOSX, 1],
  [LC_VERSION_MIN_IPHONEOS, 2],
  [LC_VERSION_MIN_TVOS, 3],
  [LC_VERSION_MIN_WATCHOS, 4],
]);

export interface MachoSymtab {
  readonly symoff: number;
  readonly nsyms: number;
  readonly stroff: number;
  readonly strsize: number;
}

export type MachoEntryRaw =
  | { readonly kind: "main"; readonly fileOffset: number }
  | { readonly kind: "thread"; readonly pc: bigint }
  | null;

export interface MachoLoadCommand {
  readonly command: number;
  readonly name: string;
  readonly offset: number;
  readonly size: number;
}

/** One command's number and its absolute base offset and size during the scan. */
export interface MachoCommandRef {
  readonly command: number;
  readonly base: number;
  readonly size: number;
}

/** Everything the image model and nlist reader derive from the command table. */
export interface MachoCommandScan {
  readonly segments: ImageSegment[];
  readonly sections: ImageSection[];
  readonly loadCommands: MachoLoadCommand[];
  readonly dylibs: MachoDylib[];
  readonly libraries: ImageLibrary[];
  readonly rpaths: string[];
  readonly buildVersions: MachoBuildVersion[];
  sourceVersion: string | null;
  uuid: string | null;
  idDylib: string | null;
  encryption: MachoEncryptionInfo | null;
  codeSignature: ImageRange | null;
  symtab: MachoSymtab | null;
  entry: MachoEntryRaw;
  hasRestrictSegment: boolean;
  usesChainedFixups: boolean;
  /** Absolute file-range ends declared by segments and link-edit data, for overlay. */
  readonly declaredEnds: number[];
}

/** Context shared by every per-command handler during the single scan pass. */
export interface MachoScanContext {
  readonly reader: ImageReader;
  readonly sliceOffset: number;
  readonly bits: 32 | 64;
  readonly cpuType: number;
  readonly diagnostics: ImageDiagnostics;
}

const formatDotVersion = (value: number): string =>
  `${value >>> 16}.${(value >>> 8) & 0xff}.${value & 0xff}`;

const permissionsOf = (initprot: number) => ({
  readable: (initprot & 0x1) !== 0,
  writable: (initprot & 0x2) !== 0,
  executable: (initprot & 0x4) !== 0,
});

const SECTION_TYPES = new Map<number, string>([
  [0x0, "S_REGULAR"],
  [0x1, "S_ZEROFILL"],
  [0x2, "S_CSTRING_LITERALS"],
  [0x3, "S_4BYTE_LITERALS"],
  [0x4, "S_8BYTE_LITERALS"],
  [0x5, "S_LITERAL_POINTERS"],
  [0x6, "S_NON_LAZY_SYMBOL_POINTERS"],
  [0x7, "S_LAZY_SYMBOL_POINTERS"],
  [0x8, "S_SYMBOL_STUBS"],
  [0x9, "S_MOD_INIT_FUNC_POINTERS"],
  [0xa, "S_MOD_TERM_FUNC_POINTERS"],
  [0xb, "S_COALESCED"],
  [0xc, "S_GB_ZEROFILL"],
  [0xd, "S_INTERPOSING"],
  [0xe, "S_16BYTE_LITERALS"],
  [0xf, "S_DTRACE_DOF"],
  [0x10, "S_LAZY_DYLIB_SYMBOL_POINTERS"],
  [0x11, "S_THREAD_LOCAL_REGULAR"],
  [0x12, "S_THREAD_LOCAL_ZEROFILL"],
  [0x13, "S_THREAD_LOCAL_VARIABLES"],
  [0x14, "S_THREAD_LOCAL_VARIABLE_POINTERS"],
  [0x15, "S_THREAD_LOCAL_INIT_FUNCTION_POINTERS"],
  [0x16, "S_INIT_FUNC_OFFSETS"],
]);

const ZERO_FILL_TYPES: readonly number[] = [0x1, 0xc, 0x12];

/** Pull sections out of one segment command into the running section list. */
const readSegmentSections = (
  context: MachoScanContext,
  layout: {
    readonly base: number;
    readonly wide: boolean;
    readonly segName: string;
    readonly initprot: number;
    readonly nsects: number;
  },
  sections: ImageSection[],
): void => {
  const { reader, sliceOffset } = context;
  const { base, wide, segName, initprot, nsects } = layout;
  const header = base + (wide ? 72 : 56);
  const width = wide ? 80 : 68;
  const permissions = permissionsOf(initprot);
  for (let i = 0; i < nsects; i++) {
    if (sections.length >= IMAGE_PARSE_LIMITS.sections) {
      context.diagnostics.add("Section list truncated at the parser bound.");
      return;
    }
    const entry = header + i * width;
    const sectName = reader.fixedString(entry, 16, "section name");
    const segField = reader.fixedString(entry + 16, 16, "section segment");
    const addr = reader.word(entry + 32, wide ? 64 : 32, "section addr");
    const size = reader.word(
      entry + (wide ? 40 : 36),
      wide ? 64 : 32,
      "section size",
    );
    const rawOffset = reader.u32(entry + (wide ? 48 : 40), "section offset");
    const flags = reader.u32(entry + (wide ? 64 : 56), "section flags");
    const type = flags & 0xff;
    const fileBacked = !ZERO_FILL_TYPES.includes(type);
    sections.push({
      index: sections.length,
      name: `${segField},${sectName}`,
      segment_name: segName,
      type: SECTION_TYPES.get(type) ?? null,
      file_offset: sliceOffset + rawOffset,
      file_size: fileBacked ? Number(size) : 0,
      virtual_address: addr,
      virtual_size: size,
      raw_flags: flags,
      ...permissions,
    });
  }
};

/** Project one LC_SEGMENT(_64) command and its sections into the scan. */
export const readSegmentCommand = (
  context: MachoScanContext,
  base: number,
  size: number,
  scan: MachoCommandScan,
): void => {
  const { reader, sliceOffset } = context;
  const wide = context.bits === 64;
  const headerSize = wide ? 72 : 56;
  if (size < headerSize) throw malformed("Mach-O segment command is truncated");
  const segName = reader.fixedString(base + 8, 16, "segment name");
  const vmaddr = reader.word(base + 24, wide ? 64 : 32, "segment vmaddr");
  const vmsize = reader.word(
    base + (wide ? 32 : 28),
    wide ? 64 : 32,
    "segment vmsize",
  );
  const fileoff = reader.safeWord(
    base + (wide ? 40 : 32),
    wide ? 64 : 32,
    "segment fileoff",
  );
  const filesize = reader.safeWord(
    base + (wide ? 48 : 36),
    wide ? 64 : 32,
    "segment filesize",
  );
  const initprot = reader.u32(base + (wide ? 60 : 44), "segment initprot");
  const nsects = reader.u32(base + (wide ? 64 : 48), "segment nsects");
  const flags = reader.u32(base + (wide ? 68 : 52), "segment flags");
  if (
    nsects > IMAGE_PARSE_LIMITS.sections ||
    nsects * (wide ? 80 : 68) > size - headerSize
  )
    throw malformed("Mach-O section table exceeds its segment command");
  if (segName === "__RESTRICT") scan.hasRestrictSegment = true;
  if (scan.segments.length < IMAGE_PARSE_LIMITS.segments)
    scan.segments.push({
      index: scan.segments.length,
      name: segName,
      type: wide ? "LC_SEGMENT_64" : "LC_SEGMENT",
      file_offset: sliceOffset + fileoff,
      file_size: filesize,
      virtual_address: vmaddr,
      memory_size: vmsize,
      raw_flags: flags,
      ...permissionsOf(initprot),
    });
  if (filesize > 0) scan.declaredEnds.push(sliceOffset + fileoff + filesize);
  readSegmentSections(
    context,
    { base, wide, segName, initprot, nsects },
    scan.sections,
  );
};

/** Record one dylib load command as both a detail entry and a library. */
export const readDylibCommand = (
  context: MachoScanContext,
  command: number,
  base: number,
  scan: MachoCommandScan,
): void => {
  const { reader } = context;
  const nameOffset = reader.u32(base + 8, "dylib name offset");
  const name =
    reader.cString(base + nameOffset, IMAGE_PARSE_LIMITS.stringBytes) ?? "";
  const current = formatDotVersion(
    reader.u32(base + 16, "dylib current version"),
  );
  const compat = formatDotVersion(
    reader.u32(base + 20, "dylib compat version"),
  );
  const kind = DYLIB_KINDS.get(command) ?? "needed";
  if (command === LC_ID_DYLIB) {
    scan.idDylib = name;
    return;
  }
  scan.dylibs.push({
    name,
    command: commandName(command),
    current_version: current,
    compatibility_version: compat,
  });
  if (scan.libraries.length < IMAGE_PARSE_LIMITS.libraries)
    scan.libraries.push({ name, kind });
};

/** Decode the thread-state program counter for the slice's architecture. */
const threadProgramCounter = (
  context: MachoScanContext,
  base: number,
  size: number,
): bigint | null => {
  const { reader, cpuType } = context;
  // Each flavor block is flavor(4) + count(4) + count 32-bit state words.
  const layout = new Map<
    number,
    { readonly flavor: number; readonly word: number; readonly wide: boolean }
  >([
    [0x0100_0007, { flavor: 4, word: 16, wide: true }],
    [0x0100_000c, { flavor: 6, word: 32, wide: true }],
    [0x7, { flavor: 1, word: 10, wide: false }],
    [0xc, { flavor: 1, word: 15, wide: false }],
  ]);
  const target = layout.get(cpuType);
  if (target === undefined) return null;
  let cursor = base + 8;
  const end = base + size;
  for (let guard = 0; guard < 64 && cursor + 8 <= end; guard++) {
    const flavor = reader.u32(cursor, "thread flavor");
    const count = reader.u32(cursor + 4, "thread state count");
    const stateStart = cursor + 8;
    const stateBytes = count * 4;
    if (stateStart + stateBytes > end) return null;
    if (flavor === target.flavor)
      return target.wide
        ? reader.u64(stateStart + target.word * 8, "thread pc")
        : BigInt(reader.u32(stateStart + target.word * 4, "thread pc"));
    cursor = stateStart + stateBytes;
  }
  return null;
};

/** Project the non-segment metadata commands into the scan. */
export const readMetadataCommand = (
  context: MachoScanContext,
  ref: MachoCommandRef,
  scan: MachoCommandScan,
): void => {
  const { reader, sliceOffset } = context;
  const { command, base, size } = ref;
  switch (command) {
    case LC_SYMTAB:
      scan.symtab = {
        symoff: sliceOffset + reader.u32(base + 8, "symoff"),
        nsyms: reader.u32(base + 12, "nsyms"),
        stroff: sliceOffset + reader.u32(base + 16, "stroff"),
        strsize: reader.u32(base + 20, "strsize"),
      };
      scan.declaredEnds.push(scan.symtab.stroff + scan.symtab.strsize);
      return;
    case LC_UUID:
      scan.uuid = reader.slice(base + 8, 16, "uuid").toString("hex");
      return;
    case LC_SOURCE_VERSION: {
      const v = reader.u64(base + 8, "source version");
      scan.sourceVersion = `${v >> 40n}.${(v >> 30n) & 0x3ffn}.${(v >> 20n) & 0x3ffn}.${(v >> 10n) & 0x3ffn}.${v & 0x3ffn}`;
      return;
    }
    case LC_BUILD_VERSION:
      scan.buildVersions.push({
        platform: reader.u32(base + 8, "build platform"),
        minimum_os: formatDotVersion(reader.u32(base + 12, "build minos")),
        sdk: formatDotVersion(reader.u32(base + 16, "build sdk")),
      });
      return;
    case LC_MAIN:
      scan.entry = {
        kind: "main",
        fileOffset: sliceOffset + reader.safeWord(base + 8, 64, "entryoff"),
      };
      return;
    case LC_UNIXTHREAD: {
      const pc = threadProgramCounter(context, base, size);
      if (pc !== null) scan.entry = { kind: "thread", pc };
      return;
    }
    case LC_CODE_SIGNATURE:
      scan.codeSignature = {
        file_offset: sliceOffset + reader.u32(base + 8, "code sig dataoff"),
        size: reader.u32(base + 12, "code sig datasize"),
      };
      scan.declaredEnds.push(
        scan.codeSignature.file_offset + scan.codeSignature.size,
      );
      return;
    case LC_ENCRYPTION_INFO:
    case LC_ENCRYPTION_INFO_64:
      scan.encryption = {
        crypt_offset: sliceOffset + reader.u32(base + 8, "cryptoff"),
        crypt_size: reader.u32(base + 12, "cryptsize"),
        crypt_id: reader.u32(base + 16, "cryptid"),
      };
      return;
    case LC_DYLD_CHAINED_FIXUPS:
      scan.usesChainedFixups = true;
      return;
    default:
      readVersionMinOrDylib(context, command, base, scan);
  }
};

/** Handle version-min, rpath and dylib commands that fall through the switch. */
const readVersionMinOrDylib = (
  context: MachoScanContext,
  command: number,
  base: number,
  scan: MachoCommandScan,
): void => {
  const { reader } = context;
  const platform = VERSION_MIN_PLATFORMS.get(command);
  if (platform !== undefined) {
    scan.buildVersions.push({
      platform,
      minimum_os: formatDotVersion(reader.u32(base + 8, "version min")),
      sdk: formatDotVersion(reader.u32(base + 12, "version min sdk")),
    });
    return;
  }
  if (command === LC_RPATH) {
    const pathOffset = reader.u32(base + 8, "rpath offset");
    const path = reader.cString(
      base + pathOffset,
      IMAGE_PARSE_LIMITS.stringBytes,
    );
    if (path !== null && scan.rpaths.length < IMAGE_PARSE_LIMITS.libraries)
      scan.rpaths.push(path);
    return;
  }
  if (DYLIB_KINDS.has(command) || command === LC_ID_DYLIB)
    readDylibCommand(context, command, base, scan);
};
