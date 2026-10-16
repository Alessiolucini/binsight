import type {
  ElfDetails,
  ElfDynamicFacts,
  ImageRange,
} from "./executableImage.js";
import { IMAGE_PARSE_LIMITS } from "./executableImage.js";
import type { ElfContext, ElfRawSection, ElfRawSegment } from "./elfImage.js";
import { resolveVaddrOffset } from "./elfImageSymbols.js";

const PT_INTERP = 3;
const PT_NOTE = 4;
const PT_DYNAMIC = 2;
const PT_GNU_STACK = 0x6474e551;
const PT_GNU_RELRO = 0x6474e552;
const SHT_SYMTAB = 2;
const SHT_NOTE = 7;
const PF_X = 1;

const DT_NEEDED = 1;
const DT_STRTAB = 5;
const DT_STRSZ = 10;
const DT_SONAME = 14;
const DT_RPATH = 15;
const DT_DEBUG = 21;
const DT_TEXTREL = 22;
const DT_BIND_NOW = 24;
const DT_RUNPATH = 29;
const DT_FLAGS = 30;
const DT_FLAGS_1 = 0x6ffffffb;

const DF_TEXTREL = 0x4;
const DF_BIND_NOW = 0x8;
const DF_1_NOW = 0x1;

const NT_GNU_BUILD_ID = 3;
const NT_GNU_PROPERTY_TYPE_0 = 5;
const GNU_PROPERTY_AARCH64_FEATURE_1_AND = 0xc0000000;
const GNU_PROPERTY_X86_FEATURE_1_AND = 0xc0000002;

const MAX_DYNAMIC_ENTRIES = 100_000;
const MAX_COMMENT_BYTES = 1 << 16;

interface DynamicRaw {
  readonly neededOffsets: readonly number[];
  readonly rpathOffsets: readonly number[];
  readonly runpathOffsets: readonly number[];
  readonly sonameOffset: number | null;
  readonly strtabVaddr: bigint | null;
  readonly strsz: number;
  readonly flags: number | null;
  readonly flags1: number | null;
  readonly bindNowTag: boolean;
  readonly debugTag: boolean;
  readonly textrelTag: boolean;
}

const emptyDynamicRaw = (): {
  neededOffsets: number[];
  rpathOffsets: number[];
  runpathOffsets: number[];
  sonameOffset: number | null;
  strtabVaddr: bigint | null;
  strsz: number;
  flags: number | null;
  flags1: number | null;
  bindNowTag: boolean;
  debugTag: boolean;
  textrelTag: boolean;
} => ({
  neededOffsets: [],
  rpathOffsets: [],
  runpathOffsets: [],
  sonameOffset: null,
  strtabVaddr: null,
  strsz: 0,
  flags: null,
  flags1: null,
  bindNowTag: false,
  debugTag: false,
  textrelTag: false,
});

const applyDynamicTag = (
  raw: ReturnType<typeof emptyDynamicRaw>,
  tag: number,
  value: bigint,
): void => {
  const low = Number(value & 0xffffffffn);
  switch (tag) {
    case DT_NEEDED:
      raw.neededOffsets.push(low);
      return;
    case DT_STRTAB:
      raw.strtabVaddr = value;
      return;
    case DT_STRSZ:
      raw.strsz = low;
      return;
    case DT_SONAME:
      raw.sonameOffset = low;
      return;
    case DT_RPATH:
      raw.rpathOffsets.push(low);
      return;
    case DT_RUNPATH:
      raw.runpathOffsets.push(low);
      return;
    case DT_FLAGS:
      raw.flags = low;
      return;
    case DT_FLAGS_1:
      raw.flags1 = low;
      return;
    case DT_BIND_NOW:
      raw.bindNowTag = true;
      return;
    case DT_DEBUG:
      raw.debugTag = true;
      return;
    case DT_TEXTREL:
      raw.textrelTag = true;
      return;
    default:
      return;
  }
};

const collectDynamicRaw = (
  ctx: ElfContext,
  segment: ElfRawSegment,
): DynamicRaw => {
  const raw = emptyDynamicRaw();
  const entrySize = ctx.bits === 64 ? 16 : 8;
  const end = segment.offset + segment.filesz;
  for (
    let pos = segment.offset, read = 0;
    pos + entrySize <= end && read < MAX_DYNAMIC_ENTRIES;
    pos += entrySize, read++
  ) {
    if (!ctx.reader.contains(pos, entrySize)) break;
    const tag = ctx.reader.word(pos, ctx.bits);
    if (tag === 0n) break;
    const value = ctx.reader.word(pos + entrySize / 2, ctx.bits);
    applyDynamicTag(raw, Number(tag & 0xffffffffn), value);
  }
  return raw;
};

const dynamicStringTable = (
  ctx: ElfContext,
  raw: DynamicRaw,
): { readonly offset: number | null; readonly size: number } => {
  if (raw.strtabVaddr !== null) {
    const offset = resolveVaddrOffset(ctx.loads, raw.strtabVaddr, 0n);
    if (offset !== null) return { offset, size: raw.strsz };
  }
  const section = ctx.sections.find((s) => s.name === ".dynstr");
  if (section) return { offset: section.offset, size: Number(section.size) };
  return { offset: null, size: 0 };
};

const splitPaths = (value: string | null): string[] =>
  value === null ? [] : value.split(":").filter((part) => part.length > 0);

const buildDynamicFacts = (
  ctx: ElfContext,
  raw: DynamicRaw,
): ElfDynamicFacts => {
  const table = dynamicStringTable(ctx, raw);
  const readString = (offset: number): string | null => {
    if (table.offset === null || offset < 0) return null;
    if (table.size > 0 && offset >= table.size) return null;
    const limit = Math.min(
      IMAGE_PARSE_LIMITS.stringBytes,
      table.size > 0 ? table.size - offset : IMAGE_PARSE_LIMITS.stringBytes,
    );
    return ctx.reader.cString(table.offset + offset, limit) ?? null;
  };
  const needed = raw.neededOffsets
    .slice(0, IMAGE_PARSE_LIMITS.libraries)
    .map(readString)
    .filter((name): name is string => name !== null);
  const flags = raw.flags;
  const flags1 = raw.flags1;
  const bindNow =
    raw.bindNowTag ||
    (flags !== null && (flags & DF_BIND_NOW) !== 0) ||
    (flags1 !== null && (flags1 & DF_1_NOW) !== 0);
  return {
    needed,
    soname: raw.sonameOffset === null ? null : readString(raw.sonameOffset),
    rpath: raw.rpathOffsets.flatMap((offset) => splitPaths(readString(offset))),
    runpath: raw.runpathOffsets.flatMap((offset) =>
      splitPaths(readString(offset)),
    ),
    flags,
    flags_1: flags1,
    bind_now: bindNow,
    has_debug_tag: raw.debugTag,
    text_relocations:
      raw.textrelTag || (flags !== null && (flags & DF_TEXTREL) !== 0),
  };
};

const parseDynamic = (ctx: ElfContext): ElfDynamicFacts | null => {
  const segment = ctx.segments.find((s) => s.type === PT_DYNAMIC);
  if (!segment) return null;
  return buildDynamicFacts(ctx, collectDynamicRaw(ctx, segment));
};

interface NoteFacts {
  buildId: string | null;
  x86Feature: number | null;
  aarch64Feature: number | null;
}

const align = (value: number, to: number): number =>
  (value + (to - 1)) & ~(to - 1);

const parseGnuProperty = (
  ctx: ElfContext,
  start: number,
  size: number,
  facts: NoteFacts,
): void => {
  const pad = ctx.bits === 64 ? 8 : 4;
  const end = start + size;
  for (let pos = start; pos + 8 <= end;) {
    if (!ctx.reader.contains(pos, 8)) break;
    const type = ctx.reader.u32(pos);
    const dataSize = ctx.reader.u32(pos + 4);
    const dataStart = pos + 8;
    if (dataSize >= 4 && ctx.reader.contains(dataStart, 4)) {
      if (type === GNU_PROPERTY_X86_FEATURE_1_AND)
        facts.x86Feature = ctx.reader.u32(dataStart);
      else if (type === GNU_PROPERTY_AARCH64_FEATURE_1_AND)
        facts.aarch64Feature = ctx.reader.u32(dataStart);
    }
    const advance = 8 + align(dataSize, pad);
    if (advance <= 0) break;
    pos += advance;
  }
};

const consumeNote = (
  ctx: ElfContext,
  pos: number,
  end: number,
  facts: NoteFacts,
): number => {
  if (!ctx.reader.contains(pos, 12) || pos + 12 > end) return -1;
  const nameSize = ctx.reader.u32(pos);
  const descSize = ctx.reader.u32(pos + 4);
  const type = ctx.reader.u32(pos + 8);
  const nameStart = pos + 12;
  const descStart = nameStart + align(nameSize, 4);
  const descEnd = descStart + descSize;
  if (descEnd > end || !ctx.reader.contains(descStart, descSize)) return -1;
  const name =
    nameSize === 0
      ? ""
      : ctx.reader.fixedString(nameStart, nameSize, "note name");
  if (name === "GNU" && type === NT_GNU_BUILD_ID && facts.buildId === null)
    facts.buildId = ctx.reader.slice(descStart, descSize).toString("hex");
  if (name === "GNU" && type === NT_GNU_PROPERTY_TYPE_0)
    parseGnuProperty(ctx, descStart, descSize, facts);
  return descStart + align(descSize, 4);
};

const noteRanges = (ctx: ElfContext): ImageRange[] => {
  if (ctx.hasSectionTable)
    return ctx.sections
      .filter((s) => s.type === SHT_NOTE && Number(s.size) > 0)
      .map((s) => ({ file_offset: s.offset, size: Number(s.size) }));
  return ctx.segments
    .filter((s) => s.type === PT_NOTE && s.filesz > 0)
    .map((s) => ({ file_offset: s.offset, size: s.filesz }));
};

const scanNotes = (ctx: ElfContext): NoteFacts => {
  const facts: NoteFacts = {
    buildId: null,
    x86Feature: null,
    aarch64Feature: null,
  };
  for (const range of noteRanges(ctx)) {
    const end = range.file_offset + range.size;
    let pos = range.file_offset;
    while (pos < end) {
      const next = consumeNote(ctx, pos, end, facts);
      if (next <= pos) break;
      pos = next;
    }
  }
  return facts;
};

const interpreter = (ctx: ElfContext): string | null => {
  const segment = ctx.segments.find((s) => s.type === PT_INTERP);
  if (!segment || segment.filesz === 0) return null;
  return ctx.reader.cString(
    segment.offset,
    Math.min(IMAGE_PARSE_LIMITS.stringBytes, segment.filesz),
  );
};

const gnuStack = (
  ctx: ElfContext,
): { readonly present: boolean; readonly executable: boolean } => {
  const segment = ctx.segments.find((s) => s.type === PT_GNU_STACK);
  return {
    present: segment !== undefined,
    executable: segment !== undefined && (segment.flags & PF_X) !== 0,
  };
};

const gnuRelro = (ctx: ElfContext): ImageRange | null => {
  const segment = ctx.segments.find((s) => s.type === PT_GNU_RELRO);
  return segment ? { file_offset: segment.offset, size: segment.filesz } : null;
};

const sectionByName = (
  ctx: ElfContext,
  name: string,
): ElfRawSection | undefined => ctx.sections.find((s) => s.name === name);

const commentStrings = (ctx: ElfContext): string[] => {
  const section = sectionByName(ctx, ".comment");
  if (!section || Number(section.size) === 0) return [];
  const size = Math.min(Number(section.size), MAX_COMMENT_BYTES);
  if (!ctx.reader.contains(section.offset, size)) return [];
  const text = ctx.reader.slice(section.offset, size).toString("utf8");
  const seen = new Set<string>();
  const result: string[] = [];
  for (const piece of text.split("\0")) {
    if (piece.length === 0 || seen.has(piece)) continue;
    seen.add(piece);
    result.push(piece);
  }
  return result;
};

const gnuDebuglink = (ctx: ElfContext): string | null => {
  const section = sectionByName(ctx, ".gnu_debuglink");
  if (!section || Number(section.size) === 0) return null;
  return ctx.reader.cString(
    section.offset,
    Math.min(IMAGE_PARSE_LIMITS.stringBytes, Number(section.size)),
  );
};

/** Project the ELF-specific detail object from the parsed context. */
export const buildElfDetails = (ctx: ElfContext): ElfDetails => {
  const notes = scanNotes(ctx);
  return {
    elf_class: ctx.bits,
    os_abi: ctx.header.osAbi,
    e_type: ctx.header.type,
    machine: ctx.header.machine,
    e_flags: ctx.header.flags,
    interpreter: interpreter(ctx),
    gnu_stack: gnuStack(ctx),
    gnu_relro: gnuRelro(ctx),
    dynamic: parseDynamic(ctx),
    build_id: notes.buildId,
    x86_feature_1: notes.x86Feature,
    aarch64_feature_1: notes.aarch64Feature,
    has_symtab: ctx.sections.some((s) => s.type === SHT_SYMTAB),
    has_debug_info: ctx.sections.some((s) => s.name.startsWith(".debug")),
    comment: commentStrings(ctx),
    gnu_debuglink: gnuDebuglink(ctx),
  };
};
