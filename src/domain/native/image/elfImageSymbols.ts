import type {
  ImageImport,
  ImageExport,
  ImageSymbol,
} from "./executableImage.js";
import { IMAGE_PARSE_LIMITS } from "./executableImage.js";
import type { ElfContext, ElfLoad, ElfRawSection } from "./elfImage.js";

/** One decoded ELF symbol-table entry, before projection to the neutral model. */
export interface ElfSymbolEntry {
  readonly index: number;
  readonly name: string;
  readonly value: bigint;
  readonly size: bigint;
  /** st_info low nibble (STT_*). */
  readonly symType: number;
  /** st_info high nibble (STB_*). */
  readonly binding: number;
  /** st_shndx; SHN_UNDEF (0) marks an undefined symbol. */
  readonly shndx: number;
}

/** A symbol table read from one section, flagged when the shared bound was hit. */
export interface ElfSymbolTable {
  readonly entries: readonly ElfSymbolEntry[];
  readonly truncated: boolean;
}

/** Symbol-version facts resolved from .gnu.version and .gnu.version_r. */
export interface ElfVersionInfo {
  /** Version index per dynamic-symbol index, or null when absent. */
  readonly versym: readonly number[] | null;
  /** Needed-version index to version name (such as GLIBC_2.34). */
  readonly verneed: ReadonlyMap<number, string>;
}

const SHT_SYMTAB = 2;
const SHT_DYNSYM = 11;
const SHT_GNU_VERSYM = 0x6fffffff;
const SHT_GNU_VERNEED = 0x6ffffffe;
const SHN_UNDEF = 0;
const STB_GLOBAL = 1;
const STB_WEAK = 2;
const STT_OBJECT = 1;
const STT_FUNC = 2;
const STT_SECTION = 3;
const STT_FILE = 4;
const STT_TLS = 6;

/** File offset backing a loaded virtual address, or null when unmapped. */
export const resolveVaddrOffset = (
  loads: readonly ElfLoad[],
  vaddr: bigint,
  size: bigint,
): number | null => {
  for (const load of loads) {
    const end = load.vaddr + BigInt(load.filesz);
    if (vaddr >= load.vaddr && vaddr + size <= end)
      return load.offset + Number(vaddr - load.vaddr);
  }
  return null;
};

const readName = (
  ctx: ElfContext,
  strtabOffset: number | null,
  strtabSize: number,
  nameOffset: number,
): string => {
  if (strtabOffset === null || nameOffset < 0 || nameOffset >= strtabSize)
    return "";
  const limit = Math.min(
    IMAGE_PARSE_LIMITS.stringBytes,
    strtabSize - nameOffset,
  );
  return ctx.reader.cString(strtabOffset + nameOffset, limit) ?? "";
};

const readSymbol = (
  ctx: ElfContext,
  base: number,
  strtab: { readonly offset: number | null; readonly size: number },
): Omit<ElfSymbolEntry, "index"> => {
  const { reader, bits } = ctx;
  const wide = bits === 64;
  const nameOffset = reader.u32(base);
  const info = wide ? reader.u8(base + 4) : reader.u8(base + 12);
  const shndx = wide ? reader.u16(base + 6) : reader.u16(base + 14);
  const value = wide ? reader.u64(base + 8) : BigInt(reader.u32(base + 4));
  const size = wide ? reader.u64(base + 16) : BigInt(reader.u32(base + 8));
  return {
    name: readName(ctx, strtab.offset, strtab.size, nameOffset),
    value,
    size,
    symType: info & 0xf,
    binding: info >> 4,
    shndx,
  };
};

/** Decode one symbol table, bounded by `limit` entries. */
export const readElfSymbolTable = (
  ctx: ElfContext,
  section: ElfRawSection,
  limit: number,
): ElfSymbolTable => {
  const width = ctx.bits === 64 ? 24 : 16;
  const linked = ctx.sections[section.link];
  const strtab = {
    offset: linked ? linked.offset : null,
    size: linked ? Number(linked.size) : 0,
  };
  const declared = Math.floor(Number(section.size) / width);
  const count = Math.max(0, declared);
  const entries: ElfSymbolEntry[] = [];
  let truncated = false;
  for (let index = 0; index < count; index++) {
    if (entries.length >= limit) {
      truncated = true;
      break;
    }
    const base = section.offset + index * width;
    if (!ctx.reader.contains(base, width)) {
      truncated = true;
      break;
    }
    entries.push({ index, ...readSymbol(ctx, base, strtab) });
  }
  return { entries, truncated };
};

const symbolTypeName = (symType: number): ImageSymbol["type"] => {
  switch (symType) {
    case STT_FUNC:
      return "function";
    case STT_OBJECT:
      return "object";
    case STT_SECTION:
      return "section";
    case STT_FILE:
      return "file";
    case STT_TLS:
      return "tls";
    default:
      return "other";
  }
};

const symbolBindingName = (binding: number): ImageSymbol["binding"] => {
  switch (binding) {
    case 0:
      return "local";
    case STB_GLOBAL:
      return "global";
    case STB_WEAK:
      return "weak";
    default:
      return "other";
  }
};

const toImageSymbol = (
  entry: ElfSymbolEntry,
  table: "dynsym" | "symtab",
): ImageSymbol => ({
  name: entry.name,
  value: entry.value,
  size: entry.size,
  type: symbolTypeName(entry.symType),
  binding: symbolBindingName(entry.binding),
  defined: entry.shndx !== SHN_UNDEF,
  table,
});

/** Symbols from .dynsym and .symtab, with coverage and the raw dynsym table. */
export const collectElfSymbols = (
  ctx: ElfContext,
): {
  readonly list: readonly ImageSymbol[];
  readonly coverage: "complete" | "truncated" | "unavailable";
  readonly dynsym: ElfSymbolTable | null;
} => {
  const dynsymSection = ctx.sections.find((s) => s.type === SHT_DYNSYM);
  const symtabSections = ctx.sections.filter((s) => s.type === SHT_SYMTAB);
  const list: ImageSymbol[] = [];
  let truncated = false;
  let dynsym: ElfSymbolTable | null = null;
  if (dynsymSection) {
    dynsym = readElfSymbolTable(ctx, dynsymSection, IMAGE_PARSE_LIMITS.symbols);
    for (const entry of dynsym.entries)
      list.push(toImageSymbol(entry, "dynsym"));
    truncated ||= dynsym.truncated;
  }
  for (const section of symtabSections) {
    const table = readElfSymbolTable(
      ctx,
      section,
      IMAGE_PARSE_LIMITS.symbols - list.length,
    );
    for (const entry of table.entries)
      list.push(toImageSymbol(entry, "symtab"));
    truncated ||= table.truncated;
  }
  const empty = !dynsymSection && symtabSections.length === 0;
  const coverage =
    !ctx.hasSectionTable || empty
      ? "unavailable"
      : truncated
        ? "truncated"
        : "complete";
  return { list, coverage, dynsym };
};

const readU16Array = (ctx: ElfContext, section: ElfRawSection): number[] => {
  const count = Math.floor(Number(section.size) / 2);
  const values: number[] = [];
  for (let index = 0; index < count; index++) {
    const at = section.offset + index * 2;
    if (!ctx.reader.contains(at, 2)) break;
    values.push(ctx.reader.u16(at));
  }
  return values;
};

const readVerneed = (
  ctx: ElfContext,
  section: ElfRawSection,
  verneed: Map<number, string>,
): void => {
  const linked = ctx.sections[section.link];
  const strtabOffset = linked ? linked.offset : null;
  const strtabSize = linked ? Number(linked.size) : 0;
  const count = Math.min(section.info, IMAGE_PARSE_LIMITS.libraries);
  let offset = section.offset;
  for (let entry = 0; entry < count; entry++) {
    if (!ctx.reader.contains(offset, 16)) break;
    const auxCount = ctx.reader.u16(offset + 2);
    const auxDelta = ctx.reader.u32(offset + 8);
    const next = ctx.reader.u32(offset + 12);
    let aux = offset + auxDelta;
    for (let a = 0; a < auxCount; a++) {
      if (!ctx.reader.contains(aux, 16)) break;
      const other = ctx.reader.u16(aux + 6) & 0x7fff;
      const nameOffset = ctx.reader.u32(aux + 8);
      verneed.set(other, readName(ctx, strtabOffset, strtabSize, nameOffset));
      const auxNext = ctx.reader.u32(aux + 12);
      if (auxNext === 0) break;
      aux += auxNext;
    }
    if (next === 0) break;
    offset += next;
  }
};

/** Parse symbol-version tables; failures degrade to empty, never fatal. */
export const readElfVersionInfo = (ctx: ElfContext): ElfVersionInfo => {
  const versymSection = ctx.sections.find((s) => s.type === SHT_GNU_VERSYM);
  const verneedSection = ctx.sections.find((s) => s.type === SHT_GNU_VERNEED);
  const versym = versymSection ? readU16Array(ctx, versymSection) : null;
  const verneed = new Map<number, string>();
  if (verneedSection) readVerneed(ctx, verneedSection, verneed);
  return { versym, verneed };
};

const importVersion = (
  versions: ElfVersionInfo,
  index: number,
): string | null => {
  if (versions.versym === null || index >= versions.versym.length) return null;
  const versionIndex = (versions.versym[index] ?? 0) & 0x7fff;
  if (versionIndex <= 1) return null;
  return versions.verneed.get(versionIndex) ?? null;
};

const exportKind = (symType: number): ImageExport["kind"] =>
  symType === STT_FUNC
    ? "function"
    : symType === STT_OBJECT
      ? "object"
      : "unknown";

/** Undefined dynamic symbols become imports; defined global/weak become exports. */
export const deriveElfImportsExports = (
  dynsym: ElfSymbolTable | null,
  versions: ElfVersionInfo,
): {
  readonly imports: readonly ImageImport[];
  readonly exports: readonly ImageExport[];
  readonly importsTruncated: boolean;
  readonly exportsTruncated: boolean;
} => {
  const imports: ImageImport[] = [];
  const exports: ImageExport[] = [];
  let importsTruncated = false;
  let exportsTruncated = false;
  for (const entry of dynsym?.entries ?? []) {
    if (entry.index === 0 || entry.name === "") continue;
    const weak = entry.binding === STB_WEAK;
    if (entry.shndx === SHN_UNDEF) {
      if (imports.length >= IMAGE_PARSE_LIMITS.imports) importsTruncated = true;
      else
        imports.push({
          library: null,
          name: entry.name,
          ordinal: null,
          delay_loaded: false,
          weak,
          version: importVersion(versions, entry.index),
        });
    } else if (entry.binding === STB_GLOBAL || weak) {
      if (exports.length >= IMAGE_PARSE_LIMITS.exports) exportsTruncated = true;
      else
        exports.push({
          name: entry.name,
          ordinal: null,
          address: entry.value,
          forwarder: null,
          kind: exportKind(entry.symType),
        });
    }
  }
  return { imports, exports, importsTruncated, exportsTruncated };
};
