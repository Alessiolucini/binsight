import type { Result } from "../../result.js";
import { readElfFixedHeader } from "../../elfFixedHeader.js";
import type {
  ExecutableImage,
  ImageArchitecture,
  ImageByteOrder,
  ImageEntryPoint,
  ImageLibrary,
  ImageListCoverage,
  ImageParseFailure,
  ImageRange,
  ImageSection,
  ImageSegment,
} from "./executableImage.js";
import { IMAGE_PARSE_LIMITS } from "./executableImage.js";
import {
  captureImageParse,
  ImageDiagnostics,
  ImageReader,
  malformed,
  overlayAfter,
  sectionContainingAddress,
} from "./imageReader.js";
import { buildElfDetails } from "./elfImageDynamic.js";
import {
  collectElfSymbols,
  deriveElfImportsExports,
  readElfVersionInfo,
  resolveVaddrOffset,
} from "./elfImageSymbols.js";

/** Fixed ELF header fields shared by both classes. */
export interface ElfHeader {
  readonly bits: 32 | 64;
  readonly osAbi: number;
  readonly type: number;
  readonly machine: number;
  readonly version: number;
  readonly entry: bigint;
  readonly phoff: number;
  readonly shoff: number;
  readonly flags: number;
  readonly ehsize: number;
  readonly phentsize: number;
  readonly phnum: number;
  readonly shentsize: number;
  readonly shnum: number;
  readonly shstrndx: number;
}

/** One section header with its resolved name. */
export interface ElfRawSection {
  readonly index: number;
  readonly nameOffset: number;
  readonly name: string;
  readonly type: number;
  readonly flags: bigint;
  readonly addr: bigint;
  readonly offset: number;
  readonly size: bigint;
  readonly link: number;
  readonly info: number;
  readonly entsize: bigint;
}

/** One program header. */
export interface ElfRawSegment {
  readonly index: number;
  readonly type: number;
  readonly flags: number;
  readonly offset: number;
  readonly filesz: number;
  readonly vaddr: bigint;
  readonly memsz: bigint;
  readonly align: bigint;
}

/** One loadable segment projected for virtual-address resolution. */
export interface ElfLoad {
  readonly vaddr: bigint;
  readonly offset: number;
  readonly filesz: number;
  readonly memsz: bigint;
  readonly flags: number;
}

/** Shared, I/O-free parsing context passed to the detail and symbol builders. */
export interface ElfContext {
  readonly reader: ImageReader;
  readonly bits: 32 | 64;
  readonly byteOrder: ImageByteOrder;
  readonly header: ElfHeader;
  readonly sections: readonly ElfRawSection[];
  readonly segments: readonly ElfRawSegment[];
  readonly loads: readonly ElfLoad[];
  readonly hasSectionTable: boolean;
  readonly diagnostics: ImageDiagnostics;
}

const SHT_NOBITS = 8;
const PT_LOAD = 1;
const SHF_WRITE = 0x1n;
const SHF_ALLOC = 0x2n;
const SHF_EXECINSTR = 0x4n;

const SHT_NAMES = new Map<number, string>([
  [0, "SHT_NULL"],
  [1, "SHT_PROGBITS"],
  [2, "SHT_SYMTAB"],
  [3, "SHT_STRTAB"],
  [4, "SHT_RELA"],
  [5, "SHT_HASH"],
  [6, "SHT_DYNAMIC"],
  [7, "SHT_NOTE"],
  [8, "SHT_NOBITS"],
  [9, "SHT_REL"],
  [10, "SHT_SHLIB"],
  [11, "SHT_DYNSYM"],
  [14, "SHT_INIT_ARRAY"],
  [15, "SHT_FINI_ARRAY"],
  [16, "SHT_PREINIT_ARRAY"],
  [17, "SHT_GROUP"],
  [18, "SHT_SYMTAB_SHNDX"],
  [19, "SHT_RELR"],
  [0x6ffffff5, "SHT_GNU_ATTRIBUTES"],
  [0x6ffffff6, "SHT_GNU_HASH"],
  [0x6ffffff7, "SHT_GNU_LIBLIST"],
  [0x6ffffffd, "SHT_GNU_verdef"],
  [0x6ffffffe, "SHT_GNU_verneed"],
  [0x6fffffff, "SHT_GNU_versym"],
]);

const PT_NAMES = new Map<number, string>([
  [0, "PT_NULL"],
  [1, "PT_LOAD"],
  [2, "PT_DYNAMIC"],
  [3, "PT_INTERP"],
  [4, "PT_NOTE"],
  [5, "PT_SHLIB"],
  [6, "PT_PHDR"],
  [7, "PT_TLS"],
  [0x6474e550, "PT_GNU_EH_FRAME"],
  [0x6474e551, "PT_GNU_STACK"],
  [0x6474e552, "PT_GNU_RELRO"],
  [0x6474e553, "PT_GNU_PROPERTY"],
  [0x6474e554, "PT_GNU_SFRAME"],
]);

const MACHINES = new Map<number, readonly [ImageArchitecture, string]>([
  [0, [null, "None"]],
  [2, ["sparc", "SPARC"]],
  [3, ["x86", "Intel 80386"]],
  [8, ["mips", "MIPS"]],
  [20, ["powerpc", "PowerPC"]],
  [21, ["powerpc", "PowerPC64"]],
  [22, ["s390", "IBM S/390"]],
  [40, ["arm", "ARM"]],
  [62, ["x86_64", "AMD x86-64"]],
  [183, ["arm64", "AArch64"]],
  [243, ["riscv", "RISC-V"]],
  [258, ["loongarch", "LoongArch"]],
]);

const architectureFor = (machine: number): ImageArchitecture =>
  MACHINES.get(machine)?.[0] ?? null;

const machineName = (machine: number): string =>
  MACHINES.get(machine)?.[1] ?? `EM_0x${machine.toString(16)}`;

const sectionTypeName = (type: number): string | null =>
  SHT_NAMES.get(type) ?? null;

const segmentTypeName = (type: number): string =>
  PT_NAMES.get(type) ?? `0x${type.toString(16)}`;

const readElfHeader = (reader: ImageReader, bits: 32 | 64): ElfHeader => {
  const wide = bits === 64;
  return {
    bits,
    osAbi: reader.u8(7),
    type: reader.u16(16),
    machine: reader.u16(18),
    version: reader.u32(20),
    entry: reader.word(24, bits),
    phoff: reader.safeWord(wide ? 32 : 28, bits, "e_phoff"),
    shoff: reader.safeWord(wide ? 40 : 32, bits, "e_shoff"),
    flags: reader.u32(wide ? 48 : 36),
    ehsize: reader.u16(wide ? 52 : 40),
    phentsize: reader.u16(wide ? 54 : 42),
    phnum: reader.u16(wide ? 56 : 44),
    shentsize: reader.u16(wide ? 58 : 46),
    shnum: reader.u16(wide ? 60 : 48),
    shstrndx: reader.u16(wide ? 62 : 50),
  };
};

const readRawSection = (
  reader: ImageReader,
  bits: 32 | 64,
  base: number,
  index: number,
): Omit<ElfRawSection, "name"> => {
  const wide = bits === 64;
  return {
    index,
    nameOffset: reader.u32(base),
    type: reader.u32(base + 4),
    flags: reader.word(base + 8, bits),
    addr: reader.word(base + (wide ? 16 : 12), bits),
    offset: reader.safeWord(base + (wide ? 24 : 16), bits, "sh_offset"),
    size: reader.word(base + (wide ? 32 : 20), bits),
    link: reader.u32(base + (wide ? 40 : 24)),
    info: reader.u32(base + (wide ? 44 : 28)),
    entsize: reader.word(base + (wide ? 56 : 36), bits),
  };
};

const resolveSectionName = (
  reader: ImageReader,
  strtab: { readonly offset: number; readonly size: number } | null,
  nameOffset: number,
): string => {
  if (strtab === null || nameOffset < 0 || nameOffset >= strtab.size) return "";
  const limit = Math.min(
    IMAGE_PARSE_LIMITS.stringBytes,
    strtab.size - nameOffset,
  );
  return reader.cString(strtab.offset + nameOffset, limit, "latin1") ?? "";
};

const readSectionTable = (
  reader: ImageReader,
  header: ElfHeader,
  diagnostics: ImageDiagnostics,
): { readonly sections: ElfRawSection[]; readonly phnumExt: number | null } => {
  if (header.shoff === 0) return { sections: [], phnumExt: null };
  const stride = header.shentsize;
  if (stride < (header.bits === 64 ? 64 : 40))
    throw malformed("ELF section header entry size is invalid");
  const first = readRawSection(reader, header.bits, header.shoff, 0);
  let shnum = header.shnum === 0 ? Number(first.size) : header.shnum;
  const shstrndx = header.shstrndx === 0xffff ? first.link : header.shstrndx;
  const phnumExt = header.phnum === 0xffff ? first.info : null;
  if (!Number.isSafeInteger(shnum) || shnum < 0)
    throw malformed("ELF section count is invalid");
  if (shnum > IMAGE_PARSE_LIMITS.sections) {
    diagnostics.add(
      `ELF section count ${shnum} capped at ${IMAGE_PARSE_LIMITS.sections}`,
    );
    shnum = IMAGE_PARSE_LIMITS.sections;
  }
  const raw: Omit<ElfRawSection, "name">[] = [];
  for (let index = 0; index < shnum; index++)
    raw.push(
      readRawSection(reader, header.bits, header.shoff + index * stride, index),
    );
  const names =
    shstrndx > 0 && shstrndx < raw.length
      ? { offset: raw[shstrndx]!.offset, size: Number(raw[shstrndx]!.size) }
      : null;
  const sections = raw.map((section) => ({
    ...section,
    name: resolveSectionName(reader, names, section.nameOffset),
  }));
  return { sections, phnumExt };
};

const readProgramHeaders = (
  reader: ImageReader,
  header: ElfHeader,
  phnum: number,
  diagnostics: ImageDiagnostics,
): { readonly segments: ElfRawSegment[]; readonly loads: ElfLoad[] } => {
  if (phnum === 0 || header.phoff === 0) return { segments: [], loads: [] };
  const stride = header.phentsize;
  if (stride < (header.bits === 64 ? 56 : 32))
    throw malformed("ELF program header entry size is invalid");
  let count = phnum;
  if (count > IMAGE_PARSE_LIMITS.segments) {
    diagnostics.add(
      `ELF segment count ${count} capped at ${IMAGE_PARSE_LIMITS.segments}`,
    );
    count = IMAGE_PARSE_LIMITS.segments;
  }
  const wide = header.bits === 64;
  const segments: ElfRawSegment[] = [];
  const loads: ElfLoad[] = [];
  for (let index = 0; index < count; index++) {
    const base = header.phoff + index * stride;
    const type = reader.u32(base);
    const flags = reader.u32(base + (wide ? 4 : 24));
    const offset = reader.safeWord(
      base + (wide ? 8 : 4),
      header.bits,
      "p_offset",
    );
    const vaddr = reader.word(base + (wide ? 16 : 8), header.bits);
    const filesz = reader.safeWord(
      base + (wide ? 32 : 16),
      header.bits,
      "p_filesz",
    );
    const memsz = reader.word(base + (wide ? 40 : 20), header.bits);
    const alignment = reader.word(base + (wide ? 48 : 28), header.bits);
    segments.push({
      index,
      type,
      flags,
      offset,
      filesz,
      vaddr,
      memsz,
      align: alignment,
    });
    if (type === PT_LOAD) loads.push({ vaddr, offset, filesz, memsz, flags });
  }
  return { segments, loads };
};

const buildImageSections = (
  sections: readonly ElfRawSection[],
): ImageSection[] =>
  sections.map((section) => ({
    index: section.index,
    name: section.name,
    segment_name: null,
    type: sectionTypeName(section.type),
    file_offset: section.offset,
    file_size: section.type === SHT_NOBITS ? 0 : Number(section.size),
    virtual_address: section.addr,
    virtual_size: section.size,
    raw_flags: Number(section.flags & 0xffffffffn),
    readable: (section.flags & SHF_ALLOC) !== 0n,
    writable: (section.flags & SHF_WRITE) !== 0n,
    executable: (section.flags & SHF_EXECINSTR) !== 0n,
  }));

const buildImageSegments = (
  segments: readonly ElfRawSegment[],
): ImageSegment[] =>
  segments.map((segment) => ({
    index: segment.index,
    name: null,
    type: segmentTypeName(segment.type),
    file_offset: segment.offset,
    file_size: segment.filesz,
    virtual_address: segment.vaddr,
    memory_size: segment.memsz,
    raw_flags: segment.flags,
    readable: (segment.flags & 0x4) !== 0,
    writable: (segment.flags & 0x2) !== 0,
    executable: (segment.flags & 0x1) !== 0,
  }));

const computeEntry = (
  ctx: ElfContext,
  sections: readonly ImageSection[],
): ImageEntryPoint => {
  const virtualAddress = ctx.header.entry;
  const containing = sectionContainingAddress(sections, virtualAddress);
  return {
    virtual_address: virtualAddress,
    file_offset: resolveVaddrOffset(ctx.loads, virtualAddress, 1n),
    section_index: containing ? containing.index : null,
  };
};

const computeOverlay = (
  ctx: ElfContext,
  sections: readonly ImageSection[],
): ImageRange | null => {
  const ends: number[] = [ctx.header.ehsize];
  for (const section of sections)
    if (section.file_size > 0)
      ends.push(section.file_offset + section.file_size);
  for (const load of ctx.loads) ends.push(load.offset + load.filesz);
  if (ctx.hasSectionTable)
    ends.push(ctx.header.shoff + ctx.sections.length * ctx.header.shentsize);
  if (ctx.segments.length > 0)
    ends.push(ctx.header.phoff + ctx.segments.length * ctx.header.phentsize);
  return overlayAfter(ctx.reader.length, ends);
};

const listCoverage = (
  hasSectionTable: boolean,
  dynsymPresent: boolean,
  truncated: boolean,
): ImageListCoverage["imports"] => {
  if (!hasSectionTable) return "unavailable";
  if (!dynsymPresent) return "complete";
  return truncated ? "truncated" : "complete";
};

/** Parse an ELF32 or ELF64 image of either byte order into the neutral model. */
export const parseElfImage = (
  bytes: Buffer,
): Result<ExecutableImage, ImageParseFailure> =>
  captureImageParse(() => {
    const fixed = readElfFixedHeader(bytes);
    if (!fixed.ok) throw malformed(fixed.error);
    const bits = fixed.value.elfClass;
    const byteOrder = fixed.value.byteOrder;
    const reader = new ImageReader(bytes, byteOrder);
    const header = readElfHeader(reader, bits);
    const diagnostics = new ImageDiagnostics(IMAGE_PARSE_LIMITS.diagnostics);
    const { sections: rawSections, phnumExt } = readSectionTable(
      reader,
      header,
      diagnostics,
    );
    const hasSectionTable = header.shoff !== 0 && rawSections.length > 0;
    const { segments: rawSegments, loads } = readProgramHeaders(
      reader,
      header,
      phnumExt ?? header.phnum,
      diagnostics,
    );
    if (!hasSectionTable)
      diagnostics.add(
        "ELF has no section header table; section-derived facts are unavailable",
      );
    const ctx: ElfContext = {
      reader,
      bits,
      byteOrder,
      header,
      sections: rawSections,
      segments: rawSegments,
      loads,
      hasSectionTable,
      diagnostics,
    };
    const sections = buildImageSections(rawSections);
    const segments = buildImageSegments(rawSegments);
    const symbols = collectElfSymbols(ctx);
    const versions = readElfVersionInfo(ctx);
    const { imports, exports, importsTruncated, exportsTruncated } =
      deriveElfImportsExports(symbols.dynsym, versions);
    const details = buildElfDetails(ctx);
    const libraries: ImageLibrary[] = (details.dynamic?.needed ?? [])
      .slice(0, IMAGE_PARSE_LIMITS.libraries)
      .map((name) => ({ name, kind: "needed" }));
    return {
      format: "elf",
      bits,
      byte_order: byteOrder,
      architecture: architectureFor(header.machine),
      machine: header.machine,
      machine_name: machineName(header.machine),
      image_offset: 0,
      image_size: bytes.length,
      entry_point: computeEntry(ctx, sections),
      sections,
      segments,
      imports,
      exports,
      libraries,
      symbols: symbols.list,
      coverage: {
        imports: listCoverage(
          hasSectionTable,
          symbols.dynsym !== null,
          importsTruncated,
        ),
        exports: listCoverage(
          hasSectionTable,
          symbols.dynsym !== null,
          exportsTruncated,
        ),
        symbols: symbols.coverage,
      },
      overlay: computeOverlay(ctx, sections),
      container: { kind: "thin" },
      diagnostics: diagnostics.list(),
      elf: details,
      pe: null,
      macho: null,
    };
  });
