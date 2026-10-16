import type { Result } from "../../result.js";
import {
  type ExecutableImage,
  type ImageArchitecture,
  type ImageEntryPoint,
  type ImageParseFailure,
  type ImageSection,
  IMAGE_PARSE_LIMITS,
  type PeDataDirectory,
  type PeDetails,
} from "./executableImage.js";
import {
  captureImageParse,
  ImageDiagnostics,
  ImageReader,
  malformed,
  overlayAfter,
  unsupported,
} from "./imageReader.js";
import { parsePeImportsExports } from "./peImageImports.js";
import {
  buildDataDirectories,
  computePeChecksum,
  parseCoffSymbols,
  parseDebugInfo,
  parseLoadConfig,
  parseRichHeader,
  parseTlsCallbacks,
} from "./peImageExtras.js";

const SCN_MEM_EXECUTE = 0x2000_0000;
const SCN_MEM_READ = 0x4000_0000;
const SCN_MEM_WRITE = 0x8000_0000;
const DIR_RESOURCE = 2;
const DIR_SECURITY = 4;
const DIR_BASERELOC = 5;
const DIR_CLR = 14;
const SECTION_HEADER_BYTES = 40;
const SYMBOL_RECORD_BYTES = 18;

/** Shared, already-validated PE facts consumed by the directory sub-parsers. */
export interface PeImageContext {
  readonly reader: ImageReader;
  readonly bits: 32 | 64;
  readonly imageBase: bigint;
  readonly sections: readonly ImageSection[];
  readonly directories: readonly PeDataDirectory[];
  readonly diagnostics: ImageDiagnostics;
  readonly peOffset: number;
  readonly pointerToSymbolTable: number;
  readonly numberOfSymbols: number;
  rvaToOffset(rva: number, size: number): number | null;
}

interface RawSection {
  readonly virtualAddress: number;
  readonly virtualSize: number;
  readonly pointerToRawData: number;
  readonly sizeOfRawData: number;
}

interface OptionalHeader {
  readonly bits: 32 | 64;
  readonly entryRva: number;
  readonly imageBase: bigint;
  readonly sizeOfImage: number;
  readonly sizeOfHeaders: number;
  readonly fileAlignment: number;
  readonly checksum: number;
  readonly subsystem: number;
  readonly dllCharacteristics: number;
  readonly linkerVersion: string;
  readonly osVersion: string;
  readonly subsystemVersion: string;
  readonly directories: readonly PeDataDirectory[];
}

interface CoffHeader {
  readonly machine: number;
  readonly numberOfSections: number;
  readonly timeDateStamp: number;
  readonly pointerToSymbolTable: number;
  readonly numberOfSymbols: number;
  readonly sizeOfOptionalHeader: number;
  readonly characteristics: number;
}

const architectureForMachine = (machine: number): ImageArchitecture => {
  switch (machine) {
    case 0x8664:
      return "x86_64";
    case 0x014c:
      return "x86";
    case 0xaa64:
      return "arm64";
    case 0x01c0:
    case 0x01c2:
    case 0x01c4:
      return "arm";
    default:
      return null;
  }
};

const MACHINE_NAMES: ReadonlyMap<number, string> = new Map([
  [0x014c, "IMAGE_FILE_MACHINE_I386"],
  [0x8664, "IMAGE_FILE_MACHINE_AMD64"],
  [0xaa64, "IMAGE_FILE_MACHINE_ARM64"],
  [0x01c0, "IMAGE_FILE_MACHINE_ARM"],
  [0x01c2, "IMAGE_FILE_MACHINE_THUMB"],
  [0x01c4, "IMAGE_FILE_MACHINE_ARMNT"],
  [0x0200, "IMAGE_FILE_MACHINE_IA64"],
]);

const machineName = (machine: number): string =>
  MACHINE_NAMES.get(machine) ??
  `IMAGE_FILE_MACHINE_0x${machine.toString(16).padStart(4, "0")}`;

const readCoffHeader = (reader: ImageReader, peOffset: number): CoffHeader => {
  if (reader.u32(peOffset, "PE signature") !== 0x0000_4550)
    throw malformed("PE signature is not 'PE\\0\\0'");
  return {
    machine: reader.u16(peOffset + 4, "PE machine"),
    numberOfSections: reader.u16(peOffset + 6, "PE section count"),
    timeDateStamp: reader.u32(peOffset + 8, "PE timestamp"),
    pointerToSymbolTable: reader.u32(peOffset + 12, "PE symbol table pointer"),
    numberOfSymbols: reader.u32(peOffset + 16, "PE symbol count"),
    sizeOfOptionalHeader: reader.u16(peOffset + 20, "PE optional header size"),
    characteristics: reader.u16(peOffset + 22, "PE characteristics"),
  };
};

const version = (reader: ImageReader, offset: number): string =>
  `${reader.u16(offset, "PE version major")}.${reader.u16(offset + 2, "PE version minor")}`;

const readDirectories = (
  reader: ImageReader,
  optional: number,
  dataDirOffset: number,
  count: number,
): PeDataDirectory[] => {
  const bounded = Math.min(count, 16);
  const entries: { readonly rva: number; readonly size: number }[] = [];
  for (let index = 0; index < bounded; index += 1) {
    const base = optional + dataDirOffset + index * 8;
    entries.push({
      rva: reader.u32(base, "PE data directory rva"),
      size: reader.u32(base + 4, "PE data directory size"),
    });
  }
  return [...buildDataDirectories(entries)];
};

const readOptionalHeader = (
  reader: ImageReader,
  optional: number,
  sizeOfOptionalHeader: number,
): OptionalHeader => {
  if (sizeOfOptionalHeader < 2)
    throw malformed("PE optional header is missing its magic field");
  const magic = reader.u16(optional, "PE optional magic");
  const bits = magic === 0x10b ? 32 : magic === 0x20b ? 64 : null;
  if (bits === null)
    throw unsupported("Only PE32 and PE32+ images are supported");
  const dataDirOffset = bits === 64 ? 112 : 96;
  if (sizeOfOptionalHeader < dataDirOffset)
    throw malformed(
      "PE optional header is truncated before its data directories",
    );
  return {
    bits,
    entryRva: reader.u32(optional + 16, "PE entry rva"),
    imageBase: reader.word(
      optional + (bits === 64 ? 24 : 28),
      bits,
      "PE image base",
    ),
    sizeOfImage: reader.u32(optional + 56, "PE size of image"),
    sizeOfHeaders: reader.u32(optional + 60, "PE size of headers"),
    fileAlignment: reader.u32(optional + 36, "PE file alignment"),
    checksum: reader.u32(optional + 64, "PE checksum"),
    subsystem: reader.u16(optional + 68, "PE subsystem"),
    dllCharacteristics: reader.u16(optional + 70, "PE dll characteristics"),
    linkerVersion: `${reader.u8(optional + 2, "PE linker major")}.${reader.u8(optional + 3, "PE linker minor")}`,
    osVersion: version(reader, optional + 40),
    subsystemVersion: version(reader, optional + 48),
    directories: readDirectories(
      reader,
      optional,
      dataDirOffset,
      reader.u32(optional + dataDirOffset - 4, "PE number of rva and sizes"),
    ),
  };
};

const roundUp = (value: number, alignment: number): number =>
  alignment > 0 ? Math.ceil(value / alignment) * alignment : value;

const stringTableName = (
  reader: ImageReader,
  raw: string,
  symbolTableEnd: number,
  diagnostics: ImageDiagnostics,
): string => {
  if (!/^\/\d+$/.test(raw)) return raw;
  const offset = symbolTableEnd + Number(raw.slice(1));
  const resolved = reader.cString(
    offset,
    IMAGE_PARSE_LIMITS.stringBytes,
    "latin1",
  );
  if (resolved === null) {
    diagnostics.add(
      `PE long section name ${raw} is outside the COFF string table`,
    );
    return raw;
  }
  return resolved;
};

const readSections = (input: {
  readonly reader: ImageReader;
  readonly coff: CoffHeader;
  readonly optional: OptionalHeader;
  readonly start: number;
  readonly diagnostics: ImageDiagnostics;
}): { readonly sections: ImageSection[]; readonly raw: RawSection[] } => {
  const { reader, coff, optional, start, diagnostics } = input;
  const count = Math.min(coff.numberOfSections, IMAGE_PARSE_LIMITS.sections);
  const symbolTableEnd =
    coff.pointerToSymbolTable === 0
      ? 0
      : coff.pointerToSymbolTable + coff.numberOfSymbols * SYMBOL_RECORD_BYTES;
  const sections: ImageSection[] = [];
  const raw: RawSection[] = [];
  for (let index = 0; index < count; index += 1) {
    const entry = start + index * SECTION_HEADER_BYTES;
    const rawName = reader.fixedString(entry, 8, "PE section name");
    const virtualSize = reader.u32(entry + 8, "PE section virtual size");
    const virtualAddress = reader.u32(entry + 12, "PE section rva");
    const sizeOfRawData = reader.u32(entry + 16, "PE section raw size");
    const pointerToRawData = reader.u32(entry + 20, "PE section raw pointer");
    const characteristics = reader.u32(
      entry + 36,
      "PE section characteristics",
    );
    const rounded =
      virtualSize === 0
        ? sizeOfRawData
        : roundUp(virtualSize, optional.fileAlignment);
    sections.push({
      index,
      name:
        symbolTableEnd === 0
          ? rawName
          : stringTableName(reader, rawName, symbolTableEnd, diagnostics),
      segment_name: null,
      type: null,
      file_offset: pointerToRawData,
      file_size: Math.min(sizeOfRawData, rounded),
      virtual_address: optional.imageBase + BigInt(virtualAddress),
      virtual_size: BigInt(virtualSize === 0 ? sizeOfRawData : virtualSize),
      raw_flags: characteristics,
      readable: (characteristics & SCN_MEM_READ) !== 0,
      writable: (characteristics & SCN_MEM_WRITE) !== 0,
      executable: (characteristics & SCN_MEM_EXECUTE) !== 0,
    });
    raw.push({ virtualAddress, virtualSize, pointerToRawData, sizeOfRawData });
  }
  return { sections, raw };
};

const makeRvaToOffset = (
  raw: readonly RawSection[],
  sizeOfHeaders: number,
  fileLength: number,
): ((rva: number, size: number) => number | null) => {
  return (rva, size) => {
    if (!Number.isSafeInteger(rva) || rva < 0) return null;
    for (const section of raw) {
      const extent =
        section.virtualSize === 0
          ? section.sizeOfRawData
          : Math.max(section.virtualSize, section.sizeOfRawData);
      if (
        rva < section.virtualAddress ||
        rva >= section.virtualAddress + extent
      )
        continue;
      const delta = rva - section.virtualAddress;
      if (delta + size > section.sizeOfRawData) return null;
      const offset = section.pointerToRawData + delta;
      return offset + size <= fileLength ? offset : null;
    }
    if (rva + size <= sizeOfHeaders && rva + size <= fileLength) return rva;
    return null;
  };
};

const entryPoint = (
  sections: readonly ImageSection[],
  imageBase: bigint,
  entryRva: number,
  rvaToOffset: (rva: number, size: number) => number | null,
): ImageEntryPoint => {
  if (entryRva === 0)
    return { virtual_address: null, file_offset: null, section_index: null };
  const virtual = imageBase + BigInt(entryRva);
  const index = sections.findIndex(
    (section) =>
      section.virtual_size > 0n &&
      virtual >= section.virtual_address &&
      virtual < section.virtual_address + section.virtual_size,
  );
  return {
    virtual_address: virtual,
    file_offset: rvaToOffset(entryRva, 0),
    section_index: index === -1 ? null : index,
  };
};

const overlayEnds = (
  raw: readonly RawSection[],
  optional: OptionalHeader,
  coff: CoffHeader,
  reader: ImageReader,
): number[] => {
  const fileLength = reader.length;
  const within = (value: number): boolean => value <= fileLength;
  const ends = [optional.sizeOfHeaders];
  for (const section of raw) {
    const end = section.pointerToRawData + section.sizeOfRawData;
    if (section.sizeOfRawData > 0 && within(end)) ends.push(end);
  }
  const security = optional.directories[DIR_SECURITY];
  if (
    security !== undefined &&
    security.size > 0 &&
    within(security.rva + security.size)
  )
    ends.push(security.rva + security.size);
  if (coff.pointerToSymbolTable !== 0) {
    const symEnd =
      coff.pointerToSymbolTable + coff.numberOfSymbols * SYMBOL_RECORD_BYTES;
    if (within(symEnd + 4))
      ends.push(symEnd + reader.u32(symEnd, "PE string table size"));
    else if (within(symEnd)) ends.push(symEnd);
  }
  return ends.filter(within);
};

const buildPeDetails = (
  ctx: PeImageContext,
  coff: CoffHeader,
  optional: OptionalHeader,
): PeDetails => {
  const debug = parseDebugInfo(ctx);
  const security = optional.directories[DIR_SECURITY];
  const dirSize = (index: number): number =>
    optional.directories[index]?.size ?? 0;
  return {
    pe32_plus: ctx.bits === 64,
    machine: coff.machine,
    time_date_stamp: coff.timeDateStamp,
    characteristics: coff.characteristics,
    subsystem: optional.subsystem,
    dll_characteristics: optional.dllCharacteristics,
    image_base: optional.imageBase,
    size_of_image: optional.sizeOfImage,
    size_of_headers: optional.sizeOfHeaders,
    checksum: optional.checksum,
    computed_checksum: computePeChecksum(ctx.reader, ctx.peOffset),
    linker_version: optional.linkerVersion,
    os_version: optional.osVersion,
    subsystem_version: optional.subsystemVersion,
    data_directories: optional.directories,
    rich_header: parseRichHeader(ctx.reader, ctx.peOffset),
    load_config: parseLoadConfig(ctx),
    tls_callbacks: parseTlsCallbacks(ctx),
    debug_types: debug.debug_types,
    codeview: debug.codeview,
    ex_dll_characteristics: debug.ex_dll_characteristics,
    security_directory:
      security !== undefined && security.size > 0
        ? { file_offset: security.rva, size: security.size }
        : null,
    managed: dirSize(DIR_CLR) > 0,
    base_relocations: dirSize(DIR_BASERELOC) > 0,
    resources: dirSize(DIR_RESOURCE) > 0,
  };
};

const buildPeImage = (bytes: Buffer, peOffset: number): ExecutableImage => {
  const reader = new ImageReader(bytes, "little");
  const diagnostics = new ImageDiagnostics(IMAGE_PARSE_LIMITS.diagnostics);
  const coff = readCoffHeader(reader, peOffset);
  const optional = readOptionalHeader(
    reader,
    peOffset + 24,
    coff.sizeOfOptionalHeader,
  );
  const sectionStart = peOffset + 24 + coff.sizeOfOptionalHeader;
  const { sections, raw } = readSections({
    reader,
    coff,
    optional,
    start: sectionStart,
    diagnostics,
  });
  const rvaToOffset = makeRvaToOffset(
    raw,
    optional.sizeOfHeaders,
    reader.length,
  );
  const ctx: PeImageContext = {
    reader,
    bits: optional.bits,
    imageBase: optional.imageBase,
    sections,
    directories: optional.directories,
    diagnostics,
    peOffset,
    pointerToSymbolTable: coff.pointerToSymbolTable,
    numberOfSymbols: coff.numberOfSymbols,
    rvaToOffset,
  };
  const importsExports = parsePeImportsExports(ctx);
  const symbols = parseCoffSymbols(ctx);
  return {
    format: "pe",
    bits: optional.bits,
    byte_order: "little",
    architecture: architectureForMachine(coff.machine),
    machine: coff.machine,
    machine_name: machineName(coff.machine),
    image_offset: 0,
    image_size: bytes.length,
    entry_point: entryPoint(
      sections,
      optional.imageBase,
      optional.entryRva,
      rvaToOffset,
    ),
    sections,
    segments: [],
    imports: importsExports.imports,
    exports: importsExports.exports,
    libraries: importsExports.libraries,
    symbols: symbols.symbols,
    coverage: {
      imports: importsExports.importCoverage,
      exports: importsExports.exportCoverage,
      symbols: symbols.coverage,
    },
    overlay: overlayAfter(
      bytes.length,
      overlayEnds(raw, optional, coff, reader),
    ),
    container: { kind: "thin" },
    diagnostics: diagnostics.list(),
    elf: null,
    pe: buildPeDetails(ctx, coff, optional),
    macho: null,
  };
};

/** Parse one PE32 or PE32+ image at `peOffset` into the shared model. */
export const parsePeImage = (
  bytes: Buffer,
  peOffset: number,
): Result<ExecutableImage, ImageParseFailure> =>
  captureImageParse(() => buildPeImage(bytes, peOffset));
