/**
 * Mach-O image parser: resolves a thin slice or one slice of a universal
 * (FAT) container into the shared format-neutral model. Interpretation of the
 * header and load-command structures lives here; static analyzers consume the
 * projected facts rather than re-reading Mach-O bytes.
 */

import { readFatContainerHeader } from "../../apple/machoContainer.js";
import type { Result } from "../../result.js";
import {
  IMAGE_PARSE_LIMITS,
  type ExecutableImage,
  type ImageArchitecture,
  type ImageContainer,
  type ImageEntryPoint,
  type ImageFatSlice,
  type ImageListCoverage,
  type ImageParseFailure,
  type ImageParseOptions,
  type MachoDetails,
} from "./executableImage.js";
import {
  captureImageParse,
  fileOffsetForAddress,
  ImageDiagnostics,
  ImageReader,
  malformed,
  overlayAfter,
  sectionContainingAddress,
  sectionContainingOffset,
  unsupported,
} from "./imageReader.js";
import {
  commandName,
  LC_SEGMENT,
  LC_SEGMENT_64,
  readMetadataCommand,
  readSegmentCommand,
  type MachoCommandScan,
  type MachoScanContext,
} from "./machoImageCommands.js";
import { readNlistSymbols, type NlistTables } from "./machoImageSymbols.js";

const FAT_MAGICS: readonly number[] = [
  0xcafe_babe, 0xcafe_babf, 0xbeba_feca, 0xbfba_feca,
];
const MACHO_LE_64 = 0xcffa_edfe;
const MACHO_LE_32 = 0xcefa_edfe;
const MACHO_BE_64 = 0xfeed_facf;
const MACHO_BE_32 = 0xfeed_face;

const ARCHITECTURES = new Map<number, Exclude<ImageArchitecture, null>>([
  [0x0100_000c, "arm64"],
  [0x0100_0007, "x86_64"],
  [0x7, "x86"],
  [0xc, "arm"],
  [0x0100_0012, "powerpc"],
]);
const MACHINE_NAMES = new Map<number, string>([
  [0x0100_000c, "ARM64"],
  [0x0100_0007, "X86_64"],
  [0x7, "X86"],
  [0xc, "ARM"],
  [0x12, "POWERPC"],
  [0x0100_0012, "POWERPC64"],
]);

const architectureOf = (cpuType: number): ImageArchitecture =>
  ARCHITECTURES.get(cpuType) ?? null;

const machineNameOf = (cpuType: number): string =>
  MACHINE_NAMES.get(cpuType) ?? `CPU_TYPE(0x${cpuType.toString(16)})`;

/** The selected slice's physical range plus the container description. */
interface SelectedSlice {
  readonly sliceOffset: number;
  readonly sliceSize: number;
  readonly container: ImageContainer;
}

const sliceByOptions = (
  slices: readonly ImageFatSlice[],
  options: ImageParseOptions,
): number => {
  const selector = options.slice;
  if (selector === undefined) return 0;
  if ("index" in selector) {
    if (
      !Number.isInteger(selector.index) ||
      selector.index < 0 ||
      selector.index >= slices.length
    )
      throw unsupported(
        `Requested FAT slice index ${selector.index} is out of range`,
      );
    return selector.index;
  }
  const match = slices.findIndex(
    (slice) => slice.architecture === selector.architecture,
  );
  if (match < 0)
    throw unsupported(
      `Requested architecture ${selector.architecture} is not in the FAT container`,
    );
  return match;
};

/** Read the FAT table, map its slices, and select one by options. */
const selectFatSlice = (
  bytes: Buffer,
  options: ImageParseOptions,
): SelectedSlice => {
  const header = readFatContainerHeader(bytes, bytes.length);
  if (header.state === "malformed") throw malformed(header.reason);
  if (header.state !== "parsed")
    throw unsupported("The FAT Mach-O container is not supported");
  const slices: ImageFatSlice[] = header.slices.map((slice) => ({
    cpu_type: slice.cpuType,
    cpu_subtype: slice.cpuSubtype,
    architecture: architectureOf(slice.cpuType),
    file_offset: slice.offset,
    size: slice.size,
    align: slice.alignmentExponent,
  }));
  const index = sliceByOptions(slices, options);
  const issue = header.rangeIssues[index];
  if (issue != null)
    throw (issue.category === "unsupported" ? unsupported : malformed)(
      issue.reason,
    );
  return {
    sliceOffset: slices[index]!.file_offset,
    sliceSize: slices[index]!.size,
    container: { kind: "fat", slices, selected_index: index },
  };
};

/** Header geometry read from the thin slice's Mach-O magic. */
interface SliceHeader {
  readonly bits: 32 | 64;
  readonly cpuType: number;
  readonly cpuSubtype: number;
  readonly fileType: number;
  readonly flags: number;
  readonly ncmds: number;
  readonly sizeofcmds: number;
  readonly headerSize: number;
}

const readSliceHeader = (
  reader: ImageReader,
  sliceOffset: number,
): SliceHeader => {
  reader.require(sliceOffset, 4, "Mach-O magic");
  const magic = reader.bytes.readUInt32BE(sliceOffset);
  if (magic === MACHO_BE_32 || magic === MACHO_BE_64)
    throw unsupported("Big-endian Mach-O images are not supported");
  if (magic !== MACHO_LE_32 && magic !== MACHO_LE_64)
    throw malformed("The slice does not begin with a Mach-O header magic");
  const bits = magic === MACHO_LE_64 ? 64 : 32;
  const headerSize = bits === 64 ? 32 : 28;
  reader.require(sliceOffset, headerSize, "Mach-O header");
  return {
    bits,
    cpuType: reader.u32(sliceOffset + 4, "cputype"),
    cpuSubtype: reader.u32(sliceOffset + 8, "cpusubtype"),
    fileType: reader.u32(sliceOffset + 12, "filetype"),
    ncmds: reader.u32(sliceOffset + 16, "ncmds"),
    sizeofcmds: reader.u32(sliceOffset + 20, "sizeofcmds"),
    flags: reader.u32(sliceOffset + 24, "flags"),
    headerSize,
  };
};

const emptyScan = (): MachoCommandScan => ({
  segments: [],
  sections: [],
  loadCommands: [],
  dylibs: [],
  libraries: [],
  rpaths: [],
  buildVersions: [],
  sourceVersion: null,
  uuid: null,
  idDylib: null,
  encryption: null,
  codeSignature: null,
  symtab: null,
  entry: null,
  hasRestrictSegment: false,
  usesChainedFixups: false,
  declaredEnds: [],
});

/** Walk the load-command table, bounded by the parser limits. */
const scanCommands = (
  context: MachoScanContext,
  header: SliceHeader,
): MachoCommandScan => {
  const { reader, sliceOffset, diagnostics } = context;
  const scan = emptyScan();
  const start = sliceOffset + header.headerSize;
  const end = start + header.sizeofcmds;
  reader.require(start, header.sizeofcmds, "Mach-O load commands");
  const count = Math.min(header.ncmds, IMAGE_PARSE_LIMITS.loadCommands);
  if (header.ncmds > IMAGE_PARSE_LIMITS.loadCommands)
    diagnostics.add("Load-command list truncated at the parser bound.");
  let offset = start;
  for (let i = 0; i < count; i++) {
    const command = reader.u32(offset, "load command");
    const size = reader.u32(offset + 4, "load command size");
    if (size < 8 || size % 4 !== 0 || offset + size > end)
      throw malformed("Mach-O load command size is invalid or truncated");
    scan.loadCommands.push({
      command,
      name: commandName(command),
      offset,
      size,
    });
    if (command === LC_SEGMENT || command === LC_SEGMENT_64) {
      if ((command === LC_SEGMENT_64) !== (header.bits === 64))
        throw malformed(
          "Mach-O segment command width disagrees with the header",
        );
      readSegmentCommand(context, offset, size, scan);
    } else readMetadataCommand(context, { command, base: offset, size }, scan);
    offset += size;
  }
  return scan;
};

const buildEntryPoint = (
  scan: MachoCommandScan,
  sections: MachoCommandScan["sections"],
): ImageEntryPoint => {
  if (scan.entry === null)
    return { virtual_address: null, file_offset: null, section_index: null };
  if (scan.entry.kind === "main") {
    const fileOffset = scan.entry.fileOffset;
    const section = sectionContainingOffset(sections, fileOffset);
    return section === undefined
      ? { virtual_address: null, file_offset: fileOffset, section_index: null }
      : {
          virtual_address:
            section.virtual_address + BigInt(fileOffset - section.file_offset),
          file_offset: fileOffset,
          section_index: section.index,
        };
  }
  const section = sectionContainingAddress(sections, scan.entry.pc);
  return {
    virtual_address: scan.entry.pc,
    file_offset: fileOffsetForAddress(sections, scan.entry.pc),
    section_index: section?.index ?? null,
  };
};

const resolveCoverage = (
  scan: MachoCommandScan,
  tables: NlistTables | null,
  diagnostics: ImageDiagnostics,
): ImageListCoverage => {
  if (tables === null) {
    diagnostics.add("No LC_SYMTAB load command; symbol lists are unavailable.");
    return {
      imports: "unavailable",
      exports: "unavailable",
      symbols: "unavailable",
    };
  }
  const list = (
    truncated: boolean,
    empty: boolean,
    label: string,
  ): "complete" | "truncated" | "unavailable" => {
    if (truncated) return "truncated";
    if (empty && scan.usesChainedFixups) {
      diagnostics.add(
        `No classic nlist ${label}; chained-fixup data is not decoded.`,
      );
      return "unavailable";
    }
    return "complete";
  };
  return {
    imports: list(
      tables.importsTruncated,
      tables.imports.length === 0,
      "imports",
    ),
    exports: list(
      tables.exportsTruncated,
      tables.exports.length === 0,
      "exports",
    ),
    symbols: tables.symbolsTruncated ? "truncated" : "complete",
  };
};

const buildDetails = (
  header: SliceHeader,
  scan: MachoCommandScan,
): MachoDetails => ({
  cpu_type: header.cpuType,
  cpu_subtype: header.cpuSubtype,
  file_type: header.fileType,
  flags: header.flags,
  load_commands: scan.loadCommands,
  uuid: scan.uuid,
  build_versions: scan.buildVersions,
  source_version: scan.sourceVersion,
  dylibs: scan.dylibs,
  id_dylib: scan.idDylib,
  rpaths: scan.rpaths,
  encryption: scan.encryption,
  code_signature: scan.codeSignature,
  has_restrict_segment: scan.hasRestrictSegment,
  uses_chained_fixups: scan.usesChainedFixups,
});

/**
 * Parse one thin Mach-O image, or the selected slice of a universal binary,
 * into the shared executable-image model. Throws typed refusals internally;
 * `captureImageParse` converts them to a Result failure at the boundary.
 */
export const parseMachoImage = (
  bytes: Buffer,
  options: ImageParseOptions,
): Result<ExecutableImage, ImageParseFailure> =>
  captureImageParse(() => {
    const isFat =
      bytes.length >= 4 && FAT_MAGICS.includes(bytes.readUInt32BE(0));
    const { sliceOffset, sliceSize, container } = isFat
      ? selectFatSlice(bytes, options)
      : {
          sliceOffset: 0,
          sliceSize: bytes.length,
          container: { kind: "thin" as const },
        };
    const reader = new ImageReader(bytes, "little");
    const header = readSliceHeader(reader, sliceOffset);
    const diagnostics = new ImageDiagnostics(IMAGE_PARSE_LIMITS.diagnostics);
    const context: MachoScanContext = {
      reader,
      sliceOffset,
      bits: header.bits,
      cpuType: header.cpuType,
      diagnostics,
    };
    const scan = scanCommands(context, header);
    const tables =
      scan.symtab === null
        ? null
        : readNlistSymbols({
            reader,
            bits: header.bits,
            symtab: scan.symtab,
            dylibNames: scan.dylibs.map((dylib) => dylib.name),
            sections: scan.sections,
          });
    const coverage = resolveCoverage(scan, tables, diagnostics);
    const declaredEnds = [
      ...scan.declaredEnds,
      sliceOffset + header.headerSize + header.sizeofcmds,
      sliceOffset + sliceSize,
      ...(container.kind === "fat"
        ? container.slices.map((slice) => slice.file_offset + slice.size)
        : []),
    ];
    return {
      format: "macho",
      bits: header.bits,
      byte_order: "little",
      architecture: architectureOf(header.cpuType),
      machine: header.cpuType,
      machine_name: machineNameOf(header.cpuType),
      image_offset: sliceOffset,
      image_size: sliceSize,
      entry_point: buildEntryPoint(scan, scan.sections),
      sections: scan.sections,
      segments: scan.segments,
      imports: tables?.imports ?? [],
      exports: tables?.exports ?? [],
      libraries: scan.libraries,
      symbols: tables?.symbols ?? [],
      coverage,
      overlay: overlayAfter(bytes.length, declaredEnds),
      container,
      diagnostics: diagnostics.list(),
      elf: null,
      pe: null,
      macho: buildDetails(header, scan),
    };
  });
