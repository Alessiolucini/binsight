import type {
  ExecutableImage,
  ImageContainer,
  ImageExport,
  ImageImport,
  ImageLibrary,
  ImagePermissions,
  ImageSection,
  ImageSegment,
  ImageSymbol,
} from "../domain/native/image/executableImage.js";
import type { z } from "zod";
import type {
  InspectExecutableInclude,
  InspectExecutableInput,
  InspectExecutableReport,
} from "../domain/triage/inspectExecutable.js";
import {
  toHexAddress,
  type triageListCoverageSchema,
} from "../domain/triage/triageCommon.js";
import {
  elfDetailBlock,
  machoDetailBlock,
  peDetailBlock,
} from "./InspectExecutableDetails.js";
import {
  checkTriageCancelled,
  requireTriageImage,
  triageSubject,
  yieldTriage,
  type TriageAnalysisContext,
} from "./triageSupport.js";

type ReportBody = Omit<InspectExecutableReport, "artifact">;
type Coverage = z.infer<typeof triageListCoverageSchema>;

interface BoundedList<T> {
  readonly list: T[];
  readonly coverage: Coverage;
}

/**
 * Unified ELF/PE/Mach-O structural view projected from the shared parsed image
 * model. Reads the selected file once without executing it; every list honors
 * the caller's max_list bound and reports its own coverage.
 */
export const analyzeInspectExecutable = async (
  bytes: Buffer,
  input: InspectExecutableInput,
  context: TriageAnalysisContext,
): Promise<ReportBody> => {
  checkTriageCancelled(context.signal);
  const image = requireTriageImage(bytes, input.slice);
  const included = new Set(input.include);
  const max = input.max_list;

  const sections = bounded(
    image.sections,
    included.has("sections"),
    max,
    mapSection,
  );
  const segments = bounded(
    image.segments,
    included.has("segments"),
    max,
    mapSegment,
  );
  const imports = bounded(
    image.imports,
    included.has("imports"),
    max,
    mapImport,
  );
  const exports = bounded(
    image.exports,
    included.has("exports"),
    max,
    mapExport,
  );
  const libraries = bounded(
    image.libraries,
    included.has("libraries"),
    max,
    mapLibrary,
  );
  const symbols = bounded(
    image.symbols,
    included.has("symbols"),
    max,
    mapSymbol,
  );
  await yieldTriage(context.signal);

  return {
    subject: triageSubject(image),
    format: image.format,
    bits: image.bits,
    byte_order: image.byte_order,
    architecture: image.architecture,
    machine: { value: image.machine, name: image.machine_name },
    entry_point: entryPoint(image),
    counts: {
      sections: image.sections.length,
      segments: image.segments.length,
      imports: image.imports.length,
      exports: image.exports.length,
      symbols: image.symbols.length,
      libraries: image.libraries.length,
    },
    sections: sections.list,
    sections_coverage: sections.coverage,
    segments: segments.list,
    segments_coverage: segments.coverage,
    imports: imports.list,
    imports_coverage: imports.coverage,
    exports: exports.list,
    exports_coverage: exports.coverage,
    libraries: libraries.list,
    libraries_coverage: libraries.coverage,
    symbols: symbols.list,
    symbols_coverage: symbols.coverage,
    overlay:
      image.overlay === null
        ? null
        : { file_offset: image.overlay.file_offset, size: image.overlay.size },
    container: container(image.container),
    elf: image.elf === null ? null : elfDetailBlock(image.elf),
    pe: image.pe === null ? null : peDetailBlock(image.pe, max),
    macho: image.macho === null ? null : machoDetailBlock(image.macho),
    limitations: limitations(image, input.include, {
      sections: sections.coverage,
      segments: segments.coverage,
      imports: imports.coverage,
      exports: exports.coverage,
      libraries: libraries.coverage,
      symbols: symbols.coverage,
    }),
  };
};

const bounded = <T, R>(
  items: readonly T[],
  include: boolean,
  max: number,
  map: (item: T) => R,
): BoundedList<R> => {
  const total = items.length;
  const returned = include ? Math.min(total, max) : 0;
  return {
    list: include ? items.slice(0, returned).map(map) : [],
    coverage: { total, returned, truncated: returned < total },
  };
};

const permissions = (value: ImagePermissions): string =>
  `${value.readable ? "r" : "-"}${value.writable ? "w" : "-"}${value.executable ? "x" : "-"}`;

const mapSection = (section: ImageSection) => ({
  index: section.index,
  name: section.name,
  type: section.type,
  segment_name: section.segment_name,
  permissions: permissions(section),
  file_offset: section.file_offset,
  file_size: section.file_size,
  virtual_address: toHexAddress(section.virtual_address),
  virtual_size: toHexAddress(section.virtual_size),
});

const mapSegment = (segment: ImageSegment) => ({
  index: segment.index,
  name: segment.name,
  type: segment.type,
  permissions: permissions(segment),
  file_offset: segment.file_offset,
  file_size: segment.file_size,
  virtual_address: toHexAddress(segment.virtual_address),
  memory_size: toHexAddress(segment.memory_size),
});

const mapImport = (entry: ImageImport) => ({
  library: entry.library,
  name: entry.name,
  ordinal: entry.ordinal,
  delay_loaded: entry.delay_loaded,
  weak: entry.weak,
  version: entry.version,
});

const mapExport = (entry: ImageExport) => ({
  name: entry.name,
  ordinal: entry.ordinal,
  address: entry.address === null ? null : toHexAddress(entry.address),
  forwarder: entry.forwarder,
  kind: entry.kind,
});

const mapLibrary = (entry: ImageLibrary) => ({
  name: entry.name,
  kind: entry.kind,
});

const mapSymbol = (symbol: ImageSymbol) => ({
  name: symbol.name,
  value: toHexAddress(symbol.value),
  size: toHexAddress(symbol.size),
  type: symbol.type,
  binding: symbol.binding,
  defined: symbol.defined,
  table: symbol.table,
});

const entryPoint = (image: ExecutableImage): ReportBody["entry_point"] => {
  const entry = image.entry_point;
  const section =
    entry.section_index === null
      ? null
      : (image.sections[entry.section_index]?.name ?? null);
  return {
    virtual_address:
      entry.virtual_address === null
        ? null
        : toHexAddress(entry.virtual_address),
    file_offset: entry.file_offset,
    section,
  };
};

const container = (value: ImageContainer): ReportBody["container"] =>
  value.kind === "thin"
    ? { kind: "thin" }
    : {
        kind: "fat",
        selected_index: value.selected_index,
        slices: value.slices.map((slice) => ({
          cpu_type: slice.cpu_type,
          cpu_subtype: slice.cpu_subtype,
          architecture: slice.architecture,
          file_offset: slice.file_offset,
          size: slice.size,
          align: slice.align,
        })),
      };

const CATEGORY_KEYS = [
  "sections",
  "segments",
  "imports",
  "exports",
  "libraries",
  "symbols",
] as const;

const limitations = (
  image: ExecutableImage,
  include: readonly InspectExecutableInclude[],
  coverages: Readonly<Record<(typeof CATEGORY_KEYS)[number], Coverage>>,
): string[] => {
  const notes: string[] = [
    "Structure is read from the file's own headers and tables; it is a shipped-artifact observation, not proof the image loads, runs, or is unmodified.",
    "The selected file is read once (up to 256 MiB) without executing it, without network access and without writing files; the report is bounded to 8 MiB and each list to the max_list bound.",
    `Only the ${image.format} detail block is populated; cross-format fields are null by construction.`,
  ];
  const includedSet = new Set(include);
  for (const key of CATEGORY_KEYS) {
    const coverage = coverages[key];
    if (!includedSet.has(key) && coverage.total > 0)
      notes.push(
        `The ${key} list was not requested; ${coverage.total} ${key} were omitted (add "${key}" to include).`,
      );
    else if (includedSet.has(key) && coverage.truncated)
      notes.push(
        `Only ${coverage.returned} of ${coverage.total} ${key} are returned; raise max_list (maximum 5000) to see more.`,
      );
  }
  for (const [key, state] of Object.entries(image.coverage))
    if (state === "truncated")
      notes.push(
        `The parser reached its internal bound for ${key}; the ${key} count is a lower bound.`,
      );
    else if (state === "unavailable")
      notes.push(`The ${key} table is unavailable for this image.`);
  if (image.container.kind === "fat")
    notes.push(
      `Universal binary: the selected slice (index ${image.container.selected_index}) was analyzed; other slices are listed under container.slices.`,
    );
  for (const diagnostic of image.diagnostics)
    notes.push(`Parser diagnostic: ${diagnostic}`);
  return notes;
};
