import {
  GoBinaryFormatFailure,
  GoBinaryResourceFailure,
  mappedFileOffset,
  type GoBinaryContainer,
} from "../go/GoBinaryContainer.js";
import { readGoBinaryContainer } from "../go/GoBinaryImage.js";
import { parseExecutableImage } from "../domain/native/image/parseExecutableImage.js";
import type { ImageArchitecture } from "../domain/native/image/executableImage.js";
import type {
  GoRecoveredFunction,
  RecoverGoSymbolsInput,
  RecoverGoSymbolsReport,
} from "../domain/triage/recoverGoSymbols.js";
import {
  toHexAddress,
  type triageListCoverageSchema,
} from "../domain/triage/triageCommon.js";
import type { z } from "zod";
import {
  checkTriageCancelled,
  TriageAnalysisFailure,
  yieldTriage,
  type TriageAnalysisContext,
} from "./triageSupport.js";
import { findPclntab } from "./RecoverGoSymbolsPclntab.js";

type Coverage = z.infer<typeof triageListCoverageSchema>;
type Report = Omit<RecoverGoSymbolsReport, "artifact">;

/** Fat Mach-O container magics that require selecting a thin slice first. */
const FAT_MAGICS = new Set([
  0xcafe_babe, 0xcafe_babf, 0xbeba_feca, 0xbfba_feca,
]);
/** Largest set of derived package prefixes returned inline. */
const PACKAGE_LIMIT = 5000;

/**
 * Recover function names and entry addresses from the Go `pclntab` embedded in
 * a stripped Go binary, reading the file once without executing it, without
 * network access and without writing files.
 */
export const analyzeRecoverGoSymbols = async (
  bytes: Buffer,
  input: RecoverGoSymbolsInput,
  context: TriageAnalysisContext,
): Promise<Report> => {
  checkTriageCancelled(context.signal);
  const loaded = loadContainer(bytes, input.slice);
  if (loaded.container === null) return notGo(loaded.sliceUsed);
  const { container, working, sliceBase } = loaded;
  const subject = {
    format:
      container.format === "macho" ? ("mach-o" as const) : container.format,
    architecture: container.architecture,
  };
  await yieldTriage(context.signal);
  const decoded = findPclntab(
    working,
    container,
    input.max_functions,
    context.signal,
  );
  if (decoded === null)
    return {
      subject,
      is_go: false,
      go_version_magic: null,
      pclntab: null,
      functions: [],
      function_coverage: emptyCoverage(),
      package_names: [],
      package_coverage: emptyCoverage(),
      limitations: noPclntabLimitations(loaded.sliceUsed),
    };
  const functions = mapFunctions(decoded.functions, container, sliceBase);
  const { packages, packageCoverage } = derivePackages(functions);
  const truncatedFunctions = functions.length < decoded.functionCount;
  const unmapped = functions.some((entry) => entry.file_offset === null);
  return {
    subject,
    is_go: true,
    go_version_magic: toHexAddress(decoded.magic >>> 0),
    pclntab: {
      file_offset: sliceBase + decoded.fileOffset,
      version: decoded.version,
      function_count: decoded.functionCount,
      pointer_size: decoded.pointerSize,
    },
    functions,
    function_coverage: {
      total: decoded.functionCount,
      returned: functions.length,
      truncated: truncatedFunctions,
    },
    package_names: packages,
    package_coverage: packageCoverage,
    limitations: recoveredLimitations(
      input.max_functions,
      truncatedFunctions,
      unmapped,
      loaded.sliceUsed,
    ),
  };
};

interface LoadedContainer {
  readonly container: GoBinaryContainer | null;
  readonly working: Buffer;
  readonly sliceBase: number;
  readonly sliceUsed: boolean;
}

/** Identify the native container, extracting a universal slice when selected. */
const loadContainer = (
  bytes: Buffer,
  slice: RecoverGoSymbolsInput["slice"],
): LoadedContainer => {
  try {
    return {
      container: readGoBinaryContainer(bytes),
      working: bytes,
      sliceBase: 0,
      sliceUsed: false,
    };
  } catch (cause) {
    return recoverContainer(bytes, slice, cause);
  }
};

const recoverContainer = (
  bytes: Buffer,
  slice: RecoverGoSymbolsInput["slice"],
  cause: unknown,
): LoadedContainer => {
  if (cause instanceof GoBinaryResourceFailure)
    throw new TriageAnalysisFailure("resource", cause.message, {
      maximum_bytes: cause.maximum_bytes,
    });
  if (!(cause instanceof GoBinaryFormatFailure)) throw cause;
  if (cause.kind === "malformed")
    throw new TriageAnalysisFailure("malformed", cause.message);
  if (!isFatContainer(bytes))
    return { container: null, working: bytes, sliceBase: 0, sliceUsed: false };
  if (slice === undefined)
    throw new TriageAnalysisFailure(
      "unsupported",
      "Universal Mach-O container: select a thin slice with `slice` before recovering Go symbols.",
    );
  return extractSlice(bytes, slice);
};

const extractSlice = (
  bytes: Buffer,
  slice: Exclude<ImageArchitecture, null>,
): LoadedContainer => {
  const parsed = parseExecutableImage(bytes, {
    slice: { architecture: slice },
  });
  if (!parsed.ok)
    throw new TriageAnalysisFailure(
      parsed.error.kind === "malformed" ? "malformed" : "unsupported",
      parsed.error.message,
    );
  const base = parsed.value.image_offset;
  const working = bytes.subarray(base, base + parsed.value.image_size);
  try {
    return {
      container: readGoBinaryContainer(working),
      working,
      sliceBase: base,
      sliceUsed: true,
    };
  } catch (cause) {
    if (cause instanceof GoBinaryResourceFailure)
      throw new TriageAnalysisFailure("resource", cause.message, {
        maximum_bytes: cause.maximum_bytes,
      });
    if (cause instanceof GoBinaryFormatFailure && cause.kind === "malformed")
      throw new TriageAnalysisFailure("malformed", cause.message);
    if (cause instanceof GoBinaryFormatFailure)
      return { container: null, working, sliceBase: base, sliceUsed: true };
    throw cause;
  }
};

const isFatContainer = (bytes: Buffer): boolean =>
  bytes.length >= 4 && FAT_MAGICS.has(bytes.readUInt32BE(0));

const mapFunctions = (
  decoded: readonly { readonly name: string; readonly entry: bigint }[],
  container: GoBinaryContainer,
  sliceBase: number,
): GoRecoveredFunction[] =>
  decoded.map((entry) => ({
    name: entry.name,
    entry: toHexAddress(entry.entry),
    file_offset: entryFileOffset(container, entry.entry, sliceBase),
  }));

/** Map an entry address to an absolute file offset, or null when not mapped. */
const entryFileOffset = (
  container: GoBinaryContainer,
  entry: bigint,
  sliceBase: number,
): number | null => {
  try {
    return (
      sliceBase +
      mappedFileOffset(container.mappings, entry, 1, container.zero_fills)
    );
  } catch (cause) {
    if (cause instanceof GoBinaryFormatFailure) return null;
    throw cause;
  }
};

const derivePackages = (
  functions: readonly GoRecoveredFunction[],
): { packages: string[]; packageCoverage: Coverage } => {
  const unique = new Set<string>();
  for (const fn of functions) {
    const pkg = packageOf(fn.name);
    if (pkg !== null) unique.add(pkg);
  }
  const sorted = [...unique].sort();
  const packages = sorted.slice(0, PACKAGE_LIMIT);
  return {
    packages,
    packageCoverage: {
      total: sorted.length,
      returned: packages.length,
      truncated: packages.length < sorted.length,
    },
  };
};

/** Package path prefix of a Go symbol name, or null when it carries none. */
const packageOf = (name: string): string | null => {
  const lastSlash = name.lastIndexOf("/");
  const segment = lastSlash < 0 ? name : name.slice(lastSlash + 1);
  const dot = segment.indexOf(".");
  if (dot <= 0) return null;
  const prefix = lastSlash < 0 ? "" : name.slice(0, lastSlash + 1);
  const pkg = prefix + segment.slice(0, dot);
  return pkg.length === 0 ? null : pkg;
};

const emptyCoverage = (): Coverage => ({
  total: 0,
  returned: 0,
  truncated: false,
});

const notGo = (sliceUsed: boolean): Report => ({
  subject: { format: "file", architecture: null },
  is_go: false,
  go_version_magic: null,
  pclntab: null,
  functions: [],
  function_coverage: emptyCoverage(),
  package_names: [],
  package_coverage: emptyCoverage(),
  limitations: [
    "The file is not an ELF, PE or thin Mach-O image, so no Go pclntab could be located; absence is not proof the file is not Go.",
    ...(sliceUsed
      ? ["The selected universal slice is not a recognized native container."]
      : []),
    "Read without executing the target, without network access, and without writing files.",
  ],
});

const AUTHORITY_CAVEATS = [
  "Function names are observed from the embedded pclntab; reachability, linkage and current validity are not established.",
  "moduledata, typelinks and inlined-function metadata are out of scope; only pclntab function names and entries are recovered.",
  "Package names are heuristic prefixes derived from returned function names, not an authoritative module list.",
];

const noPclntabLimitations = (sliceUsed: boolean): string[] => [
  "No decodable pclntab magic was found in read-only sections; the file may be non-Go, a Go object without a pclntab, or use an unsupported layout.",
  ...(sliceUsed
    ? ["Analysis was limited to the selected universal slice."]
    : []),
  "Read without executing the target, without network access, and without writing files.",
];

const recoveredLimitations = (
  maxFunctions: number,
  truncated: boolean,
  unmapped: boolean,
  sliceUsed: boolean,
): string[] => [
  ...AUTHORITY_CAVEATS,
  ...(truncated
    ? [
        `At most ${maxFunctions} named functions are returned inline, and entries without a recoverable name are omitted; totals are reported through function_coverage.`,
      ]
    : []),
  ...(unmapped
    ? [
        "Some entry addresses are not file-backed by the container mappings; their file_offset is reported as null.",
      ]
    : []),
  ...(sliceUsed
    ? [
        "Offsets are absolute in the whole file, recovered from the selected universal slice.",
      ]
    : []),
  "Read without executing the target, without network access, and without writing files.",
];
