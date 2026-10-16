import {
  IMAGE_PARSE_LIMITS,
  type ImageExport,
  type ImageImport,
  type ImageLibrary,
  type ImageLibraryKind,
} from "./executableImage.js";
import type { PeImageContext } from "./peImage.js";

const DIR_EXPORT = 0;
const DIR_IMPORT = 1;
const DIR_DELAY_IMPORT = 13;
const IMPORT_DESCRIPTOR_BYTES = 20;
const DELAY_DESCRIPTOR_BYTES = 32;
const EXPORT_DIRECTORY_BYTES = 40;

/** Imports, exports and the per-library index projected from the PE directories. */
export interface PeImportsExports {
  readonly imports: readonly ImageImport[];
  readonly exports: readonly ImageExport[];
  readonly libraries: readonly ImageLibrary[];
  readonly importCoverage: "complete" | "truncated" | "unavailable";
  readonly exportCoverage: "complete" | "truncated" | "unavailable";
}

const readRvaString = (ctx: PeImageContext, rva: number): string | null => {
  if (rva === 0) return null;
  const offset = ctx.rvaToOffset(rva, 1);
  if (offset === null) return null;
  return ctx.reader.cString(offset, IMAGE_PARSE_LIMITS.stringBytes, "latin1");
};

/** Walk one import lookup table (ILT or, as fallback, the IAT). */
const walkThunks = (
  ctx: PeImageContext,
  tableRva: number,
  library: string | null,
  delayLoaded: boolean,
): { readonly entries: ImageImport[]; readonly truncated: boolean } => {
  const entries: ImageImport[] = [];
  const width = ctx.bits / 8;
  const ordinalFlag = ctx.bits === 64 ? 1n << 63n : 1n << 31n;
  for (let index = 0; index < IMAGE_PARSE_LIMITS.imports + 1; index += 1) {
    const slotOffset = ctx.rvaToOffset(tableRva + index * width, width);
    if (slotOffset === null) break;
    const value = ctx.reader.word(slotOffset, ctx.bits, "PE import thunk");
    if (value === 0n) break;
    if (entries.length >= IMAGE_PARSE_LIMITS.imports)
      return { entries, truncated: true };
    entries.push(
      (value & ordinalFlag) !== 0n
        ? ordinalImport(value, library, delayLoaded)
        : namedImport(ctx, Number(value & 0x7fff_ffffn), library, delayLoaded),
    );
  }
  return { entries, truncated: false };
};

const ordinalImport = (
  value: bigint,
  library: string | null,
  delayLoaded: boolean,
): ImageImport => ({
  library,
  name: null,
  ordinal: Number(value & 0xffffn),
  delay_loaded: delayLoaded,
  weak: false,
  version: null,
});

const namedImport = (
  ctx: PeImageContext,
  hintNameRva: number,
  library: string | null,
  delayLoaded: boolean,
): ImageImport => {
  const offset = ctx.rvaToOffset(hintNameRva, 2);
  const name =
    offset === null
      ? null
      : ctx.reader.cString(
          offset + 2,
          IMAGE_PARSE_LIMITS.stringBytes,
          "latin1",
        );
  return {
    library,
    name,
    ordinal: null,
    delay_loaded: delayLoaded,
    weak: false,
    version: null,
  };
};

/** One descriptor table (normal or delay-load) yields imports and library names. */
const walkDescriptors = (
  ctx: PeImageContext,
  delayLoaded: boolean,
  out: { readonly imports: ImageImport[]; readonly libraries: string[] },
): boolean => {
  const directory =
    ctx.directories[delayLoaded ? DIR_DELAY_IMPORT : DIR_IMPORT];
  if (directory === undefined || directory.rva === 0) return false;
  const stride = delayLoaded ? DELAY_DESCRIPTOR_BYTES : IMPORT_DESCRIPTOR_BYTES;
  const nameField = delayLoaded ? 4 : 12;
  const iltField = delayLoaded ? 16 : 0;
  const iatField = delayLoaded ? 12 : 16;
  for (let index = 0; index < IMAGE_PARSE_LIMITS.libraries; index += 1) {
    const base = ctx.rvaToOffset(directory.rva + index * stride, stride);
    if (base === null) break;
    const names = ctx.reader.u32(base + nameField, "PE import name rva");
    const ilt = ctx.reader.u32(base + iltField, "PE import lookup table");
    const iat = ctx.reader.u32(base + iatField, "PE import address table");
    if (names === 0 && ilt === 0 && iat === 0) break;
    const library = resolveLibrary(ctx, names, delayLoaded);
    out.libraries.push(library ?? "");
    const table = ilt !== 0 ? ilt : iat;
    const walked = walkThunks(ctx, table, library, delayLoaded);
    out.imports.push(...walked.entries);
    if (walked.truncated) return true;
    if (out.imports.length >= IMAGE_PARSE_LIMITS.imports) return true;
  }
  return false;
};

const resolveLibrary = (
  ctx: PeImageContext,
  nameRva: number,
  delayLoaded: boolean,
): string | null => {
  const effective =
    delayLoaded && nameRva >= Number(ctx.imageBase)
      ? nameRva - Number(ctx.imageBase)
      : nameRva;
  return readRvaString(ctx, effective);
};

const parseImports = (
  ctx: PeImageContext,
): {
  readonly imports: ImageImport[];
  readonly libraries: ImageLibrary[];
  readonly coverage: "complete" | "truncated" | "unavailable";
} => {
  const out = { imports: [] as ImageImport[], libraries: [] as string[] };
  let truncated = false;
  try {
    const normalTruncated = walkDescriptors(ctx, false, out);
    const delayCount = out.libraries.length;
    const delayTruncated = walkDescriptors(ctx, true, out);
    truncated = normalTruncated || delayTruncated;
    const libraries = out.libraries
      .filter((name) => name.length > 0)
      .map<ImageLibrary>((name, position) => ({
        name,
        kind: (position >= delayCount ? "delay" : "needed") as ImageLibraryKind,
      }));
    return {
      imports: out.imports,
      libraries,
      coverage: truncated ? "truncated" : "complete",
    };
  } catch (cause) {
    ctx.diagnostics.add(`PE import directory parse failed: ${String(cause)}`);
    return { imports: out.imports, libraries: [], coverage: "unavailable" };
  }
};

const parseExports = (
  ctx: PeImageContext,
): {
  readonly exports: ImageExport[];
  readonly coverage: "complete" | "truncated" | "unavailable";
} => {
  const directory = ctx.directories[DIR_EXPORT];
  if (directory === undefined || directory.rva === 0)
    return { exports: [], coverage: "complete" };
  try {
    return readExportDirectory(ctx, directory.rva);
  } catch (cause) {
    ctx.diagnostics.add(`PE export directory parse failed: ${String(cause)}`);
    return { exports: [], coverage: "unavailable" };
  }
};

const readExportDirectory = (
  ctx: PeImageContext,
  dirRva: number,
): {
  readonly exports: ImageExport[];
  readonly coverage: "complete" | "truncated" | "unavailable";
} => {
  const base = ctx.rvaToOffset(dirRva, EXPORT_DIRECTORY_BYTES);
  if (base === null) return { exports: [], coverage: "unavailable" };
  const reader = ctx.reader;
  const ordinalBase = reader.u32(base + 16, "PE export base");
  const functionCount = reader.u32(base + 20, "PE export function count");
  const nameCount = reader.u32(base + 24, "PE export name count");
  const functionsRva = reader.u32(base + 28, "PE export functions");
  const namesRva = reader.u32(base + 32, "PE export names");
  const ordinalsRva = reader.u32(base + 36, "PE export name ordinals");
  if (functionCount > IMAGE_PARSE_LIMITS.exports)
    return { exports: [], coverage: "truncated" };
  const names = exportNameMap(ctx, nameCount, namesRva, ordinalsRva);
  const exports: ImageExport[] = [];
  for (let index = 0; index < functionCount; index += 1) {
    const slot = ctx.rvaToOffset(functionsRva + index * 4, 4);
    if (slot === null) break;
    const funcRva = reader.u32(slot, "PE export function rva");
    if (funcRva === 0) continue;
    exports.push(
      exportEntry(ctx, funcRva, ordinalBase + index, names.get(index) ?? null),
    );
  }
  return { exports, coverage: "complete" };
};

const exportNameMap = (
  ctx: PeImageContext,
  nameCount: number,
  namesRva: number,
  ordinalsRva: number,
): Map<number, string | null> => {
  const map = new Map<number, string | null>();
  const bounded = Math.min(nameCount, IMAGE_PARSE_LIMITS.exports);
  for (let index = 0; index < bounded; index += 1) {
    const ordSlot = ctx.rvaToOffset(ordinalsRva + index * 2, 2);
    const nameSlot = ctx.rvaToOffset(namesRva + index * 4, 4);
    if (ordSlot === null || nameSlot === null) break;
    const functionIndex = ctx.reader.u16(ordSlot, "PE export ordinal");
    const nameRva = ctx.reader.u32(nameSlot, "PE export name rva");
    if (!map.has(functionIndex))
      map.set(functionIndex, readRvaString(ctx, nameRva));
  }
  return map;
};

const exportEntry = (
  ctx: PeImageContext,
  funcRva: number,
  ordinal: number,
  name: string | null,
): ImageExport => {
  const directory = ctx.directories[DIR_EXPORT];
  const forwards =
    directory !== undefined &&
    funcRva >= directory.rva &&
    funcRva < directory.rva + directory.size;
  if (forwards)
    return {
      name,
      ordinal,
      address: null,
      forwarder: readRvaString(ctx, funcRva),
      kind: "function",
    };
  return {
    name,
    ordinal,
    address: ctx.imageBase + BigInt(funcRva),
    forwarder: null,
    kind: "function",
  };
};

/** Project the PE import, delay-import and export directories into the model. */
export const parsePeImportsExports = (
  ctx: PeImageContext,
): PeImportsExports => {
  const importResult = parseImports(ctx);
  const exportResult = parseExports(ctx);
  return {
    imports: importResult.imports,
    exports: exportResult.exports,
    libraries: importResult.libraries,
    importCoverage: importResult.coverage,
    exportCoverage: exportResult.coverage,
  };
};
