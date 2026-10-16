import type { ExecutableImage } from "../domain/native/image/executableImage.js";
import {
  COMPARE_HARDENING_LIMIT,
  compareExecutablesReportSchema,
  type CompareExecutablesReport,
  type ExportReference,
  type HardeningChange,
  type ImportReference,
  type SectionEntropyDelta,
} from "../domain/triage/compareExecutables.js";
import {
  toHexAddress,
  triageArtifactSchema,
  type triageListCoverageSchema,
} from "../domain/triage/triageCommon.js";
import type { z } from "zod";
import {
  compareUnicodeCodePoints,
  compositeKey,
} from "../domain/unicodeCodePointOrder.js";
import {
  checkTriageCancelled,
  roundTo,
  shannonEntropy,
  triageSubject,
  yieldTriage,
} from "./triageSupport.js";
import type { TriageAnalysisContext } from "./triageSupport.js";

type Coverage = z.infer<typeof triageListCoverageSchema>;
type Artifact = z.infer<typeof triageArtifactSchema>;

/** One side of the comparison: the exact snapshot bytes and its parsed image. */
export interface CompareSide {
  readonly identity: Artifact;
  readonly bytes: Buffer;
  readonly image: ExecutableImage | null;
}

/** Yield cadence while measuring per-section entropy across both images. */
const SECTION_YIELD_STRIDE = 128;

/**
 * Diff two parsed executable images by name. Pure, deterministic and bounded:
 * every difference list is sorted and clamped to `maxList`, section entropy is
 * computed only over in-bounds file-backed bytes, and nothing is executed.
 */
export const compareExecutableImages = async (
  base: CompareSide,
  target: CompareSide,
  maxList: number,
  context: Pick<TriageAnalysisContext, "signal">,
): Promise<CompareExecutablesReport> => {
  const baseFormat = triageSubject(base.image).format;
  const targetFormat = triageSubject(target.image).format;

  const baseImports = importMap(base.image);
  const targetImports = importMap(target.image);
  const baseExports = exportMap(base.image);
  const targetExports = exportMap(target.image);
  const baseLibraries = libraryNames(base.image);
  const targetLibraries = libraryNames(target.image);
  const baseSections = sectionNames(base.image);
  const targetSections = sectionNames(target.image);

  const addedImports = boundRefs(
    missingKeys(targetImports, baseImports),
    maxList,
  );
  const removedImports = boundRefs(
    missingKeys(baseImports, targetImports),
    maxList,
  );
  const addedExports = boundRefs(
    missingKeys(targetExports, baseExports),
    maxList,
  );
  const removedExports = boundRefs(
    missingKeys(baseExports, targetExports),
    maxList,
  );

  const addedLibraries = boundNames(
    sortedDifference(targetLibraries, baseLibraries),
    maxList,
  );
  const removedLibraries = boundNames(
    sortedDifference(baseLibraries, targetLibraries),
    maxList,
  );
  const addedSections = boundNames(
    sortedDifference(targetSections, baseSections),
    maxList,
  );
  const removedSections = boundNames(
    sortedDifference(baseSections, targetSections),
    maxList,
  );

  checkTriageCancelled(context.signal);
  const entropy = await sectionEntropyDeltas(base, target, maxList, context);

  return compareExecutablesReportSchema.parse({
    base: base.identity,
    target: target.identity,
    subject: triageSubject(target.image),
    identical: base.identity.sha256 === target.identity.sha256,
    format_changed: {
      changed: baseFormat !== targetFormat,
      base: baseFormat,
      target: targetFormat,
    },
    size_delta: target.identity.bytes - base.identity.bytes,
    entry_point_changed: entryPointChange(base.image, target.image),
    added_imports: addedImports.returned,
    added_import_coverage: addedImports.coverage,
    removed_imports: removedImports.returned,
    removed_import_coverage: removedImports.coverage,
    added_exports: addedExports.returned,
    added_export_coverage: addedExports.coverage,
    removed_exports: removedExports.returned,
    removed_export_coverage: removedExports.coverage,
    added_libraries: addedLibraries.returned,
    added_library_coverage: addedLibraries.coverage,
    removed_libraries: removedLibraries.returned,
    removed_library_coverage: removedLibraries.coverage,
    added_sections: addedSections.returned,
    added_section_coverage: addedSections.coverage,
    removed_sections: removedSections.returned,
    removed_section_coverage: removedSections.coverage,
    section_entropy_deltas: entropy.returned,
    section_entropy_delta_coverage: entropy.coverage,
    ...hardeningFields(base.image, target.image),
    limitations: limitations(base, target, entropy.clamped, [
      addedImports.coverage,
      removedImports.coverage,
      addedExports.coverage,
      removedExports.coverage,
      addedLibraries.coverage,
      removedLibraries.coverage,
      addedSections.coverage,
      removedSections.coverage,
      entropy.coverage,
    ]),
  });
};

const importMap = (
  image: ExecutableImage | null,
): Map<string, ImportReference> => {
  const map = new Map<string, ImportReference>();
  if (image === null) return map;
  for (const entry of image.imports) {
    const reference: ImportReference = {
      library: entry.library,
      name: entry.name,
      ordinal: entry.ordinal,
    };
    map.set(
      compositeKey([entry.library, entry.name, entry.ordinal]),
      reference,
    );
  }
  return map;
};

const exportMap = (
  image: ExecutableImage | null,
): Map<string, ExportReference> => {
  const map = new Map<string, ExportReference>();
  if (image === null) return map;
  for (const entry of image.exports)
    map.set(compositeKey([entry.name, entry.ordinal]), {
      name: entry.name,
      ordinal: entry.ordinal,
    });
  return map;
};

const libraryNames = (image: ExecutableImage | null): Set<string> =>
  new Set(image === null ? [] : image.libraries.map((entry) => entry.name));

const sectionNames = (image: ExecutableImage | null): Set<string> =>
  new Set(image === null ? [] : image.sections.map((entry) => entry.name));

const missingKeys = <T>(
  from: ReadonlyMap<string, T>,
  present: ReadonlyMap<string, unknown>,
): { key: string; value: T }[] => {
  const result: { key: string; value: T }[] = [];
  for (const [key, value] of from)
    if (!present.has(key)) result.push({ key, value });
  return result.sort((left, right) =>
    compareUnicodeCodePoints(left.key, right.key),
  );
};

const sortedDifference = (
  from: ReadonlySet<string>,
  present: ReadonlySet<string>,
): string[] =>
  [...from].filter((name) => !present.has(name)).sort(compareUnicodeCodePoints);

const boundRefs = <T>(
  entries: readonly { readonly value: T }[],
  maxList: number,
): { readonly returned: T[]; readonly coverage: Coverage } => ({
  returned: entries.slice(0, maxList).map((entry) => entry.value),
  coverage: coverage(entries.length, Math.min(entries.length, maxList)),
});

const boundNames = (
  names: readonly string[],
  maxList: number,
): { readonly returned: string[]; readonly coverage: Coverage } => ({
  returned: names.slice(0, maxList),
  coverage: coverage(names.length, Math.min(names.length, maxList)),
});

const entryPointChange = (
  base: ExecutableImage | null,
  target: ExecutableImage | null,
) => {
  const baseAddress = entryAddress(base);
  const targetAddress = entryAddress(target);
  return {
    changed: baseAddress !== targetAddress,
    base: baseAddress,
    target: targetAddress,
  };
};

const entryAddress = (image: ExecutableImage | null): string | null =>
  image === null || image.entry_point.virtual_address === null
    ? null
    : toHexAddress(image.entry_point.virtual_address);

const sectionEntropyDeltas = async (
  base: CompareSide,
  target: CompareSide,
  maxList: number,
  context: Pick<TriageAnalysisContext, "signal">,
): Promise<{
  readonly returned: SectionEntropyDelta[];
  readonly coverage: Coverage;
  readonly clamped: boolean;
}> => {
  if (base.image === null || target.image === null)
    return { returned: [], coverage: coverage(0, 0), clamped: false };
  const targetByName = new Map(
    target.image.sections.map((section) => [section.name, section]),
  );
  const deltas: SectionEntropyDelta[] = [];
  let clamped = false;
  let examined = 0;
  for (const section of base.image.sections) {
    const counterpart = targetByName.get(section.name);
    if (
      counterpart === undefined ||
      section.file_size === 0 ||
      counterpart.file_size === 0
    )
      continue;
    const baseEntropy = sectionEntropy(
      base,
      section.file_offset,
      section.file_size,
    );
    const targetEntropy = sectionEntropy(
      target,
      counterpart.file_offset,
      counterpart.file_size,
    );
    if (baseEntropy.clamped || targetEntropy.clamped) clamped = true;
    deltas.push({
      name: section.name,
      base_entropy: baseEntropy.value,
      target_entropy: targetEntropy.value,
      delta: roundTo(targetEntropy.value - baseEntropy.value),
    });
    examined += 1;
    if (examined % SECTION_YIELD_STRIDE === 0)
      await yieldTriage(context.signal);
  }
  deltas.sort((left, right) => compareUnicodeCodePoints(left.name, right.name));
  return {
    returned: deltas.slice(0, maxList),
    coverage: coverage(deltas.length, Math.min(deltas.length, maxList)),
    clamped,
  };
};

const sectionEntropy = (
  side: CompareSide,
  relativeOffset: number,
  declared: number,
): { readonly value: number; readonly clamped: boolean } => {
  const image = side.image;
  if (image === null) return { value: 0, clamped: false };
  const start = Math.min(
    Math.max(image.image_offset + relativeOffset, 0),
    side.bytes.length,
  );
  const available = Math.max(0, Math.min(declared, side.bytes.length - start));
  return {
    value: roundTo(shannonEntropy(side.bytes, start, start + available)),
    clamped: available < declared,
  };
};

const coverage = (total: number, returned: number): Coverage => ({
  total,
  returned,
  truncated: returned < total,
});

const hardeningFields = (
  base: ExecutableImage | null,
  target: ExecutableImage | null,
) => {
  const baseIndicators = hardeningIndicators(base);
  const targetIndicators = hardeningIndicators(target);
  const names = [
    ...new Set([...baseIndicators.keys(), ...targetIndicators.keys()]),
  ].sort(compareUnicodeCodePoints);
  const changes: HardeningChange[] = [];
  for (const indicator of names) {
    const baseValue = baseIndicators.get(indicator) ?? null;
    const targetValue = targetIndicators.get(indicator) ?? null;
    if (baseValue !== targetValue)
      changes.push({ indicator, base: baseValue, target: targetValue });
  }
  const returned = changes.slice(0, COMPARE_HARDENING_LIMIT);
  return {
    hardening_changes: returned,
    hardening_change_coverage: coverage(changes.length, returned.length),
  };
};

const symbolNames = (image: ExecutableImage): Set<string> => {
  const names = new Set<string>();
  for (const entry of image.imports)
    if (entry.name !== null) names.add(entry.name);
  for (const entry of image.symbols) names.add(entry.name);
  return names;
};

/** Observed/inferred hardening indicators for one image, keyed by indicator id. */
export const hardeningIndicators = (
  image: ExecutableImage | null,
): Map<string, string> => {
  const map = new Map<string, string>();
  if (image === null) return map;
  if (image.elf !== null) elfIndicators(image, image.elf, map);
  else if (image.pe !== null) peIndicators(image.pe, map);
  else if (image.macho !== null) machoIndicators(image, image.macho, map);
  return map;
};

const elfIndicators = (
  image: ExecutableImage,
  elf: NonNullable<ExecutableImage["elf"]>,
  map: Map<string, string>,
): void => {
  map.set(
    "elf.pie",
    elf.e_type === 2
      ? "no-pie"
      : elf.e_type === 3
        ? elf.interpreter !== null
          ? "pie"
          : "dso"
        : `type-${elf.e_type}`,
  );
  map.set(
    "elf.relro",
    elf.gnu_relro === null
      ? "none"
      : elf.dynamic?.bind_now === true
        ? "full"
        : "partial",
  );
  map.set(
    "elf.nx",
    elf.gnu_stack.present
      ? elf.gnu_stack.executable
        ? "exec-stack"
        : "nx"
      : "default",
  );
  const names = symbolNames(image);
  map.set(
    "elf.stack_canary",
    names.has("__stack_chk_fail") || names.has("__stack_chk_guard")
      ? "present"
      : "not-observed",
  );
  map.set(
    "elf.fortify",
    [...names].some((name) => name.endsWith("_chk"))
      ? "present"
      : "not-observed",
  );
  map.set("elf.stripped", elf.has_symtab ? "no" : "yes");
};

const PE_DLL_FLAGS = {
  "pe.high_entropy_va": 0x0020,
  "pe.dynamic_base": 0x0040,
  "pe.force_integrity": 0x0080,
  "pe.nx_compat": 0x0100,
  "pe.no_seh": 0x0400,
  "pe.guard_cf": 0x4000,
} as const;

const peIndicators = (
  pe: NonNullable<ExecutableImage["pe"]>,
  map: Map<string, string>,
): void => {
  for (const [indicator, flag] of Object.entries(PE_DLL_FLAGS))
    map.set(
      indicator,
      (pe.dll_characteristics & flag) === flag ? "enabled" : "disabled",
    );
  map.set(
    "pe.authenticode",
    pe.security_directory !== null ? "present" : "absent",
  );
};

const MACHO_PIE = 0x200000;
const MACHO_ALLOW_STACK_EXECUTION = 0x20000;

const machoIndicators = (
  image: ExecutableImage,
  macho: NonNullable<ExecutableImage["macho"]>,
  map: Map<string, string>,
): void => {
  map.set(
    "macho.pie",
    (macho.flags & MACHO_PIE) === MACHO_PIE ? "enabled" : "disabled",
  );
  map.set(
    "macho.allow_stack_execution",
    (macho.flags & MACHO_ALLOW_STACK_EXECUTION) === MACHO_ALLOW_STACK_EXECUTION
      ? "enabled"
      : "disabled",
  );
  map.set(
    "macho.code_signature",
    macho.code_signature !== null ? "present" : "absent",
  );
  map.set(
    "macho.encrypted",
    macho.encryption !== null && macho.encryption.crypt_id !== 0 ? "yes" : "no",
  );
  map.set("macho.restrict_segment", macho.has_restrict_segment ? "yes" : "no");
  map.set(
    "macho.arm64e",
    image.architecture === "arm64" && (macho.cpu_subtype & 0xff) === 2
      ? "yes"
      : "no",
  );
};

const limitations = (
  base: CompareSide,
  target: CompareSide,
  entropyClamped: boolean,
  coverages: readonly Coverage[],
): string[] => {
  const notes = [
    "This is a structural diff derived from two shipped files. Differences are observed from file content and do not establish intent, authorship, or that the target was built from the baseline.",
    "Imports, exports, libraries and sections are diffed by name (imports and exports also by ordinal). A renamed or re-ordinaled symbol appears as one removal and one addition, not as a rename.",
    "Hardening indicators are inferred: header bits for most, and for ELF stack-canary and FORTIFY the presence of symbol names. An absent symbol in a stripped binary does not prove a mitigation is off, and an indicator that does not apply to a file's format is reported as null.",
    "Each file is read once and bounded to 256 MiB; neither file is executed and no network access or temporary files are used. Section entropy is computed only over in-bounds file-backed bytes.",
  ];
  if (base.image === null || target.image === null)
    notes.push(
      "One or both files are not a recognized ELF, PE or Mach-O image. Structural lists for a non-image side are empty, and only size, hash and format differences are reported for it.",
    );
  else if (base.image.format !== target.image.format)
    notes.push(
      "The two files are different executable formats, so hardening indicators and most structural lists have no common basis; every item appears as added or removed.",
    );
  if (
    base.image?.container.kind === "fat" ||
    target.image?.container.kind === "fat"
  )
    notes.push(
      "A universal binary was compared on a single slice (the caller's slice or the first declared slice); other slices were not diffed.",
    );
  if (entropyClamped)
    notes.push(
      "A section declared more file bytes than its artifact contains; entropy for it was measured only over the in-bounds portion.",
    );
  if (coverages.some((entry) => entry.truncated))
    notes.push(
      "A difference list reached the max_list bound; further entries were omitted and are reflected in that list's coverage.",
    );
  return notes;
};
