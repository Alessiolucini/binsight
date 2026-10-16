import { z } from "zod";
import {
  hexAddressSchema,
  triageArtifactSchema,
  triageListCoverageSchema,
  triagePathSchema,
  triageSliceSchema,
  triageSubjectFormatSchema,
  triageSubjectSchema,
} from "./triageCommon.js";

/** Default and largest number of entries returned for each difference list. */
export const COMPARE_LIST_LIMIT = { default: 500, max: 5000 } as const;
/** Largest number of hardening indicator changes returned before truncation. */
export const COMPARE_HARDENING_LIMIT = 256;

const boundedListSize = z
  .number()
  .int()
  .min(1)
  .max(COMPARE_LIST_LIMIT.max)
  .default(COMPARE_LIST_LIMIT.default)
  .describe(
    "Largest number of entries returned for each added/removed list; longer lists are truncated with coverage",
  );

/** Two explicit local files to diff, with an optional Mach-O slice applied to both. */
export const compareExecutablesInputSchema = z.strictObject({
  base_path: triagePathSchema.describe(
    "Absolute path to the baseline (older) executable",
  ),
  target_path: triagePathSchema.describe(
    "Absolute path to the target (newer) executable compared against the baseline",
  ),
  slice: triageSliceSchema,
  max_list: boundedListSize,
});

export type CompareExecutablesInput = z.infer<
  typeof compareExecutablesInputSchema
>;

/** Imported symbol identity diffed by library, name and ordinal. */
export const importReferenceSchema = z.strictObject({
  library: z.string().nullable(),
  name: z.string().nullable(),
  ordinal: z.number().int().nonnegative().nullable(),
});

/** Exported symbol identity diffed by name and ordinal. */
export const exportReferenceSchema = z.strictObject({
  name: z.string().nullable(),
  ordinal: z.number().int().nonnegative().nullable(),
});

const entropyValueSchema = z.number().min(0).max(8);

/** Per-section Shannon-entropy change for a section present in both images. */
export const sectionEntropyDeltaSchema = z.strictObject({
  name: z.string(),
  base_entropy: entropyValueSchema,
  target_entropy: entropyValueSchema,
  /** target_entropy - base_entropy in bits per byte. */
  delta: z.number().min(-8).max(8),
});

/** One inferred hardening indicator whose observed value changed between images. */
export const hardeningChangeSchema = z.strictObject({
  indicator: z.string().min(1),
  /** Observed value in the baseline, or null when the indicator does not apply to its format. */
  base: z.string().nullable(),
  /** Observed value in the target, or null when the indicator does not apply to its format. */
  target: z.string().nullable(),
});

/** Executable-format family change between the two files. */
export const formatChangeSchema = z.strictObject({
  changed: z.boolean(),
  base: triageSubjectFormatSchema,
  target: triageSubjectFormatSchema,
});

/** Entry-point virtual-address change between the two files. */
export const entryPointChangeSchema = z.strictObject({
  changed: z.boolean(),
  base: hexAddressSchema.nullable(),
  target: hexAddressSchema.nullable(),
});

export type ImportReference = z.infer<typeof importReferenceSchema>;
export type ExportReference = z.infer<typeof exportReferenceSchema>;
export type SectionEntropyDelta = z.infer<typeof sectionEntropyDeltaSchema>;
export type HardeningChange = z.infer<typeof hardeningChangeSchema>;

/**
 * Structural diff of two shipped executables. The Evidence subject is the
 * target file's identity; the baseline identity is carried in `base`. Every
 * difference list is bounded and reports its own coverage.
 */
export const compareExecutablesReportSchema = z
  .strictObject({
    /** Exact identity of the baseline bytes read for this report. */
    base: triageArtifactSchema,
    /** Exact identity of the target bytes; also the Evidence subject. */
    target: triageArtifactSchema,
    subject: triageSubjectSchema,
    /** Whether both files hash to the same SHA-256. */
    identical: z.boolean(),
    format_changed: formatChangeSchema,
    /** target bytes - base bytes. */
    size_delta: z.number().int(),
    entry_point_changed: entryPointChangeSchema,
    added_imports: z.array(importReferenceSchema),
    added_import_coverage: triageListCoverageSchema,
    removed_imports: z.array(importReferenceSchema),
    removed_import_coverage: triageListCoverageSchema,
    added_exports: z.array(exportReferenceSchema),
    added_export_coverage: triageListCoverageSchema,
    removed_exports: z.array(exportReferenceSchema),
    removed_export_coverage: triageListCoverageSchema,
    added_libraries: z.array(z.string()),
    added_library_coverage: triageListCoverageSchema,
    removed_libraries: z.array(z.string()),
    removed_library_coverage: triageListCoverageSchema,
    added_sections: z.array(z.string()),
    added_section_coverage: triageListCoverageSchema,
    removed_sections: z.array(z.string()),
    removed_section_coverage: triageListCoverageSchema,
    section_entropy_deltas: z.array(sectionEntropyDeltaSchema),
    section_entropy_delta_coverage: triageListCoverageSchema,
    hardening_changes: z.array(hardeningChangeSchema),
    hardening_change_coverage: triageListCoverageSchema,
    limitations: z.array(z.string()),
  })
  .superRefine(refineCompareReport);

export type CompareExecutablesReport = z.infer<
  typeof compareExecutablesReportSchema
>;

type CompareReportShape = {
  readonly base: { readonly sha256: string; readonly bytes: number };
  readonly target: { readonly sha256: string; readonly bytes: number };
  readonly identical: boolean;
  readonly size_delta: number;
  readonly format_changed: {
    readonly changed: boolean;
    readonly base: string;
    readonly target: string;
  };
  readonly entry_point_changed: {
    readonly changed: boolean;
    readonly base: string | null;
    readonly target: string | null;
  };
  readonly section_entropy_deltas: readonly SectionEntropyDelta[];
  readonly added_imports: readonly unknown[];
  readonly removed_imports: readonly unknown[];
  readonly added_exports: readonly unknown[];
  readonly removed_exports: readonly unknown[];
  readonly added_libraries: readonly unknown[];
  readonly removed_libraries: readonly unknown[];
  readonly added_sections: readonly unknown[];
  readonly removed_sections: readonly unknown[];
  readonly hardening_changes: readonly unknown[];
  readonly added_import_coverage: z.infer<typeof triageListCoverageSchema>;
  readonly removed_import_coverage: z.infer<typeof triageListCoverageSchema>;
  readonly added_export_coverage: z.infer<typeof triageListCoverageSchema>;
  readonly removed_export_coverage: z.infer<typeof triageListCoverageSchema>;
  readonly added_library_coverage: z.infer<typeof triageListCoverageSchema>;
  readonly removed_library_coverage: z.infer<typeof triageListCoverageSchema>;
  readonly added_section_coverage: z.infer<typeof triageListCoverageSchema>;
  readonly removed_section_coverage: z.infer<typeof triageListCoverageSchema>;
  readonly section_entropy_delta_coverage: z.infer<
    typeof triageListCoverageSchema
  >;
  readonly hardening_change_coverage: z.infer<typeof triageListCoverageSchema>;
};

function refineScalars(report: CompareReportShape, ctx: z.RefinementCtx): void {
  if (report.identical !== (report.base.sha256 === report.target.sha256))
    issue(
      ctx,
      ["identical"],
      "identical disagrees with the two SHA-256 digests.",
    );
  if (report.size_delta !== report.target.bytes - report.base.bytes)
    issue(
      ctx,
      ["size_delta"],
      "size_delta does not equal target bytes minus base bytes.",
    );
  if (
    report.format_changed.changed !==
    (report.format_changed.base !== report.format_changed.target)
  )
    issue(
      ctx,
      ["format_changed", "changed"],
      "format_changed.changed disagrees with the two formats.",
    );
  if (
    report.entry_point_changed.changed !==
    (report.entry_point_changed.base !== report.entry_point_changed.target)
  )
    issue(
      ctx,
      ["entry_point_changed", "changed"],
      "entry_point_changed.changed disagrees with the two entry-point addresses.",
    );
  for (const delta of report.section_entropy_deltas.values())
    if (
      Math.abs(delta.delta - (delta.target_entropy - delta.base_entropy)) > 1e-3
    )
      issue(
        ctx,
        ["section_entropy_deltas"],
        `Entropy delta for ${delta.name} does not equal target minus base entropy.`,
      );
}

function refineCoverages(
  report: CompareReportShape,
  ctx: z.RefinementCtx,
): void {
  const lists: readonly [
    number,
    z.infer<typeof triageListCoverageSchema>,
    string,
  ][] = [
    [
      report.added_imports.length,
      report.added_import_coverage,
      "added_import_coverage",
    ],
    [
      report.removed_imports.length,
      report.removed_import_coverage,
      "removed_import_coverage",
    ],
    [
      report.added_exports.length,
      report.added_export_coverage,
      "added_export_coverage",
    ],
    [
      report.removed_exports.length,
      report.removed_export_coverage,
      "removed_export_coverage",
    ],
    [
      report.added_libraries.length,
      report.added_library_coverage,
      "added_library_coverage",
    ],
    [
      report.removed_libraries.length,
      report.removed_library_coverage,
      "removed_library_coverage",
    ],
    [
      report.added_sections.length,
      report.added_section_coverage,
      "added_section_coverage",
    ],
    [
      report.removed_sections.length,
      report.removed_section_coverage,
      "removed_section_coverage",
    ],
    [
      report.section_entropy_deltas.length,
      report.section_entropy_delta_coverage,
      "section_entropy_delta_coverage",
    ],
    [
      report.hardening_changes.length,
      report.hardening_change_coverage,
      "hardening_change_coverage",
    ],
  ];
  for (const [length, coverage, field] of lists)
    checkCoverage(length, coverage, [field], ctx);
}

function refineCompareReport(
  report: CompareReportShape,
  ctx: z.RefinementCtx,
): void {
  refineScalars(report, ctx);
  refineCoverages(report, ctx);
}

const issue = (
  ctx: z.RefinementCtx,
  path: (string | number)[],
  message: string,
): void => {
  ctx.addIssue({ code: "custom", path, message });
};

const checkCoverage = (
  returnedLength: number,
  coverage: z.infer<typeof triageListCoverageSchema>,
  path: (string | number)[],
  ctx: z.RefinementCtx,
): void => {
  if (coverage.returned !== returnedLength)
    issue(
      ctx,
      [...path, "returned"],
      "Coverage returned count disagrees with the list length.",
    );
  if (coverage.returned > coverage.total)
    issue(
      ctx,
      [...path, "returned"],
      `Returned ${coverage.returned} exceeds total ${coverage.total}.`,
    );
  if (coverage.truncated !== coverage.returned < coverage.total)
    issue(
      ctx,
      [...path, "truncated"],
      "Truncation flag disagrees with the returned and total counts.",
    );
};
