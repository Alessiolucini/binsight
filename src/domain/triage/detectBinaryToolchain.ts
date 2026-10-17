import { z } from "zod";
import {
  refineOffsetsInside,
  triageListCoverageSchema,
  triageLocationSchema,
  triagePathSchema,
  triageReportBase,
} from "./triageCommon.js";

/** Largest indicator, per-indicator match and packed-reason lists returned. */
export const TOOLCHAIN_INDICATOR_LIMIT = 64;
export const TOOLCHAIN_MATCH_LIMIT = 16;
export const TOOLCHAIN_PACKED_REASON_LIMIT = 16;

/** Family of the identified tool; the signature table owns the mapping. */
export const toolchainCategorySchema = z.enum([
  "compiler",
  "linker",
  "packer",
  "protector",
  "installer",
  "language",
  "bundler",
]);

export const toolchainConfidenceSchema = z.enum(["high", "medium", "low"]);

/** One concrete marker supporting an indicator, with its position when known. */
export const toolchainMatchSchema = z.strictObject({
  /** Why this marker is consistent with the tool; never a verdict. */
  reason: z.string().min(1),
  /** File position of the marker, or null for markers without a byte offset. */
  location: triageLocationSchema.nullable(),
});

/** One inferred tool identification, aggregating every marker that supports it. */
export const toolchainIndicatorSchema = z.strictObject({
  /** Stable identifier such as "upx", "msvc" or "go". */
  id: z.string().min(1),
  name: z.string().min(1),
  category: toolchainCategorySchema,
  confidence: toolchainConfidenceSchema,
  /** Every classification here is layered over observed bytes. */
  evidence_kind: z.literal("inferred"),
  matches: z.array(toolchainMatchSchema).min(1),
  match_coverage: triageListCoverageSchema,
});

/** Entropy-assisted, non-destructive packing assessment; never unpacks. */
export const packedIndicatorSchema = z.strictObject({
  status: z.enum(["likely_packed", "not_observed", "unknown"]),
  evidence_kind: z.literal("inferred"),
  /** Whole-file Shannon entropy in bits per byte. */
  file_entropy: z.number().min(0).max(8),
  /** The section the entry point falls in, when the bytes parse as an image. */
  entry_point_section: z
    .strictObject({
      name: z.string(),
      writable: z.boolean(),
      executable: z.boolean(),
      entropy: z.number().min(0).max(8),
    })
    .nullable(),
  reasons: z.array(z.string()),
});

/** One explicit local executable or library to classify by its markers. */
export const detectBinaryToolchainInputSchema = z.strictObject({
  path: triagePathSchema,
});

export type ToolchainIndicator = z.infer<typeof toolchainIndicatorSchema>;
export type ToolchainMatch = z.infer<typeof toolchainMatchSchema>;
export type PackedIndicator = z.infer<typeof packedIndicatorSchema>;
export type DetectBinaryToolchainInput = z.infer<
  typeof detectBinaryToolchainInputSchema
>;

/**
 * Inferred compiler, linker, packer, protector, installer, language and
 * bundler identifications drawn from a BinSight-authored signature table over the
 * exact file bytes. Detection only: nothing is unpacked or executed.
 */
export const detectBinaryToolchainReportSchema = z
  .strictObject({
    ...triageReportBase,
    indicators: z.array(toolchainIndicatorSchema),
    indicator_coverage: triageListCoverageSchema,
    packed_indicator: packedIndicatorSchema,
  })
  .superRefine((report, ctx) => {
    refineOffsetsInside(report.artifact.bytes, matchOffsets(report), ctx);
    checkCoverage(report.indicator_coverage, ["indicator_coverage"], ctx);
    for (const [index, indicator] of report.indicators.entries())
      checkCoverage(
        indicator.match_coverage,
        ["indicators", index, "match_coverage"],
        ctx,
      );
  });

export type DetectBinaryToolchainReport = z.infer<
  typeof detectBinaryToolchainReportSchema
>;

const matchOffsets = (
  report: z.infer<typeof detectBinaryToolchainReportSchema>,
): { offset: number; path: (string | number)[] }[] => {
  const offsets: { offset: number; path: (string | number)[] }[] = [];
  for (const [index, indicator] of report.indicators.entries())
    for (const [position, match] of indicator.matches.entries())
      if (match.location !== null)
        offsets.push({
          offset: match.location.file_offset,
          path: ["indicators", index, "matches", position, "location"],
        });
  return offsets;
};

const checkCoverage = (
  coverage: z.infer<typeof triageListCoverageSchema>,
  path: (string | number)[],
  ctx: z.RefinementCtx,
): void => {
  if (coverage.returned > coverage.total)
    ctx.addIssue({
      code: "custom",
      message: `Returned ${coverage.returned} exceeds total ${coverage.total}`,
      path: [...path, "returned"],
    });
  if (coverage.truncated !== coverage.returned < coverage.total)
    ctx.addIssue({
      code: "custom",
      message: "Truncation flag disagrees with the returned and total counts",
      path: [...path, "truncated"],
    });
};
