import { z } from "zod";
import {
  refineOffsetsInside,
  triageListCoverageSchema,
  triageLocationSchema,
  triagePathSchema,
  triageReportBase,
} from "./triageCommon.js";

const nonNegative = z.number().int().nonnegative();

/** One caller-supplied pattern. `type` selects the matching grammar. */
export const scanBytePatternSchema = z.strictObject({
  id: z
    .string()
    .min(1)
    .max(64)
    .describe("Caller label echoed back on every match from this pattern"),
  type: z
    .enum(["hex", "text", "regex"])
    .describe(
      "hex = YARA-style hex subset (bytes, ?? nibble wildcards, [n-m]/[n-] jumps, (aa|bb) alternation); text = literal string; regex = JS RegExp without backreferences",
    ),
  value: z
    .string()
    .min(1)
    .max(8192)
    .describe("Pattern body, interpreted according to `type`"),
  nocase: z
    .boolean()
    .optional()
    .describe("Case-insensitive matching for text and regex patterns"),
  wide: z
    .boolean()
    .optional()
    .describe(
      "For text patterns, also match the UTF-16LE encoding of the value",
    ),
  ascii: z
    .boolean()
    .optional()
    .describe(
      "For text patterns, match the ASCII/Latin-1 encoding; defaults to true unless only `wide` is requested",
    ),
});

export type ScanBytePattern = z.infer<typeof scanBytePatternSchema>;

/** Caller input: one file, up to 64 patterns, and a bounded result size. */
export const scanBytePatternsInputSchema = z
  .strictObject({
    path: triagePathSchema,
    patterns: z
      .array(scanBytePatternSchema)
      .min(1)
      .max(64)
      .describe("Patterns to search for; each must carry a unique id"),
    max_matches: nonNegative
      .min(1)
      .max(10000)
      .default(500)
      .describe(
        "Maximum matches returned in total and scanned per pattern before truncation",
      ),
  })
  .superRefine((input, ctx) => {
    const seen = new Set<string>();
    for (const [index, pattern] of input.patterns.entries()) {
      if (seen.has(pattern.id))
        ctx.addIssue({
          code: "custom",
          path: ["patterns", index, "id"],
          message: `Pattern id "${pattern.id}" is duplicated; each pattern id must be unique.`,
        });
      seen.add(pattern.id);
    }
  });

export type ScanBytePatternsInput = z.infer<typeof scanBytePatternsInputSchema>;

/** One observed occurrence of a pattern in the analyzed bytes. */
export const scanByteMatchSchema = z.strictObject({
  pattern_id: z.string().min(1),
  location: triageLocationSchema,
  /** Matched byte length; may exceed the preview when variable gaps are used. */
  length: z.number().int().positive(),
  /** Lowercase hex of up to the first 32 matched bytes. */
  preview_hex: z.string().regex(/^([0-9a-f]{2}){1,32}$/u),
});

/** Per-pattern tallies so callers see counts even when the global list truncates. */
export const scanBytePatternCountSchema = z.strictObject({
  pattern_id: z.string().min(1),
  /** Occurrences counted for this pattern, capped at the per-pattern bound. */
  total: nonNegative,
  /** Occurrences from this pattern included in `matches`. */
  returned: nonNegative,
  /** The per-pattern scan stopped at the match bound. */
  truncated: z.boolean(),
});

/** Observed byte-pattern search result over one immutable snapshot. */
export const scanBytePatternsReportSchema = z
  .strictObject({
    ...triageReportBase,
    matches: z.array(scanByteMatchSchema),
    match_coverage: triageListCoverageSchema,
    per_pattern_counts: z.array(scanBytePatternCountSchema),
  })
  .superRefine((report, ctx) => {
    refineOffsetsInside(
      report.artifact.bytes,
      report.matches.map((match, index) => ({
        offset: match.location.file_offset,
        path: ["matches", index, "location", "file_offset"],
      })),
      ctx,
    );
    if (report.match_coverage.returned !== report.matches.length)
      ctx.addIssue({
        code: "custom",
        path: ["match_coverage", "returned"],
        message:
          "match_coverage.returned must equal the number of returned matches.",
      });
    const returnedTotal = report.per_pattern_counts.reduce(
      (sum, entry) => sum + entry.returned,
      0,
    );
    if (returnedTotal !== report.matches.length)
      ctx.addIssue({
        code: "custom",
        path: ["per_pattern_counts"],
        message:
          "per_pattern_counts returned values must sum to the number of returned matches.",
      });
    for (const [index, entry] of report.per_pattern_counts.entries())
      if (entry.returned > entry.total)
        ctx.addIssue({
          code: "custom",
          path: ["per_pattern_counts", index, "returned"],
          message: "A pattern cannot return more matches than it found.",
        });
  });

export type ScanByteMatch = z.infer<typeof scanByteMatchSchema>;
export type ScanBytePatternCount = z.infer<typeof scanBytePatternCountSchema>;
export type ScanBytePatternsReport = z.infer<
  typeof scanBytePatternsReportSchema
>;
