import { z } from "zod";
import {
  hexAddressSchema,
  triageArtifactSchema,
  triageListCoverageSchema,
  triagePathSchema,
  triageSubjectSchema,
} from "./triageCommon.js";

/** Bounds for the raw binary comparison. */
export const COMPARE_BINARIES_LIMITS = {
  regionGapMax: 4096,
  maxRegions: 5000,
  samplesPerRegionMax: 64,
} as const;

/** Two explicit local files to compare byte-for-byte, with reporting bounds. */
export const compareBinariesInputSchema = z.strictObject({
  base_path: triagePathSchema.describe("Absolute path to the baseline file"),
  target_path: triagePathSchema.describe(
    "Absolute path to the target file compared against the baseline",
  ),
  region_gap: z
    .number()
    .int()
    .min(0)
    .max(COMPARE_BINARIES_LIMITS.regionGapMax)
    .default(32)
    .describe(
      "Maximum run of equal bytes that still merges two changes into one region",
    ),
  max_regions: z
    .number()
    .int()
    .min(1)
    .max(COMPARE_BINARIES_LIMITS.maxRegions)
    .default(500)
    .describe("Maximum changed regions returned before truncation"),
  word_size: z
    .union([z.literal(1), z.literal(2), z.literal(4)])
    .default(2)
    .describe("Byte width used to report before/after values (little-endian)"),
  samples_per_region: z
    .number()
    .int()
    .min(0)
    .max(COMPARE_BINARIES_LIMITS.samplesPerRegionMax)
    .default(6)
    .describe("Maximum before/after value samples listed per region"),
});
export type CompareBinariesInput = z.infer<typeof compareBinariesInputSchema>;

/** One changed value inside a region, as little-endian unsigned integers. */
export const binaryValueSampleSchema = z.strictObject({
  offset: hexAddressSchema,
  before: z.number().int().nonnegative(),
  after: z.number().int().nonnegative(),
});

/** One contiguous changed region and how its bytes changed. */
export const binaryChangeRegionSchema = z.strictObject({
  offset: hexAddressSchema,
  length: z.number().int().positive(),
  /** zeroed: all became 0x00; filled: all became 0xFF; modified: other. */
  kind: z.enum(["zeroed", "filled", "modified"]),
  samples: z.array(binaryValueSampleSchema),
});

export const compareBinariesReportSchema = z.strictObject({
  base: triageArtifactSchema,
  target: triageArtifactSchema,
  subject: triageSubjectSchema,
  identical: z.boolean(),
  /** target bytes minus base bytes. */
  size_delta: z.number().int(),
  /** Bytes compared (the shorter of the two files). */
  compared_bytes: z.number().int().nonnegative(),
  changed_bytes: z.number().int().nonnegative(),
  /** Fraction of compared bytes that differ, in [0, 1]. */
  changed_ratio: z.number().min(0).max(1),
  changed_range: z
    .strictObject({ start: hexAddressSchema, end: hexAddressSchema })
    .nullable(),
  summary: z.strictObject({
    region_count: z.number().int().nonnegative(),
    zeroed_bytes: z.number().int().nonnegative(),
    filled_bytes: z.number().int().nonnegative(),
    other_changed_bytes: z.number().int().nonnegative(),
  }),
  regions: z.array(binaryChangeRegionSchema),
  region_coverage: triageListCoverageSchema,
  limitations: z.array(z.string()),
});
export type CompareBinariesReport = z.infer<typeof compareBinariesReportSchema>;
