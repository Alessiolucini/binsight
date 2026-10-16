import { z } from "zod";
import {
  refineOffsetsInside,
  triageListCoverageSchema,
  triagePathSchema,
  triageReportBase,
} from "./triageCommon.js";

/** Smallest and largest caller-selectable block, and the default, in bytes. */
export const ENTROPY_BLOCK_SIZE = {
  min: 256,
  max: 1_048_576,
  default: 4096,
} as const;
/** Largest number of blocks scanned before the block list is truncated. */
export const ENTROPY_MAX_BLOCKS = {
  min: 1,
  max: 65_536,
  default: 4096,
} as const;
/** A block at or above this bits/byte is reported as part of a high-entropy run. */
export const HIGH_ENTROPY_THRESHOLD = 7.2;
/** A block at or below this bits/byte is reported as part of a low-entropy run. */
export const LOW_ENTROPY_THRESHOLD = 1.0;
/** Largest number of entropy runs and sections returned before truncation. */
export const ENTROPY_RUN_LIMIT = 4096;
export const ENTROPY_SECTION_LIMIT = 4096;

const nonNegative = z.number().int().nonnegative();
/** Shannon entropy in bits per byte: 0 for constant data, 8 for a uniform byte. */
const entropyValueSchema = z.number().min(0).max(8);
/** Pearson chi-square statistic against a uniform byte distribution. */
const chiSquareSchema = z.number().min(0);

const isPowerOfTwo = (value: number): boolean =>
  value > 0 && (value & (value - 1)) === 0;

/** One explicit local file, with the block grid used to profile its bytes. */
export const measureBinaryEntropyInputSchema = z.strictObject({
  path: triagePathSchema,
  block_size: z
    .number()
    .int()
    .min(ENTROPY_BLOCK_SIZE.min)
    .max(ENTROPY_BLOCK_SIZE.max)
    .refine(isPowerOfTwo, "block_size must be a power of two")
    .default(ENTROPY_BLOCK_SIZE.default)
    .describe(
      "Block length in bytes for the entropy profile; a power of two in [256, 1048576]",
    ),
  max_blocks: z
    .number()
    .int()
    .min(ENTROPY_MAX_BLOCKS.min)
    .max(ENTROPY_MAX_BLOCKS.max)
    .default(ENTROPY_MAX_BLOCKS.default)
    .describe(
      "Largest number of blocks scanned; the block grid is truncated beyond this",
    ),
});

/** Entropy and chi-square over one file-backed section's bytes. */
export const sectionEntropySchema = z.strictObject({
  name: z.string(),
  /** Absolute file offset of the section's first byte. */
  file_offset: nonNegative,
  /** File-backed byte count measured; zero for uninitialized sections. */
  size: nonNegative,
  entropy: entropyValueSchema,
  chi_square: chiSquareSchema,
});

/** A maximal run of consecutive blocks all above or all below a threshold. */
export const entropyRunSchema = z.strictObject({
  /** Absolute file offset of the first byte of the run. */
  start: nonNegative,
  /** Absolute file offset one past the last measured byte of the run. */
  end: nonNegative,
  block_count: z.number().int().positive(),
  mean_entropy: entropyValueSchema,
});

export type SectionEntropy = z.infer<typeof sectionEntropySchema>;
export type EntropyRun = z.infer<typeof entropyRunSchema>;
export type MeasureBinaryEntropyInput = z.infer<
  typeof measureBinaryEntropyInputSchema
>;

/** Whole-file and per-block entropy observations over the exact snapshot bytes. */
export const measureBinaryEntropyReportSchema = z
  .strictObject({
    ...triageReportBase,
    /** Effective block length used for the profile (the caller's block_size). */
    block_size: z.number().int().positive(),
    /** Shannon entropy of the whole file in bits per byte. */
    file_entropy: entropyValueSchema,
    /** Chi-square of the whole file's byte distribution against uniform. */
    file_chi_square: chiSquareSchema,
    /** Arithmetic mean of the file's byte values (uniform random tends to 127.5). */
    mean: z.number().min(0).max(255),
    high_entropy_threshold: z.literal(HIGH_ENTROPY_THRESHOLD),
    low_entropy_threshold: z.literal(LOW_ENTROPY_THRESHOLD),
    /** Per-section entropy when the bytes parse as an executable image; else empty. */
    section_entropy: z.array(sectionEntropySchema),
    section_coverage: triageListCoverageSchema,
    high_entropy_runs: z.array(entropyRunSchema),
    high_entropy_run_coverage: triageListCoverageSchema,
    low_entropy_runs: z.array(entropyRunSchema),
    low_entropy_run_coverage: triageListCoverageSchema,
    /** Blocks examined for the run profile against the total in the file. */
    block_coverage: triageListCoverageSchema,
  })
  .superRefine((report, ctx) => {
    const bytes = report.artifact.bytes;
    refineOffsetsInside(
      bytes,
      report.section_entropy.map((section, index) => ({
        offset: section.file_offset + section.size,
        path: ["section_entropy", index, "size"],
      })),
      ctx,
    );
    checkRuns(bytes, report.high_entropy_runs, "high_entropy_runs", ctx);
    checkRuns(bytes, report.low_entropy_runs, "low_entropy_runs", ctx);
    checkCoverage(report.section_coverage, ["section_coverage"], ctx);
    checkCoverage(report.block_coverage, ["block_coverage"], ctx);
    checkCoverage(
      report.high_entropy_run_coverage,
      ["high_entropy_run_coverage"],
      ctx,
    );
    checkCoverage(
      report.low_entropy_run_coverage,
      ["low_entropy_run_coverage"],
      ctx,
    );
  });

export type MeasureBinaryEntropyReport = z.infer<
  typeof measureBinaryEntropyReportSchema
>;

const checkRuns = (
  bytes: number,
  runs: readonly EntropyRun[],
  field: string,
  ctx: z.RefinementCtx,
): void => {
  for (const [index, run] of runs.entries()) {
    if (run.start >= run.end)
      ctx.addIssue({
        code: "custom",
        message: `Run ${index} does not advance (start ${run.start} >= end ${run.end})`,
        path: [field, index, "end"],
      });
    if (run.end > bytes)
      ctx.addIssue({
        code: "custom",
        message: `Run ${index} end ${run.end} lies outside the ${bytes}-byte artifact`,
        path: [field, index, "end"],
      });
  }
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
