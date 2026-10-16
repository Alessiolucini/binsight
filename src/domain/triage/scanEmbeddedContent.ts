import { z } from "zod";
import { CARVING_TYPES } from "./carvingSignatures.js";
import {
  triageListCoverageSchema,
  triagePathSchema,
  triageReportBase,
} from "./triageCommon.js";

const nonNegative = z.number().int().nonnegative();

/** Default and bound for the number of reported findings. */
export const SCAN_MAX_FINDINGS_DEFAULT = 1000;
/** Default sliding-window width, in bytes, for the entropy profile. */
export const SCAN_ENTROPY_WINDOW_DEFAULT = 8192;

/** One local file selected for embedded-content identification. */
export const scanEmbeddedContentInputSchema = z.strictObject({
  path: triagePathSchema,
  max_findings: nonNegative
    .min(1)
    .max(10_000)
    .default(SCAN_MAX_FINDINGS_DEFAULT)
    .describe(
      "Maximum number of identified regions to return, most confident and earliest first",
    ),
  entropy_window: nonNegative
    .min(256)
    .max(1_048_576)
    .default(SCAN_ENTROPY_WINDOW_DEFAULT)
    .describe(
      "Requested width in bytes of each entropy-profile sample; widened for very large files",
    ),
});

export type ScanEmbeddedContentInput = z.infer<
  typeof scanEmbeddedContentInputSchema
>;

/** Closed set of content families the signature table can classify. */
export const carvingTypeSchema = z.enum(CARVING_TYPES);

/** Confidence that a candidate magic really begins the named content. */
export const carvingConfidenceSchema = z.enum(["high", "medium", "low"]);

/**
 * One identified region. `file_offset` is where the content begins; `size` is
 * the byte length when the structure declares or lets us derive one, else null
 * (identification is not extraction). `validated` is true when a structural
 * check beyond the magic bytes succeeded.
 */
export const embeddedFindingSchema = z.strictObject({
  type: carvingTypeSchema,
  file_offset: nonNegative,
  size: nonNegative.nullable(),
  confidence: carvingConfidenceSchema,
  validated: z.boolean(),
  description: z.string().min(1),
});

export type EmbeddedFinding = z.infer<typeof embeddedFindingSchema>;

/** A maximal run of a single padding byte, `end` exclusive. */
export const paddingRunSchema = z
  .strictObject({
    byte: z.enum(["00", "ff"]),
    start: nonNegative,
    end: nonNegative,
  })
  .refine((run) => run.end > run.start, {
    message: "A padding run must end after it starts.",
  });

export type PaddingRun = z.infer<typeof paddingRunSchema>;

/** Shannon entropy (bits/byte) measured over one window beginning at `offset`. */
export const entropyPointSchema = z.strictObject({
  offset: nonNegative,
  entropy: z.number().min(0).max(8),
});

export type EntropyPoint = z.infer<typeof entropyPointSchema>;

/** Complete, bounded embedded-content report. */
export const scanEmbeddedContentReportSchema = z
  .strictObject({
    ...triageReportBase,
    /** Actual entropy window used, which may exceed the requested value. */
    entropy_window: nonNegative,
    findings: z.array(embeddedFindingSchema),
    findings_coverage: triageListCoverageSchema,
    padding_runs: z.array(paddingRunSchema),
    padding_runs_coverage: triageListCoverageSchema,
    entropy_profile: z.array(entropyPointSchema),
    entropy_profile_coverage: triageListCoverageSchema,
  })
  .superRefine((report, ctx) => {
    const limit = report.artifact.bytes;
    for (const [index, finding] of report.findings.entries()) {
      const declaredEnd =
        finding.size === null
          ? finding.file_offset
          : finding.file_offset + finding.size;
      if (finding.file_offset > limit || declaredEnd > limit)
        ctx.addIssue({
          code: "custom",
          path: ["findings", index],
          message: `Finding at ${finding.file_offset} extends past the ${limit}-byte artifact.`,
        });
    }
    for (const [index, run] of report.padding_runs.entries())
      if (run.end > limit)
        ctx.addIssue({
          code: "custom",
          path: ["padding_runs", index],
          message: `Padding run ends at ${run.end}, past the ${limit}-byte artifact.`,
        });
    for (const [index, point] of report.entropy_profile.entries())
      if (point.offset > limit)
        ctx.addIssue({
          code: "custom",
          path: ["entropy_profile", index],
          message: `Entropy sample offset ${point.offset} is past the ${limit}-byte artifact.`,
        });
  });

export type ScanEmbeddedContentReport = z.infer<
  typeof scanEmbeddedContentReportSchema
>;
