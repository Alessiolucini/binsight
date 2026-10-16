import { z } from "zod";
import {
  refineOffsetsInside,
  triageListCoverageSchema,
  triagePathSchema,
  triageReportBase,
} from "./triageCommon.js";

/**
 * Static scan for well-known cryptographic and hashing constant tables. A
 * match is an observed byte sequence; attributing it to an algorithm is an
 * inference, so every finding carries `evidence_kind: "inferred"`.
 */

const nonNegative = z.number().int().nonnegative();

/** One explicit local file to scan; no slice, the whole file is searched. */
export const identifyCryptoConstantsInputSchema = z.strictObject({
  path: triagePathSchema,
});

export type IdentifyCryptoConstantsInput = z.infer<
  typeof identifyCryptoConstantsInputSchema
>;

/** Family of constant a finding belongs to. */
export const cryptoFindingKindSchema = z.enum([
  "sbox",
  "iv",
  "round_constant",
  "table",
  "magic",
  "curve_param",
]);

/** One constant located in the file. Byte order is the word encoding matched. */
export const cryptoFindingSchema = z.strictObject({
  algorithm: z.string().min(1),
  kind: cryptoFindingKindSchema,
  evidence_kind: z.literal("inferred"),
  file_offset: nonNegative,
  section: z.string().nullable(),
  byte_order: z.enum(["le", "be", "any"]),
  length: z.number().int().positive(),
});

export type CryptoFinding = z.infer<typeof cryptoFindingSchema>;

/** How many of a given algorithm were located, for a quick scan of the result. */
export const cryptoAlgorithmCountSchema = z.strictObject({
  algorithm: z.string().min(1),
  count: z.number().int().positive(),
});

/** Bounded constant inventory. An empty `findings` list is an observed absence of known tables. */
export const identifyCryptoConstantsReportSchema = z
  .strictObject({
    ...triageReportBase,
    findings: z.array(cryptoFindingSchema),
    finding_coverage: triageListCoverageSchema,
    algorithm_summary: z.array(cryptoAlgorithmCountSchema),
  })
  .superRefine((report, context) => {
    refineOffsetsInside(
      report.artifact.bytes,
      report.findings.map((finding, index) => ({
        offset: finding.file_offset + finding.length,
        path: ["findings", index, "file_offset"],
      })),
      context,
    );
    if (report.finding_coverage.returned !== report.findings.length)
      context.addIssue({
        code: "custom",
        path: ["finding_coverage", "returned"],
        message:
          "Coverage returned count does not match the findings array length.",
      });
    const summed = report.algorithm_summary.reduce(
      (total, entry) => total + entry.count,
      0,
    );
    if (summed !== report.findings.length)
      context.addIssue({
        code: "custom",
        path: ["algorithm_summary"],
        message:
          "Algorithm summary counts do not sum to the number of findings.",
      });
  });

export type IdentifyCryptoConstantsReport = z.infer<
  typeof identifyCryptoConstantsReportSchema
>;
