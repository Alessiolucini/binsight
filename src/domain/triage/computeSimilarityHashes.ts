import { z } from "zod";
import { digestSchema } from "../digests.js";
import {
  hexAddressSchema,
  refineOffsetsInside,
  triageListCoverageSchema,
  triagePathSchema,
  triageReportBase,
  triageSliceSchema,
} from "./triageCommon.js";

/** Lowercase 32-hex MD5, as every MD5-based identifier here is emitted. */
export const md5Schema = z.string().regex(/^[a-f0-9]{32}$/u);

/** Canonical TLSH "T1" digest: version byte plus 70 uppercase hex nibbles. */
export const tlshSchema = z.string().regex(/^T1[0-9A-F]{70}$/u);

/** Canonical ssdeep digest `blocksize:signature1:signature2`. */
export const ssdeepSchema = z
  .string()
  .regex(/^[0-9]+:[A-Za-z0-9+\x2f]*:[A-Za-z0-9+\x2f]*$/u);

/** One file-backed section and the SHA-256 of exactly its on-disk bytes. */
export const perSectionDigestSchema = z.strictObject({
  name: z.string(),
  file_offset: z.number().int().nonnegative(),
  size: z.number().int().positive(),
  virtual_address: hexAddressSchema.nullable(),
  sha256: digestSchema,
});

export type PerSectionDigest = z.infer<typeof perSectionDigestSchema>;

/** One explicit local file, with an optional universal-binary slice selector. */
export const computeSimilarityHashesInputSchema = z.strictObject({
  path: triagePathSchema,
  slice: triageSliceSchema,
});

export type ComputeSimilarityHashesInput = z.infer<
  typeof computeSimilarityHashesInputSchema
>;

/**
 * Whole-file and image-derived similarity identifiers. A field is null (never
 * absent) when its inputs are not present in the selected file or slice; a
 * matching limitation is recorded for each null field.
 */
export const computeSimilarityHashesReportSchema = z
  .strictObject({
    ...triageReportBase,
    /** SHA-256 of the whole analyzed file. */
    sha256: digestSchema,
    /** MD5 of the whole analyzed file. */
    md5: md5Schema,
    /** pefile-compatible PE import hash, or null for non-PE / no imports. */
    imphash: md5Schema.nullable(),
    /** imphash over the same import tokens sorted, or null when imphash is null. */
    imphash_sorted: md5Schema.nullable(),
    /** MD5 of the unmasked PE Rich header bytes, or null when absent. */
    rich_pe_hash: md5Schema.nullable(),
    /** TLSH over the ELF dynamic-symbol function names, or null when absent/short. */
    telfhash: tlshSchema.nullable(),
    /** MD5 of the Mach-O external undefined symbol names, or null when absent. */
    symhash: md5Schema.nullable(),
    /** TLSH over the whole file, or null when too short or too uniform. */
    tlsh: tlshSchema.nullable(),
    /** ssdeep (CTPH) digest over the whole file; always present. */
    ssdeep: ssdeepSchema,
    per_section_sha256: z.array(perSectionDigestSchema),
    per_section_coverage: triageListCoverageSchema,
    limitations: z.array(z.string()),
  })
  .superRefine((report, context) => {
    refineOffsetsInside(
      report.artifact.bytes,
      report.per_section_sha256.map((section, index) => ({
        offset: section.file_offset + section.size,
        path: ["per_section_sha256", index, "file_offset"],
      })),
      context,
    );
    if (report.imphash === null && report.imphash_sorted !== null)
      context.addIssue({
        code: "custom",
        path: ["imphash_sorted"],
        message: "imphash_sorted must be null whenever imphash is null.",
      });
    const coverage = report.per_section_coverage;
    if (
      coverage.returned !== report.per_section_sha256.length ||
      coverage.returned > coverage.total ||
      coverage.truncated !== coverage.returned < coverage.total
    )
      context.addIssue({
        code: "custom",
        path: ["per_section_coverage"],
        message: "Section coverage does not match the returned digests.",
      });
  });

export type ComputeSimilarityHashesReport = z.infer<
  typeof computeSimilarityHashesReportSchema
>;
