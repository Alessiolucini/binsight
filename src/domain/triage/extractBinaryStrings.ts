import { z } from "zod";
import {
  TRIAGE_OUTPUT_BYTES,
  refineOffsetsInside,
  triageListCoverageSchema,
  triagePathSchema,
  triageReportBase,
} from "./triageCommon.js";

/** Encodings scanned for printable runs: single-byte, UTF-16LE, and multi-byte UTF-8. */
export const stringEncodingSchema = z.enum(["ascii", "utf16le", "utf8"]);
export type StringEncoding = z.infer<typeof stringEncodingSchema>;

/**
 * Inferred classifications layered over observed bytes. A tag is a pattern
 * match, never a judgement about secrecy, validity, or reachability.
 */
export const stringTagSchema = z.enum([
  "url",
  "ipv4",
  "ipv6",
  "domain",
  "email",
  "path_windows",
  "path_posix",
  "registry_key",
  "guid",
  "base64_blob",
  "pem",
  "jwt",
  "user_agent",
  "format_string",
  "sql",
]);
export type StringTag = z.infer<typeof stringTagSchema>;

/** Default byte ceiling for the returned string text, before a typed resource refusal. */
export const EXTRACT_STRINGS_DEFAULT_MAX_TOTAL_BYTES = 1024 * 1024;

/** One explicit local file; strings are read from its bytes without executing it. */
export const extractBinaryStringsInputSchema = z.strictObject({
  path: triagePathSchema,
  min_length: z
    .number()
    .int()
    .min(4)
    .max(64)
    .default(5)
    .describe("Minimum printable character count for a reported string"),
  encodings: z
    .array(stringEncodingSchema)
    .min(1)
    .max(3)
    .default(["ascii", "utf16le"])
    .describe("Character encodings to scan for printable runs"),
  categories: z
    .array(stringTagSchema)
    .min(1)
    .max(15)
    .optional()
    .describe(
      "Return only strings carrying at least one of these inferred tags; omit for no tag filter",
    ),
  max_strings: z
    .number()
    .int()
    .min(1)
    .max(20_000)
    .default(2000)
    .describe("Maximum number of strings to return before truncating"),
  max_total_bytes: z
    .number()
    .int()
    .min(1024)
    .max(TRIAGE_OUTPUT_BYTES)
    .default(EXTRACT_STRINGS_DEFAULT_MAX_TOTAL_BYTES)
    .describe(
      "Maximum total bytes of returned string text; exceeding it is a typed resource refusal",
    ),
});
export type ExtractBinaryStringsInput = z.infer<
  typeof extractBinaryStringsInputSchema
>;

/** One recovered printable run with inferred tags and its position in the file. */
export const extractedStringSchema = z.strictObject({
  text: z.string(),
  encoding: stringEncodingSchema,
  file_offset: z.number().int().nonnegative(),
  /** Containing section of the default image slice, or null when unmapped or not an image. */
  section: z.string().nullable(),
  /** Printable character count of the run, which may exceed `text.length` when capped. */
  length: z.number().int().positive(),
  tags: z.array(stringTagSchema),
});
export type ExtractedString = z.infer<typeof extractedStringSchema>;

/** Observed string recovery plus inferred tag classifications. */
export const extractBinaryStringsReportSchema = z
  .strictObject({
    ...triageReportBase,
    min_length: z.number().int().min(4).max(64),
    encodings: z.array(stringEncodingSchema).min(1),
    categories: z.array(stringTagSchema).nullable(),
    strings: z.array(extractedStringSchema),
    string_coverage: triageListCoverageSchema,
    /** Tag occurrence counts among the returned strings only. */
    tag_summary: z.partialRecord(stringTagSchema, z.number().int().positive()),
  })
  .superRefine((report, ctx) => {
    refineOffsetsInside(
      report.artifact.bytes,
      report.strings.map((entry, index) => ({
        offset: entry.file_offset,
        path: ["strings", index, "file_offset"],
      })),
      ctx,
    );
    if (report.string_coverage.returned !== report.strings.length)
      ctx.addIssue({
        code: "custom",
        path: ["string_coverage", "returned"],
        message:
          "Coverage returned count does not match the string list length.",
      });
    if (report.string_coverage.returned > report.string_coverage.total)
      ctx.addIssue({
        code: "custom",
        path: ["string_coverage", "total"],
        message: "Coverage returned count exceeds the total qualifying count.",
      });
  });
export type ExtractBinaryStringsReport = z.infer<
  typeof extractBinaryStringsReportSchema
>;
