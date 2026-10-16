import { z } from "zod";
import { digestSchema } from "../digests.js";
import { localPathStringSchema } from "../localPath.js";

/** Largest file every static triage reader admits into memory. */
export const TRIAGE_INPUT_BYTES = 256 * 1024 * 1024;
/** Largest complete inline report before a typed transport failure. */
export const TRIAGE_OUTPUT_BYTES = 8 * 1024 * 1024;

const nonNegative = z.number().int().nonnegative();

/** Exact identity of the bytes that were read once for one report. */
export const triageArtifactSchema = z.strictObject({
  path: localPathStringSchema,
  sha256: digestSchema,
  bytes: nonNegative,
});

/** Evidence subject family; `file` for content without an executable header. */
export const triageSubjectFormatSchema = z.enum([
  "elf",
  "pe",
  "mach-o",
  "file",
]);
export type TriageSubjectFormat = z.infer<typeof triageSubjectFormatSchema>;

export const triageSubjectSchema = z.strictObject({
  format: triageSubjectFormatSchema,
  /** Normalized architecture family, or null when unknown or not applicable. */
  architecture: z.string().min(1).nullable(),
});

/** Lowercase 0x-prefixed hexadecimal address preserving 64-bit precision. */
export const hexAddressSchema = z.string().regex(/^0x[0-9a-f]+$/u);

export const toHexAddress = (value: bigint | number): string =>
  `0x${value.toString(16)}`;

/** Shared caller path field for every static triage tool. */
export const triagePathSchema = localPathStringSchema.describe(
  "Absolute filesystem path to the selected local file",
);

/** Caller-selected Mach-O universal slice, by normalized architecture name. */
export const triageSliceSchema = z
  .enum(["x86", "x86_64", "arm", "arm64", "powerpc"])
  .optional()
  .describe(
    "Architecture of the Mach-O universal slice to analyze; defaults to the first declared slice",
  );

/** Position of an analyzed region: file offset plus section and address when mapped. */
export const triageLocationSchema = z.strictObject({
  file_offset: nonNegative,
  section: z.string().nullable(),
  virtual_address: hexAddressSchema.nullable(),
});

/** Fields every triage report carries in addition to its own observations. */
export const triageReportBase = {
  artifact: triageArtifactSchema,
  subject: triageSubjectSchema,
  limitations: z.array(z.string()),
} as const;

/** One bounded list together with whether the bound was reached. */
export const triageListCoverageSchema = z.strictObject({
  total: nonNegative,
  returned: nonNegative,
  truncated: z.boolean(),
});

/** Ensure every file offset in a report lies inside the analyzed artifact. */
export const refineOffsetsInside = (
  bytes: number,
  offsets: readonly {
    readonly offset: number;
    readonly path: (string | number)[];
  }[],
  ctx: z.RefinementCtx,
): void => {
  for (const { offset, path } of offsets)
    if (offset > bytes)
      ctx.addIssue({
        code: "custom",
        message: `Offset ${offset} lies outside the ${bytes}-byte artifact`,
        path,
      });
};
