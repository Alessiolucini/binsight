import { z } from "zod";
import {
  hexAddressSchema,
  triageListCoverageSchema,
  triagePathSchema,
  triageReportBase,
  triageSliceSchema,
} from "./triageCommon.js";

const nonNegative = z.number().int().nonnegative();

/** Largest number of recovered functions returned before coverage truncation. */
export const RECOVER_GO_SYMBOLS_MAX_FUNCTIONS_LIMIT = 200_000;
const DEFAULT_MAX_FUNCTIONS = 20_000;

/** One explicit local file plus the optional universal slice and output bound. */
export const recoverGoSymbolsInputSchema = z.strictObject({
  path: triagePathSchema,
  slice: triageSliceSchema,
  max_functions: nonNegative
    .min(1)
    .max(RECOVER_GO_SYMBOLS_MAX_FUNCTIONS_LIMIT)
    .default(DEFAULT_MAX_FUNCTIONS)
    .describe(
      "Maximum recovered functions to return inline; the remainder is reported through function_coverage",
    ),
});

/** Published `pclntab` header magic values, each identifying a format revision. */
export const GO_PCLNTAB_VERSIONS = ["1.2", "1.16", "1.18", "1.20"] as const;

/** Decoded `pclntab` header identity; absent sources leave every list empty. */
export const goPclntabSchema = z.strictObject({
  file_offset: nonNegative,
  version: z.enum(GO_PCLNTAB_VERSIONS),
  /** Header-declared function count, which may exceed the returned functions. */
  function_count: nonNegative,
  pointer_size: z.union([z.literal(4), z.literal(8)]),
});

/** One function name observed in the embedded table, with its entry address. */
export const goRecoveredFunctionSchema = z.strictObject({
  name: z.string().min(1),
  entry: hexAddressSchema,
  /** Mapped file offset of the entry address, or null when not file-backed. */
  file_offset: nonNegative.nullable(),
});

export type GoRecoveredFunction = z.infer<typeof goRecoveredFunctionSchema>;

/** Bounded observation of the Go `pclntab`; absence is not a language verdict. */
export const recoverGoSymbolsReportSchema = z
  .strictObject({
    ...triageReportBase,
    /** A decodable `pclntab` was located; false leaves pclntab and lists empty. */
    is_go: z.boolean(),
    /** Lowercase 0x-prefixed header magic, or null when no table was found. */
    go_version_magic: hexAddressSchema.nullable(),
    pclntab: goPclntabSchema.nullable(),
    functions: z.array(goRecoveredFunctionSchema),
    function_coverage: triageListCoverageSchema,
    /** Package prefixes derived from recovered function names (returned set). */
    package_names: z.array(z.string().min(1)),
    package_coverage: triageListCoverageSchema,
  })
  .superRefine((report, context) => {
    const bytes = report.artifact.bytes;
    const addIssue = (path: (string | number)[], message: string): void => {
      context.addIssue({ code: "custom", path, message });
    };
    if (report.pclntab === null) {
      if (report.is_go)
        addIssue(["is_go"], "A Go report without a pclntab cannot be is_go.");
      if (
        report.functions.length !== 0 ||
        report.package_names.length !== 0 ||
        report.go_version_magic !== null
      )
        addIssue(
          ["pclntab"],
          "A report without a pclntab must carry no functions, packages or magic.",
        );
    } else if (report.pclntab.file_offset > bytes) {
      addIssue(
        ["pclntab", "file_offset"],
        `pclntab offset ${report.pclntab.file_offset} lies outside the ${bytes}-byte artifact.`,
      );
    }
    for (const [index, entry] of report.functions.entries())
      if (entry.file_offset !== null && entry.file_offset > bytes)
        addIssue(
          ["functions", index, "file_offset"],
          `Function offset ${entry.file_offset} lies outside the ${bytes}-byte artifact.`,
        );
    checkCoverage(
      report.function_coverage,
      report.functions.length,
      ["function_coverage"],
      addIssue,
    );
    checkCoverage(
      report.package_coverage,
      report.package_names.length,
      ["package_coverage"],
      addIssue,
    );
  });

const checkCoverage = (
  coverage: z.infer<typeof triageListCoverageSchema>,
  returned: number,
  path: (string | number)[],
  addIssue: (path: (string | number)[], message: string) => void,
): void => {
  if (coverage.returned !== returned)
    addIssue(path, "Coverage returned count disagrees with the emitted list.");
  if (coverage.returned > coverage.total)
    addIssue(path, "Coverage returned count exceeds its total.");
  if (coverage.truncated !== coverage.returned < coverage.total)
    addIssue(path, "Coverage truncation flag disagrees with its counts.");
};

/** Parsed input the analyzer consumes, with defaults resolved. */
export type RecoverGoSymbolsInput = z.infer<typeof recoverGoSymbolsInputSchema>;
export type RecoverGoSymbolsReport = z.infer<
  typeof recoverGoSymbolsReportSchema
>;
