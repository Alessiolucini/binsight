import { z } from "zod";
import { CAPABILITY_TAXONOMY_VERSION } from "./capabilitySignatures.js";
import {
  triageListCoverageSchema,
  triagePathSchema,
  triageReportBase,
  triageSliceSchema,
} from "./triageCommon.js";

/** Largest number of supporting imports recorded per capability. */
export const CLASSIFY_CAPABILITIES_MAX_SUPPORT = 64;

/** One explicit local executable whose import table is classified. */
export const classifyImportCapabilitiesInputSchema = z.strictObject({
  path: triagePathSchema,
  slice: triageSliceSchema,
  max_support: z
    .number()
    .int()
    .min(1)
    .max(CLASSIFY_CAPABILITIES_MAX_SUPPORT)
    .default(16)
    .describe(
      "Maximum supporting imports listed per capability before truncation",
    ),
});
export type ClassifyImportCapabilitiesInput = z.infer<
  typeof classifyImportCapabilitiesInputSchema
>;

const supportingImportSchema = z.strictObject({
  library: z.string().nullable(),
  name: z.string(),
});

/** One inferred capability class with the imports that triggered it. */
export const importCapabilitySchema = z.strictObject({
  id: z.string().min(1),
  label: z.string().min(1),
  confidence: z.enum(["high", "medium", "low"]),
  evidence_kind: z.literal("inferred"),
  supporting_imports: z.array(supportingImportSchema),
  supporting_coverage: triageListCoverageSchema,
});

export const classifyImportCapabilitiesReportSchema = z.strictObject({
  ...triageReportBase,
  taxonomy_version: z.literal(CAPABILITY_TAXONOMY_VERSION),
  /** Imports examined after de-duplication by library+name. */
  import_count: z.number().int().nonnegative(),
  /** A runtime symbol-resolution API (GetProcAddress/dlsym/...) is imported. */
  unresolved_dynamic: z.boolean(),
  capabilities: z.array(importCapabilitySchema),
});
export type ClassifyImportCapabilitiesReport = z.infer<
  typeof classifyImportCapabilitiesReportSchema
>;
