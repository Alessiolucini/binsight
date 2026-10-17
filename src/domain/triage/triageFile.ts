import { z } from "zod";
import {
  triagePathSchema,
  triageReportBase,
  triageSliceSchema,
} from "./triageCommon.js";

/** One explicit local file to triage in a single read-only pass. */
export const triageFileInputSchema = z.strictObject({
  path: triagePathSchema,
  slice: triageSliceSchema,
});
export type TriageFileInput = z.infer<typeof triageFileInputSchema>;

const indicatorSchema = z.strictObject({
  name: z.string().min(1),
  category: z.string().min(1),
  confidence: z.enum(["high", "medium", "low"]),
});

const formatSummarySchema = z.strictObject({
  format: z.enum(["elf", "pe", "macho"]),
  bits: z.union([z.literal(32), z.literal(64)]),
  architecture: z.string().nullable(),
  entry_point: z.string().nullable(),
  imports: z.number().int().nonnegative(),
  exports: z.number().int().nonnegative(),
  libraries: z.number().int().nonnegative(),
  has_overlay: z.boolean(),
});

const entropySummarySchema = z.strictObject({
  file: z.number(),
  overlay: z.number().nullable(),
  classification: z.enum(["low", "normal", "high"]),
});

const toolchainSummarySchema = z.strictObject({
  indicators: z.array(indicatorSchema),
  packed: z.enum(["likely_packed", "not_observed", "unknown"]),
});

const capabilitySummarySchema = z.strictObject({
  ids: z.array(z.string()),
  unresolved_dynamic: z.boolean(),
});

const signatureSummarySchema = z.strictObject({
  present: z.boolean(),
  format: z.enum(["authenticode", "macho"]).nullable(),
});

const stringsSummarySchema = z.strictObject({
  total: z.number().int().nonnegative(),
  tag_summary: z.record(z.string(), z.number().int().nonnegative()),
});

/** A suggested follow-up BinSight operation and why it is worth running next. */
export const nextProbeSchema = z.strictObject({
  operation: z.string().min(1),
  rationale: z.string().min(1),
});

/** Compact one-call triage summary with evidence-backed facets and next steps. */
export const triageFileReportSchema = z.strictObject({
  ...triageReportBase,
  file_type: z.enum(["elf", "pe", "macho", "data"]),
  md5: z.string().regex(/^[0-9a-f]{32}$/u),
  format: formatSummarySchema.nullable(),
  entropy: entropySummarySchema,
  toolchain: toolchainSummarySchema,
  capabilities: capabilitySummarySchema,
  code_signature: signatureSummarySchema,
  strings: stringsSummarySchema,
  next_probes: z.array(nextProbeSchema),
});
export type TriageFileReport = z.infer<typeof triageFileReportSchema>;
