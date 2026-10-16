import { z } from "zod";
import {
  triagePathSchema,
  triageReportBase,
  triageSliceSchema,
} from "./triageCommon.js";

/** One explicit local file to summarize as a shareable Markdown report. */
export const generateTriageReportInputSchema = z.strictObject({
  path: triagePathSchema,
  slice: triageSliceSchema,
});
export type GenerateTriageReportInput = z.infer<
  typeof generateTriageReportInputSchema
>;

/** A rendered Markdown triage report plus the facets it was built from. */
export const generateTriageReportReportSchema = z.strictObject({
  ...triageReportBase,
  file_type: z.enum(["elf", "pe", "macho", "data"]),
  sha256: z.string().regex(/^[0-9a-f]{64}$/u),
  md5: z.string().regex(/^[0-9a-f]{32}$/u),
  /** GitHub-flavored Markdown; all values are REA labels, hashes and numbers. */
  markdown: z.string().min(1),
});
export type GenerateTriageReportReport = z.infer<
  typeof generateTriageReportReportSchema
>;
