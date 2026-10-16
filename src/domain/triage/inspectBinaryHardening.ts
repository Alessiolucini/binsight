import { z } from "zod";
import {
  hexAddressSchema,
  refineOffsetsInside,
  triageListCoverageSchema,
  triagePathSchema,
  triageReportBase,
  triageSliceSchema,
} from "./triageCommon.js";

/**
 * Cross-platform binary-hardening inspection (checksec-style). Each indicator
 * is reported together with whether it was read from a header/structure bit
 * (`observed`) or inferred from symbols or a heuristic (`inferred`). The
 * overall `mitigations` summary is always inferred.
 */
export const inspectBinaryHardeningInputSchema = z.strictObject({
  path: triagePathSchema,
  slice: triageSliceSchema,
});

export type InspectBinaryHardeningInput = z.infer<
  typeof inspectBinaryHardeningInputSchema
>;

const nonNegative = z.number().int().nonnegative();

/** Whether an indicator value is a header/structure observation or an inference. */
export const hardeningEvidenceKindSchema = z.enum(["observed", "inferred"]);
export type HardeningEvidenceKind = z.infer<typeof hardeningEvidenceKindSchema>;

/** A boolean indicator carrying its own evidence provenance. */
export const hardeningFlagSchema = z.strictObject({
  value: z.boolean(),
  evidence_kind: hardeningEvidenceKindSchema,
});
export type HardeningFlag = z.infer<typeof hardeningFlagSchema>;

/** One writable-and-executable loadable segment (a W^X violation). */
export const rwxSegmentSchema = z.strictObject({
  index: nonNegative,
  type: z.string(),
  file_offset: nonNegative,
  virtual_address: hexAddressSchema,
});
export type RwxSegment = z.infer<typeof rwxSegmentSchema>;

/** FORTIFY_SOURCE accounting inferred from imported `__*_chk` functions. */
export const fortifySchema = z.strictObject({
  fortified_count: nonNegative,
  fortifiable_count: nonNegative,
  evidence_kind: hardeningEvidenceKindSchema,
});

/** ELF hardening indicators, modeled on checksec.sh. */
export const elfHardeningSchema = z.strictObject({
  relro: z.strictObject({
    value: z.enum(["none", "partial", "full"]),
    evidence_kind: hardeningEvidenceKindSchema,
  }),
  stack_canary: hardeningFlagSchema,
  nx: hardeningFlagSchema,
  pie: z.strictObject({
    value: z.enum(["pie", "no-pie", "dso"]),
    evidence_kind: hardeningEvidenceKindSchema,
  }),
  rpath: z.array(z.string()),
  runpath: z.array(z.string()),
  fortify: fortifySchema.nullable(),
  cet_ibt: hardeningFlagSchema,
  cet_shstk: hardeningFlagSchema,
  pac: hardeningFlagSchema,
  bti: hardeningFlagSchema,
  stripped: hardeningFlagSchema,
  rwx_segments: z.array(rwxSegmentSchema),
  rwx_segment_coverage: triageListCoverageSchema,
});
export type ElfHardening = z.infer<typeof elfHardeningSchema>;

/** PE hardening indicators, modeled on winchecksec. */
export const peHardeningSchema = z.strictObject({
  dynamic_base: hardeningFlagSchema,
  high_entropy_va: hardeningFlagSchema,
  nx_compat: hardeningFlagSchema,
  force_integrity: hardeningFlagSchema,
  no_seh: hardeningFlagSchema,
  guard_cf: hardeningFlagSchema,
  safe_seh: hardeningFlagSchema,
  gs_cookie: hardeningFlagSchema,
  cet_compat: hardeningFlagSchema,
  isolation: hardeningFlagSchema,
  appcontainer: hardeningFlagSchema,
  relocations_stripped: hardeningFlagSchema,
  authenticode_present: hardeningFlagSchema,
});
export type PeHardening = z.infer<typeof peHardeningSchema>;

/** Mach-O hardening indicators. */
export const machoHardeningSchema = z.strictObject({
  pie: hardeningFlagSchema,
  allow_stack_execution: hardeningFlagSchema,
  no_heap_execution: hardeningFlagSchema,
  encrypted: hardeningFlagSchema,
  hardened_runtime: hardeningFlagSchema,
  arm64e: hardeningFlagSchema,
  restrict_segment: hardeningFlagSchema,
  stack_chk: hardeningFlagSchema,
});
export type MachoHardening = z.infer<typeof machoHardeningSchema>;

/** Normalized, always-inferred roll-up of the headline protections. */
export const mitigationsSchema = z.strictObject({
  evidence_kind: z.literal("inferred"),
  protections: z.array(
    z.strictObject({
      id: z.string().min(1),
      status: z.enum(["enabled", "disabled", "partial", "unknown"]),
    }),
  ),
});
export type Mitigations = z.infer<typeof mitigationsSchema>;

/** Full hardening report; exactly one per-format block is populated. */
export const inspectBinaryHardeningReportSchema = z
  .strictObject({
    ...triageReportBase,
    format: z.enum(["elf", "pe", "macho"]),
    elf: elfHardeningSchema.nullable(),
    pe: peHardeningSchema.nullable(),
    macho: machoHardeningSchema.nullable(),
    mitigations: mitigationsSchema,
  })
  .superRefine((report, context) => {
    const populated = [report.elf, report.pe, report.macho].filter(
      (block) => block !== null,
    ).length;
    if (populated !== 1)
      context.addIssue({
        code: "custom",
        path: ["format"],
        message:
          "Exactly one of elf, pe or macho must be populated for a hardening report.",
      });
    if (
      (report.format === "elf" && report.elf === null) ||
      (report.format === "pe" && report.pe === null) ||
      (report.format === "macho" && report.macho === null)
    )
      context.addIssue({
        code: "custom",
        path: ["format"],
        message: "Report format does not match the populated detail block.",
      });
    if (report.elf !== null)
      refineOffsetsInside(
        report.artifact.bytes,
        report.elf.rwx_segments.map((segment, index) => ({
          offset: segment.file_offset,
          path: ["elf", "rwx_segments", index, "file_offset"],
        })),
        context,
      );
  });

export type InspectBinaryHardeningReport = z.infer<
  typeof inspectBinaryHardeningReportSchema
>;
