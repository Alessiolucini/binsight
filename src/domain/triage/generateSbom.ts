import { z } from "zod";
import {
  hexAddressSchema,
  refineOffsetsInside,
  triageListCoverageSchema,
  triageLocationSchema,
  triagePathSchema,
  triageReportBase,
} from "./triageCommon.js";

/** Output document families this tool can render inline. */
export const sbomFormatSchema = z
  .enum(["both", "cyclonedx", "spdx"])
  .default("both")
  .describe(
    "Which SBOM document(s) to render inline alongside the normalized list",
  );

/** One explicit local file; the inventory never executes or writes anything. */
export const generateSbomInputSchema = z.strictObject({
  path: triagePathSchema,
  format: sbomFormatSchema,
});

/** Where an identity was derived from; absence of a source is never completeness. */
export const componentSourceSchema = z.enum([
  "go-buildinfo",
  "cargo-auditable",
  "binary-classifier",
]);

/** One inventoried component. `module` denotes a language runtime/toolchain. */
export const sbomComponentSchema = z.strictObject({
  name: z.string().min(1),
  /** Observed or recorded version; null when the source carries none. */
  version: z.string().min(1).nullable(),
  type: z.enum(["library", "application", "module"]),
  source: componentSourceSchema,
  /** Package URL when a canonical coordinate exists, else null. */
  purl: z.string().min(1).nullable(),
  /** Derived from recorded metadata, or inferred from a byte signature. */
  evidence_kind: z.enum(["derived", "inferred"]),
  /** Bounded file positions supporting the component. */
  locations: z.array(triageLocationSchema).min(1),
});

export type SbomComponent = z.infer<typeof sbomComponentSchema>;

/** CycloneDX 1.6-shaped document rendered from the normalized components. */
const cyclonedxComponentSchema = z.strictObject({
  "bom-ref": z.string().min(1),
  type: z.enum(["library", "application"]),
  name: z.string().min(1),
  version: z.string().min(1).optional(),
  purl: z.string().min(1).optional(),
});

export const cyclonedxDocumentSchema = z.strictObject({
  bomFormat: z.literal("CycloneDX"),
  specVersion: z.literal("1.6"),
  version: z.literal(1),
  metadata: z.strictObject({
    tools: z.strictObject({
      components: z.array(
        z.strictObject({
          type: z.literal("application"),
          name: z.string().min(1),
          version: z.string().min(1),
        }),
      ),
    }),
  }),
  components: z.array(cyclonedxComponentSchema),
});

/** SPDX 2.3-shaped document rendered from the normalized components. */
const spdxPackageSchema = z.strictObject({
  SPDXID: z.string().regex(/^SPDXRef-[0-9A-Za-z.\x2d]+$/u),
  name: z.string().min(1),
  versionInfo: z.string().min(1).optional(),
  downloadLocation: z.literal("NOASSERTION"),
  filesAnalyzed: z.literal(false),
  externalRefs: z
    .array(
      z.strictObject({
        referenceCategory: z.literal("PACKAGE-MANAGER"),
        referenceType: z.literal("purl"),
        referenceLocator: z.string().min(1),
      }),
    )
    .optional(),
});

export const spdxDocumentSchema = z.strictObject({
  spdxVersion: z.literal("SPDX-2.3"),
  dataLicense: z.literal("CC0-1.0"),
  SPDXID: z.literal("SPDXRef-DOCUMENT"),
  name: z.string().min(1),
  documentNamespace: z.string().regex(/^urn:binsight:sbom:[0-9a-f]{64}$/u),
  creationInfo: z.strictObject({
    created: z.string(),
    creators: z.array(z.string().min(1)).min(1),
  }),
  packages: z.array(spdxPackageSchema),
});

/** Complete bounded component inventory; `completeness` is always partial. */
export const generateSbomReportSchema = z
  .strictObject({
    ...triageReportBase,
    components: z.array(sbomComponentSchema),
    component_coverage: triageListCoverageSchema,
    completeness: z.literal("partial"),
    cyclonedx: cyclonedxDocumentSchema.nullable(),
    spdx: spdxDocumentSchema.nullable(),
    /** Entry point address of the analyzed image, or null for a plain file. */
    entry_point: hexAddressSchema.nullable(),
  })
  .superRefine((report, context) => {
    refineOffsetsInside(
      report.artifact.bytes,
      report.components.flatMap((component, componentIndex) =>
        component.locations.map((location, locationIndex) => ({
          offset: location.file_offset,
          path: [
            "components",
            componentIndex,
            "locations",
            locationIndex,
            "file_offset",
          ],
        })),
      ),
      context,
    );
    if (report.component_coverage.returned !== report.components.length)
      context.addIssue({
        code: "custom",
        path: ["component_coverage", "returned"],
        message:
          "Returned coverage count disagrees with the component list length.",
      });
    if (
      report.cyclonedx !== null &&
      report.cyclonedx.components.length !== report.components.length
    )
      context.addIssue({
        code: "custom",
        path: ["cyclonedx", "components"],
        message:
          "CycloneDX component count disagrees with the normalized list.",
      });
    if (
      report.spdx !== null &&
      report.spdx.packages.length !== report.components.length
    )
      context.addIssue({
        code: "custom",
        path: ["spdx", "packages"],
        message: "SPDX package count disagrees with the normalized list.",
      });
  });

export type GenerateSbomInput = z.infer<typeof generateSbomInputSchema>;
export type GenerateSbomReport = z.infer<typeof generateSbomReportSchema>;
export type CyclonedxDocument = z.infer<typeof cyclonedxDocumentSchema>;
export type SpdxDocument = z.infer<typeof spdxDocumentSchema>;
