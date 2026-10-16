import { createHash } from "node:crypto";
import type { ExecutableImage } from "../domain/native/image/executableImage.js";
import type {
  TriageFileInput,
  TriageFileReport,
} from "../domain/triage/triageFile.js";
import { detectBinaryToolchainInputSchema } from "../domain/triage/detectBinaryToolchain.js";
import { extractBinaryStringsInputSchema } from "../domain/triage/extractBinaryStrings.js";
import { toHexAddress } from "../domain/triage/triageCommon.js";
import { classifyImportTable } from "./ClassifyImportCapabilities.js";
import { analyzeDetectBinaryToolchain } from "./DetectBinaryToolchain.js";
import { analyzeExtractBinaryStrings } from "./ExtractBinaryStrings.js";
import {
  loadTriageImage,
  roundTo,
  shannonEntropy,
  triageSubject,
  type TriageAnalysisContext,
} from "./triageSupport.js";

type ReportBody = Omit<TriageFileReport, "artifact">;

const HIGH_ENTROPY = 7.2;
const LOW_ENTROPY = 1.0;
const TOP_INDICATORS = 8;

const entropyClass = (value: number): "low" | "normal" | "high" =>
  value >= HIGH_ENTROPY ? "high" : value <= LOW_ENTROPY ? "low" : "normal";

const formatSummary = (image: ExecutableImage): ReportBody["format"] => ({
  format: image.format,
  bits: image.bits,
  architecture: image.architecture,
  entry_point:
    image.entry_point.virtual_address === null
      ? null
      : toHexAddress(image.entry_point.virtual_address),
  imports: image.imports.length,
  exports: image.exports.length,
  libraries: image.libraries.length,
  has_overlay: image.overlay !== null,
});

const signatureSummary = (
  image: ExecutableImage | null,
): ReportBody["code_signature"] => {
  if (
    image?.pe?.security_directory != null &&
    image.pe.security_directory.size > 0
  )
    return { present: true, format: "authenticode" };
  if (image?.macho?.code_signature != null)
    return { present: true, format: "macho" };
  return { present: false, format: null };
};

const nextProbes = (
  image: ExecutableImage | null,
  packed: string,
  signature: boolean,
): ReportBody["next_probes"] => {
  const probes: ReportBody["next_probes"] = [];
  if (image !== null) {
    probes.push({
      operation: "inspect_executable",
      rationale: "Enumerate full sections, imports and exports.",
    });
    if (image.imports.length > 0)
      probes.push({
        operation: "classify_import_capabilities",
        rationale: "Review the imported API capabilities in detail.",
      });
    probes.push({
      operation: "inspect_binary_hardening",
      rationale: "Assess exploit-mitigation posture.",
    });
  }
  if (packed === "likely_packed")
    probes.push({
      operation: "measure_binary_entropy",
      rationale: "High entropy suggests packing or compression; profile it.",
    });
  if (signature)
    probes.push({
      operation: "inspect_code_signature",
      rationale: "Parse the embedded signature and certificate metadata.",
    });
  probes.push({
    operation: "extract_binary_strings",
    rationale: "Recover feature anchors and IOC candidates.",
  });
  return probes;
};

const LIMITATIONS: readonly string[] = [
  "This is a routing summary composed from several static readers over one file snapshot; every classification is an inference, not proof of behavior.",
  "Facets are summarized and bounded; run the operations in next_probes for complete, paged evidence.",
  "The file is read once without executing it, without network access and without writing files.",
];

/** Compose a compact, read-only triage summary for one local file. */
export const analyzeTriageFile = async (
  bytes: Buffer,
  input: TriageFileInput,
  context: TriageAnalysisContext,
): Promise<ReportBody> => {
  const loaded = loadTriageImage(bytes, input.slice);
  const image = loaded.image;
  const fileEntropy = roundTo(shannonEntropy(bytes));
  const overlay = image?.overlay ?? null;
  const overlayEntropy =
    overlay === null
      ? null
      : roundTo(
          shannonEntropy(
            bytes,
            overlay.file_offset,
            overlay.file_offset + overlay.size,
          ),
        );
  const toolchain = await analyzeDetectBinaryToolchain(
    bytes,
    detectBinaryToolchainInputSchema.parse({ path: input.path }),
    context,
  );
  const strings = await analyzeExtractBinaryStrings(
    bytes,
    extractBinaryStringsInputSchema.parse({ path: input.path }),
    context,
  );
  const capabilities =
    image === null
      ? { ids: [], unresolved_dynamic: false }
      : (() => {
          const classified = classifyImportTable(image.imports, 1);
          return {
            ids: classified.capabilities.map((capability) => capability.id),
            unresolved_dynamic: classified.unresolved_dynamic,
          };
        })();
  const signature = signatureSummary(image);
  return {
    subject: triageSubject(image),
    file_type: image === null ? "data" : image.format,
    md5: createHash("md5").update(bytes).digest("hex"),
    format: image === null ? null : formatSummary(image),
    entropy: {
      file: fileEntropy,
      overlay: overlayEntropy,
      classification: entropyClass(fileEntropy),
    },
    toolchain: {
      indicators: toolchain.indicators
        .slice(0, TOP_INDICATORS)
        .map((indicator) => ({
          name: indicator.name,
          category: indicator.category,
          confidence: indicator.confidence,
        })),
      packed: toolchain.packed_indicator.status,
    },
    capabilities,
    code_signature: signature,
    strings: {
      total: strings.string_coverage.total,
      tag_summary: strings.tag_summary,
    },
    next_probes: nextProbes(
      image,
      toolchain.packed_indicator.status,
      signature.present,
    ),
    limitations: [...LIMITATIONS],
  };
};
