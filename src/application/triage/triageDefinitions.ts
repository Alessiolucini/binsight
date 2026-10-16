import type { StaticTriageInput } from "./StaticTriagePort.js";
import type {
  StaticTriageDefinition,
  StaticTriageReportShape,
} from "./StaticTriageService.js";
import {
  classifyImportCapabilitiesInputSchema,
  classifyImportCapabilitiesReportSchema,
} from "../../domain/triage/classifyImportCapabilities.js";
import {
  computeSimilarityHashesInputSchema,
  computeSimilarityHashesReportSchema,
} from "../../domain/triage/computeSimilarityHashes.js";
import {
  detectBinaryToolchainInputSchema,
  detectBinaryToolchainReportSchema,
} from "../../domain/triage/detectBinaryToolchain.js";
import {
  extractBinaryStringsInputSchema,
  extractBinaryStringsReportSchema,
} from "../../domain/triage/extractBinaryStrings.js";
import {
  generateSbomInputSchema,
  generateSbomReportSchema,
} from "../../domain/triage/generateSbom.js";
import {
  identifyCryptoConstantsInputSchema,
  identifyCryptoConstantsReportSchema,
} from "../../domain/triage/identifyCryptoConstants.js";
import {
  inspectBinaryHardeningInputSchema,
  inspectBinaryHardeningReportSchema,
} from "../../domain/triage/inspectBinaryHardening.js";
import {
  inspectCodeSignatureInputSchema,
  inspectCodeSignatureReportSchema,
} from "../../domain/triage/inspectCodeSignature.js";
import {
  inspectExecutableInputSchema,
  inspectExecutableReportSchema,
} from "../../domain/triage/inspectExecutable.js";
import {
  measureBinaryEntropyInputSchema,
  measureBinaryEntropyReportSchema,
} from "../../domain/triage/measureBinaryEntropy.js";
import {
  recoverGoSymbolsInputSchema,
  recoverGoSymbolsReportSchema,
} from "../../domain/triage/recoverGoSymbols.js";
import {
  scanBytePatternsInputSchema,
  scanBytePatternsReportSchema,
} from "../../domain/triage/scanBytePatterns.js";
import {
  scanEmbeddedContentInputSchema,
  scanEmbeddedContentReportSchema,
} from "../../domain/triage/scanEmbeddedContent.js";
import {
  triageFileInputSchema,
  triageFileReportSchema,
} from "../../domain/triage/triageFile.js";
import {
  generateTriageReportInputSchema,
  generateTriageReportReportSchema,
} from "../../domain/triage/generateTriageReport.js";

/**
 * Widen one concrete tool definition to the shared base. Inputs and reports
 * are re-validated by their own schemas at the service boundary, so the stored
 * definition only needs the operation, schemas, and epistemic class.
 */
const define = <
  TInput extends StaticTriageInput,
  TReport extends StaticTriageReportShape,
>(
  definition: StaticTriageDefinition<TInput, TReport>,
): StaticTriageDefinition => definition as unknown as StaticTriageDefinition;

/** Every single-path static triage operation, keyed registration order. */
export const TRIAGE_DEFINITIONS: readonly StaticTriageDefinition[] = [
  define({
    operation: "inspect_executable",
    inputSchema: inspectExecutableInputSchema,
    reportSchema: inspectExecutableReportSchema,
    confidence: "observed",
    authority: "shipped-artifact",
  }),
  define({
    operation: "inspect_binary_hardening",
    inputSchema: inspectBinaryHardeningInputSchema,
    reportSchema: inspectBinaryHardeningReportSchema,
    confidence: "inferred",
    authority: "shipped-artifact",
  }),
  define({
    operation: "measure_binary_entropy",
    inputSchema: measureBinaryEntropyInputSchema,
    reportSchema: measureBinaryEntropyReportSchema,
    confidence: "observed",
    authority: "shipped-artifact",
  }),
  define({
    operation: "detect_binary_toolchain",
    inputSchema: detectBinaryToolchainInputSchema,
    reportSchema: detectBinaryToolchainReportSchema,
    confidence: "inferred",
    authority: "shipped-artifact",
  }),
  define({
    operation: "extract_binary_strings",
    inputSchema: extractBinaryStringsInputSchema,
    reportSchema: extractBinaryStringsReportSchema,
    confidence: "observed",
    authority: "shipped-artifact",
  }),
  define({
    operation: "identify_crypto_constants",
    inputSchema: identifyCryptoConstantsInputSchema,
    reportSchema: identifyCryptoConstantsReportSchema,
    confidence: "inferred",
    authority: "shipped-artifact",
  }),
  define({
    operation: "classify_import_capabilities",
    inputSchema: classifyImportCapabilitiesInputSchema,
    reportSchema: classifyImportCapabilitiesReportSchema,
    confidence: "inferred",
    authority: "shipped-artifact",
  }),
  define({
    operation: "scan_byte_patterns",
    inputSchema: scanBytePatternsInputSchema,
    reportSchema: scanBytePatternsReportSchema,
    confidence: "observed",
    authority: "shipped-artifact",
  }),
  define({
    operation: "compute_similarity_hashes",
    inputSchema: computeSimilarityHashesInputSchema,
    reportSchema: computeSimilarityHashesReportSchema,
    confidence: "derived",
    authority: "analyst-inference",
  }),
  define({
    operation: "inspect_code_signature",
    inputSchema: inspectCodeSignatureInputSchema,
    reportSchema: inspectCodeSignatureReportSchema,
    confidence: "observed",
    authority: "shipped-artifact",
  }),
  define({
    operation: "scan_embedded_content",
    inputSchema: scanEmbeddedContentInputSchema,
    reportSchema: scanEmbeddedContentReportSchema,
    confidence: "observed",
    authority: "shipped-artifact",
  }),
  define({
    operation: "generate_sbom",
    inputSchema: generateSbomInputSchema,
    reportSchema: generateSbomReportSchema,
    confidence: "derived",
    authority: "analyst-inference",
  }),
  define({
    operation: "recover_go_symbols",
    inputSchema: recoverGoSymbolsInputSchema,
    reportSchema: recoverGoSymbolsReportSchema,
    confidence: "observed",
    authority: "shipped-artifact",
  }),
  define({
    operation: "triage_file",
    inputSchema: triageFileInputSchema,
    reportSchema: triageFileReportSchema,
    confidence: "derived",
    authority: "analyst-inference",
  }),
  define({
    operation: "generate_triage_report",
    inputSchema: generateTriageReportInputSchema,
    reportSchema: generateTriageReportReportSchema,
    confidence: "derived",
    authority: "analyst-inference",
  }),
];
