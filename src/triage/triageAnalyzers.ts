import type { StaticTriageInput } from "../application/triage/StaticTriagePort.js";
import type { TriageAnalyzer } from "./StaticTriageProvider.js";
import type { TriageAnalysisContext } from "./triageSupport.js";
import { analyzeClassifyImportCapabilities } from "./ClassifyImportCapabilities.js";
import { analyzeComputeSimilarityHashes } from "./ComputeSimilarityHashes.js";
import { analyzeDetectBinaryToolchain } from "./DetectBinaryToolchain.js";
import { analyzeExtractBinaryStrings } from "./ExtractBinaryStrings.js";
import { analyzeGenerateSbom } from "./GenerateSbom.js";
import { analyzeIdentifyCryptoConstants } from "./IdentifyCryptoConstants.js";
import { analyzeInspectBinaryHardening } from "./InspectBinaryHardening.js";
import { analyzeInspectCodeSignature } from "./InspectCodeSignature.js";
import { analyzeInspectExecutable } from "./InspectExecutable.js";
import { analyzeMeasureBinaryEntropy } from "./MeasureBinaryEntropy.js";
import { analyzeRecoverGoSymbols } from "./RecoverGoSymbols.js";
import { analyzeScanBytePatterns } from "./ScanBytePatterns.js";
import { analyzeScanEmbeddedContent } from "./ScanEmbeddedContent.js";
import { analyzeTriageFile } from "./TriageFile.js";
import { analyzeGenerateTriageReport } from "./GenerateTriageReport.js";

/**
 * Adapt one concrete analyzer to the shared analyzer shape. The caller input
 * and the produced report are re-validated by the tool's own schemas at the
 * service boundary, so the common shape only needs the call signature.
 */
const analyzer = <TInput extends StaticTriageInput, TReport>(
  fn: (
    bytes: Buffer,
    input: TInput,
    context: TriageAnalysisContext,
  ) => Promise<TReport>,
): TriageAnalyzer => fn as unknown as TriageAnalyzer;

/** Operation-keyed analyzers for the shared static triage provider. */
export const TRIAGE_ANALYZERS: Readonly<Record<string, TriageAnalyzer>> = {
  inspect_executable: analyzer(analyzeInspectExecutable),
  inspect_binary_hardening: analyzer(analyzeInspectBinaryHardening),
  measure_binary_entropy: analyzer(analyzeMeasureBinaryEntropy),
  detect_binary_toolchain: analyzer(analyzeDetectBinaryToolchain),
  extract_binary_strings: analyzer(analyzeExtractBinaryStrings),
  identify_crypto_constants: analyzer(analyzeIdentifyCryptoConstants),
  classify_import_capabilities: analyzer(analyzeClassifyImportCapabilities),
  scan_byte_patterns: analyzer(analyzeScanBytePatterns),
  compute_similarity_hashes: analyzer(analyzeComputeSimilarityHashes),
  inspect_code_signature: analyzer(analyzeInspectCodeSignature),
  scan_embedded_content: analyzer(analyzeScanEmbeddedContent),
  generate_sbom: analyzer(analyzeGenerateSbom),
  recover_go_symbols: analyzer(analyzeRecoverGoSymbols),
  triage_file: analyzer(analyzeTriageFile),
  generate_triage_report: analyzer(analyzeGenerateTriageReport),
};
