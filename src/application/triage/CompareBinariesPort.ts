import type {
  ExecutionOptions,
  ProviderIdentity,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type {
  CompareBinariesInput,
  CompareBinariesReport,
} from "../../domain/triage/compareBinaries.js";
import type { Result } from "../../domain/result.js";

/**
 * Replaceable in-process reader that diffs two caller-selected files at the
 * byte level. It reads both files and never executes them, writes files or
 * uses a network.
 */
export interface CompareBinariesPort {
  readonly identity: ProviderIdentity;
  close?(): Promise<void>;
  compare(
    input: CompareBinariesInput,
    options?: ExecutionOptions,
  ): Promise<Result<CompareBinariesReport, AnalysisError>>;
}
