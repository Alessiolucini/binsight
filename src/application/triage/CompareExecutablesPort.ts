import type {
  ExecutionOptions,
  ProviderIdentity,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type {
  CompareExecutablesInput,
  CompareExecutablesReport,
} from "../../domain/triage/compareExecutables.js";
import type { Result } from "../../domain/result.js";

/**
 * Replaceable in-process reader that diffs two caller-selected files. It reads
 * both files and never executes them, writes files or uses a network.
 */
export interface CompareExecutablesPort {
  readonly identity: ProviderIdentity;
  close?(): Promise<void>;
  compare(
    input: CompareExecutablesInput,
    options?: ExecutionOptions,
  ): Promise<Result<CompareExecutablesReport, AnalysisError>>;
}
