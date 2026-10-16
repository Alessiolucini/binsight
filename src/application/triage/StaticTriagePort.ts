import type {
  ExecutionOptions,
  ProviderIdentity,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { Result } from "../../domain/result.js";

/** Validated caller input shared by every static triage operation. */
export interface StaticTriageInput {
  readonly path: string;
}

/**
 * Replaceable in-process reader for static triage operations. It reads one
 * caller-selected file and never executes it, writes files or uses a network.
 */
export interface StaticTriagePort {
  readonly identity: ProviderIdentity;
  close?(): Promise<void>;
  analyze(
    operation: string,
    input: StaticTriageInput,
    options?: ExecutionOptions,
  ): Promise<Result<unknown, AnalysisError>>;
}
