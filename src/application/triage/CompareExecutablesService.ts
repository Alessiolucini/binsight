import { isAbsolute } from "node:path";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { CompareExecutablesPort } from "./CompareExecutablesPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import {
  BINARY_ARCHITECTURES,
  RAW_ONLY_ARCHITECTURES,
  type BinaryArchitecture,
} from "../../domain/binaryTargetTypes.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import type { JsonValue } from "../../domain/jsonValue.js";
import {
  compareExecutablesInputSchema,
  compareExecutablesReportSchema,
  type CompareExecutablesInput,
  type CompareExecutablesReport,
} from "../../domain/triage/compareExecutables.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { err, type Result } from "../../domain/result.js";
import { completeProviderEvidence } from "../ProviderOperationExecution.js";

const OPERATION = "compare_executables";

const SUBJECT_ARCHITECTURES: readonly string[] = BINARY_ARCHITECTURES.filter(
  (architecture) =>
    !(RAW_ONLY_ARCHITECTURES as readonly string[]).includes(architecture),
);

const subjectArchitecture = (
  architecture: string | null,
): BinaryArchitecture | undefined =>
  architecture !== null && SUBJECT_ARCHITECTURES.includes(architecture)
    ? (architecture as BinaryArchitecture)
    : undefined;

/**
 * Shared exact input validation and target-bound Evidence for the two-path
 * executable comparison over CLI and MCP. The Evidence subject is the target
 * file; the baseline identity is preserved inside the report.
 */
export class CompareExecutablesService {
  constructor(readonly provider: CompareExecutablesPort) {}

  close(): Promise<void> {
    return this.provider.close?.() ?? Promise.resolve();
  }

  /** Compare two explicitly selected files without acquiring a binary session. */
  async compare(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(
        new AnalysisCancelledError(OPERATION, { cause: options.signal.reason }),
      );
    const input = compareExecutablesInputSchema.safeParse(rawInput);
    if (!input.success)
      return err(
        analysisInputErrorFromIssues(OPERATION, input.error.issues, rawInput, {
          cause: input.error,
        }),
      );
    for (const field of ["base_path", "target_path"] as const)
      if (!isAbsolute(input.data[field]))
        return err(
          new AnalysisInputError(OPERATION, undefined, [
            {
              path: [field],
              reason: "invalid_format",
              message: "Expected an absolute filesystem path on this host.",
            },
          ]),
        );
    const compared = await this.provider.compare(input.data, options);
    if (!compared.ok) return compared;
    const report = compareExecutablesReportSchema.safeParse(compared.value);
    if (
      !report.success ||
      report.data.base.path !== input.data.base_path ||
      report.data.target.path !== input.data.target_path
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "Executable comparison returned a malformed report or changed the selected artifact identities.",
          ...(report.success ? [] : [{ cause: report.error }]),
        ),
      );
    return completeProviderEvidence(
      evidenceFor(this.provider.identity, input.data, report.data),
      options?.signal,
    );
  }
}

const parametersOf = (
  input: CompareExecutablesInput,
): Readonly<Record<string, JsonValue>> => ({
  base_path: input.base_path,
  target_path: input.target_path,
  max_list: input.max_list,
  ...(input.slice === undefined ? {} : { slice: input.slice }),
});

const evidenceFor = (
  provider: CompareExecutablesPort["identity"],
  input: CompareExecutablesInput,
  value: CompareExecutablesReport,
): Evidence => {
  const architecture = subjectArchitecture(value.subject.architecture);
  return createEvidence(
    {
      path: value.target.path,
      sha256: value.target.sha256,
      format: value.subject.format,
      ...(architecture === undefined ? {} : { architecture }),
    },
    provider,
    {
      operation: OPERATION,
      parameters: parametersOf(input),
      result: value as unknown as JsonValue,
      confidence: "derived",
      authority: "analyst-inference",
      limitations: value.limitations,
      locations: [
        { kind: "artifact-path", path: value.target.path },
        { kind: "artifact-path", path: value.base.path },
      ],
      evidenceLinks: [],
    },
  );
};
