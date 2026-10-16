import { isAbsolute } from "node:path";
import type { z } from "zod";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import type {
  StaticTriageInput,
  StaticTriagePort,
} from "./StaticTriagePort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import {
  BINARY_ARCHITECTURES,
  RAW_ONLY_ARCHITECTURES,
} from "../../domain/binaryTargetTypes.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import type { JsonValue } from "../../domain/jsonValue.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { err, type Result } from "../../domain/result.js";
import type { TriageSubjectFormat } from "../../domain/triage/triageCommon.js";
import { completeProviderEvidence } from "../ProviderOperationExecution.js";

/** Report fields the service needs to bind Evidence to the analyzed bytes. */
export interface StaticTriageReportShape {
  readonly artifact: {
    readonly path: string;
    readonly sha256: string;
    readonly bytes: number;
  };
  readonly subject: {
    readonly format: TriageSubjectFormat;
    readonly architecture: string | null;
  };
  readonly limitations: readonly string[];
}

/** One static triage operation: its exact schemas and epistemic class. */
export interface StaticTriageDefinition<
  TInput extends StaticTriageInput = StaticTriageInput,
  TReport extends StaticTriageReportShape = StaticTriageReportShape,
> {
  readonly operation: string;
  readonly inputSchema: z.ZodType<TInput, unknown>;
  readonly reportSchema: z.ZodType<TReport, unknown>;
  /** Observed bytes, values derived from other Evidence, or inferred classifications. */
  readonly confidence: "observed" | "derived" | "inferred";
  readonly authority: "shipped-artifact" | "analyst-inference";
}

const SUBJECT_ARCHITECTURES: readonly string[] = BINARY_ARCHITECTURES.filter(
  (architecture) =>
    !(RAW_ONLY_ARCHITECTURES as readonly string[]).includes(architecture),
);

type SubjectArchitecture = Exclude<
  (typeof BINARY_ARCHITECTURES)[number],
  (typeof RAW_ONLY_ARCHITECTURES)[number]
>;

const subjectArchitecture = (
  architecture: string | null,
): SubjectArchitecture | undefined =>
  architecture !== null && SUBJECT_ARCHITECTURES.includes(architecture)
    ? (architecture as SubjectArchitecture)
    : undefined;

/** Shared exact validation and artifact-bound Evidence for static triage over CLI and MCP. */
export class StaticTriageService {
  constructor(readonly provider: StaticTriagePort) {}

  close(): Promise<void> {
    return this.provider.close?.() ?? Promise.resolve();
  }

  /** Analyze one explicitly selected file without acquiring a binary session. */
  async run<
    TInput extends StaticTriageInput,
    TReport extends StaticTriageReportShape,
  >(
    definition: StaticTriageDefinition<TInput, TReport>,
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    const operation = definition.operation;
    if (options?.signal?.aborted)
      return err(
        new AnalysisCancelledError(operation, { cause: options.signal.reason }),
      );
    const input = definition.inputSchema.safeParse(rawInput);
    if (!input.success)
      return err(
        analysisInputErrorFromIssues(operation, input.error.issues, rawInput, {
          cause: input.error,
        }),
      );
    if (!isAbsolute(input.data.path))
      return err(
        new AnalysisInputError(operation, undefined, [
          {
            path: ["path"],
            reason: "invalid_format",
            message: "Expected an absolute filesystem path on this host.",
          },
        ]),
      );
    const analyzed = await this.provider.analyze(
      operation,
      input.data,
      options,
    );
    if (!analyzed.ok) return analyzed;
    const report = definition.reportSchema.safeParse(analyzed.value);
    if (!report.success || report.data.artifact.path !== input.data.path)
      return err(
        new AnalysisOutputError(
          operation,
          "Static triage reader returned a malformed report or changed the selected artifact identity.",
          ...(report.success ? [] : [{ cause: report.error }]),
        ),
      );
    return completeProviderEvidence(
      evidenceFor(this.provider, definition, input.data, report.data),
      options?.signal,
    );
  }
}

const evidenceFor = <
  TInput extends StaticTriageInput,
  TReport extends StaticTriageReportShape,
>(
  provider: StaticTriagePort,
  definition: StaticTriageDefinition<TInput, TReport>,
  parameters: TInput,
  value: TReport,
): Evidence => {
  const architecture = subjectArchitecture(value.subject.architecture);
  return createEvidence(
    {
      path: value.artifact.path,
      sha256: value.artifact.sha256,
      format: value.subject.format,
      ...(architecture === undefined ? {} : { architecture }),
    },
    provider.identity,
    {
      operation: definition.operation,
      parameters: parameters as unknown as Readonly<Record<string, JsonValue>>,
      result: value as unknown as JsonValue,
      confidence: definition.confidence,
      authority: definition.authority,
      limitations: value.limitations,
      locations: [{ kind: "artifact-path", path: value.artifact.path }],
    },
  );
};
