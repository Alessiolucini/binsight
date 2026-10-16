import { readStableArtifact } from "../artifacts/readStableArtifact.js";
import {
  ArtifactFileCleanupFailure,
  assertArtifactReadActive,
  bindArtifactFileCleanup,
} from "../artifacts/ArtifactFileOperation.js";
import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import type { ExecutionOptions } from "../application/AnalysisProvider.js";
import type {
  StaticTriageInput,
  StaticTriagePort,
} from "../application/triage/StaticTriagePort.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import { analysisErrorWithCleanupFailure } from "../domain/analysisErrorCleanup.js";
import {
  AnalysisAccessDeniedError,
  AnalysisArtifactChangedError,
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisResourceConstraintError,
  AnalysisUnsupportedTargetError,
} from "../domain/analysisErrorCore.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  TRIAGE_INPUT_BYTES,
  TRIAGE_OUTPUT_BYTES,
} from "../domain/triage/triageCommon.js";
import {
  TriageAnalysisFailure,
  type TriageAnalysisContext,
} from "./triageSupport.js";

/** Bundled engine identity; analyzed file content is a separate observed fact. */
export const STATIC_TRIAGE_PROVIDER_IDENTITY = {
  id: "rea-static-triage",
  name: "REA static triage engine",
  version: "1",
} as const;

/** Pure analyzer over one immutable snapshot; returns the report without artifact identity. */
export type TriageAnalyzer = (
  bytes: Buffer,
  input: StaticTriageInput,
  context: TriageAnalysisContext,
) => Promise<Readonly<Record<string, unknown>>>;

/**
 * Stable in-process static analysis without subprocesses, temporary files,
 * network access or target execution. Every operation reads the selected
 * file once through the stable-snapshot reader.
 */
export class StaticTriageProvider implements StaticTriagePort {
  readonly identity = STATIC_TRIAGE_PROVIDER_IDENTITY;
  readonly #resources = new ArtifactResourceScope();

  constructor(
    private readonly analyzers: Readonly<Record<string, TriageAnalyzer>>,
  ) {}

  async close(): Promise<void> {
    try {
      await this.#resources.close();
    } catch (cause: unknown) {
      if (
        !(cause instanceof ArtifactReaderFailure) ||
        cause.cleanup === undefined
      )
        throw cause;
      const error = new ProviderCleanupError(
        STATIC_TRIAGE_PROVIDER_IDENTITY.id,
        cause.cleanup.resources,
        { reason: cause.cleanup.reason },
        { cause, operation: "static_triage" },
      );
      bindArtifactFileCleanup(cause, error);
      throw error;
    }
  }

  async analyze(
    operation: string,
    input: StaticTriageInput,
    options?: ExecutionOptions,
  ): Promise<Result<unknown, AnalysisError>> {
    const analyzer = this.analyzers[operation];
    if (analyzer === undefined)
      return err(
        new ProviderAdapterError(
          STATIC_TRIAGE_PROVIDER_IDENTITY.id,
          operation,
          {
            diagnostics: {
              reason: "No analyzer is registered for the operation.",
            },
          },
        ),
      );
    const signal = options?.signal;
    try {
      return await this.#resources.run(async () => {
        const snapshot = await readStableArtifact(
          input.path,
          TRIAGE_INPUT_BYTES,
          signal,
          undefined,
          this.#resources,
        );
        assertArtifactReadActive(signal);
        const body = await analyzer(snapshot.bytes, input, {
          signal,
          sha256: snapshot.sha256,
        });
        const report = {
          ...body,
          artifact: {
            path: input.path,
            sha256: snapshot.sha256,
            bytes: snapshot.bytes.length,
          },
        };
        if (
          Buffer.byteLength(JSON.stringify(report), "utf8") >
          TRIAGE_OUTPUT_BYTES
        )
          throw new AnalysisResourceConstraintError(
            operation,
            "transport",
            `The complete ${operation} report for ${input.path} exceeds the inline output budget; narrow the request with the tool's limit or filter inputs. No partial success is returned.`,
            { maximum_output_bytes: TRIAGE_OUTPUT_BYTES },
          );
        assertArtifactReadActive(signal);
        return ok(report);
      });
    } catch (cause: unknown) {
      return err(failureFor(operation, cause, input.path, signal));
    }
  }
}

const failureFor = (
  operation: string,
  cause: unknown,
  path: string,
  signal?: AbortSignal,
): AnalysisError => {
  const primary =
    cause instanceof ArtifactFileCleanupFailure &&
    cause.fileCleanupFailure.outcome.kind === "failed"
      ? primaryFailure(
          operation,
          cause.fileCleanupFailure.outcome.cause,
          path,
          signal,
        )
      : primaryFailure(operation, cause, path, signal);
  if (!(cause instanceof ArtifactReaderFailure) || cause.cleanup === undefined)
    return primary;
  const cleanup = new ProviderCleanupError(
    STATIC_TRIAGE_PROVIDER_IDENTITY.id,
    cause.cleanup.resources,
    { reason: cause.cleanup.reason },
    { cause, operation },
  );
  const error = analysisErrorWithCleanupFailure(primary, cleanup, operation);
  bindArtifactFileCleanup(cause, error);
  return error;
};

const primaryFailure = (
  operation: string,
  cause: unknown,
  path: string,
  signal?: AbortSignal,
): AnalysisError => {
  if (cause instanceof AnalysisError) return cause;
  if (signal?.aborted)
    return new AnalysisCancelledError(operation, { cause: signal.reason });
  if (cause instanceof TriageAnalysisFailure)
    return analysisFailure(operation, cause, path);
  if (cause instanceof ArtifactReaderFailure)
    return readerFailure(operation, cause, path);
  if (cause instanceof Error && "code" in cause) {
    if (cause.code === "EACCES" || cause.code === "EPERM")
      return new AnalysisAccessDeniedError(operation, path, cause.code, {
        cause,
      });
    if (
      ["ENOENT", "ENOTDIR", "ELOOP", "ENAMETOOLONG"].includes(
        String(cause.code),
      )
    )
      return new AnalysisInputError(operation, { cause }, [
        {
          path: ["path"],
          reason: "invalid_value",
          message: `Selected artifact could not be read (${String(cause.code)}): ${path}.`,
        },
      ]);
  }
  return new ProviderAdapterError(
    STATIC_TRIAGE_PROVIDER_IDENTITY.id,
    operation,
    {
      cause,
      diagnostics: {
        path,
        reason: cause instanceof Error ? cause.message : String(cause),
      },
    },
  );
};

const analysisFailure = (
  operation: string,
  cause: TriageAnalysisFailure,
  path: string,
): AnalysisError => {
  if (cause.kind === "unsupported")
    return new AnalysisUnsupportedTargetError(operation, path, cause.message, {
      cause,
    });
  if (cause.kind === "resource")
    return new AnalysisResourceConstraintError(
      operation,
      "memory",
      `Selected artifact ${path}: ${cause.message}`,
      cause.limits,
      { cause },
    );
  return new AnalysisInputError(operation, { cause }, [
    {
      path: ["path"],
      reason: "invalid_format",
      message: `Selected artifact ${path}: ${cause.message}`,
    },
  ]);
};

const readerFailure = (
  operation: string,
  cause: ArtifactReaderFailure,
  path: string,
): AnalysisError => {
  switch (cause.reason) {
    case "integrity":
      return new AnalysisArtifactChangedError(operation, path, cause.message, {
        cause,
      });
    case "cancelled":
      return new AnalysisCancelledError(operation, { cause: cause.cause });
    case "limit":
      return new AnalysisResourceConstraintError(
        operation,
        "file-size",
        cause.message,
        { maximum_input_bytes: TRIAGE_INPUT_BYTES },
        { cause },
      );
    case "path":
      return new AnalysisInputError(operation, { cause }, [
        { path: ["path"], reason: "invalid_format", message: cause.message },
      ]);
    default:
      return new ProviderAdapterError(
        STATIC_TRIAGE_PROVIDER_IDENTITY.id,
        operation,
        { cause, diagnostics: { path, reason: cause.message } },
      );
  }
};
