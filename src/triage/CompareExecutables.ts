import { readStableArtifact } from "../artifacts/readStableArtifact.js";
import {
  ArtifactFileCleanupFailure,
  assertArtifactReadActive,
  bindArtifactFileCleanup,
} from "../artifacts/ArtifactFileOperation.js";
import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import type { ExecutionOptions } from "../application/AnalysisProvider.js";
import type { CompareExecutablesPort } from "../application/triage/CompareExecutablesPort.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import { analysisErrorWithCleanupFailure } from "../domain/analysisErrorCleanup.js";
import {
  AnalysisAccessDeniedError,
  AnalysisArtifactChangedError,
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisResourceConstraintError,
} from "../domain/analysisErrorCore.js";
import type { ImageArchitecture } from "../domain/native/image/executableImage.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import { err, ok, type Result } from "../domain/result.js";
import type {
  CompareExecutablesInput,
  CompareExecutablesReport,
} from "../domain/triage/compareExecutables.js";
import {
  triageArtifactSchema,
  TRIAGE_INPUT_BYTES,
  TRIAGE_OUTPUT_BYTES,
} from "../domain/triage/triageCommon.js";
import { loadTriageImage } from "./triageSupport.js";
import {
  compareExecutableImages,
  hardeningIndicators,
  type CompareSide,
} from "./CompareExecutablesDiff.js";

export { compareExecutableImages, hardeningIndicators };
export type { CompareSide };

/** Bundled reader identity. Differences between the two files are observed facts. */
export const COMPARE_EXECUTABLES_PROVIDER_IDENTITY = {
  id: "rea-compare-executables",
  name: "REA executable comparison engine",
  version: "1",
} as const;
const OPERATION = "compare_executables";

/**
 * Stable in-process comparison of two selected files without subprocesses,
 * temporary files, network access or target execution. Each file is read once
 * through the stable-snapshot reader and parsed by the shared image parser.
 */
export class CompareExecutablesProvider implements CompareExecutablesPort {
  readonly identity = COMPARE_EXECUTABLES_PROVIDER_IDENTITY;
  readonly #resources = new ArtifactResourceScope();

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
        COMPARE_EXECUTABLES_PROVIDER_IDENTITY.id,
        cause.cleanup.resources,
        { reason: cause.cleanup.reason },
        { cause, operation: OPERATION },
      );
      bindArtifactFileCleanup(cause, error);
      throw error;
    }
  }

  async compare(
    input: CompareExecutablesInput,
    options?: ExecutionOptions,
  ): Promise<Result<CompareExecutablesReport, AnalysisError>> {
    const signal = options?.signal;
    const slice =
      input.slice === undefined
        ? undefined
        : (input.slice as Exclude<ImageArchitecture, null>);
    try {
      return await this.#resources.run(async () => {
        const base = await this.#read(input.base_path, slice, signal);
        const target = await this.#read(input.target_path, slice, signal);
        assertArtifactReadActive(signal);
        const report = await compareExecutableImages(
          base,
          target,
          input.max_list,
          {
            signal,
          },
        );
        if (
          Buffer.byteLength(JSON.stringify(report), "utf8") >
          TRIAGE_OUTPUT_BYTES
        )
          throw new AnalysisResourceConstraintError(
            OPERATION,
            "transport",
            `The complete comparison of ${input.base_path} and ${input.target_path} exceeds the inline output budget; narrow it with max_list. No partial success is returned.`,
            { maximum_output_bytes: TRIAGE_OUTPUT_BYTES },
          );
        assertArtifactReadActive(signal);
        return ok(report);
      });
    } catch (cause: unknown) {
      return err(failureFor(cause, input, signal));
    }
  }

  async #read(
    path: string,
    slice: Exclude<ImageArchitecture, null> | undefined,
    signal: AbortSignal | undefined,
  ): Promise<CompareSide> {
    const snapshot = await readStableArtifact(
      path,
      TRIAGE_INPUT_BYTES,
      signal,
      undefined,
      this.#resources,
    );
    assertArtifactReadActive(signal);
    return {
      identity: triageArtifactSchema.parse({
        path,
        sha256: snapshot.sha256,
        bytes: snapshot.bytes.length,
      }),
      bytes: snapshot.bytes,
      image: loadTriageImage(snapshot.bytes, slice).image,
    };
  }
}

const failureFor = (
  cause: unknown,
  input: CompareExecutablesInput,
  signal?: AbortSignal,
): AnalysisError => {
  const paths = `${input.base_path}, ${input.target_path}`;
  const primary =
    cause instanceof ArtifactFileCleanupFailure &&
    cause.fileCleanupFailure.outcome.kind === "failed"
      ? primaryFailure(cause.fileCleanupFailure.outcome.cause, paths, signal)
      : primaryFailure(cause, paths, signal);
  if (!(cause instanceof ArtifactReaderFailure) || cause.cleanup === undefined)
    return primary;
  const cleanup = new ProviderCleanupError(
    COMPARE_EXECUTABLES_PROVIDER_IDENTITY.id,
    cause.cleanup.resources,
    { reason: cause.cleanup.reason },
    { cause, operation: OPERATION },
  );
  const error = analysisErrorWithCleanupFailure(primary, cleanup, OPERATION);
  bindArtifactFileCleanup(cause, error);
  return error;
};

const primaryFailure = (
  cause: unknown,
  paths: string,
  signal?: AbortSignal,
): AnalysisError => {
  if (cause instanceof AnalysisError) return cause;
  if (signal?.aborted)
    return new AnalysisCancelledError(OPERATION, { cause: signal.reason });
  if (cause instanceof ArtifactReaderFailure)
    return readerFailure(cause, paths);
  if (cause instanceof Error && "code" in cause) {
    const code = String(cause.code);
    if (code === "EACCES" || code === "EPERM")
      return new AnalysisAccessDeniedError(OPERATION, paths, code, { cause });
    if (["ENOENT", "ENOTDIR", "ELOOP", "ENAMETOOLONG"].includes(code))
      return new AnalysisInputError(OPERATION, { cause }, [
        {
          path: ["path"],
          reason: "invalid_value",
          message: `A selected artifact could not be read (${code}): ${paths}.`,
        },
      ]);
  }
  return new ProviderAdapterError(
    COMPARE_EXECUTABLES_PROVIDER_IDENTITY.id,
    OPERATION,
    {
      cause,
      diagnostics: {
        paths,
        reason: cause instanceof Error ? cause.message : String(cause),
      },
    },
  );
};

const readerFailure = (
  cause: ArtifactReaderFailure,
  paths: string,
): AnalysisError => {
  switch (cause.reason) {
    case "integrity":
      return new AnalysisArtifactChangedError(OPERATION, paths, cause.message, {
        cause,
      });
    case "cancelled":
      return new AnalysisCancelledError(OPERATION, { cause: cause.cause });
    case "limit":
      return new AnalysisResourceConstraintError(
        OPERATION,
        "file-size",
        cause.message,
        { maximum_input_bytes: TRIAGE_INPUT_BYTES },
        { cause },
      );
    case "path":
      return new AnalysisInputError(OPERATION, { cause }, [
        { path: ["path"], reason: "invalid_format", message: cause.message },
      ]);
    default:
      return new ProviderAdapterError(
        COMPARE_EXECUTABLES_PROVIDER_IDENTITY.id,
        OPERATION,
        { cause, diagnostics: { paths, reason: cause.message } },
      );
  }
};
