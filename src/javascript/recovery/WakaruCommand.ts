import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { access, realpath, stat } from "node:fs/promises";
import { isAbsolute } from "node:path";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { ProviderAdapterError } from "../../domain/providerAdapterError.js";
import { ProviderCleanupError } from "../../domain/providerCleanupError.js";
import { cleanupOwnedProcessGroup } from "../../process/ProcessOwnership.js";
import {
  ProviderProcessSupervisor,
  spawnOwnedProviderProcess,
  type OwnedProviderProcessSpawnOptions,
  type SpawnedOwnedProviderProcess,
} from "../../process/ProviderProcess.js";
import {
  checkRecoveryDeadline,
  inventoryRecoveryFiles,
  fingerprintRecoveryFile,
  recoveryFailureMessage,
} from "./RecoveryFiles.js";
import { RECOVERY_LIMITS } from "./WakaruRelease.js";

const OPERATION = "recover_javascript_sources";
const WAKARU_REQUIREMENT =
  "Provide an absolute REA_WAKARU_COMMAND pointing to a Wakaru ^1.13.0 binary (verified with 1.14.0); no tool is installed by BinSight. Supported hosts: Linux x64 (hard limits via util-linux prlimit) and macOS arm64/x64 (soft limits via /bin/sh ulimit). See docs/javascript-recovery.md#install-wakaru.";

const SUPPORTED_HOSTS: ReadonlyArray<readonly [NodeJS.Platform, string]> = [
  ["linux", "x64"],
  ["darwin", "arm64"],
  ["darwin", "x64"],
];

const isSupportedHost = (): boolean =>
  SUPPORTED_HOSTS.some(
    ([platform, arch]) =>
      process.platform === platform && process.arch === arch,
  );

/** Default resource limiter path for the current host. */
const defaultLimiterCommand = (): string =>
  process.platform === "darwin" ? "/bin/sh" : "/usr/bin/prlimit";

/** Inject the owned process launcher while retaining production protocol parsing. */
export type WakaruLauncher = (
  options: OwnedProviderProcessSpawnOptions,
) => Promise<SpawnedOwnedProviderProcess>;

/** Cleanup failure carrying the live supervisor so the provider can retry it. */
export class WakaruCleanupFailure extends ProviderCleanupError {
  constructor(
    readonly cleanupOwner: ProviderProcessSupervisor,
    readonly runId: string,
    readonly cwd: string,
    reason: string,
    previousError: unknown,
    snapshot: ReturnType<ProviderProcessSupervisor["snapshot"]>,
  ) {
    super(
      "wakaru",
      [runId, cwd],
      {
        reason,
        previous_error:
          previousError instanceof Error ? previousError.message : null,
        exit_code: snapshot.exitCode ?? null,
        signal: snapshot.signal ?? null,
      },
      { operation: OPERATION, cause: previousError },
    );
  }
}

/** Resolve and fingerprint explicitly configured tools; acquire nothing at startup. */
export const resolveWakaruCommand = async (
  environment: Readonly<Record<string, string | undefined>>,
) => {
  const configured = environment.REA_WAKARU_COMMAND;
  if (!isSupportedHost() || configured === undefined || !isAbsolute(configured))
    throw new AnalysisCapabilityUnavailableError(
      "wakaru",
      OPERATION,
      WAKARU_REQUIREMENT,
      { userMessage: WAKARU_REQUIREMENT },
    );
  try {
    const command = await realpath(configured);
    await access(command, constants.R_OK | constants.X_OK);
    const fingerprint = await fingerprintRecoveryFile(
      command,
      RECOVERY_LIMITS.outputBytes,
    );
    const limiter =
      environment.REA_JAVASCRIPT_PRLIMIT_COMMAND ?? defaultLimiterCommand();
    if (!isAbsolute(limiter))
      throw new TypeError("REA_JAVASCRIPT_PRLIMIT_COMMAND must be absolute");
    await access(limiter, constants.X_OK);
    if (!(await stat(limiter)).isFile())
      throw new TypeError(`Resource limiter is not a regular file: ${limiter}`);
    return { command, limiter, ...fingerprint };
  } catch (cause: unknown) {
    const limiterLabel =
      process.platform === "darwin"
        ? "/bin/sh ulimit wrapper"
        : "util-linux prlimit";
    const reason = `Configured Wakaru or ${limiterLabel} is unavailable: ${recoveryFailureMessage(cause)}`;
    throw new AnalysisCapabilityUnavailableError("wakaru", OPERATION, reason, {
      cause,
      userMessage: reason,
    });
  }
};

type WakaruCommandContext = {
  command: string;
  limiter: string;
  arguments: readonly string[];
  cwd: string;
  deadline: number;
  environment: Readonly<Record<string, string | undefined>>;
  signal?: AbortSignal;
  launcher?: WakaruLauncher;
  staging?: string;
};

/** Produce the launcher argv for the host's resource-limit wrapper.
 *
 * Linux: util-linux `prlimit` enforces address space, file size, cores and CPU
 * time as hard rlimits before `execve`-ing Wakaru. macOS has no equivalent
 * CLI, so we fall back to `/bin/sh -c "ulimit ...; exec ..."`. `ulimit -v`
 * (address space) is not available on darwin bash, so we only cap CPU time,
 * file size and core dumps there, and rely on the Node-level deadline
 * (`checkRecoveryDeadline`) plus the supervisor byte guard for the rest.
 */
const buildLimiterArguments = (context: WakaruCommandContext): string[] => {
  const outputBytes = RECOVERY_LIMITS.outputBytes;
  const addressBytes = RECOVERY_LIMITS.addressSpaceBytes;
  if (process.platform === "darwin") {
    // `ulimit -f` is in 1024-byte blocks on bash/zsh; round up.
    const fsizeBlocks = Math.ceil(outputBytes / 1024);
    const script = `ulimit -c 0; ulimit -t 120; ulimit -f ${String(fsizeBlocks)}; exec "$@"`;
    return [
      "-c",
      script,
      "wakaru-limited",
      context.command,
      ...context.arguments,
    ];
  }
  return [
    `--as=${String(addressBytes)}`,
    `--fsize=${String(outputBytes)}`,
    "--core=0",
    "--cpu=120",
    "--",
    context.command,
    ...context.arguments,
  ];
};

/** Run one bounded command and verify cleanup before consuming its output. */
export const runWakaruCommand = async (context: WakaruCommandContext) => {
  checkRecoveryDeadline(context.deadline, context.signal);
  const runId = `binsight-wakaru-${randomUUID()}`;
  const spawned = await (context.launcher ?? spawnOwnedProviderProcess)({
    command: context.limiter,
    arguments: buildLimiterArguments(context),
    expectedCommand: null,
    runId,
    cwd: context.cwd,
    hostEnvironment: context.environment,
    ...(context.signal === undefined ? {} : { signal: context.signal }),
    env: { TMPDIR: context.cwd, RAYON_NUM_THREADS: "1", NO_COLOR: "1" },
  }).catch((cause: unknown) => {
    if (context.signal?.aborted === true)
      throw new AnalysisCancelledError(OPERATION);
    const limiterLabel =
      process.platform === "darwin"
        ? "/bin/sh ulimit wrapper"
        : "util-linux prlimit";
    throw new ProviderAdapterError("wakaru", OPERATION, {
      cause,
      diagnostics: {
        reason: `Failed to launch configured Wakaru through ${limiterLabel}`,
        command: context.command,
        detail: recoveryFailureMessage(cause),
      },
    });
  });
  let oversized = false;
  const supervisor = new ProviderProcessSupervisor(
    {
      ...spawned,
      ownsProcessLifetime: true,
      cleanup:
        spawned.cleanup ?? (() => cleanupOwnedProcessGroup(spawned.ownership)),
    },
    {
      onDiagnostic: (event) => {
        if (
          event.type === "output" &&
          event.totalBytes > RECOVERY_LIMITS.reportBytes
        )
          oversized = true;
      },
    },
  );
  let failure: unknown;
  try {
    while (!(await supervisor.waitForOutputClose(100))) {
      checkRecoveryDeadline(context.deadline, context.signal);
      if (oversized)
        throw new AnalysisOutputError(
          OPERATION,
          "Wakaru diagnostic stream exceeds 8 MiB",
        );
      if (context.staging !== undefined)
        await inventoryRecoveryFiles(context.staging, context.signal);
    }
    checkRecoveryDeadline(context.deadline, context.signal);
    if (oversized)
      throw new AnalysisOutputError(
        OPERATION,
        "Wakaru diagnostic stream exceeds 8 MiB",
      );
  } catch (cause: unknown) {
    failure = cause;
  }
  const stopped = await supervisor.stop();
  const snapshot = supervisor.snapshot();
  if (stopped.status === "incomplete")
    throw new WakaruCleanupFailure(
      supervisor,
      runId,
      context.cwd,
      stopped.reason,
      failure,
      snapshot,
    );
  if (failure !== undefined) throw failure;
  if (context.signal?.aborted === true)
    throw new AnalysisCancelledError(OPERATION);
  return {
    exit_code: snapshot.exitCode ?? null,
    signal: snapshot.signal ?? null,
    stdout: snapshot.stdout.text,
    stderr: snapshot.stderr.text,
    command: context.command,
    arguments: [...context.arguments],
    resource_limiter: context.limiter,
  };
};
