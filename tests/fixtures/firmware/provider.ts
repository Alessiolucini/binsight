import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { access, mkdir, rm, writeFile } from "node:fs/promises";
import { expect, onTestFinished } from "vitest";
import { createFirmwareAnalysisProvider } from "../../../src/composition/firmware.js";
import { FirmwareAnalysisService } from "../../../src/application/firmware/FirmwareAnalysisService.js";
import { spawnOwnedProviderProcess } from "../../../src/process/ProviderProcess.js";
import { cleanupOwnedProcessGroup } from "../../../src/process/ProcessOwnership.js";
import { createTestTempDirectory } from "../temporaryDirectory.js";

/** Exercise real subprocess ownership with synthetic pinned producer representations. */
export const firmwareFixture = async (mode = "normal", banner?: string) => {
  const root = await createTestTempDirectory("binsight-firmware-test-");
  const path = join(root, "input.bin");
  await writeFile(path, Buffer.from("fixture-input-data"));
  onTestFinished(() => rm(root, { recursive: true, force: true }));
  // Give each engine its own configured file so the resolved command names
  // the engine. Host utilities are not stable stand-ins: on Ubuntu 26.04
  // /usr/bin/true resolves to /usr/bin/gnutrue. The launcher below runs
  // producer.mjs instead, so these files are only resolved and hashed.
  const tools = join(root, "tools");
  await mkdir(tools);
  const commands = {
    binwalk: join(tools, "binwalk"),
    unblob: join(tools, "unblob"),
  };
  for (const command of Object.values(commands))
    await writeFile(command, "#!/bin/sh\nexit 127\n", { mode: 0o700 });
  const launches: {
    cwd: string | undefined;
    pid: number | undefined;
    args: readonly string[];
  }[] = [];
  let cleanupUnverified = mode === "cleanup-failure";
  const provider = createFirmwareAnalysisProvider(
    {
      ...process.env,
      REA_BINWALK_COMMAND: commands.binwalk,
      REA_UNBLOB_COMMAND: commands.unblob,
    },
    async (options) => {
      const start = options.arguments.indexOf("--") + 2;
      const args = options.arguments.slice(start);
      const command = options.arguments[start - 1];
      const engine =
        command === commands.binwalk
          ? "binwalk"
          : command === commands.unblob
            ? "unblob"
            : undefined;
      if (engine === undefined)
        throw new Error(
          `Unexpected firmware fixture command: ${String(command)}`,
        );
      const spawned = await spawnOwnedProviderProcess({
        ...options,
        command: process.execPath,
        expectedCommand: process.execPath,
        arguments: [
          fileURLToPath(new URL("./producer.mjs", import.meta.url)),
          ...args,
        ],
        env: {
          ...options.env,
          REA_FIRMWARE_FIXTURE_MODE: mode,
          REA_FIRMWARE_FIXTURE_ENGINE: engine,
          ...(banner === undefined
            ? {}
            : { REA_FIRMWARE_FIXTURE_VERSION: banner }),
        },
      });
      launches.push({
        cwd: options.cwd,
        pid: spawned.process.pid,
        args: options.arguments,
      });
      if (mode === "cleanup-failure") {
        return {
          ...spawned,
          cleanup: () =>
            cleanupUnverified
              ? Promise.resolve({
                  cleaned: false,
                  reason: "injected ownership failure",
                })
              : cleanupOwnedProcessGroup(spawned.ownership),
        };
      }
      return spawned;
    },
  );
  const close = async () => {
    if (provider.close === undefined)
      throw new Error("Expected firmware provider cleanup capability");
    await provider.close();
  };
  onTestFinished(async () => {
    cleanupUnverified = false;
    await close();
  });
  return {
    provider,
    service: new FirmwareAnalysisService(provider),
    path,
    output: join(root, "output"),
    root,
    launches,
    close,
    restoreCleanup: () => {
      cleanupUnverified = false;
    },
  };
};

/** Verify only the acquired process groups and private runtime directories. */
export const assertFirmwareCleanup = async (
  launches: Awaited<ReturnType<typeof firmwareFixture>>["launches"],
): Promise<void> => {
  for (const launch of launches) {
    const pid = launch.pid;
    if (pid !== undefined)
      expect(() => process.kill(-pid, 0)).toThrowError(
        expect.objectContaining({ code: "ESRCH" }),
      );
    if (launch.cwd !== undefined)
      await expect(access(launch.cwd)).rejects.toMatchObject({
        code: "ENOENT",
      });
  }
};
