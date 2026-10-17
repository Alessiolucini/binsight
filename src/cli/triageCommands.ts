import { z } from "incur";
import {
  createCompareBinariesService,
  createCompareExecutablesService,
  createStaticTriageService,
} from "../composition/triage.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import { TRIAGE_DEFINITIONS } from "../application/triage/triageDefinitions.js";
import { finishAnalysisCommand } from "./finishAnalysisCommand.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";
import { absoluteCallerPath } from "../filesystem/callerPath.js";

const PROVIDER_ID = "binsight-static-triage";

/** CLI command name and one-line help for each single-path triage operation. */
const SINGLE_PATH_COMMANDS: Readonly<
  Record<string, { command: string; description: string }>
> = {
  inspect_executable: {
    command: CLI_COMMANDS.inspectExecutable,
    description:
      "Inspect ELF/PE/Mach-O structure (sections, imports, exports, entry) without target execution",
  },
  inspect_binary_hardening: {
    command: CLI_COMMANDS.inspectBinaryHardening,
    description:
      "Inspect ELF/PE/Mach-O exploit-mitigation indicators without target execution",
  },
  measure_binary_entropy: {
    command: CLI_COMMANDS.measureBinaryEntropy,
    description:
      "Measure file, section and block Shannon entropy without target execution",
  },
  detect_binary_toolchain: {
    command: CLI_COMMANDS.detectBinaryToolchain,
    description:
      "Identify compiler, packer, installer and language markers without target execution",
  },
  extract_binary_strings: {
    command: CLI_COMMANDS.extractBinaryStrings,
    description:
      "Extract and classify ASCII/UTF-16 strings and IOC candidates without target execution",
  },
  identify_crypto_constants: {
    command: CLI_COMMANDS.identifyCryptoConstants,
    description:
      "Identify well-known cryptographic constant tables without target execution",
  },
  classify_import_capabilities: {
    command: CLI_COMMANDS.classifyImportCapabilities,
    description:
      "Classify imported APIs into coarse capability classes without target execution",
  },
  scan_byte_patterns: {
    command: CLI_COMMANDS.scanBytePatterns,
    description:
      "Search a file for caller-supplied byte, text and regex patterns without target execution",
  },
  compute_similarity_hashes: {
    command: CLI_COMMANDS.computeSimilarityHashes,
    description:
      "Compute imphash, Rich, symhash, telfhash, ssdeep and TLSH similarity hashes without target execution",
  },
  inspect_code_signature: {
    command: CLI_COMMANDS.inspectCodeSignature,
    description:
      "Parse Authenticode and Mach-O code-signature structure without evaluating trust or executing the target",
  },
  scan_embedded_content: {
    command: CLI_COMMANDS.scanEmbeddedContent,
    description:
      "Identify embedded files and padding by validated signatures without target execution",
  },
  generate_sbom: {
    command: CLI_COMMANDS.generateSbom,
    description:
      "Generate a component inventory (CycloneDX/SPDX) from embedded metadata without target execution",
  },
  recover_go_symbols: {
    command: CLI_COMMANDS.recoverGoSymbols,
    description:
      "Recover function names from an embedded Go pclntab without target execution",
  },
  triage_file: {
    command: CLI_COMMANDS.triageFile,
    description:
      "Triage one file in a single read-only pass: type, hashes, entropy, packing, capabilities, signature and next steps",
  },
  generate_triage_report: {
    command: CLI_COMMANDS.generateTriageReport,
    description:
      "Render a shareable Markdown triage report for one file without target execution",
  },
};

/** Register every static triage command against the shared CLI/MCP workflow. */
export const registerTriageCommands = (
  cli: CliInstance,
  logger: Logger,
): void => {
  for (const definition of TRIAGE_DEFINITIONS) {
    const entry = SINGLE_PATH_COMMANDS[definition.operation];
    if (entry === undefined) continue;
    cli.command(entry.command, {
      description: entry.description,
      args: z.object({
        path: z.string().describe("Local file to inspect"),
      }),
      run: ({ args }) =>
        withCommandCancellation((signal) => {
          const service = createStaticTriageService();
          return logCliCommand(logger, entry.command, () =>
            finishAnalysisCommand(
              () =>
                service.run(
                  definition,
                  { path: absoluteCallerPath(args.path) },
                  { signal },
                ),
              service,
              PROVIDER_ID,
              definition.operation,
              undefined,
              signal,
            ),
          );
        }),
    });
  }
  cli.command(CLI_COMMANDS.compareExecutables, {
    description:
      "Compare two local executables (imports, exports, sections, hardening, entropy) without target execution",
    args: z.object({
      basePath: z.string().describe("Baseline local executable"),
      targetPath: z
        .string()
        .describe("Target local executable to compare against the baseline"),
    }),
    run: ({ args }) =>
      withCommandCancellation((signal) => {
        const service = createCompareExecutablesService();
        return logCliCommand(logger, CLI_COMMANDS.compareExecutables, () =>
          finishAnalysisCommand(
            () =>
              service.compare(
                {
                  base_path: absoluteCallerPath(args.basePath),
                  target_path: absoluteCallerPath(args.targetPath),
                },
                { signal },
              ),
            service,
            PROVIDER_ID,
            "compare_executables",
            undefined,
            signal,
          ),
        );
      }),
  });
  cli.command(CLI_COMMANDS.compareBinaries, {
    description:
      "Compare two local files byte-for-byte and explain what changed (firmware, calibration dumps, app updates) without target execution",
    args: z.object({
      basePath: z.string().describe("Baseline local file"),
      targetPath: z
        .string()
        .describe("Target local file to compare against the baseline"),
    }),
    run: ({ args }) =>
      withCommandCancellation((signal) => {
        const service = createCompareBinariesService();
        return logCliCommand(logger, CLI_COMMANDS.compareBinaries, () =>
          finishAnalysisCommand(
            () =>
              service.compare(
                {
                  base_path: absoluteCallerPath(args.basePath),
                  target_path: absoluteCallerPath(args.targetPath),
                },
                { signal },
              ),
            service,
            "binsight-compare-binaries",
            "compare_binaries",
            undefined,
            signal,
          ),
        );
      }),
  });
};
