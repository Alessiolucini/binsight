import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import type { CompareExecutablesService } from "../application/triage/CompareExecutablesService.js";
import type { StaticTriageService } from "../application/triage/StaticTriageService.js";
import { TRIAGE_DEFINITIONS } from "../application/triage/triageDefinitions.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import { TOOL_CONTRACTS, toolContract } from "../contracts/toolContracts.js";
import type { Logger } from "pino";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";
import { createEvidenceToolHandler } from "./contractToolHandler.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";

type ToolContractName = (typeof TOOL_CONTRACTS)[number]["name"];

/** Bind every static triage contract to its shared workflow and session ledger. */
export const registerTriageTools = (
  server: EvidenceMcpServer,
  staticTriage: StaticTriageService,
  compareExecutables: CompareExecutablesService,
  logger: Logger,
  recordEvidence?: EvidenceWriter["recordEvidence"],
  withAdmittedAnalysis?: WithAdmittedAnalysis,
): void => {
  for (const definition of TRIAGE_DEFINITIONS) {
    const contract = toolContract(definition.operation as ToolContractName);
    const handler = createEvidenceToolHandler(
      server,
      (input, options) => staticTriage.run(definition, input, options),
      logger,
      recordEvidence,
      withAdmittedAnalysis,
    );
    server.registerTool(
      contract.name,
      toolRegistrationOptions(contract),
      handler(contract),
    );
  }
  const compareContract = toolContract("compare_executables");
  const compareHandler = createEvidenceToolHandler(
    server,
    (input, options) => compareExecutables.compare(input, options),
    logger,
    recordEvidence,
    withAdmittedAnalysis,
  );
  server.registerTool(
    compareContract.name,
    toolRegistrationOptions(compareContract),
    compareHandler(compareContract),
  );
};
