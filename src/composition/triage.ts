import { CompareBinariesService } from "../application/triage/CompareBinariesService.js";
import { CompareExecutablesService } from "../application/triage/CompareExecutablesService.js";
import { StaticTriageService } from "../application/triage/StaticTriageService.js";
import { CompareBinariesProvider } from "../triage/CompareBinaries.js";
import { CompareExecutablesProvider } from "../triage/CompareExecutables.js";
import { StaticTriageProvider } from "../triage/StaticTriageProvider.js";
import { TRIAGE_ANALYZERS } from "../triage/triageAnalyzers.js";

/** Compose the shared single-path static triage workflow with no child process. */
export const createStaticTriageService = (): StaticTriageService =>
  new StaticTriageService(new StaticTriageProvider(TRIAGE_ANALYZERS));

/** Compose the two-path executable comparison workflow with no child process. */
export const createCompareExecutablesService = (): CompareExecutablesService =>
  new CompareExecutablesService(new CompareExecutablesProvider());

/** Compose the two-path raw binary comparison workflow with no child process. */
export const createCompareBinariesService = (): CompareBinariesService =>
  new CompareBinariesService(new CompareBinariesProvider());
