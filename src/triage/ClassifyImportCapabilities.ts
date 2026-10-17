import {
  CAPABILITY_RULES,
  CAPABILITY_TAXONOMY_VERSION,
  DYNAMIC_RESOLUTION_APIS,
  type CapabilityRule,
} from "../domain/triage/capabilitySignatures.js";
import type {
  ClassifyImportCapabilitiesInput,
  ClassifyImportCapabilitiesReport,
} from "../domain/triage/classifyImportCapabilities.js";
import type { ImageImport } from "../domain/native/image/executableImage.js";
import {
  requireTriageImage,
  triageSubject,
  type TriageAnalysisContext,
} from "./triageSupport.js";

type ReportBody = Omit<ClassifyImportCapabilitiesReport, "artifact">;
type Support = { readonly library: string | null; readonly name: string };

/** Normalize a Win32/POSIX import name to the taxonomy's lowercase basename. */
const normalizeImportName = (name: string): string => {
  const lowered = name.toLowerCase().replace(/^_+/u, "");
  return /[a-z]w$|[a-z]a$/u.test(lowered) ? lowered.slice(0, -1) : lowered;
};

/** De-duplicate imports by library+name while keeping their display form. */
const dedupeImports = (
  imports: readonly ImageImport[],
): readonly { readonly display: Support; readonly normalized: string }[] => {
  const seen = new Set<string>();
  const result: { display: Support; normalized: string }[] = [];
  for (const entry of imports) {
    if (entry.name === null) continue;
    const key = `${entry.library ?? ""}\u0001${entry.name}`;
    if (seen.has(key)) continue;
    seen.add(key);
    result.push({
      display: { library: entry.library, name: entry.name },
      normalized: normalizeImportName(entry.name),
    });
  }
  return result;
};

/** Confidence from how many distinct APIs of a rule matched. */
const confidenceFor = (matches: number): "high" | "medium" | "low" =>
  matches >= 3 ? "high" : matches === 2 ? "medium" : "low";

const matchRule = (
  rule: CapabilityRule,
  imports: readonly {
    readonly display: Support;
    readonly normalized: string;
  }[],
  maxSupport: number,
): ReportBody["capabilities"][number] | null => {
  const api = new Set(rule.apis);
  const support = imports.filter((entry) => api.has(entry.normalized));
  if (support.length === 0) return null;
  const distinct = new Set(support.map((entry) => entry.normalized)).size;
  return {
    id: rule.id,
    label: rule.label,
    confidence: confidenceFor(distinct),
    evidence_kind: "inferred",
    supporting_imports: support
      .slice(0, maxSupport)
      .map((entry) => entry.display),
    supporting_coverage: {
      total: support.length,
      returned: Math.min(support.length, maxSupport),
      truncated: support.length > maxSupport,
    },
  };
};

const LIMITATIONS: readonly string[] = [
  "Capabilities are inferred from the import table and are stated as imports consistent with a behavior, never as proof that the behavior occurs or is reachable.",
  "Only statically declared imports are examined. Imports resolved at runtime (for example through GetProcAddress or dlsym) are not classified; unresolved_dynamic reports whether such resolution is imported.",
  `Classification uses BinSight capability taxonomy version ${CAPABILITY_TAXONOMY_VERSION}; an absent capability means no matching import was observed, not that the behavior is impossible.`,
  "Import names are read without executing the target, without network access and without writing files.",
];

/** Capability classification over a parsed import table, independent of I/O. */
export const classifyImportTable = (
  imports: readonly ImageImport[],
  maxSupport: number,
): Pick<ReportBody, "capabilities" | "unresolved_dynamic" | "import_count"> => {
  const deduped = dedupeImports(imports);
  return {
    import_count: deduped.length,
    unresolved_dynamic: deduped.some((entry) =>
      DYNAMIC_RESOLUTION_APIS.includes(entry.normalized),
    ),
    capabilities: CAPABILITY_RULES.map((rule) =>
      matchRule(rule, deduped, maxSupport),
    ).filter((value): value is NonNullable<typeof value> => value !== null),
  };
};

/** Classify an executable's import table into coarse capability classes. */
export const analyzeClassifyImportCapabilities = async (
  bytes: Buffer,
  input: ClassifyImportCapabilitiesInput,
  _context: TriageAnalysisContext,
): Promise<ReportBody> => {
  const image = requireTriageImage(bytes, input.slice);
  const classified = classifyImportTable(image.imports, input.max_support);
  const limitations =
    image.coverage.imports === "unavailable"
      ? [
          "The import table could not be read for this image, so no capabilities were classified.",
          ...LIMITATIONS,
        ]
      : [...LIMITATIONS];
  return {
    subject: triageSubject(image),
    taxonomy_version: CAPABILITY_TAXONOMY_VERSION,
    ...classified,
    limitations,
  };
};
