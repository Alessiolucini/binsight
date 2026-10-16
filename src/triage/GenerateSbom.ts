import type { ExecutableImage } from "../domain/native/image/executableImage.js";
import { compositeKey } from "../domain/unicodeCodePointOrder.js";
import { readGoBinaryImage } from "../go/GoBinaryImage.js";
import { parseGoModuleText } from "../go/GoModuleText.js";
import { readRustBinaryImage } from "../rust/RustBinaryImage.js";
import type { GoModule } from "../domain/go/goBinary.js";
import type {
  GenerateSbomInput,
  GenerateSbomReport,
  SbomComponent,
} from "../domain/triage/generateSbom.js";
import { toHexAddress } from "../domain/triage/triageCommon.js";
import {
  COMPONENT_SCAN_LIMIT_BYTES,
  COMPONENT_SCAN_MAX_HITS,
  scanComponentSignatures,
  type ComponentHit,
} from "../domain/triage/componentSignatures.js";
import {
  checkTriageCancelled,
  loadTriageImage,
  triageLocation,
  triageSubject,
  yieldTriage,
  type TriageAnalysisContext,
} from "./triageSupport.js";
import { buildCyclonedx, buildSpdx } from "./GenerateSbomDocuments.js";

/** Largest component list retained before truncation is reported. */
const MAX_COMPONENTS = 20_000;
/** Largest file positions retained per component. */
const MAX_LOCATIONS = 16;

type Location = SbomComponent["locations"][number];

/**
 * Inventory the components a local file records about itself. Go build
 * information and Rust cargo-auditable metadata yield derived identities; a
 * REA-authored signature table infers further components from embedded version
 * banners. The file is read once and never executed; no network or vulnerability
 * database is consulted; nothing is written. Completeness is always partial:
 * an absent source is not evidence that a component is absent.
 */
export const analyzeGenerateSbom = async (
  bytes: Buffer,
  input: GenerateSbomInput,
  context: TriageAnalysisContext,
): Promise<Omit<GenerateSbomReport, "artifact">> => {
  const image = loadTriageImage(bytes).image;
  const locate = (offset: number): Location => triageLocation(image, offset);
  const limitations: string[] = [];
  const components: SbomComponent[] = [];

  checkTriageCancelled(context.signal);
  collectGo(bytes, locate, limitations, components);
  await yieldTriage(context.signal);
  collectRust(bytes, locate, limitations, components);
  await yieldTriage(context.signal);
  const scanTruncated = collectClassifier(bytes, locate, components);
  await yieldTriage(context.signal);

  const total = components.length;
  const truncated = total > MAX_COMPONENTS;
  const returned = truncated ? components.slice(0, MAX_COMPONENTS) : components;

  const format = input.format;
  return {
    subject: triageSubject(image),
    entry_point: entryPoint(image),
    components: returned,
    component_coverage: {
      total,
      returned: returned.length,
      truncated,
    },
    completeness: "partial",
    cyclonedx:
      format === "both" || format === "cyclonedx"
        ? buildCyclonedx(returned)
        : null,
    spdx:
      format === "both" || format === "spdx"
        ? buildSpdx(returned, context.sha256)
        : null,
    limitations: baseLimitations(
      limitations,
      truncated,
      scanTruncated,
      bytes.length,
    ),
  };
};

const entryPoint = (image: ExecutableImage | null): string | null =>
  image === null || image.entry_point.virtual_address === null
    ? null
    : toHexAddress(image.entry_point.virtual_address);

const collectGo = (
  bytes: Buffer,
  locate: (offset: number) => Location,
  limitations: string[],
  components: SbomComponent[],
): void => {
  let go;
  try {
    go = readGoBinaryImage(bytes);
  } catch (cause) {
    limitations.push(
      `Go build information was not read (${reason(cause)}); Go module components are not included.`,
    );
    return;
  }
  const info = go.build_info;
  if (info === null) return;
  const versionLocation = locate(info.version_location.offset);
  const moduleLocation = locate(info.module_location.offset);
  if (info.go_version !== null)
    components.push({
      name: "stdlib",
      version: info.go_version,
      type: "module",
      source: "go-buildinfo",
      purl: null,
      evidence_kind: "derived",
      locations: [versionLocation],
    });
  if (info.module_text === null) {
    limitations.push(
      "Go module records were not UTF-8 decodable; dependency identities are omitted.",
    );
    return;
  }
  const module = parseGoModuleText(info.module_text);
  if (module.main !== null)
    components.push(goComponent(module.main, "application", moduleLocation));
  for (const dependency of module.dependencies)
    components.push(goComponent(dependency, "library", moduleLocation));
  if (!module.complete)
    limitations.push(
      "Some Go module records were unrecognized; the dependency inventory may be incomplete.",
    );
};

const goComponent = (
  module: GoModule,
  type: SbomComponent["type"],
  location: Location,
): SbomComponent => ({
  name: module.path,
  version: module.version === "" ? null : module.version,
  type,
  source: "go-buildinfo",
  purl:
    module.version === ""
      ? null
      : `pkg:golang/${module.path}@${module.version}`,
  evidence_kind: "derived",
  locations: [location],
});

const collectRust = (
  bytes: Buffer,
  locate: (offset: number) => Location,
  limitations: string[],
  components: SbomComponent[],
): void => {
  let rust;
  try {
    rust = readRustBinaryImage(bytes);
  } catch (cause) {
    limitations.push(
      `Rust cargo-auditable metadata was not read (${reason(cause)}); Rust components are not included.`,
    );
    return;
  }
  const metadata = rust.auditable_metadata;
  if (metadata === null) return;
  const location = locate(metadata.file_offset);
  for (const pkg of metadata.packages)
    components.push({
      name: pkg.name,
      version: pkg.version,
      type: pkg.root ? "application" : "library",
      source: "cargo-auditable",
      purl: `pkg:cargo/${pkg.name}@${pkg.version}`,
      evidence_kind: "derived",
      locations: [location],
    });
};

const collectClassifier = (
  bytes: Buffer,
  locate: (offset: number) => Location,
  components: SbomComponent[],
): boolean => {
  const scan = scanComponentSignatures(bytes);
  const grouped = new Map<string, SbomComponent>();
  const order: string[] = [];
  for (const hit of scan.hits) {
    const key = compositeKey([hit.name, hit.version]);
    const existing = grouped.get(key);
    if (existing === undefined) {
      grouped.set(key, classifierComponent(hit, locate));
      order.push(key);
    } else if (existing.locations.length < MAX_LOCATIONS)
      existing.locations.push(locate(hit.file_offset));
  }
  for (const key of order) {
    const component = grouped.get(key);
    if (component !== undefined) components.push(component);
  }
  return scan.truncated;
};

const classifierComponent = (
  hit: ComponentHit,
  locate: (offset: number) => Location,
): SbomComponent => ({
  name: hit.name,
  version: hit.version,
  type: hit.type,
  source: "binary-classifier",
  purl: `pkg:${hit.purl_type}/${hit.name}@${hit.version}`,
  evidence_kind: "inferred",
  locations: [locate(hit.file_offset)],
});

const baseLimitations = (
  collected: readonly string[],
  truncated: boolean,
  scanTruncated: boolean,
  fileBytes: number,
): string[] => {
  const limitations = [
    "Component identities are derived from recorded metadata or inferred from byte signatures; they are not proof that a component is linked, reachable, executed or current.",
    "Completeness is always partial: an absent source is not evidence that a component is absent, and statically linked or vendored code may carry no recorded identity.",
    "No network, package registry or vulnerability database is consulted; versions and package URLs are reported exactly as observed and are not validated.",
    "SBOM documents use a fixed creation timestamp because analysis is deterministic and reads no clock.",
    ...collected,
  ];
  if (truncated)
    limitations.push(
      `More than ${MAX_COMPONENTS} components were found; the list and both documents are truncated to the first ${MAX_COMPONENTS}.`,
    );
  if (scanTruncated)
    limitations.push(
      `Signature scanning stopped at ${COMPONENT_SCAN_MAX_HITS} matches or the ${COMPONENT_SCAN_LIMIT_BYTES}-byte scan window; classifier results may be incomplete.`,
    );
  else if (fileBytes > COMPONENT_SCAN_LIMIT_BYTES)
    limitations.push(
      `Only the first ${COMPONENT_SCAN_LIMIT_BYTES} bytes were scanned for component signatures.`,
    );
  return limitations;
};

const reason = (cause: unknown): string =>
  cause instanceof Error ? cause.message : String(cause);
