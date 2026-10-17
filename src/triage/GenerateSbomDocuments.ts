import type {
  CyclonedxDocument,
  SbomComponent,
  SpdxDocument,
} from "../domain/triage/generateSbom.js";

/** Bundled engine identity recorded as the SBOM-producing tool. */
const TOOL_NAME = "binsight-static-triage";
const TOOL_VERSION = "1.0";
/**
 * Fixed creation timestamp. Static triage is deterministic and reads no clock,
 * so the same bytes always render the same document; the limitations state this.
 */
const FIXED_CREATED = "1970-01-01T00:00:00Z";

/** Render a CycloneDX 1.6-shaped document from the normalized components. */
export const buildCyclonedx = (
  components: readonly SbomComponent[],
): CyclonedxDocument => ({
  bomFormat: "CycloneDX",
  specVersion: "1.6",
  version: 1,
  metadata: {
    tools: {
      components: [
        { type: "application", name: TOOL_NAME, version: TOOL_VERSION },
      ],
    },
  },
  components: components.map((component, index) => ({
    "bom-ref": `component-${index + 1}`,
    type: component.type === "application" ? "application" : "library",
    name: component.name,
    ...(component.version === null ? {} : { version: component.version }),
    ...(component.purl === null ? {} : { purl: component.purl }),
  })),
});

/** Render an SPDX 2.3-shaped document from the normalized components. */
export const buildSpdx = (
  components: readonly SbomComponent[],
  sha256: string,
): SpdxDocument => ({
  spdxVersion: "SPDX-2.3",
  dataLicense: "CC0-1.0",
  SPDXID: "SPDXRef-DOCUMENT",
  name:
    components.find((component) => component.type === "application")?.name ??
    "component-inventory",
  documentNamespace: `urn:binsight:sbom:${sha256}`,
  creationInfo: {
    created: FIXED_CREATED,
    creators: [`Tool: ${TOOL_NAME}-${TOOL_VERSION}`],
  },
  packages: components.map((component, index) => ({
    SPDXID: `SPDXRef-Package-${index + 1}`,
    name: component.name,
    ...(component.version === null ? {} : { versionInfo: component.version }),
    downloadLocation: "NOASSERTION",
    filesAnalyzed: false,
    ...(component.purl === null
      ? {}
      : {
          externalRefs: [
            {
              referenceCategory: "PACKAGE-MANAGER",
              referenceType: "purl",
              referenceLocator: component.purl,
            },
          ],
        }),
  })),
});
