import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createGoBinaryFixture } from "../../tests/fixtures/go/image.js";
import { createRustImage } from "../../tests/fixtures/rust/image.js";
import {
  generateSbomReportSchema,
  type GenerateSbomInput,
  type GenerateSbomReport,
} from "../domain/triage/generateSbom.js";
import { analyzeGenerateSbom } from "./GenerateSbom.js";
import type { TriageAnalysisContext } from "./triageSupport.js";

const context = (bytes: Buffer): TriageAnalysisContext => ({
  sha256: createHash("sha256").update(bytes).digest("hex"),
});

const run = async (
  bytes: Buffer,
  format: GenerateSbomInput["format"] = "both",
): Promise<GenerateSbomReport> => {
  const body = await analyzeGenerateSbom(
    bytes,
    { path: "/artifacts/application", format },
    context(bytes),
  );
  const report = {
    ...body,
    artifact: {
      path: "/artifacts/application",
      sha256: createHash("sha256").update(bytes).digest("hex"),
      bytes: bytes.length,
    },
  };
  return generateSbomReportSchema.parse(report);
};

describe("analyzeGenerateSbom", () => {
  it("inventories Go build information as derived components", async () => {
    const { bytes } = createGoBinaryFixture();
    const report = await run(bytes);
    const names = report.components.map((component) => component.name);
    expect(names).toContain("stdlib");
    expect(names).toContain("example.com/tool");
    expect(names).toContain("example.com/dependency");

    const main = report.components.find(
      (component) => component.name === "example.com/tool",
    );
    expect(main?.type).toBe("application");
    expect(main?.source).toBe("go-buildinfo");
    expect(main?.evidence_kind).toBe("derived");

    const dependency = report.components.find(
      (component) => component.name === "example.com/dependency",
    );
    expect(dependency?.type).toBe("library");
    expect(dependency?.version).toBe("v1.2.3");
    expect(dependency?.purl).toBe("pkg:golang/example.com/dependency@v1.2.3");

    const stdlib = report.components.find(
      (component) => component.name === "stdlib",
    );
    expect(stdlib?.type).toBe("module");
    expect(stdlib?.version).toBe("go1.26.0");
    expect(stdlib?.purl).toBeNull();

    expect(report.completeness).toBe("partial");
  });

  it("inventories Rust cargo-auditable packages", async () => {
    const bytes = createRustImage({ format: "elf" });
    const report = await run(bytes);
    const cargo = report.components.filter(
      (component) => component.source === "cargo-auditable",
    );
    expect(cargo.map((component) => component.name).sort()).toEqual([
      "itoa",
      "sample",
    ]);
    const root = cargo.find((component) => component.name === "sample");
    expect(root?.type).toBe("application");
    expect(root?.evidence_kind).toBe("derived");
    const itoa = cargo.find((component) => component.name === "itoa");
    expect(itoa?.type).toBe("library");
    expect(itoa?.purl).toBe("pkg:cargo/itoa@1.0.18");
  });

  it("infers components from embedded version banners", async () => {
    const bytes = Buffer.from(
      "padding\0deflate 1.3.1 Copyright 1995\0OpenSSL 3.5.7 10 Jul 2025\0libcurl/8.5.0\0tail",
      "latin1",
    );
    const report = await run(bytes);
    const classifier = report.components.filter(
      (component) => component.source === "binary-classifier",
    );
    expect(
      classifier.map((component) => `${component.name}@${component.version}`),
    ).toEqual(
      expect.arrayContaining(["zlib@1.3.1", "openssl@3.5.7", "curl@8.5.0"]),
    );
    for (const component of classifier) {
      expect(component.evidence_kind).toBe("inferred");
      expect(component.purl).toContain("pkg:generic/");
    }
    // A plain file carries no executable subject.
    expect(report.subject.format).toBe("file");
    expect(report.entry_point).toBeNull();
  });

  it("deduplicates repeated banners into one component with many locations", async () => {
    const banner = "OpenSSL 3.5.7 x\0";
    const bytes = Buffer.from(banner.repeat(5), "latin1");
    const report = await run(bytes);
    const openssl = report.components.filter(
      (component) => component.name === "openssl",
    );
    expect(openssl).toHaveLength(1);
    expect(openssl[0]?.locations.length).toBe(5);
  });

  it("renders only the requested document family", async () => {
    const bytes = Buffer.from("OpenSSL 3.5.7 x", "latin1");
    const cyclonedxOnly = await run(bytes, "cyclonedx");
    expect(cyclonedxOnly.cyclonedx).not.toBeNull();
    expect(cyclonedxOnly.spdx).toBeNull();
    expect(cyclonedxOnly.cyclonedx?.specVersion).toBe("1.6");

    const spdxOnly = await run(bytes, "spdx");
    expect(spdxOnly.spdx).not.toBeNull();
    expect(spdxOnly.cyclonedx).toBeNull();
    expect(spdxOnly.spdx?.spdxVersion).toBe("SPDX-2.3");
    expect(spdxOnly.spdx?.documentNamespace).toMatch(
      /^urn:rea:sbom:[0-9a-f]{64}$/u,
    );
  });

  it("reports an empty partial inventory for content with no recorded components", async () => {
    const bytes = Buffer.alloc(4096, 0);
    const report = await run(bytes);
    expect(report.components).toHaveLength(0);
    expect(report.component_coverage).toEqual({
      total: 0,
      returned: 0,
      truncated: false,
    });
    expect(report.completeness).toBe("partial");
    expect(report.cyclonedx?.components).toHaveLength(0);
    expect(report.spdx?.packages).toHaveLength(0);
  });

  it("is deterministic across runs", async () => {
    const { bytes } = createGoBinaryFixture();
    const first = await run(bytes);
    const second = await run(bytes);
    expect(JSON.stringify(first)).toBe(JSON.stringify(second));
  });

  it("honors cooperative cancellation", async () => {
    const controller = new AbortController();
    controller.abort();
    await expect(
      analyzeGenerateSbom(
        Buffer.alloc(64, 0),
        { path: "/artifacts/application", format: "both" },
        { sha256: "0".repeat(64), signal: controller.signal },
      ),
    ).rejects.toThrow();
  });
});
