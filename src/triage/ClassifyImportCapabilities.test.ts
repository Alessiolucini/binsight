import { describe, expect, it } from "vitest";
import type { ImageImport } from "../domain/native/image/executableImage.js";
import {
  classifyImportCapabilitiesReportSchema,
  CLASSIFY_CAPABILITIES_MAX_SUPPORT,
} from "../domain/triage/classifyImportCapabilities.js";
import { CAPABILITY_TAXONOMY_VERSION } from "../domain/triage/capabilitySignatures.js";
import { analyzeClassifyImportCapabilities } from "./ClassifyImportCapabilities.js";
import { classifyImportTable } from "./ClassifyImportCapabilities.js";

const imp = (library: string | null, name: string | null): ImageImport => ({
  library,
  name,
  ordinal: null,
  delay_loaded: false,
  weak: false,
  version: null,
});

describe("classifyImportTable", () => {
  it("maps known Win32 APIs to capability classes, normalizing A/W suffixes", () => {
    const result = classifyImportTable(
      [
        imp("kernel32.dll", "CreateProcessW"),
        imp("kernel32.dll", "VirtualAllocEx"),
        imp("kernel32.dll", "WriteProcessMemory"),
        imp("kernel32.dll", "CreateRemoteThread"),
        imp("ws2_32.dll", "socket"),
        imp("advapi32.dll", "RegOpenKeyExA"),
      ],
      16,
    );
    const ids = result.capabilities.map((c) => c.id);
    expect(ids).toContain("process:create");
    expect(ids).toContain("process:inject");
    expect(ids).toContain("net:socket");
    expect(ids).toContain("registry:access");
    const inject = result.capabilities.find((c) => c.id === "process:inject");
    expect(inject?.confidence).toBe("high");
    expect(inject?.evidence_kind).toBe("inferred");
    expect(result.import_count).toBe(6);
  });

  it("detects runtime symbol resolution and leaves unknown imports unclassified", () => {
    const result = classifyImportTable(
      [imp("kernel32.dll", "GetProcAddress"), imp("app.dll", "DoThing")],
      16,
    );
    expect(result.unresolved_dynamic).toBe(true);
    expect(result.capabilities).toHaveLength(0);
  });

  it("bounds supporting imports and reports truncation", () => {
    const fsApis = [
      "writefile",
      "createfile",
      "movefile",
      "copyfile",
      "deletefile",
      "fopen",
      "fwrite",
      "open",
      "unlink",
      "rename",
    ];
    const many = fsApis.map((name) => imp("libc.so.6", name));
    const result = classifyImportTable(many, 3);
    const fs = result.capabilities.find((c) => c.id === "fs:write");
    expect(fs?.supporting_imports).toHaveLength(3);
    expect(fs?.supporting_coverage.truncated).toBe(true);
    expect(fs?.supporting_coverage.total).toBe(10);
  });

  it("deduplicates identical library+name imports", () => {
    const result = classifyImportTable(
      [imp("ws2_32.dll", "connect"), imp("ws2_32.dll", "connect")],
      16,
    );
    expect(result.import_count).toBe(1);
  });
});

describe("analyzeClassifyImportCapabilities", () => {
  it("rejects non-executable bytes as an unsupported target", async () => {
    await expect(
      analyzeClassifyImportCapabilities(
        Buffer.from("not an executable payload"),
        { path: "/artifacts/sample", max_support: 16 },
        { sha256: "0".repeat(64) },
      ),
    ).rejects.toMatchObject({ kind: "unsupported" });
  });

  it("caps the default support bound within the schema maximum", () => {
    expect(CLASSIFY_CAPABILITIES_MAX_SUPPORT).toBeGreaterThanOrEqual(16);
  });

  it("produces a schema-valid report shape for an empty import set", () => {
    const body = classifyImportTable([], 16);
    const candidate = {
      artifact: {
        path: "/artifacts/sample",
        sha256: "0".repeat(64),
        bytes: 10,
      },
      subject: { format: "pe" as const, architecture: "x86_64" },
      taxonomy_version: CAPABILITY_TAXONOMY_VERSION,
      ...body,
      limitations: ["example limitation"],
    };
    expect(() =>
      classifyImportCapabilitiesReportSchema.parse(candidate),
    ).not.toThrow();
  });
});
