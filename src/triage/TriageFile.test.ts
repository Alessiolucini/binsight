import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createRustImage } from "../../tests/fixtures/rust/image.js";
import { triageFileReportSchema } from "../domain/triage/triageFile.js";
import { analyzeTriageFile } from "./TriageFile.js";

const context = (bytes: Buffer) => ({
  sha256: createHash("sha256").update(bytes).digest("hex"),
});

const withArtifact = (bytes: Buffer, body: Record<string, unknown>) => ({
  artifact: {
    path: "/artifacts/sample",
    sha256: createHash("sha256").update(bytes).digest("hex"),
    bytes: bytes.length,
  },
  ...body,
});

describe("analyzeTriageFile", () => {
  it("summarizes an executable image with structure, entropy and next steps", async () => {
    const bytes = createRustImage({ format: "elf" });
    const body = await analyzeTriageFile(
      bytes,
      { path: "/artifacts/sample" },
      context(bytes),
    );
    expect(body.file_type).toBe("elf");
    expect(body.format).not.toBeNull();
    expect(body.md5).toMatch(/^[0-9a-f]{32}$/u);
    expect(body.entropy.file).toBeGreaterThan(0);
    expect(["low", "normal", "high"]).toContain(body.entropy.classification);
    expect(body.next_probes.length).toBeGreaterThan(0);
    expect(body.next_probes.map((p) => p.operation)).toContain(
      "inspect_executable",
    );
    expect(() =>
      triageFileReportSchema.parse(withArtifact(bytes, body)),
    ).not.toThrow();
  });

  it("summarizes non-executable bytes as data without refusing", async () => {
    const bytes = Buffer.alloc(4096, 0x41);
    const body = await analyzeTriageFile(
      bytes,
      { path: "/artifacts/sample" },
      context(bytes),
    );
    expect(body.file_type).toBe("data");
    expect(body.format).toBeNull();
    expect(body.capabilities.ids).toHaveLength(0);
    expect(body.code_signature.present).toBe(false);
    expect(() =>
      triageFileReportSchema.parse(withArtifact(bytes, body)),
    ).not.toThrow();
  });

  it("classifies a low-entropy constant buffer as low", async () => {
    const bytes = Buffer.alloc(8192, 0);
    const body = await analyzeTriageFile(
      bytes,
      { path: "/artifacts/sample" },
      context(bytes),
    );
    expect(body.entropy.classification).toBe("low");
  });
});
