import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createRustImage } from "../../tests/fixtures/rust/image.js";
import { generateTriageReportReportSchema } from "../domain/triage/generateTriageReport.js";
import { analyzeGenerateTriageReport } from "./GenerateTriageReport.js";

const context = (bytes: Buffer) => ({
  sha256: createHash("sha256").update(bytes).digest("hex"),
});

describe("analyzeGenerateTriageReport", () => {
  it("renders a Markdown report for an executable image", async () => {
    const bytes = createRustImage({ format: "pe" });
    const body = await analyzeGenerateTriageReport(
      bytes,
      { path: "/artifacts/sample.exe" },
      context(bytes),
    );
    expect(body.file_type).toBe("pe");
    expect(body.markdown).toContain("# Triage report");
    expect(body.markdown).toContain("## Structure");
    expect(body.markdown).toContain("## Suggested next steps");
    expect(body.markdown).toContain(body.sha256);
    expect(body.sha256).toMatch(/^[0-9a-f]{64}$/u);
    expect(() =>
      generateTriageReportReportSchema.parse({
        artifact: {
          path: "/artifacts/sample.exe",
          sha256: body.sha256,
          bytes: bytes.length,
        },
        ...body,
      }),
    ).not.toThrow();
  });

  it("renders a data report for non-executable bytes", async () => {
    const bytes = Buffer.from("plain text payload for triage reporting");
    const body = await analyzeGenerateTriageReport(
      bytes,
      { path: "/artifacts/sample.txt" },
      context(bytes),
    );
    expect(body.file_type).toBe("data");
    expect(body.markdown).toContain("treated as data");
  });
});
