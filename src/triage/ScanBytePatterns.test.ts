import { describe, expect, it } from "vitest";
import { createRustImage } from "../../tests/fixtures/rust/image.js";
import {
  scanBytePatternsReportSchema,
  type ScanBytePattern,
  type ScanBytePatternsInput,
} from "../domain/triage/scanBytePatterns.js";
import { analyzeScanBytePatterns } from "./ScanBytePatterns.js";
import { TriageAnalysisFailure } from "./triageSupport.js";

const SHA = "0".repeat(64);

// Layout: MZ(0) ABC(4) MZ(7) 4d9943(9) abc(12) wide"Hi"(15), length 19.
const data = Buffer.from([
  0x4d, 0x5a, 0x90, 0x00, 0x41, 0x42, 0x43, 0x4d, 0x5a, 0x4d, 0x99, 0x43, 0x61,
  0x62, 0x63, 0x48, 0x00, 0x69, 0x00,
]);

const run = async (
  bytes: Buffer,
  patterns: readonly ScanBytePattern[],
  maxMatches = 500,
) => {
  const input: ScanBytePatternsInput = {
    path: "/artifacts/sample",
    patterns: [...patterns],
    max_matches: maxMatches,
  };
  const body = await analyzeScanBytePatterns(bytes, input, { sha256: SHA });
  const report = scanBytePatternsReportSchema.parse({
    ...body,
    artifact: { path: input.path, sha256: SHA, bytes: bytes.length },
  });
  return report;
};

const offsets = (
  report: Awaited<ReturnType<typeof run>>,
  id: string,
): number[] =>
  report.matches
    .filter((match) => match.pattern_id === id)
    .map((match) => match.location.file_offset);

describe("analyzeScanBytePatterns hex grammar", () => {
  it("finds literal byte sequences and previews the matched bytes", async () => {
    const report = await run(data, [{ id: "mz", type: "hex", value: "4D 5A" }]);
    expect(offsets(report, "mz")).toEqual([0, 7]);
    expect(report.matches[0]?.preview_hex).toBe("4d5a");
    expect(report.matches[0]?.length).toBe(2);
    expect(report.match_coverage).toEqual({
      total: 2,
      returned: 2,
      truncated: false,
    });
  });

  it("applies full-byte and single-nibble wildcards", async () => {
    const report = await run(data, [
      { id: "any", type: "hex", value: "4D ??" },
      { id: "nibble", type: "hex", value: "4? 9?" },
    ]);
    expect(offsets(report, "any")).toEqual([0, 7, 9]);
    expect(offsets(report, "nibble")).toEqual([9]);
  });

  it("matches bounded jumps between anchors", async () => {
    const report = await run(data, [
      { id: "jump", type: "hex", value: "4D [1-1] 43" },
    ]);
    expect(offsets(report, "jump")).toEqual([9]);
    expect(report.matches[0]?.length).toBe(3);
    expect(report.matches[0]?.preview_hex).toBe("4d9943");
  });

  it("matches alternation branches", async () => {
    const report = await run(data, [
      { id: "alt", type: "hex", value: "(4D5A|616263)" },
    ]);
    expect(offsets(report, "alt")).toEqual([0, 7, 12]);
  });
});

describe("analyzeScanBytePatterns text and regex", () => {
  it("matches ASCII literals and honors nocase", async () => {
    const exact = await run(data, [{ id: "abc", type: "text", value: "ABC" }]);
    expect(offsets(exact, "abc")).toEqual([4]);
    const folded = await run(data, [
      { id: "abc", type: "text", value: "ABC", nocase: true },
    ]);
    expect(offsets(folded, "abc")).toEqual([4, 12]);
  });

  it("matches the UTF-16LE encoding when wide is requested", async () => {
    const report = await run(data, [
      { id: "hi", type: "text", value: "Hi", wide: true },
    ]);
    expect(offsets(report, "hi")).toEqual([15]);
    expect(report.matches[0]?.preview_hex).toBe("48006900");
  });

  it("searches both encodings when ascii and wide are both set", async () => {
    const mixed = Buffer.concat([Buffer.from("Hi"), data]);
    const report = await run(mixed, [
      { id: "hi", type: "text", value: "Hi", ascii: true, wide: true },
    ]);
    expect(offsets(report, "hi")).toEqual([0, 17]);
  });

  it("runs caller regular expressions over the bytes", async () => {
    const report = await run(data, [
      { id: "re", type: "regex", value: "ABC", nocase: true },
    ]);
    expect(offsets(report, "re")).toEqual([4, 12]);
  });
});

describe("analyzeScanBytePatterns bounds and provenance", () => {
  it("truncates at max_matches and records per-pattern counts", async () => {
    const report = await run(
      data,
      [{ id: "any", type: "hex", value: "4D ??" }],
      2,
    );
    expect(report.matches).toHaveLength(2);
    expect(report.match_coverage.truncated).toBe(true);
    expect(report.per_pattern_counts[0]).toEqual({
      pattern_id: "any",
      total: 2,
      returned: 2,
      truncated: true,
    });
  });

  it("reports a plain file with null sections", async () => {
    const report = await run(data, [{ id: "mz", type: "hex", value: "4D5A" }]);
    expect(report.subject).toEqual({ format: "file", architecture: null });
    expect(report.matches[0]?.location.section).toBeNull();
    expect(report.matches[0]?.location.virtual_address).toBeNull();
  });

  it("recognizes an executable image for subject classification", async () => {
    const elf = createRustImage({ format: "elf" });
    const report = await run(elf, [
      { id: "magic", type: "hex", value: "7F454C46" },
    ]);
    expect(report.subject.format).toBe("elf");
    expect(offsets(report, "magic")).toContain(0);
  });

  it("handles no matches without failing", async () => {
    const report = await run(data, [
      { id: "absent", type: "text", value: "nowhere" },
    ]);
    expect(report.matches).toHaveLength(0);
    expect(report.match_coverage).toEqual({
      total: 0,
      returned: 0,
      truncated: false,
    });
    expect(report.per_pattern_counts[0]?.total).toBe(0);
  });
});

describe("analyzeScanBytePatterns rejections", () => {
  const rejects = async (pattern: ScanBytePattern): Promise<void> => {
    await expect(run(data, [pattern])).rejects.toBeInstanceOf(
      TriageAnalysisFailure,
    );
  };

  it("rejects malformed hex, jumps, and alternations", async () => {
    await rejects({ id: "p", type: "hex", value: "[0-2] 4D" });
    await rejects({ id: "p", type: "hex", value: "4D [0-2]" });
    await rejects({ id: "p", type: "hex", value: "ZZ" });
    await rejects({ id: "p", type: "hex", value: "4" });
    await rejects({ id: "p", type: "hex", value: "(4D5A)" });
    await rejects({ id: "p", type: "hex", value: "[1-2]" });
    await rejects({ id: "p", type: "hex", value: "4D [0-2000000] 43" });
  });

  it("rejects regex backreferences and invalid syntax", async () => {
    await rejects({ id: "p", type: "regex", value: "(ab)\\1" });
    await rejects({ id: "p", type: "regex", value: "(unterminated" });
  });

  it("rejects a text pattern with neither encoding enabled", async () => {
    await rejects({
      id: "p",
      type: "text",
      value: "x",
      ascii: false,
      wide: false,
    });
  });
});
