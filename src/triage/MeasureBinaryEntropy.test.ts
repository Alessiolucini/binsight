import { describe, expect, it } from "vitest";
import {
  measureBinaryEntropyInputSchema,
  measureBinaryEntropyReportSchema,
  type MeasureBinaryEntropyReport,
} from "../domain/triage/measureBinaryEntropy.js";
import {
  analyzeMeasureBinaryEntropy,
  chiSquareFromCounts,
  entropyFromCounts,
  meanFromCounts,
} from "./MeasureBinaryEntropy.js";
import { createRustImage } from "../../tests/fixtures/rust/image.js";
import type { TriageAnalysisContext } from "./triageSupport.js";

const SHA = "a".repeat(64);
const context: TriageAnalysisContext = { sha256: SHA };

const input = (overrides: Record<string, unknown> = {}) =>
  measureBinaryEntropyInputSchema.parse({
    path: "/artifacts/sample",
    ...overrides,
  });

/** Attach artifact identity and validate the complete report against its schema. */
const validate = (
  body: Omit<MeasureBinaryEntropyReport, "artifact">,
  bytes: number,
): MeasureBinaryEntropyReport =>
  measureBinaryEntropyReportSchema.parse({
    ...body,
    artifact: { path: "/artifacts/sample", sha256: SHA, bytes },
  });

const histogram = (values: readonly number[]): Uint32Array => {
  const counts = new Uint32Array(256);
  for (const value of values) counts[value] = (counts[value] as number) + 1;
  return counts;
};

describe("entropy histogram helpers", () => {
  it("reports zero entropy and the constant mean for one repeated byte", () => {
    const counts = histogram(Array.from({ length: 1000 }, () => 7));
    expect(entropyFromCounts(counts, 1000)).toBe(0);
    expect(meanFromCounts(counts, 1000)).toBe(7);
    expect(chiSquareFromCounts(counts, 1000)).toBeGreaterThan(0);
  });

  it("reports eight bits and zero chi-square for a uniform byte distribution", () => {
    const counts = histogram(
      Array.from({ length: 256 }, (_unused, index) => index),
    );
    expect(entropyFromCounts(counts, 256)).toBe(8);
    expect(chiSquareFromCounts(counts, 256)).toBe(0);
    expect(meanFromCounts(counts, 256)).toBe(127.5);
  });

  it("returns zero for an empty histogram", () => {
    const counts = new Uint32Array(256);
    expect(entropyFromCounts(counts, 0)).toBe(0);
    expect(chiSquareFromCounts(counts, 0)).toBe(0);
    expect(meanFromCounts(counts, 0)).toBe(0);
  });
});

describe("analyzeMeasureBinaryEntropy", () => {
  it("measures an all-zero file as a single low-entropy run", async () => {
    const bytes = Buffer.alloc(256 * 3);
    const report = await analyzeMeasureBinaryEntropy(
      bytes,
      input({ block_size: 256 }),
      context,
    );
    expect(report.file_entropy).toBe(0);
    expect(report.mean).toBe(0);
    expect(report.subject.format).toBe("file");
    expect(report.high_entropy_runs).toHaveLength(0);
    expect(report.low_entropy_runs).toEqual([
      { start: 0, end: 768, block_count: 3, mean_entropy: 0 },
    ]);
    expect(report.block_coverage).toEqual({
      total: 3,
      returned: 3,
      truncated: false,
    });
    expect(report.section_entropy).toEqual([]);
    expect(() => validate(report, bytes.length)).not.toThrow();
  });

  it("measures a uniform-byte file as a single high-entropy run", async () => {
    const bytes = Buffer.alloc(256 * 4);
    for (let index = 0; index < bytes.length; index += 1)
      bytes[index] = index % 256;
    const report = await analyzeMeasureBinaryEntropy(
      bytes,
      input({ block_size: 256 }),
      context,
    );
    expect(report.file_entropy).toBe(8);
    expect(report.file_chi_square).toBe(0);
    expect(report.mean).toBe(127.5);
    expect(report.low_entropy_runs).toHaveLength(0);
    expect(report.high_entropy_runs).toEqual([
      { start: 0, end: 1024, block_count: 4, mean_entropy: 8 },
    ]);
    expect(() => validate(report, bytes.length)).not.toThrow();
  });

  it("truncates the block grid at max_blocks while keeping whole-file entropy", async () => {
    const bytes = Buffer.alloc(256 * 5);
    const report = await analyzeMeasureBinaryEntropy(
      bytes,
      input({ block_size: 256, max_blocks: 2 }),
      context,
    );
    expect(report.file_entropy).toBe(0);
    expect(report.block_coverage).toEqual({
      total: 5,
      returned: 2,
      truncated: true,
    });
    expect(report.low_entropy_runs).toEqual([
      { start: 0, end: 512, block_count: 2, mean_entropy: 0 },
    ]);
    expect(
      report.limitations.some((note) => note.includes("max_blocks bound")),
    ).toBe(true);
    expect(() => validate(report, bytes.length)).not.toThrow();
  });

  it("handles an empty file without blocks or runs", async () => {
    const report = await analyzeMeasureBinaryEntropy(
      Buffer.alloc(0),
      input(),
      context,
    );
    expect(report.file_entropy).toBe(0);
    expect(report.block_coverage).toEqual({
      total: 0,
      returned: 0,
      truncated: false,
    });
    expect(report.high_entropy_runs).toHaveLength(0);
    expect(() => validate(report, 0)).not.toThrow();
  });

  it("profiles sections when the bytes parse as an executable image", async () => {
    const bytes = createRustImage({ format: "elf" });
    const report = await analyzeMeasureBinaryEntropy(bytes, input(), context);
    expect(report.subject.format).toBe("elf");
    expect(report.section_entropy.length).toBeGreaterThan(0);
    expect(report.section_coverage.returned).toBe(
      report.section_entropy.length,
    );
    for (const section of report.section_entropy) {
      expect(section.file_offset + section.size).toBeLessThanOrEqual(
        bytes.length,
      );
      expect(section.entropy).toBeGreaterThanOrEqual(0);
      expect(section.entropy).toBeLessThanOrEqual(8);
    }
    const parsed = validate(report, bytes.length);
    expect(parsed.subject.architecture).toBe("x86_64");
  });

  it("stops when the abort signal is already aborted", async () => {
    const controller = new AbortController();
    controller.abort();
    await expect(
      analyzeMeasureBinaryEntropy(
        Buffer.alloc(256 * 3),
        input({ block_size: 256 }),
        {
          sha256: SHA,
          signal: controller.signal,
        },
      ),
    ).rejects.toThrow();
  });
});

describe("measureBinaryEntropyInputSchema", () => {
  it("applies default block_size and max_blocks", () => {
    expect(input()).toMatchObject({ block_size: 4096, max_blocks: 4096 });
  });

  it("rejects a non power-of-two block size", () => {
    expect(() => input({ block_size: 1000 })).toThrow();
  });

  it("rejects a block size below the minimum", () => {
    expect(() => input({ block_size: 128 })).toThrow();
  });

  it("rejects a zero max_blocks", () => {
    expect(() => input({ max_blocks: 0 })).toThrow();
  });
});
