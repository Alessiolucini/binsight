import { describe, expect, it } from "vitest";
import {
  detectBinaryToolchainInputSchema,
  detectBinaryToolchainReportSchema,
  TOOLCHAIN_MATCH_LIMIT,
  type DetectBinaryToolchainReport,
} from "../domain/triage/detectBinaryToolchain.js";
import {
  aggregate,
  analyzeDetectBinaryToolchain,
  assessPacking,
  commentContributions,
  cooperativeFileEntropy,
  richContributions,
  sectionContributions,
} from "./DetectBinaryToolchain.js";
import type {
  ExecutableImage,
  ImageSection,
  PeRichHeader,
} from "../domain/native/image/executableImage.js";
import { createGoBinaryFixture } from "../../tests/fixtures/go/image.js";
import type { TriageAnalysisContext } from "./triageSupport.js";

const SHA = "a".repeat(64);
const context: TriageAnalysisContext = { sha256: SHA };

const input = (overrides: Record<string, unknown> = {}) =>
  detectBinaryToolchainInputSchema.parse({
    path: "/artifacts/sample",
    ...overrides,
  });

/** Attach artifact identity and validate the full report against its schema. */
const validate = (
  body: Omit<DetectBinaryToolchainReport, "artifact">,
  bytes: number,
): DetectBinaryToolchainReport =>
  detectBinaryToolchainReportSchema.parse({
    ...body,
    artifact: { path: "/artifacts/sample", sha256: SHA, bytes },
  });

const section = (overrides: Partial<ImageSection> = {}): ImageSection => ({
  index: 0,
  name: ".text",
  segment_name: null,
  type: null,
  file_offset: 0,
  file_size: 16,
  virtual_address: 0x1000n,
  virtual_size: 16n,
  raw_flags: 0,
  readable: true,
  writable: false,
  executable: true,
  ...overrides,
});

const image = (overrides: Partial<ExecutableImage> = {}): ExecutableImage => ({
  format: "pe",
  bits: 64,
  byte_order: "little",
  architecture: "x86_64",
  machine: 0x8664,
  machine_name: "AMD64",
  image_offset: 0,
  image_size: 0x10000,
  entry_point: { virtual_address: 0x1000n, file_offset: 0, section_index: 0 },
  sections: [section()],
  segments: [],
  imports: [],
  exports: [],
  libraries: [],
  symbols: [],
  coverage: { imports: "complete", exports: "complete", symbols: "complete" },
  overlay: null,
  container: { kind: "thin" },
  diagnostics: [],
  elf: null,
  pe: null,
  macho: null,
  ...overrides,
});

describe("cooperativeFileEntropy", () => {
  it("is zero for one repeated byte and eight for a uniform distribution", async () => {
    expect(await cooperativeFileEntropy(Buffer.alloc(4096), context)).toBe(0);
    const uniform = Buffer.from(
      Array.from({ length: 2560 }, (_u, i) => i % 256),
    );
    expect(await cooperativeFileEntropy(uniform, context)).toBe(8);
  });
});

describe("sectionContributions", () => {
  it("matches UPX packer sections by prefix with a located reason", () => {
    const found = sectionContributions(
      image({
        sections: [
          section({ index: 0, name: "UPX0", writable: true }),
          section({ index: 1, name: "UPX1", file_offset: 0x1000 }),
          section({ index: 2, name: ".text", file_offset: 0x2000 }),
        ],
      }),
    );
    expect(found.map((c) => c.id)).toEqual(["upx", "upx"]);
    expect(found[0]?.category).toBe("packer");
    expect(found[0]?.match.location?.file_offset).toBe(0);
    expect(found[1]?.match.location?.file_offset).toBe(0x1000);
  });

  it("matches a Themida exact section name", () => {
    const found = sectionContributions(
      image({ sections: [section({ name: ".themida" })] }),
    );
    expect(found[0]?.id).toBe("themida");
    expect(found[0]?.category).toBe("protector");
  });
});

describe("richContributions", () => {
  const rich = (overrides: Partial<PeRichHeader> = {}): PeRichHeader => ({
    offset: 0x80,
    end_offset: 0x120,
    xor_key: 0x1234,
    entries: [
      { product_id: 259, build: 25930, count: 18 },
      { product_id: 1, build: 0, count: 96 },
    ],
    checksum_valid: true,
    clear_bytes: Buffer.alloc(0),
    ...overrides,
  });

  it("emits a high-confidence MSVC indicator from a valid Rich header", () => {
    const found = richContributions(image(), rich());
    expect(found.every((c) => c.id === "msvc")).toBe(true);
    expect(found[0]?.confidence).toBe("high");
    expect(found[0]?.match.location?.file_offset).toBe(0x80);
    expect(found.some((c) => c.match.reason.includes("build 25930"))).toBe(
      true,
    );
    expect(
      found.some((c) =>
        c.match.reason.includes("imported object (legacy import record)"),
      ),
    ).toBe(true);
  });

  it("drops confidence to medium when the checksum does not validate", () => {
    const found = richContributions(image(), rich({ checksum_valid: false }));
    expect(found[0]?.confidence).toBe("medium");
    expect(found[0]?.match.reason).toContain("checksum mismatch");
  });
});

describe("commentContributions", () => {
  it("recovers GCC and Clang banners from the ELF .comment", () => {
    const found = commentContributions([
      "GCC: (Debian 14.2.0-19) 14.2.0",
      "clang version 18.1.3",
      "unrelated note",
    ]);
    expect(found.map((c) => c.id)).toEqual(["gcc", "clang"]);
    expect(found[0]?.match.reason).toContain("14.2.0");
    expect(found[0]?.match.location).toBeNull();
  });
});

describe("aggregate", () => {
  it("merges contributions per id, keeping the strongest confidence", () => {
    const { indicators } = aggregate([
      {
        id: "upx",
        name: "UPX",
        category: "packer",
        confidence: "medium",
        match: { reason: "a", location: null },
      },
      {
        id: "upx",
        name: "UPX",
        category: "packer",
        confidence: "high",
        match: { reason: "b", location: null },
      },
      {
        id: "go",
        name: "Go",
        category: "language",
        confidence: "high",
        match: { reason: "c", location: null },
      },
    ]);
    const upx = indicators.find((i) => i.id === "upx");
    expect(upx?.confidence).toBe("high");
    expect(upx?.matches).toHaveLength(2);
    expect(indicators[0]?.evidence_kind).toBe("inferred");
  });

  it("bounds per-indicator matches and records truncation in coverage", () => {
    const many = Array.from({ length: TOOLCHAIN_MATCH_LIMIT + 5 }, (_u, i) => ({
      id: "msvc",
      name: "MSVC",
      category: "compiler" as const,
      confidence: "high" as const,
      match: { reason: `entry ${i}`, location: null },
    }));
    const { indicators } = aggregate(many);
    const msvc = indicators[0];
    expect(msvc?.matches).toHaveLength(TOOLCHAIN_MATCH_LIMIT);
    expect(msvc?.match_coverage).toEqual({
      total: TOOLCHAIN_MATCH_LIMIT + 5,
      returned: TOOLCHAIN_MATCH_LIMIT,
      truncated: true,
    });
  });
});

describe("assessPacking", () => {
  it("reports likely_packed when a packer indicator is present", () => {
    const packed = assessPacking(image(), Buffer.alloc(32), 3.1, [
      {
        id: "upx",
        name: "UPX",
        category: "packer",
        confidence: "high",
        evidence_kind: "inferred",
        matches: [{ reason: "x", location: null }],
        match_coverage: { total: 1, returned: 1, truncated: false },
      },
    ]);
    expect(packed.status).toBe("likely_packed");
    expect(packed.reasons[0]).toContain("UPX");
  });

  it("reports not_observed for ordinary low-entropy compiler output", () => {
    const packed = assessPacking(image(), Buffer.alloc(32), 3.0, []);
    expect(packed.status).toBe("not_observed");
    expect(packed.entry_point_section?.name).toBe(".text");
  });

  it("infers packing from a writable entry section with high entropy", () => {
    const img = image({
      entry_point: {
        virtual_address: 0x1000n,
        file_offset: 0,
        section_index: 0,
      },
      sections: [section({ name: "UPX1", writable: true, executable: true })],
    });
    const packed = assessPacking(img, Buffer.alloc(32), 7.1, []);
    expect(packed.status).toBe("likely_packed");
    expect(packed.entry_point_section?.writable).toBe(true);
  });

  it("is unknown for a non-image file and notes high entropy", () => {
    const packed = assessPacking(null, Buffer.alloc(32), 7.95, []);
    expect(packed.status).toBe("unknown");
    expect(packed.entry_point_section).toBeNull();
    expect(packed.reasons.some((r) => r.includes("very high"))).toBe(true);
  });
});

describe("analyzeDetectBinaryToolchain", () => {
  it("identifies Go from a parseable Go ELF image", async () => {
    const { bytes } = createGoBinaryFixture({ format: "elf" });
    const report = await analyzeDetectBinaryToolchain(bytes, input(), context);
    expect(report.subject.format).toBe("elf");
    const go = report.indicators.find((i) => i.id === "go");
    expect(go?.category).toBe("language");
    expect(go?.confidence).toBe("high");
    expect(() => validate(report, bytes.length)).not.toThrow();
  });

  it("finds content markers in a non-image file and flags packing from UPX", async () => {
    const bytes = Buffer.concat([
      Buffer.from("....Nullsoft Install System v3.08...."),
      Buffer.from("padding"),
      Buffer.from("UPX!"),
      Buffer.alloc(64),
    ]);
    const report = await analyzeDetectBinaryToolchain(bytes, input(), context);
    expect(report.subject.format).toBe("file");
    expect(report.indicators.map((i) => i.id).sort()).toEqual(["nsis", "upx"]);
    expect(report.packed_indicator.status).toBe("likely_packed");
    expect(report.packed_indicator.entry_point_section).toBeNull();
    expect(() => validate(report, bytes.length)).not.toThrow();
  });

  it("reports no indicators and unknown packing for an unrecognized file", async () => {
    const bytes = Buffer.alloc(2048);
    const report = await analyzeDetectBinaryToolchain(bytes, input(), context);
    expect(report.indicators).toEqual([]);
    expect(report.indicator_coverage).toEqual({
      total: 0,
      returned: 0,
      truncated: false,
    });
    expect(report.packed_indicator.status).toBe("unknown");
    expect(report.packed_indicator.file_entropy).toBe(0);
    expect(() => validate(report, bytes.length)).not.toThrow();
  });
});
