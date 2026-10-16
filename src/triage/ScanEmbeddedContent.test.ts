import { gzipSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import {
  SCAN_ENTROPY_WINDOW_DEFAULT,
  SCAN_MAX_FINDINGS_DEFAULT,
  scanEmbeddedContentReportSchema,
} from "../domain/triage/scanEmbeddedContent.js";
import type {
  EmbeddedFinding,
  ScanEmbeddedContentInput,
} from "../domain/triage/scanEmbeddedContent.js";
import { analyzeScanEmbeddedContent } from "./ScanEmbeddedContent.js";
import type { TriageAnalysisContext } from "./triageSupport.js";

const CONTEXT: TriageAnalysisContext = {
  signal: undefined,
  sha256: "0".repeat(64),
};

const input = (
  over: Partial<ScanEmbeddedContentInput> = {},
): ScanEmbeddedContentInput => ({
  path: "/artifacts/sample",
  max_findings: SCAN_MAX_FINDINGS_DEFAULT,
  entropy_window: SCAN_ENTROPY_WINDOW_DEFAULT,
  ...over,
});

/** Run the analyzer and validate the full report shape via its schema. */
const run = async (
  bytes: Buffer,
  over: Partial<ScanEmbeddedContentInput> = {},
): Promise<EmbeddedFinding[]> => {
  const body = await analyzeScanEmbeddedContent(bytes, input(over), CONTEXT);
  const report = {
    ...body,
    artifact: {
      path: "/artifacts/sample",
      sha256: "0".repeat(64),
      bytes: bytes.length,
    },
  };
  scanEmbeddedContentReportSchema.parse(report);
  return body.findings;
};

const findAt = (
  findings: EmbeddedFinding[],
  type: string,
  offset: number,
): EmbeddedFinding | undefined =>
  findings.find((f) => f.type === type && f.file_offset === offset);

const elf64 = (): Buffer => {
  const b = Buffer.alloc(0x40);
  b.set([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01], 0);
  b.writeUInt16LE(2, 16); // e_type EXEC
  b.writeUInt16LE(0x3e, 18); // x86-64
  return b;
};

const minimalPe = (): Buffer => {
  const peOff = 0x40;
  const optStart = peOff + 24;
  const optSize = 0xf0;
  const b = Buffer.alloc(optStart + optSize);
  b.writeUInt16LE(0x5a4d, 0); // MZ
  b.writeUInt32LE(peOff, 0x3c); // e_lfanew
  b.writeUInt32BE(0x50_45_00_00, peOff); // PE\0\0
  b.writeUInt16LE(0x8664, peOff + 4); // machine x86-64
  b.writeUInt16LE(0, peOff + 6); // section count
  b.writeUInt16LE(optSize, peOff + 20);
  b.writeUInt16LE(0x20b, optStart); // PE32+
  return b;
};

const storedZip = (): Buffer => {
  const name = Buffer.from("a");
  const data = Buffer.from("hi");
  const local = Buffer.alloc(30);
  local.set([0x50, 0x4b, 0x03, 0x04], 0);
  local.writeUInt16LE(20, 4);
  local.writeUInt32LE(2, 18); // compressed size
  local.writeUInt32LE(2, 22); // uncompressed size
  local.writeUInt16LE(1, 26); // name length
  const localPart = Buffer.concat([local, name, data]);
  const central = Buffer.alloc(46);
  central.set([0x50, 0x4b, 0x01, 0x02], 0);
  central.writeUInt32LE(2, 20);
  central.writeUInt32LE(2, 24);
  central.writeUInt16LE(1, 28); // name length
  const centralPart = Buffer.concat([central, name]);
  const eocd = Buffer.alloc(22);
  eocd.set([0x50, 0x4b, 0x05, 0x06], 0);
  eocd.writeUInt16LE(1, 8);
  eocd.writeUInt16LE(1, 10);
  eocd.writeUInt32LE(centralPart.length, 12);
  eocd.writeUInt32LE(localPart.length, 16);
  return Buffer.concat([localPart, centralPart, eocd]);
};

const png = (): Buffer => {
  const sig = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const ihdr = Buffer.alloc(12 + 13);
  ihdr.writeUInt32BE(13, 0);
  ihdr.write("IHDR", 4, "latin1");
  const iend = Buffer.alloc(12);
  iend.writeUInt32BE(0, 0);
  iend.write("IEND", 4, "latin1");
  return Buffer.concat([sig, ihdr, iend]);
};

const fatMacho = (): Buffer => {
  const b = Buffer.alloc(8 + 20);
  b.writeUInt32BE(0xcafe_babe, 0);
  b.writeUInt32BE(1, 4); // nfat_arch
  b.writeUInt32BE(0x0100_0007, 8); // cputype x86_64
  b.writeUInt32BE(0, 12); // cpusubtype
  b.writeUInt32BE(28, 16); // offset
  b.writeUInt32BE(0, 20); // size
  return b;
};

const javaClass = (): Buffer => {
  const b = Buffer.alloc(16);
  b.writeUInt32BE(0xcafe_babe, 0);
  b.writeUInt16BE(0, 4); // minor
  b.writeUInt16BE(52, 6); // major (Java 8)
  b.writeUInt16BE(5, 8); // constant pool count
  return b;
};

describe("analyzeScanEmbeddedContent", () => {
  it("identifies a thin ELF image and derives its size", async () => {
    const findings = await run(elf64());
    const elf = findAt(findings, "elf", 0);
    expect(elf?.validated).toBe(true);
    expect(elf?.size).toBe(0x40);
    expect(elf?.confidence).toBe("high");
  });

  it("identifies a PE image by its PE header, not the bare MZ", async () => {
    const pe = findAt(await run(minimalPe()), "pe", 0);
    expect(pe?.validated).toBe(true);
    expect(pe?.description).toContain("machine 0x8664");
  });

  it("does not report a stray MZ without a PE header", async () => {
    const b = Buffer.alloc(4096);
    b.writeUInt16LE(0x5a4d, 100); // MZ with no reachable PE header
    expect(findAt(await run(b), "pe", 100)).toBeUndefined();
  });

  it("collapses a well-formed ZIP into one archive finding", async () => {
    const zip = storedZip();
    const findings = await run(zip);
    const archive = findAt(findings, "zip", 0);
    expect(archive?.validated).toBe(true);
    expect(archive?.size).toBe(zip.length);
    expect(
      findings.filter((f) => f.type === "zip_central_directory"),
    ).toHaveLength(0);
  });

  it("validates gzip via a bounded deflate probe", async () => {
    const member = gzipSync(Buffer.from("hello embedded world".repeat(8)));
    const gz = findAt(await run(member), "gzip", 0);
    expect(gz?.validated).toBe(true);
    expect(gz?.confidence).toBe("high");
  });

  it("walks PNG chunks to IEND for the size", async () => {
    const image = png();
    expect(findAt(await run(image), "png", 0)?.size).toBe(image.length);
  });

  it("locates content at non-zero offsets and maps a padding run", async () => {
    const pad = Buffer.alloc(2048); // zero padding, above the run threshold
    const blob = Buffer.concat([
      pad,
      elf64(),
      gzipSync(Buffer.from("x".repeat(64))),
    ]);
    const body = await analyzeScanEmbeddedContent(blob, input(), CONTEXT);
    expect(findAt(body.findings, "elf", 2048)).toBeDefined();
    expect(findAt(body.findings, "gzip", 2048 + 0x40)).toBeDefined();
    expect(
      body.padding_runs.some(
        (r) => r.byte === "00" && r.start === 0 && r.end === 2048,
      ),
    ).toBe(true);
  });

  it("disambiguates universal Mach-O from a Java class at CA FE BA BE", async () => {
    const fat = await run(fatMacho());
    expect(findAt(fat, "macho_fat", 0)?.validated).toBe(true);
    expect(findAt(fat, "java_class", 0)).toBeUndefined();

    const java = await run(javaClass());
    expect(findAt(java, "java_class", 0)?.validated).toBe(true);
    expect(findAt(java, "macho_fat", 0)).toBeUndefined();
  });

  it("reports an entropy profile and marks random data high entropy", async () => {
    const random = Buffer.from(
      Array.from({ length: 16384 }, (_v, i) => (i * 2654435761) & 0xff),
    );
    const body = await analyzeScanEmbeddedContent(random, input(), CONTEXT);
    expect(body.entropy_profile.length).toBeGreaterThan(0);
    const max = Math.max(...body.entropy_profile.map((p) => p.entropy));
    expect(max).toBeGreaterThan(7);
  });

  it("reports subject as a plain file for non-executable content", async () => {
    const body = await analyzeScanEmbeddedContent(
      storedZip(),
      input(),
      CONTEXT,
    );
    expect(body.subject.format).toBe("file");
    expect(body.limitations.length).toBeGreaterThan(0);
  });

  it("honors max_findings with truncation coverage", async () => {
    const parts = Array.from({ length: 5 }, () => elf64());
    const blob = Buffer.concat(parts);
    const body = await analyzeScanEmbeddedContent(
      blob,
      input({ max_findings: 2 }),
      CONTEXT,
    );
    expect(body.findings.length).toBeLessThanOrEqual(2);
    expect(body.findings_coverage.truncated).toBe(true);
    expect(body.findings_coverage.total).toBeGreaterThanOrEqual(5);
  });

  it("widens the entropy window so the profile stays bounded", async () => {
    const big = Buffer.alloc(8192 * 2000, 0x41);
    const body = await analyzeScanEmbeddedContent(
      big,
      input({ entropy_window: 8192 }),
      CONTEXT,
    );
    expect(body.entropy_profile.length).toBeLessThanOrEqual(1024);
    expect(body.entropy_window).toBeGreaterThan(8192);
  });
});
