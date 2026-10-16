import { describe, expect, it } from "vitest";
import { analyzeIdentifyCryptoConstants } from "./IdentifyCryptoConstants.js";
import {
  AES_SBOX,
  BASE64_STD_ALPHABET,
} from "../domain/triage/cryptoSignatures.js";
import { identifyCryptoConstantsReportSchema } from "../domain/triage/identifyCryptoConstants.js";
import type { IdentifyCryptoConstantsReport } from "../domain/triage/identifyCryptoConstants.js";

const SHA256 =
  "0000000000000000000000000000000000000000000000000000000000000000";

const run = async (
  bytes: Buffer,
): Promise<Omit<IdentifyCryptoConstantsReport, "artifact">> =>
  analyzeIdentifyCryptoConstants(
    bytes,
    { path: "/artifacts/sample" },
    {
      sha256: SHA256,
    },
  );

/** Validate the complete report, as the provider assembles it with artifact identity. */
const validate = (
  body: Omit<IdentifyCryptoConstantsReport, "artifact">,
  bytes: Buffer,
): IdentifyCryptoConstantsReport =>
  identifyCryptoConstantsReportSchema.parse({
    ...body,
    artifact: {
      path: "/artifacts/sample",
      sha256: SHA256,
      bytes: bytes.length,
    },
  });

const wordsLe = (words: readonly number[]): Buffer => {
  const buffer = Buffer.alloc(words.length * 4);
  words.forEach((word, index) => buffer.writeUInt32LE(word >>> 0, index * 4));
  return buffer;
};

const wordsBe = (words: readonly number[]): Buffer => {
  const buffer = Buffer.alloc(words.length * 4);
  words.forEach((word, index) => buffer.writeUInt32BE(word >>> 0, index * 4));
  return buffer;
};

/** Embed `payload` at `offset` inside a NUL-filled buffer of `size` bytes. */
const embed = (payload: Buffer, offset: number, size: number): Buffer => {
  const buffer = Buffer.alloc(size);
  payload.copy(buffer, offset);
  return buffer;
};

const SHA256_H = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
  0x1f83d9ab, 0x5be0cd19,
];
const MD5_INIT = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];

describe("analyzeIdentifyCryptoConstants", () => {
  it("locates the AES S-box as a byte-order-independent sbox finding", async () => {
    const bytes = embed(Buffer.from(AES_SBOX), 128, 512);
    const report = await run(bytes);
    const sbox = report.findings.find((f) => f.algorithm === "AES");
    expect(sbox).toMatchObject({
      kind: "sbox",
      evidence_kind: "inferred",
      file_offset: 128,
      byte_order: "any",
      length: 256,
      section: null,
    });
    validate(report, bytes);
  });

  it("locates a little-endian SHA-256 init vector with byte_order le", async () => {
    const bytes = embed(wordsLe(SHA256_H), 64, 256);
    const report = await run(bytes);
    const finding = report.findings.find(
      (f) => f.algorithm === "SHA-256 (init)",
    );
    expect(finding).toMatchObject({ byte_order: "le", kind: "iv", length: 32 });
  });

  it("locates a big-endian SHA-256 init vector with byte_order be", async () => {
    const bytes = embed(wordsBe(SHA256_H), 64, 256);
    const report = await run(bytes);
    const finding = report.findings.find(
      (f) => f.algorithm === "SHA-256 (init)",
    );
    expect(finding?.byte_order).toBe("be");
  });

  it("matches the first SHA-256 K words as a prefix anchor", async () => {
    const k8 = [
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
      0x923f82a4, 0xab1c5ed5,
    ];
    const report = await run(embed(wordsLe(k8), 0, 64));
    expect(
      report.findings.some(
        (f) => f.algorithm === "SHA-256 (round constants K)",
      ),
    ).toBe(true);
  });

  it("locates MD5 init words and the ChaCha sigma string", async () => {
    const parts = Buffer.concat([
      wordsLe(MD5_INIT),
      Buffer.from("expand 32-byte k", "latin1"),
    ]);
    const report = await run(embed(parts, 32, 256));
    const algorithms = report.findings.map((f) => f.algorithm);
    expect(algorithms).toContain("MD5 (init)");
    expect(algorithms).toContain("ChaCha/Salsa20 (sigma)");
  });

  it("locates the CRC-32 polynomial magic in both byte orders", async () => {
    const both = Buffer.concat([wordsLe([0xedb88320]), wordsBe([0xedb88320])]);
    const report = await run(embed(both, 16, 128));
    const orders = report.findings
      .filter((f) => f.algorithm === "CRC-32 (polynomial 0xEDB88320)")
      .map((f) => f.byte_order)
      .sort();
    expect(orders).toEqual(["be", "le"]);
  });

  it("locates the secp256k1 field prime as a curve parameter", async () => {
    const prime = Buffer.from(
      "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
      "hex",
    );
    const report = await run(embed(prime, 48, 256));
    expect(
      report.findings.find((f) => f.algorithm === "secp256k1 (field prime)"),
    ).toMatchObject({ kind: "curve_param", byte_order: "be", length: 32 });
  });

  it("detects the standard Base64 alphabet", async () => {
    const report = await run(
      embed(Buffer.from(BASE64_STD_ALPHABET, "latin1"), 10, 256),
    );
    expect(
      report.findings.some((f) => f.algorithm === "Base64 (standard alphabet)"),
    ).toBe(true);
  });

  it("flags a custom 64-unique-printable run without duplicating a known alphabet", async () => {
    const custom =
      "0123456789+/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    expect(new Set(custom).size).toBe(64);
    const report = await run(embed(Buffer.from(custom, "latin1"), 20, 256));
    const base64 = report.findings.filter((f) =>
      f.algorithm.startsWith("Base64"),
    );
    expect(base64.some((f) => f.algorithm === "Base64 (custom alphabet)")).toBe(
      true,
    );
    // The standard alphabet must not also be reported at the same offset.
    expect(base64.filter((f) => f.file_offset === 20).length).toBe(1);
  });

  it("reports no findings and consistent coverage for random-free zero bytes", async () => {
    const report = await run(Buffer.alloc(4096));
    expect(report.findings).toHaveLength(0);
    expect(report.finding_coverage).toEqual({
      total: 0,
      returned: 0,
      truncated: false,
    });
    expect(report.algorithm_summary).toHaveLength(0);
  });

  it("marks a non-executable file subject and keeps sections null", async () => {
    const bytes = embed(Buffer.from(AES_SBOX), 0, 300);
    const report = await run(bytes);
    expect(report.subject).toEqual({ format: "file", architecture: null });
    expect(report.findings.every((f) => f.section === null)).toBe(true);
  });

  it("produces findings sorted by file offset with a summary that sums to the total", async () => {
    const bytes = Buffer.alloc(1024);
    Buffer.from("expand 32-byte k", "latin1").copy(bytes, 600);
    Buffer.from(AES_SBOX).copy(bytes, 100);
    const report = await run(bytes);
    const offsets = report.findings.map((f) => f.file_offset);
    expect(offsets).toEqual([...offsets].sort((a, b) => a - b));
    const summed = report.algorithm_summary.reduce((t, e) => t + e.count, 0);
    expect(summed).toBe(report.findings.length);
    validate(report, bytes);
  });
});
