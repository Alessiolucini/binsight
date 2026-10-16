import { describe, expect, it } from "vitest";
import {
  extractBinaryStringsInputSchema,
  extractBinaryStringsReportSchema,
  type ExtractBinaryStringsReport,
  type ExtractedString,
  type StringTag,
} from "../domain/triage/extractBinaryStrings.js";
import { analyzeExtractBinaryStrings } from "./ExtractBinaryStrings.js";
import { MAX_STRING_CHARS } from "./ExtractBinaryStringsScan.js";
import { TriageAnalysisFailure } from "./triageSupport.js";

const SHA = "a".repeat(64);

/** Parse defaults, run the analyzer, and return a schema-validated full report. */
const run = async (
  bytes: Buffer,
  overrides: Record<string, unknown> = {},
): Promise<ExtractBinaryStringsReport> => {
  const input = extractBinaryStringsInputSchema.parse({
    path: "/artifacts/sample",
    ...overrides,
  });
  const body = await analyzeExtractBinaryStrings(bytes, input, { sha256: SHA });
  const report = {
    ...body,
    artifact: { path: "/artifacts/sample", sha256: SHA, bytes: bytes.length },
  };
  return extractBinaryStringsReportSchema.parse(report);
};

/** Join ASCII parts with NUL separators so each becomes its own run. */
const asciiBlob = (...parts: readonly string[]): Buffer =>
  Buffer.from(parts.join("\0"), "latin1");

const utf16leBuffer = (text: string): Buffer => Buffer.from(text, "utf16le");

const tagsByText = (
  strings: readonly ExtractedString[],
): Map<string, StringTag[]> =>
  new Map(strings.map((entry) => [entry.text, entry.tags]));

describe("analyzeExtractBinaryStrings", () => {
  it("recovers ASCII runs and honors min_length", async () => {
    const report = await run(asciiBlob("abcd", "abcde", "longenough"), {
      encodings: ["ascii"],
    });
    const texts = report.strings.map((entry) => entry.text);
    expect(texts).toContain("abcde");
    expect(texts).toContain("longenough");
    expect(texts).not.toContain("abcd");
    expect(report.subject.format).toBe("file");
    expect(report.strings.every((entry) => entry.section === null)).toBe(true);
    expect(report.strings.every((entry) => entry.encoding === "ascii")).toBe(
      true,
    );
  });

  it("recovers UTF-16LE runs", async () => {
    const bytes = Buffer.concat([
      Buffer.from([0x01, 0x02, 0x03]),
      utf16leBuffer("WideHello"),
      Buffer.from([0xff, 0xfe]),
    ]);
    const report = await run(bytes, { encodings: ["utf16le"], min_length: 5 });
    const wide = report.strings.find((entry) => entry.text === "WideHello");
    expect(wide).toBeDefined();
    expect(wide?.encoding).toBe("utf16le");
    expect(wide?.length).toBe(9);
  });

  it("recovers multi-byte UTF-8 runs without duplicating ASCII", async () => {
    const bytes = Buffer.from("café_déjà_vu_日本語", "utf8");
    const report = await run(bytes, {
      encodings: ["ascii", "utf8"],
      min_length: 5,
    });
    const utf8 = report.strings.filter((entry) => entry.encoding === "utf8");
    expect(utf8.map((entry) => entry.text)).toContain("café_déjà_vu_日本語");
    expect(report.strings.some((entry) => entry.encoding === "ascii")).toBe(
      false,
    );
  });
});

describe("analyzeExtractBinaryStrings tagging", () => {
  it("tags observed strings with inferred classifications", async () => {
    const samples = [
      "https://example.com/a/b",
      "connect 192.168.1.1 now",
      "addr fe80::1ff:fe23:4567:890a",
      "user@mail.example.org",
      "C:\\Windows\\System32\\cmd.exe",
      "/usr/local/bin/tool",
      "HKLM\\Software\\Microsoft\\Windows",
      "{01234567-89ab-cdef-0123-456789abcdef}",
      "TWFuIGlzIGRpc3Rpbmd1aXNoZWQgZnJvbWFsbA==",
      "-----BEGIN CERTIFICATE-----",
      "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdef29f8",
      "Mozilla/5.0 (Windows NT 10.0)",
      "format value=%d name=%s here",
      "SELECT id FROM users WHERE x=1",
      "download.microsoft.com",
    ];
    const report = await run(asciiBlob(...samples), { encodings: ["ascii"] });
    const tags = tagsByText(report.strings);
    expect(tags.get("https://example.com/a/b")).toContain("url");
    expect(tags.get("connect 192.168.1.1 now")).toContain("ipv4");
    expect(tags.get("addr fe80::1ff:fe23:4567:890a")).toContain("ipv6");
    expect(tags.get("user@mail.example.org")).toContain("email");
    expect(tags.get("C:\\Windows\\System32\\cmd.exe")).toContain(
      "path_windows",
    );
    expect(tags.get("/usr/local/bin/tool")).toContain("path_posix");
    expect(tags.get("HKLM\\Software\\Microsoft\\Windows")).toContain(
      "registry_key",
    );
    expect(tags.get("{01234567-89ab-cdef-0123-456789abcdef}")).toContain(
      "guid",
    );
    expect(tags.get("TWFuIGlzIGRpc3Rpbmd1aXNoZWQgZnJvbWFsbA==")).toContain(
      "base64_blob",
    );
    expect(tags.get("-----BEGIN CERTIFICATE-----")).toContain("pem");
    expect(
      tags.get("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdef29f8"),
    ).toContain("jwt");
    expect(tags.get("Mozilla/5.0 (Windows NT 10.0)")).toContain("user_agent");
    expect(tags.get("format value=%d name=%s here")).toContain("format_string");
    expect(tags.get("SELECT id FROM users WHERE x=1")).toContain("sql");
    expect(tags.get("download.microsoft.com")).toContain("domain");
  });

  it("summarizes tags across the returned strings", async () => {
    const report = await run(
      asciiBlob("https://a.example.com", "https://b.example.net"),
      { encodings: ["ascii"] },
    );
    expect(report.tag_summary.url).toBe(2);
    expect(report.tag_summary.domain).toBe(2);
    expect(report.tag_summary.sql).toBeUndefined();
  });

  it("filters to requested tag categories", async () => {
    const report = await run(
      asciiBlob("plain text no tags here", "visit https://tagged.example.com"),
      { encodings: ["ascii"], categories: ["url"] },
    );
    expect(report.strings).toHaveLength(1);
    expect(report.strings[0]?.text).toContain("https://tagged.example.com");
    expect(report.string_coverage.total).toBe(1);
    expect(report.categories).toEqual(["url"]);
  });

  it("truncates to max_strings and reports coverage", async () => {
    const parts = Array.from(
      { length: 20 },
      (_, index) => `string_${index}_xx`,
    );
    const report = await run(asciiBlob(...parts), {
      encodings: ["ascii"],
      max_strings: 5,
    });
    expect(report.strings).toHaveLength(5);
    expect(report.string_coverage.total).toBe(20);
    expect(report.string_coverage.returned).toBe(5);
    expect(report.string_coverage.truncated).toBe(true);
  });

  it("refuses when returned text exceeds max_total_bytes", async () => {
    const parts = Array.from(
      { length: 60 },
      (_, index) => `padding_string_entry_number_${index}_abcdefghij`,
    );
    let caught: unknown;
    try {
      await run(asciiBlob(...parts), {
        encodings: ["ascii"],
        max_strings: 2000,
        max_total_bytes: 1024,
      });
    } catch (error: unknown) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(TriageAnalysisFailure);
    expect((caught as TriageAnalysisFailure).kind).toBe("resource");
  });

  it("deduplicates requested encodings in the report", async () => {
    const report = await run(asciiBlob("hello world"), {
      encodings: ["ascii", "ascii"],
    });
    expect(report.encodings).toEqual(["ascii"]);
  });

  it("caps an over-long run's text while preserving its true length", async () => {
    const giant = "A".repeat(MAX_STRING_CHARS + 500);
    const report = await run(Buffer.from(giant, "latin1"), {
      encodings: ["ascii"],
    });
    const entry = report.strings[0];
    expect(entry?.length).toBe(MAX_STRING_CHARS + 500);
    expect(entry?.text.length).toBe(MAX_STRING_CHARS);
  });

  it("attributes strings to the containing ELF section", async () => {
    const marker = "SECTIONMARKERSTRINGABC";
    const report = await run(buildElfWithRodata(marker), {
      encodings: ["ascii"],
    });
    expect(report.subject.format).toBe("elf");
    const entry = report.strings.find((item) => item.text === marker);
    expect(entry?.section).toBe(".rodata");
  });
});

const RODATA_OFF = 0x100;
const SHSTR_OFF = 0x200;
const SHOFF = 0x280;
const ELF_TOTAL = 0x400;
const SHSTR = "\0.rodata\0.shstrtab\0";

const writeShdr = (
  buf: Buffer,
  index: number,
  fields: readonly [number, number, bigint, bigint, number, number],
): void => {
  const base = SHOFF + index * 64;
  const [name, type, flags, addr, offset, size] = fields;
  buf.writeUInt32LE(name, base);
  buf.writeUInt32LE(type, base + 4);
  buf.writeBigUInt64LE(flags, base + 8);
  buf.writeBigUInt64LE(addr, base + 16);
  buf.writeBigUInt64LE(BigInt(offset), base + 24);
  buf.writeBigUInt64LE(BigInt(size), base + 32);
};

/** A minimal ELF64 LE image with one file-backed `.rodata` section holding `marker`. */
const buildElfWithRodata = (marker: string): Buffer => {
  const buf = Buffer.alloc(ELF_TOTAL);
  buf.writeUInt32BE(0x7f454c46, 0);
  buf[4] = 2; // ELFCLASS64
  buf[5] = 1; // little-endian
  buf[6] = 1;
  buf.writeUInt16LE(2, 16); // e_type EXEC
  buf.writeUInt16LE(62, 18); // e_machine x86_64
  buf.writeUInt32LE(1, 20);
  buf.writeBigUInt64LE(0x401000n, 24); // e_entry
  buf.writeBigUInt64LE(BigInt(SHOFF), 40); // e_shoff
  buf.writeUInt16LE(64, 52); // e_ehsize
  buf.writeUInt16LE(64, 58); // e_shentsize
  buf.writeUInt16LE(3, 60); // e_shnum
  buf.writeUInt16LE(2, 62); // e_shstrndx
  buf.write(marker, RODATA_OFF, "latin1");
  buf.write(SHSTR, SHSTR_OFF, "latin1");
  writeShdr(buf, 0, [0, 0, 0n, 0n, 0, 0]);
  writeShdr(buf, 1, [1, 1, 0x2n, 0x401100n, RODATA_OFF, marker.length]);
  writeShdr(buf, 2, [9, 3, 0n, 0n, SHSTR_OFF, SHSTR.length]);
  return buf;
};
