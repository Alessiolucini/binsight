import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createRustImage } from "../../tests/fixtures/rust/image.js";
import {
  inspectExecutableInputSchema,
  inspectExecutableReportSchema,
  type InspectExecutableInput,
} from "../domain/triage/inspectExecutable.js";
import { analyzeInspectExecutable } from "./InspectExecutable.js";
import type { TriageAnalysisContext } from "./triageSupport.js";

const DYNSTR = "\0libc.so.6\0mylib.so.1\0printf\0add\0";
const SHSTR = "\0.text\0.dynsym\0.dynstr\0.dynamic\0.shstrtab\0.bss\0";
const PHOFF = 64;
const DYNSTR_OFF = 0x100;
const DYNSYM_OFF = 0x140;
const DYN_OFF = 0x200;
const SHSTR_OFF = 0x300;
const SHOFF = 0x400;
const TOTAL = 0x600;

const writeShdr = (
  buf: Buffer,
  index: number,
  fields: readonly [
    number,
    number,
    bigint,
    bigint,
    number,
    number,
    number,
    number,
  ],
): void => {
  const base = SHOFF + index * 64;
  const [name, type, flags, addr, offset, size, link, entsize] = fields;
  buf.writeUInt32LE(name, base);
  buf.writeUInt32LE(type, base + 4);
  buf.writeBigUInt64LE(flags, base + 8);
  buf.writeBigUInt64LE(addr, base + 16);
  buf.writeBigUInt64LE(BigInt(offset), base + 24);
  buf.writeBigUInt64LE(BigInt(size), base + 32);
  buf.writeUInt32LE(link, base + 40);
  buf.writeBigUInt64LE(BigInt(entsize), base + 56);
};

const writeSym = (
  buf: Buffer,
  index: number,
  fields: readonly [number, number, number, bigint, bigint],
): void => {
  const base = DYNSYM_OFF + index * 24;
  const [name, info, shndx, value, size] = fields;
  buf.writeUInt32LE(name, base);
  buf.writeUInt8(info, base + 4);
  buf.writeUInt16LE(shndx, base + 6);
  buf.writeBigUInt64LE(value, base + 8);
  buf.writeBigUInt64LE(size, base + 16);
};

const writeDyn = (
  buf: Buffer,
  index: number,
  tag: number,
  value: number,
): void => {
  const base = DYN_OFF + index * 16;
  buf.writeBigUInt64LE(BigInt(tag), base);
  buf.writeBigUInt64LE(BigInt(value), base + 8);
};

/** A complete, cross-referenced synthetic ELF64 little-endian image. */
const buildDynamicElf = (): Buffer => {
  const buf = Buffer.alloc(TOTAL);
  buf.writeUInt32BE(0x7f454c46, 0);
  buf[4] = 2;
  buf[5] = 1;
  buf[6] = 1;
  buf.writeUInt16LE(3, 16);
  buf.writeUInt16LE(62, 18);
  buf.writeUInt32LE(1, 20);
  buf.writeBigUInt64LE(0x1000n, 24);
  buf.writeBigUInt64LE(BigInt(PHOFF), 32);
  buf.writeBigUInt64LE(BigInt(SHOFF), 40);
  buf.writeUInt16LE(64, 52);
  buf.writeUInt16LE(56, 54);
  buf.writeUInt16LE(2, 56);
  buf.writeUInt16LE(64, 58);
  buf.writeUInt16LE(7, 60);
  buf.writeUInt16LE(5, 62);
  buf.writeUInt32LE(1, PHOFF);
  buf.writeUInt32LE(5, PHOFF + 4);
  buf.writeBigUInt64LE(BigInt(TOTAL), PHOFF + 32);
  buf.writeBigUInt64LE(BigInt(TOTAL + 8), PHOFF + 40);
  buf.writeUInt32LE(2, PHOFF + 56);
  buf.writeUInt32LE(6, PHOFF + 56 + 4);
  buf.writeBigUInt64LE(BigInt(DYN_OFF), PHOFF + 56 + 8);
  buf.writeBigUInt64LE(BigInt(DYN_OFF), PHOFF + 56 + 16);
  buf.writeBigUInt64LE(96n, PHOFF + 56 + 32);
  buf.write(DYNSTR, DYNSTR_OFF, "latin1");
  buf.write(SHSTR, SHSTR_OFF, "latin1");
  writeSym(buf, 1, [22, 0x12, 0, 0n, 0n]);
  writeSym(buf, 2, [29, 0x12, 1, 0x1000n, 4n]);
  writeDyn(buf, 0, 5, DYNSTR_OFF);
  writeDyn(buf, 1, 6, DYNSYM_OFF);
  writeDyn(buf, 2, 10, DYNSTR.length);
  writeDyn(buf, 3, 1, 1);
  writeDyn(buf, 4, 14, 11);
  writeDyn(buf, 5, 0, 0);
  writeShdr(buf, 0, [0, 0, 0n, 0n, 0, 0, 0, 0]);
  writeShdr(buf, 1, [1, 1, 0x6n, 0x1000n, 0x80, 4, 0, 0]);
  writeShdr(buf, 2, [7, 11, 0x2n, 0x140n, DYNSYM_OFF, 72, 3, 24]);
  writeShdr(buf, 3, [15, 3, 0x2n, 0x100n, DYNSTR_OFF, DYNSTR.length, 0, 0]);
  writeShdr(buf, 4, [23, 6, 0x3n, 0x200n, DYN_OFF, 96, 3, 16]);
  writeShdr(buf, 5, [32, 3, 0n, 0n, SHSTR_OFF, SHSTR.length, 0, 0]);
  writeShdr(buf, 6, [42, 8, 0x3n, 0x2000n, 0x500, 8, 0, 0]);
  return buf;
};

const context = (bytes: Buffer): TriageAnalysisContext => ({
  sha256: createHash("sha256").update(bytes).digest("hex"),
  signal: undefined,
});

const input = (
  overrides: Partial<Record<string, unknown>> = {},
): InspectExecutableInput =>
  inspectExecutableInputSchema.parse({
    path: "/artifacts/application",
    ...overrides,
  });

const run = async (bytes: Buffer, overrides: Record<string, unknown> = {}) => {
  const body = await analyzeInspectExecutable(
    bytes,
    input(overrides),
    context(bytes),
  );
  const report = {
    ...body,
    artifact: {
      path: "/artifacts/application",
      sha256: context(bytes).sha256,
      bytes: bytes.length,
    },
  };
  const parsed = inspectExecutableReportSchema.safeParse(report);
  if (!parsed.success)
    throw new Error(`report failed schema: ${parsed.error.message}`);
  return parsed.data;
};

describe("analyzeInspectExecutable", () => {
  it("projects identity, sections and the ELF detail block", async () => {
    const report = await run(createRustImage({ format: "elf" }));
    expect(report.format).toBe("elf");
    expect(report.subject.format).toBe("elf");
    expect(report.bits).toBe(64);
    expect(report.byte_order).toBe("little");
    expect(report.architecture).toBe("x86_64");
    expect(report.machine.value).toBe(62);
    expect(report.container).toEqual({ kind: "thin" });
    expect(report.elf).not.toBeNull();
    expect(report.pe).toBeNull();
    expect(report.macho).toBeNull();
    expect(report.sections.length).toBe(report.counts.sections);
    expect(report.sections_coverage.truncated).toBe(false);
  });

  it("derives imports, exports, libraries and entry section", async () => {
    const report = await run(buildDynamicElf());
    expect(report.imports).toEqual([
      {
        library: null,
        name: "printf",
        ordinal: null,
        delay_loaded: false,
        weak: false,
        version: null,
      },
    ]);
    expect(report.exports.map((entry) => entry.name)).toContain("add");
    expect(report.libraries).toContainEqual({
      name: "libc.so.6",
      kind: "needed",
    });
    expect(report.elf?.soname).toBe("mylib.so.1");
    expect(report.entry_point.section).toBe(".text");
    const text = report.sections.find((section) => section.name === ".text");
    expect(text?.permissions).toBe("r-x");
  });

  it("excludes symbols by default and reports them as omitted", async () => {
    const report = await run(buildDynamicElf());
    expect(report.symbols).toEqual([]);
    expect(report.counts.symbols).toBeGreaterThan(0);
    expect(report.symbols_coverage.returned).toBe(0);
    expect(report.symbols_coverage.truncated).toBe(true);
    expect(
      report.limitations.some((note) =>
        note.includes("symbols list was not requested"),
      ),
    ).toBe(true);
  });

  it("returns symbols when explicitly included", async () => {
    const report = await run(buildDynamicElf(), {
      include: ["sections", "symbols"],
    });
    expect(report.symbols.length).toBe(report.counts.symbols);
    expect(report.symbols_coverage.truncated).toBe(false);
    expect(report.imports).toEqual([]);
    expect(report.imports_coverage.returned).toBe(0);
  });

  it("bounds each list by max_list and records truncation", async () => {
    const report = await run(buildDynamicElf(), { max_list: 2 });
    expect(report.sections.length).toBe(2);
    expect(report.sections_coverage).toEqual({
      total: 7,
      returned: 2,
      truncated: true,
    });
    expect(report.counts.sections).toBe(7);
    expect(
      report.limitations.some((note) =>
        note.includes("of 7 sections are returned"),
      ),
    ).toBe(true);
  });

  it("projects a PE image detail block", async () => {
    const report = await run(createRustImage({ format: "pe" }));
    expect(report.format).toBe("pe");
    expect(report.pe).not.toBeNull();
    expect(report.pe?.pe32_plus).toBe(true);
    expect(report.elf).toBeNull();
  });

  it("projects a thin Mach-O image detail block", async () => {
    const report = await run(createRustImage({ format: "macho" }));
    expect(report.format).toBe("macho");
    expect(report.subject.format).toBe("mach-o");
    expect(report.architecture).toBe("arm64");
    expect(report.macho).not.toBeNull();
    expect(report.macho?.load_command_count).toBeGreaterThan(0);
    expect(report.container.kind).toBe("thin");
  });

  it("refuses content that is not an executable image", async () => {
    const bytes = Buffer.from("this is plainly not an executable image");
    await expect(
      analyzeInspectExecutable(bytes, input(), context(bytes)),
    ).rejects.toThrow();
  });
});
