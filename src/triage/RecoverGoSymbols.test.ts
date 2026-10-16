import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import {
  recoverGoSymbolsReportSchema,
  type RecoverGoSymbolsInput,
} from "../domain/triage/recoverGoSymbols.js";
import type { GoBinaryContainer } from "../go/GoBinaryContainer.js";
import {
  findPclntab,
  type GoPclntabVersion,
} from "./RecoverGoSymbolsPclntab.js";
import { analyzeRecoverGoSymbols } from "./RecoverGoSymbols.js";
import { TriageAnalysisFailure } from "./triageSupport.js";

const TEXT_BASE = 0x400000n;

interface SymbolInput {
  readonly name: string;
  readonly entry: bigint;
}

const MAGIC: Record<GoPclntabVersion, number> = {
  "1.2": 0xffff_fffb,
  "1.16": 0xffff_fffa,
  "1.18": 0xffff_fff0,
  "1.20": 0xffff_fff1,
};

const writeUptr = (
  buffer: Buffer,
  offset: number,
  value: bigint,
  ptr: 4 | 8,
): void => {
  if (ptr === 8) buffer.writeBigUInt64LE(value, offset);
  else buffer.writeUInt32LE(Number(value), offset);
};

const align = (value: number, to: number): number => Math.ceil(value / to) * to;

/** Build a byte-exact little-endian pclntab for one header revision. */
const buildPclntab = (
  version: GoPclntabVersion,
  symbols: readonly SymbolInput[],
  ptr: 4 | 8 = 8,
  textStart = TEXT_BASE,
): Buffer => {
  const count = symbols.length;
  const wide = version === "1.2" || version === "1.16";
  const functabStride = wide ? ptr * 2 : 8;
  const funcStructSize = wide ? ptr + 8 : 16;
  const headerSize = version === "1.2" ? 16 : version === "1.16" ? 64 : 72;
  const nameBaseOffset = version === "1.2" ? 0 : headerSize;
  const names = buildNameTable(symbols);
  const nametabStart = version === "1.2" ? -1 : headerSize;
  const functabStart =
    version === "1.2" ? headerSize : align(headerSize + names.bytes.length, 8);
  const functabSize = (count + 1) * functabStride;
  const funcStart = functabStart + functabSize;
  const funcRegion = count * funcStructSize;
  const legacyNameStart = funcStart + funcRegion;
  const total =
    version === "1.2"
      ? legacyNameStart + names.bytes.length
      : funcStart + funcRegion;
  const buffer = Buffer.alloc(total);
  buffer.writeUInt32LE(MAGIC[version] >>> 0, 0);
  buffer[6] = 1; // minimum line-table quantum
  buffer[7] = ptr;
  writeHeader(buffer, version, {
    ptr,
    count,
    textStart,
    funcnameOffset: version === "1.2" ? 0 : headerSize,
    pclnOffset: functabStart,
  });
  const nameAbsolute = (index: number): number =>
    (version === "1.2" ? legacyNameStart : (nametabStart as number)) +
    names.offsets[index]!;
  const nameRelative = (index: number): number =>
    nameAbsolute(index) - nameBaseOffset;
  for (let index = 0; index < count; index += 1) {
    const slot = functabStart + index * functabStride;
    const funcStruct = funcStart + index * funcStructSize;
    // Go 1.2 func offsets are relative to the table start; later versions to
    // the pcln region (the functab start).
    const funcOffset =
      version === "1.2" ? funcStruct : funcStruct - functabStart;
    const symbol = symbols[index]!;
    if (wide) {
      writeUptr(buffer, slot, symbol.entry, ptr);
      writeUptr(buffer, slot + ptr, BigInt(funcOffset), ptr);
      writeUptr(buffer, funcStruct, symbol.entry, ptr);
      buffer.writeInt32LE(nameRelative(index), funcStruct + ptr);
    } else {
      const entryOff = Number(symbol.entry - textStart);
      buffer.writeUInt32LE(entryOff, slot);
      buffer.writeUInt32LE(funcOffset, slot + 4);
      buffer.writeUInt32LE(entryOff, funcStruct);
      buffer.writeInt32LE(nameRelative(index), funcStruct + 4);
    }
  }
  if (version === "1.2") names.bytes.copy(buffer, legacyNameStart);
  else names.bytes.copy(buffer, nametabStart);
  return buffer;
};

const buildNameTable = (
  symbols: readonly SymbolInput[],
): { bytes: Buffer; offsets: number[] } => {
  const parts: Buffer[] = [];
  const offsets: number[] = [];
  let cursor = 0;
  for (const symbol of symbols) {
    offsets.push(cursor);
    const encoded = Buffer.concat([
      Buffer.from(symbol.name, "utf8"),
      Buffer.from([0]),
    ]);
    parts.push(encoded);
    cursor += encoded.length;
  }
  return { bytes: Buffer.concat(parts), offsets };
};

const writeHeader = (
  buffer: Buffer,
  version: GoPclntabVersion,
  fields: {
    ptr: 4 | 8;
    count: number;
    textStart: bigint;
    funcnameOffset: number;
    pclnOffset: number;
  },
): void => {
  const { ptr, count, textStart, funcnameOffset, pclnOffset } = fields;
  if (version === "1.2") {
    writeUptr(buffer, 8, BigInt(count), ptr);
    return;
  }
  let cursor = 8;
  writeUptr(buffer, cursor, BigInt(count), ptr);
  cursor += ptr; // nfunc
  cursor += ptr; // nfiles
  if (version !== "1.16") {
    writeUptr(buffer, cursor, textStart, ptr);
    cursor += ptr;
  }
  writeUptr(buffer, cursor, BigInt(funcnameOffset), ptr);
  cursor += ptr; // funcnametab
  cursor += ptr; // cutab
  cursor += ptr; // filetab
  cursor += ptr; // pctab
  writeUptr(buffer, cursor, BigInt(pclnOffset), ptr);
};

/** Place a pclntab inside a buffer with one read-only section and a load map. */
const containerFor = (
  pclntab: Buffer,
  pclntabOffset: number,
  fileBytes: number,
): { bytes: Buffer; container: GoBinaryContainer } => {
  const bytes = Buffer.alloc(fileBytes);
  pclntab.copy(bytes, pclntabOffset);
  const container: GoBinaryContainer = {
    format: "elf",
    architecture: "x86_64",
    bits: 64,
    byte_order: "little",
    mappings: [{ address: TEXT_BASE, offset: 0, size: fileBytes }],
    zero_fills: [],
    sections: [
      {
        name: ".gopclntab",
        offset: pclntabOffset,
        size: pclntab.length,
        file_backed: true,
        read_only: true,
        compressed: false,
      },
    ],
    search: [],
  };
  return { bytes, container };
};

const SYMBOLS: readonly SymbolInput[] = [
  { name: "main.main", entry: TEXT_BASE + 0x10n },
  { name: "main.init", entry: TEXT_BASE + 0x40n },
  { name: "fmt.Println", entry: TEXT_BASE + 0x80n },
  { name: "github.com/acme/widget.New", entry: TEXT_BASE + 0xc0n },
];

describe("findPclntab", () => {
  for (const version of ["1.2", "1.16", "1.18", "1.20"] as const) {
    it(`round-trips Go ${version} function names and entries`, () => {
      const pclntab = buildPclntab(version, SYMBOLS);
      const { bytes, container } = containerFor(pclntab, 0x100, 0x4000);
      const decoded = findPclntab(bytes, container, 1000);
      expect(decoded).not.toBeNull();
      expect(decoded?.version).toBe(version);
      expect((decoded?.magic ?? 0) >>> 0).toBe(MAGIC[version] >>> 0);
      expect(decoded?.functionCount).toBe(SYMBOLS.length);
      expect(decoded?.functions.map((entry) => entry.name)).toEqual(
        SYMBOLS.map((symbol) => symbol.name),
      );
      expect(decoded?.functions.map((entry) => entry.entry)).toEqual(
        SYMBOLS.map((symbol) => symbol.entry),
      );
      expect(decoded?.fileOffset).toBe(0x100);
    });
  }

  it("round-trips a 32-bit Go 1.20 table", () => {
    const pclntab = buildPclntab("1.20", SYMBOLS, 4);
    const { bytes, container } = containerFor(pclntab, 0x80, 0x2000);
    const decoded = findPclntab(bytes, { ...container, bits: 32 }, 1000);
    expect(decoded?.pointerSize).toBe(4);
    expect(decoded?.functions.map((entry) => entry.name)).toEqual(
      SYMBOLS.map((symbol) => symbol.name),
    );
  });

  it("honors the max-functions bound while reporting the full count", () => {
    const pclntab = buildPclntab("1.18", SYMBOLS);
    const { bytes, container } = containerFor(pclntab, 0x100, 0x4000);
    const decoded = findPclntab(bytes, container, 2);
    expect(decoded?.functionCount).toBe(SYMBOLS.length);
    expect(decoded?.functions).toHaveLength(2);
  });

  it("ignores the magic outside a read-only section", () => {
    const pclntab = buildPclntab("1.16", SYMBOLS);
    const { bytes, container } = containerFor(pclntab, 0x100, 0x4000);
    const writable: GoBinaryContainer = {
      ...container,
      sections: container.sections.map((section) => ({
        ...section,
        read_only: false,
      })),
    };
    expect(findPclntab(bytes, writable, 1000)).toBeNull();
  });

  it("rejects a bare magic with no valid header", () => {
    const bytes = Buffer.alloc(0x400);
    bytes.writeUInt32LE(0xffff_fffb, 0x100);
    bytes[0x100 + 6] = 9; // invalid quantum
    const { container } = containerFor(Buffer.alloc(0x10), 0x100, 0x400);
    const broken: GoBinaryContainer = {
      ...container,
      sections: [{ ...container.sections[0]!, size: 0x40 }],
    };
    expect(findPclntab(bytes, broken, 1000)).toBeNull();
  });
});

/** Minimal valid ELF64 wrapping a .gopclntab section and one load segment. */
const buildElf = (pclntab: Buffer): Buffer => {
  const phOffset = 64;
  const dataStart = 0x200;
  const pclntabOffset = dataStart;
  const shstr = Buffer.from("\0.gopclntab\0.shstrtab\0", "latin1");
  const shstrOffset = align(pclntabOffset + pclntab.length, 8);
  const shOffset = align(shstrOffset + shstr.length, 8);
  const shCount = 3;
  const fileLength = shOffset + shCount * 64;
  const bytes = Buffer.alloc(fileLength);
  bytes.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1], 0); // e_ident
  bytes.writeUInt16LE(2, 16); // e_type ET_EXEC
  bytes.writeUInt16LE(0x3e, 18); // e_machine x86-64
  bytes.writeUInt32LE(1, 20); // e_version
  bytes.writeBigUInt64LE(BigInt(phOffset), 32); // e_phoff
  bytes.writeBigUInt64LE(BigInt(shOffset), 40); // e_shoff
  bytes.writeUInt16LE(64, 52); // e_ehsize
  bytes.writeUInt16LE(56, 54); // e_phentsize
  bytes.writeUInt16LE(1, 56); // e_phnum
  bytes.writeUInt16LE(64, 58); // e_shentsize
  bytes.writeUInt16LE(shCount, 60); // e_shnum
  bytes.writeUInt16LE(2, 62); // e_shstrndx
  // PT_LOAD mapping the whole file at the text base, read + execute.
  bytes.writeUInt32LE(1, phOffset); // p_type PT_LOAD
  bytes.writeUInt32LE(5, phOffset + 4); // p_flags R+X
  bytes.writeBigUInt64LE(0n, phOffset + 8); // p_offset
  bytes.writeBigUInt64LE(TEXT_BASE, phOffset + 16); // p_vaddr
  bytes.writeBigUInt64LE(BigInt(fileLength), phOffset + 32); // p_filesz
  bytes.writeBigUInt64LE(BigInt(fileLength), phOffset + 40); // p_memsz
  pclntab.copy(bytes, pclntabOffset);
  shstr.copy(bytes, shstrOffset);
  writeSectionHeader(bytes, shOffset + 64, {
    name: 1,
    type: 1,
    flags: 2n,
    offset: pclntabOffset,
    size: pclntab.length,
  });
  writeSectionHeader(bytes, shOffset + 128, {
    name: 12,
    type: 3,
    flags: 0n,
    offset: shstrOffset,
    size: shstr.length,
  });
  return bytes;
};

const writeSectionHeader = (
  bytes: Buffer,
  at: number,
  section: {
    name: number;
    type: number;
    flags: bigint;
    offset: number;
    size: number;
  },
): void => {
  bytes.writeUInt32LE(section.name, at);
  bytes.writeUInt32LE(section.type, at + 4);
  bytes.writeBigUInt64LE(section.flags, at + 8);
  bytes.writeBigUInt64LE(0n, at + 16); // sh_addr
  bytes.writeBigUInt64LE(BigInt(section.offset), at + 24);
  bytes.writeBigUInt64LE(BigInt(section.size), at + 32);
};

const CONTEXT = { sha256: "0".repeat(64) } as const;
const INPUT: RecoverGoSymbolsInput = {
  path: "/artifacts/app",
  max_functions: 20_000,
};

const parseReport = (
  body: Awaited<ReturnType<typeof analyzeRecoverGoSymbols>>,
  bytes: Buffer,
) =>
  recoverGoSymbolsReportSchema.parse({
    ...body,
    artifact: {
      path: "/artifacts/app",
      sha256: createHash("sha256").update(bytes).digest("hex"),
      bytes: bytes.length,
    },
  });

describe("analyzeRecoverGoSymbols", () => {
  it("recovers symbols from a synthesized stripped Go ELF", async () => {
    const elf = buildElf(buildPclntab("1.20", SYMBOLS));
    const body = await analyzeRecoverGoSymbols(elf, INPUT, CONTEXT);
    expect(body.is_go).toBe(true);
    expect(body.go_version_magic).toBe("0xfffffff1");
    expect(body.pclntab?.version).toBe("1.20");
    expect(body.pclntab?.function_count).toBe(SYMBOLS.length);
    expect(body.functions.map((entry) => entry.name)).toEqual(
      SYMBOLS.map((symbol) => symbol.name),
    );
    expect(body.functions[0]?.entry).toBe("0x400010");
    expect(body.functions[0]?.file_offset).toBe(0x10);
    expect(body.package_names).toEqual([
      "fmt",
      "github.com/acme/widget",
      "main",
    ]);
    const report = parseReport(body, elf);
    expect(report.subject.format).toBe("elf");
    expect(report.function_coverage).toEqual({
      total: SYMBOLS.length,
      returned: SYMBOLS.length,
      truncated: false,
    });
  });

  it("reports a non-Go executable without a pclntab", async () => {
    const elf = buildElf(Buffer.alloc(0x40)); // read-only section holds no magic
    const body = await analyzeRecoverGoSymbols(elf, INPUT, CONTEXT);
    expect(body.is_go).toBe(false);
    expect(body.pclntab).toBeNull();
    expect(body.go_version_magic).toBeNull();
    expect(body.subject.format).toBe("elf");
    expect(() => parseReport(body, elf)).not.toThrow();
  });

  it("reports a non-executable file as not Go", async () => {
    const bytes = Buffer.from("not an executable, just text bytes here");
    const body = await analyzeRecoverGoSymbols(bytes, INPUT, CONTEXT);
    expect(body.is_go).toBe(false);
    expect(body.subject.format).toBe("file");
    expect(() => parseReport(body, bytes)).not.toThrow();
  });

  it("refuses a malformed recognized container", async () => {
    const truncated = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]);
    await expect(
      analyzeRecoverGoSymbols(truncated, INPUT, CONTEXT),
    ).rejects.toBeInstanceOf(TriageAnalysisFailure);
  });

  it("truncates the returned function list to the requested bound", async () => {
    const elf = buildElf(buildPclntab("1.16", SYMBOLS));
    const body = await analyzeRecoverGoSymbols(
      elf,
      { path: "/artifacts/app", max_functions: 1 },
      CONTEXT,
    );
    expect(body.functions).toHaveLength(1);
    expect(body.function_coverage).toEqual({
      total: SYMBOLS.length,
      returned: 1,
      truncated: true,
    });
    expect(() => parseReport(body, elf)).not.toThrow();
  });
});
