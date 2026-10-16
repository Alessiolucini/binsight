import { describe, expect, it } from "vitest";
import type { ExecutableImage } from "./executableImage.js";
import { parsePeImage } from "./peImage.js";

const PE_OFFSET = 0xa0;
const OPT = PE_OFFSET + 24;
const OPT_SIZE = 240;
const SECTIONS = OPT + OPT_SIZE;
const IMAGE_BASE = 0x1_4000_0000n;

const u16 = (buf: Buffer, offset: number, value: number): void => {
  buf.writeUInt16LE(value, offset);
};
const u32 = (buf: Buffer, offset: number, value: number): void => {
  buf.writeUInt32LE(value, offset);
};
const u64 = (buf: Buffer, offset: number, value: bigint): void => {
  buf.writeBigUInt64LE(value, offset);
};

const writeDosAndRich = (buf: Buffer): void => {
  buf.write("MZ", 0, "latin1");
  u32(buf, 0x3c, PE_OFFSET);
  const key = 0x1234_5678;
  u32(buf, 0x80, 0x536e_6144 ^ key); // DanS ^ key
  u32(buf, 0x84, key);
  u32(buf, 0x88, key);
  u32(buf, 0x8c, key);
  u32(buf, 0x90, ((0x00a1 << 16) | 0x00b2) ^ key); // product 0xa1, build 0xb2
  u32(buf, 0x94, 7 ^ key); // count 7
  buf.write("Rich", 0x98, "latin1");
  u32(buf, 0x9c, key);
};

const writeCoffAndOptional = (buf: Buffer): void => {
  buf.write("PE\0\0", PE_OFFSET, "latin1");
  u16(buf, PE_OFFSET + 4, 0x8664); // machine AMD64
  u16(buf, PE_OFFSET + 6, 3); // sections
  u32(buf, PE_OFFSET + 8, 0xdead_beef); // timestamp
  u32(buf, PE_OFFSET + 12, 0xc00); // PointerToSymbolTable
  u32(buf, PE_OFFSET + 16, 2); // NumberOfSymbols
  u16(buf, PE_OFFSET + 20, OPT_SIZE);
  u16(buf, PE_OFFSET + 22, 0x0022); // characteristics
  u16(buf, OPT, 0x20b); // PE32+ magic
  buf.writeUInt8(14, OPT + 2); // linker major
  buf.writeUInt8(29, OPT + 3); // linker minor
  u32(buf, OPT + 16, 0x1000); // entry rva
  u64(buf, OPT + 24, IMAGE_BASE);
  u32(buf, OPT + 32, 0x1000); // section alignment
  u32(buf, OPT + 36, 0x200); // file alignment
  u16(buf, OPT + 40, 6); // os major
  u16(buf, OPT + 48, 6); // subsystem major
  u16(buf, OPT + 50, 1); // subsystem minor
  u32(buf, OPT + 56, 0x4000); // size of image
  u32(buf, OPT + 60, 0x400); // size of headers
  u16(buf, OPT + 68, 3); // subsystem
  u16(buf, OPT + 70, 0x160); // dll characteristics
  u32(buf, OPT + 108, 16); // NumberOfRvaAndSizes
};

const writeDataDirectory = (
  buf: Buffer,
  index: number,
  rva: number,
  size: number,
): void => {
  const base = OPT + 112 + index * 8;
  u32(buf, base, rva);
  u32(buf, base + 4, size);
};

interface SectionSpec {
  readonly index: number;
  readonly name: string;
  readonly rva: number;
  readonly vsize: number;
  readonly rawPtr: number;
  readonly rawSize: number;
  readonly characteristics: number;
}

const writeSectionHeader = (buf: Buffer, spec: SectionSpec): void => {
  const base = SECTIONS + spec.index * 40;
  buf.write(spec.name, base, 8, "latin1");
  u32(buf, base + 8, spec.vsize);
  u32(buf, base + 12, spec.rva);
  u32(buf, base + 16, spec.rawSize);
  u32(buf, base + 20, spec.rawPtr);
  u32(buf, base + 36, spec.characteristics);
};

const writeImportDirectory = (buf: Buffer): void => {
  // descriptor @ file 0x600 (rva 0x2000)
  u32(buf, 0x600, 0x2030); // OriginalFirstThunk (ILT rva)
  u32(buf, 0x60c, 0x2060); // Name rva
  u32(buf, 0x610, 0x2080); // FirstThunk
  // ILT @ file 0x630 (rva 0x2030)
  u64(buf, 0x630, 0x2050n); // -> IMAGE_IMPORT_BY_NAME rva
  u64(buf, 0x638, (1n << 63n) | 7n); // ordinal import 7
  u64(buf, 0x640, 0n); // terminator
  // hint/name @ file 0x650 (rva 0x2050)
  u16(buf, 0x650, 0); // hint
  buf.write("Foo\0", 0x652, "latin1");
  // dll name @ file 0x660 (rva 0x2060)
  buf.write("TEST.dll\0", 0x660, "latin1");
};

const writeExportDirectory = (buf: Buffer): void => {
  // export directory @ file 0x700 (rva 0x2100)
  u32(buf, 0x710, 5); // Base
  u32(buf, 0x714, 1); // NumberOfFunctions
  u32(buf, 0x718, 1); // NumberOfNames
  u32(buf, 0x71c, 0x2130); // AddressOfFunctions
  u32(buf, 0x720, 0x2140); // AddressOfNames
  u32(buf, 0x724, 0x2150); // AddressOfNameOrdinals
  u32(buf, 0x70c, 0x2160); // Name rva
  u32(buf, 0x730, 0x1000); // functions[0] rva -> .text
  u32(buf, 0x740, 0x2170); // names[0] rva
  u16(buf, 0x750, 0); // nameOrdinals[0]
  buf.write("mylib.dll\0", 0x760, "latin1");
  buf.write("Bar\0", 0x770, "latin1");
};

const writeTlsDirectory = (buf: Buffer): void => {
  // TLS directory @ file 0x800 (rva 0x2200), AddressOfCallBacks @ +24
  u64(buf, 0x800 + 24, IMAGE_BASE + 0x2240n);
  // callback array @ file 0x840 (rva 0x2240)
  u64(buf, 0x840, IMAGE_BASE + 0x1000n);
  u64(buf, 0x848, 0n);
};

const writeSymbols = (buf: Buffer): void => {
  // symbol table @ 0xC00
  buf.write(".file\0\0\0", 0xc00, 8, "latin1");
  buf.writeInt16LE(-2, 0xc00 + 12); // section debug
  buf.writeUInt8(103, 0xc00 + 16); // storage class FILE
  // second symbol @ 0xC12, string-table name
  u32(buf, 0xc12, 0); // name via string table
  u32(buf, 0xc12 + 4, 18); // offset into string table -> "myfunc"
  u32(buf, 0xc12 + 8, 0x1000); // value
  buf.writeInt16LE(1, 0xc12 + 12); // section 1
  u16(buf, 0xc12 + 14, 0x20); // type function
  buf.writeUInt8(2, 0xc12 + 16); // storage external
  // string table @ 0xC24
  u32(buf, 0xc24, 25);
  buf.write(".text\0", 0xc28, "latin1"); // offset 4
  buf.write("secLong\0", 0xc2e, "latin1"); // offset 10
  buf.write("myfunc\0", 0xc36, "latin1"); // offset 18
};

const buildPe64 = (): Buffer => {
  const buf = Buffer.alloc(0xc3d);
  writeDosAndRich(buf);
  writeCoffAndOptional(buf);
  writeDataDirectory(buf, 0, 0x2100, 40); // EXPORT
  writeDataDirectory(buf, 1, 0x2000, 40); // IMPORT
  writeDataDirectory(buf, 9, 0x2200, 40); // TLS
  const code = 0x6000_0020; // EXECUTE | READ | CODE
  const rdata = 0x4000_0040; // READ | INITIALIZED_DATA
  writeSectionHeader(buf, {
    index: 0,
    name: ".text",
    rva: 0x1000,
    vsize: 0x100,
    rawPtr: 0x400,
    rawSize: 0x200,
    characteristics: code,
  });
  writeSectionHeader(buf, {
    index: 1,
    name: ".rdata",
    rva: 0x2000,
    vsize: 0x300,
    rawPtr: 0x600,
    rawSize: 0x400,
    characteristics: rdata,
  });
  writeSectionHeader(buf, {
    index: 2,
    name: "/10",
    rva: 0x3000,
    vsize: 0x40,
    rawPtr: 0xa00,
    rawSize: 0x200,
    characteristics: rdata,
  });
  writeImportDirectory(buf);
  writeExportDirectory(buf);
  writeTlsDirectory(buf);
  writeSymbols(buf);
  return buf;
};

const parsed = (): ExecutableImage => {
  const result = parsePeImage(buildPe64(), PE_OFFSET);
  if (!result.ok) throw new Error(`PE should parse: ${result.error.message}`);
  return result.value;
};

describe("parsePeImage", () => {
  it("parses PE32+ identity, entry point and sections", () => {
    const image = parsed();
    expect(image.format).toBe("pe");
    expect(image.bits).toBe(64);
    expect(image.architecture).toBe("x86_64");
    expect(image.machine).toBe(0x8664);
    expect(image.machine_name).toBe("IMAGE_FILE_MACHINE_AMD64");
    expect(image.byte_order).toBe("little");
    expect(image.image_offset).toBe(0);
    expect(image.image_size).toBe(0xc3d);
    expect(image.segments).toEqual([]);
    expect(image.entry_point).toEqual({
      virtual_address: IMAGE_BASE + 0x1000n,
      file_offset: 0x400,
      section_index: 0,
    });
    expect(image.sections.map((section) => section.name)).toEqual([
      ".text",
      ".rdata",
      "secLong",
    ]);
    const text = image.sections[0]!;
    expect(text.executable && text.readable && !text.writable).toBe(true);
    expect(text.file_size).toBe(0x200);
    expect(text.virtual_size).toBe(0x100n);
    expect(text.virtual_address).toBe(IMAGE_BASE + 0x1000n);
    expect(image.diagnostics).toEqual([]);
    expect(image.overlay).toBeNull();
    expect(image.container).toEqual({ kind: "thin" });
    expect(image.elf).toBeNull();
    expect(image.macho).toBeNull();
  });

  it("parses imports, libraries and ordinal imports", () => {
    const image = parsed();
    expect(image.coverage.imports).toBe("complete");
    expect(image.imports.length).toBe(2);
    expect(image.imports.find((entry) => entry.name === "Foo")).toEqual({
      library: "TEST.dll",
      name: "Foo",
      ordinal: null,
      delay_loaded: false,
      weak: false,
      version: null,
    });
    expect(image.imports.find((entry) => entry.name === null)?.ordinal).toBe(7);
    expect(image.libraries).toEqual([{ name: "TEST.dll", kind: "needed" }]);
  });

  it("parses exports with ordinal base and absolute address", () => {
    const image = parsed();
    expect(image.coverage.exports).toBe("complete");
    expect(image.exports).toEqual([
      {
        name: "Bar",
        ordinal: 5,
        address: IMAGE_BASE + 0x1000n,
        forwarder: null,
        kind: "function",
      },
    ]);
  });

  it("parses TLS callbacks, COFF symbols and long section names", () => {
    const image = parsed();
    expect(image.pe?.tls_callbacks).toEqual([IMAGE_BASE + 0x1000n]);
    expect(image.coverage.symbols).toBe("complete");
    expect(image.symbols.find((symbol) => symbol.name === "myfunc")).toEqual({
      name: "myfunc",
      value: 0x1000n,
      size: 0n,
      type: "function",
      binding: "global",
      defined: true,
      table: "coff",
    });
    const file = image.symbols.find((symbol) => symbol.name === ".file");
    expect(file?.type).toBe("file");
    expect(file?.defined).toBe(false);
  });

  it("projects PE detail, data directories and rich header", () => {
    const pe = parsed().pe;
    if (pe === null) throw new Error("expected PE detail");
    expect({
      pe32_plus: pe.pe32_plus,
      image_base: pe.image_base,
      size_of_image: pe.size_of_image,
      size_of_headers: pe.size_of_headers,
      linker_version: pe.linker_version,
      subsystem: pe.subsystem,
      dll_characteristics: pe.dll_characteristics,
      base_relocations: pe.base_relocations,
      managed: pe.managed,
      load_config: pe.load_config,
    }).toEqual({
      pe32_plus: true,
      image_base: IMAGE_BASE,
      size_of_image: 0x4000,
      size_of_headers: 0x400,
      linker_version: "14.29",
      subsystem: 3,
      dll_characteristics: 0x160,
      base_relocations: false,
      managed: false,
      load_config: null,
    });
    expect(pe.data_directories.length).toBe(16);
    expect(pe.data_directories[1]).toEqual({
      index: 1,
      name: "IMPORT",
      rva: 0x2000,
      size: 40,
    });
    expect(pe.rich_header).toEqual({
      offset: 0x80,
      end_offset: 0xa0,
      xor_key: 0x1234_5678,
      entries: [{ product_id: 0xa1, build: 0xb2, count: 7 }],
      checksum_valid: pe.rich_header?.checksum_valid ?? false,
      clear_bytes: pe.rich_header?.clear_bytes ?? Buffer.alloc(0),
    });
  });

  it("rejects a truncated optional header magic", () => {
    const result = parsePeImage(
      Buffer.from(buildPe64().subarray(0, OPT + 1)),
      PE_OFFSET,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.kind).toBe("malformed");
  });

  it("rejects an unsupported optional header magic", () => {
    const buf = buildPe64();
    u16(buf, OPT, 0x107); // ROM image magic
    const result = parsePeImage(buf, PE_OFFSET);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.kind).toBe("unsupported");
  });

  it("rejects a bad PE signature", () => {
    const buf = buildPe64();
    buf.write("XX\0\0", PE_OFFSET, "latin1");
    const result = parsePeImage(buf, PE_OFFSET);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.kind).toBe("malformed");
  });
});
