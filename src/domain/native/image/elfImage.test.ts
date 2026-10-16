import { describe, expect, it } from "vitest";
import { parseElfImage } from "./elfImage.js";
import type { ExecutableImage } from "./executableImage.js";

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
const buildElf64 = (withSections = true): Buffer => {
  const buf = Buffer.alloc(TOTAL);
  buf.writeUInt32BE(0x7f454c46, 0);
  buf[4] = 2;
  buf[5] = 1;
  buf[6] = 1;
  buf.writeUInt16LE(3, 16); // e_type DYN
  buf.writeUInt16LE(62, 18); // e_machine x86_64
  buf.writeUInt32LE(1, 20);
  buf.writeBigUInt64LE(0x1000n, 24); // e_entry
  buf.writeBigUInt64LE(BigInt(PHOFF), 32);
  buf.writeBigUInt64LE(BigInt(withSections ? SHOFF : 0), 40);
  buf.writeUInt16LE(64, 52); // e_ehsize
  buf.writeUInt16LE(56, 54); // e_phentsize
  buf.writeUInt16LE(2, 56); // e_phnum
  buf.writeUInt16LE(64, 58); // e_shentsize
  buf.writeUInt16LE(withSections ? 7 : 0, 60);
  buf.writeUInt16LE(withSections ? 5 : 0, 62);
  // PT_LOAD over the whole file, PT_DYNAMIC.
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
  writeSym(buf, 1, [22, 0x12, 0, 0n, 0n]); // printf, undefined import
  writeSym(buf, 2, [29, 0x12, 1, 0x1000n, 4n]); // add, defined export in .text
  writeDyn(buf, 0, 5, DYNSTR_OFF);
  writeDyn(buf, 1, 6, DYNSYM_OFF);
  writeDyn(buf, 2, 10, DYNSTR.length);
  writeDyn(buf, 3, 1, 1); // DT_NEEDED libc.so.6
  writeDyn(buf, 4, 14, 11); // DT_SONAME mylib.so.1
  writeDyn(buf, 5, 0, 0); // DT_NULL
  writeShdr(buf, 0, [0, 0, 0n, 0n, 0, 0, 0, 0]);
  writeShdr(buf, 1, [1, 1, 0x6n, 0x1000n, 0x80, 4, 0, 0]); // .text
  writeShdr(buf, 2, [7, 11, 0x2n, 0x140n, DYNSYM_OFF, 72, 3, 24]); // .dynsym
  writeShdr(buf, 3, [15, 3, 0x2n, 0x100n, DYNSTR_OFF, DYNSTR.length, 0, 0]); // .dynstr
  writeShdr(buf, 4, [23, 6, 0x3n, 0x200n, DYN_OFF, 96, 3, 16]); // .dynamic
  writeShdr(buf, 5, [32, 3, 0n, 0n, SHSTR_OFF, SHSTR.length, 0, 0]); // .shstrtab
  writeShdr(buf, 6, [42, 8, 0x3n, 0x2000n, 0x500, 8, 0, 0]); // .bss NOBITS
  return buf;
};

const parsed = (bytes: Buffer): ExecutableImage => {
  const result = parseElfImage(bytes);
  if (!result.ok)
    throw new Error(`unexpected failure: ${result.error.message}`);
  return result.value;
};

describe("parseElfImage", () => {
  it("projects identity, sections, segments and entry point", () => {
    const image = parsed(buildElf64());
    expect(image.format).toBe("elf");
    expect(image.bits).toBe(64);
    expect(image.byte_order).toBe("little");
    expect(image.architecture).toBe("x86_64");
    expect(image.machine).toBe(62);
    expect(image.machine_name).toBe("AMD x86-64");
    expect(image.image_offset).toBe(0);
    expect(image.image_size).toBe(0x600);
    expect(image.container).toEqual({ kind: "thin" });
    expect(image.sections.map((s) => s.name)).toEqual([
      "",
      ".text",
      ".dynsym",
      ".dynstr",
      ".dynamic",
      ".shstrtab",
      ".bss",
    ]);
    expect(image.segments.map((s) => s.type)).toEqual([
      "PT_LOAD",
      "PT_DYNAMIC",
    ]);
    const text = image.sections[1]!;
    expect(text.type).toBe("SHT_PROGBITS");
    expect(text.executable).toBe(true);
    expect(text.writable).toBe(false);
    const bss = image.sections[6]!;
    expect(bss.type).toBe("SHT_NOBITS");
    expect(bss.file_size).toBe(0);
    expect(bss.virtual_size).toBe(8n);
    expect(image.entry_point).toEqual({
      virtual_address: 0x1000n,
      file_offset: null,
      section_index: 1,
    });
  });

  it("derives imports, exports, libraries and dynamic facts", () => {
    const image = parsed(buildElf64());
    expect(image.imports).toEqual([
      {
        library: null,
        name: "printf",
        ordinal: null,
        delay_loaded: false,
        weak: false,
        version: null,
      },
    ]);
    expect(image.exports).toEqual([
      {
        name: "add",
        ordinal: null,
        address: 0x1000n,
        forwarder: null,
        kind: "function",
      },
    ]);
    expect(image.libraries).toEqual([{ name: "libc.so.6", kind: "needed" }]);
    expect(image.elf?.dynamic?.needed).toEqual(["libc.so.6"]);
    expect(image.elf?.dynamic?.soname).toBe("mylib.so.1");
    expect(image.elf?.e_type).toBe(3);
    expect(image.elf?.has_symtab).toBe(false);
    expect(image.symbols).toHaveLength(3);
    expect(image.symbols[2]).toEqual({
      name: "add",
      value: 0x1000n,
      size: 4n,
      type: "function",
      binding: "global",
      defined: true,
      table: "dynsym",
    });
    expect(image.coverage).toEqual({
      imports: "complete",
      exports: "complete",
      symbols: "complete",
    });
    expect(image.overlay).toBeNull();
  });

  it("parses via program headers when the section table is absent", () => {
    const image = parsed(buildElf64(false));
    expect(image.sections).toEqual([]);
    expect(image.segments.map((s) => s.type)).toEqual([
      "PT_LOAD",
      "PT_DYNAMIC",
    ]);
    expect(image.entry_point.virtual_address).toBe(0x1000n);
    expect(image.elf?.dynamic?.needed).toEqual(["libc.so.6"]);
    expect(image.coverage).toEqual({
      imports: "unavailable",
      exports: "unavailable",
      symbols: "unavailable",
    });
    expect(image.diagnostics.some((d) => d.includes("no section header"))).toBe(
      true,
    );
  });

  it("refuses non-ELF and truncated identification", () => {
    const notElf = parseElfImage(Buffer.from("MZ not an elf image here"));
    expect(notElf.ok).toBe(false);
    if (!notElf.ok) expect(notElf.error.kind).toBe("malformed");
    const truncated = parseElfImage(
      Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1]),
    );
    expect(truncated.ok).toBe(false);
  });
});
