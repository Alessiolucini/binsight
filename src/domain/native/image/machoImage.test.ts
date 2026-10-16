import { describe, expect, it } from "vitest";

import { parseMachoImage } from "./machoImage.js";
import type { ExecutableImage } from "./executableImage.js";

const CPU_ARM64 = 0x0100_000c;
const CPU_X86_64 = 0x0100_0007;
const BASE = 0x1_0000_0000n;

interface SegmentSpec {
  readonly name: string;
  readonly vmaddr: bigint;
  readonly fileoff: number;
  readonly filesize: number;
  readonly prot: number;
  readonly nsects: number;
}

const writeSegment64 = (spec: SegmentSpec): Buffer => {
  const buf = Buffer.alloc(72 + spec.nsects * 80);
  buf.writeUInt32LE(0x19, 0);
  buf.writeUInt32LE(buf.length, 4);
  buf.write(spec.name, 8, "latin1");
  buf.writeBigUInt64LE(spec.vmaddr, 24);
  buf.writeBigUInt64LE(0x4000n, 32);
  buf.writeBigUInt64LE(BigInt(spec.fileoff), 40);
  buf.writeBigUInt64LE(BigInt(spec.filesize), 48);
  buf.writeUInt32LE(spec.prot, 56);
  buf.writeUInt32LE(spec.prot, 60);
  buf.writeUInt32LE(spec.nsects, 64);
  return buf;
};

interface SectionSpec {
  readonly sect: string;
  readonly seg: string;
  readonly addr: bigint;
  readonly size: number;
  readonly fileoff: number;
}

const writeSection64 = (buf: Buffer, spec: SectionSpec): void => {
  buf.write(spec.sect, 72, "latin1");
  buf.write(spec.seg, 72 + 16, "latin1");
  buf.writeBigUInt64LE(spec.addr, 72 + 32);
  buf.writeBigUInt64LE(BigInt(spec.size), 72 + 40);
  buf.writeUInt32LE(spec.fileoff, 72 + 48);
};

const mainCommand = (entryoff: number): Buffer => {
  const buf = Buffer.alloc(24);
  buf.writeUInt32LE(0x8000_0028, 0);
  buf.writeUInt32LE(24, 4);
  buf.writeBigUInt64LE(BigInt(entryoff), 8);
  return buf;
};

const unixThreadArm64 = (pc: bigint): Buffer => {
  const buf = Buffer.alloc(8 + 8 + 68 * 4);
  buf.writeUInt32LE(0x5, 0);
  buf.writeUInt32LE(buf.length, 4);
  buf.writeUInt32LE(6, 8); // ARM_THREAD_STATE64
  buf.writeUInt32LE(68, 12);
  buf.writeBigUInt64LE(pc, 16 + 32 * 8);
  return buf;
};

const fixedCommands = (): Buffer[] => {
  const dylib = Buffer.alloc(24 + 24);
  dylib.writeUInt32LE(0xc, 0);
  dylib.writeUInt32LE(dylib.length, 4);
  dylib.writeUInt32LE(24, 8);
  dylib.writeUInt32LE(0x01_02_03, 16);
  dylib.writeUInt32LE(0x01_00_00, 20);
  dylib.write("/usr/lib/libTest.dylib", 24, "latin1");
  const uuid = Buffer.alloc(24);
  uuid.writeUInt32LE(0x1b, 0);
  uuid.writeUInt32LE(24, 4);
  Buffer.from("0123456789abcdef", "latin1").copy(uuid, 8);
  const chained = Buffer.alloc(16);
  chained.writeUInt32LE(0x8000_0034, 0);
  chained.writeUInt32LE(16, 4);
  return [dylib, uuid, chained];
};

const STRINGS = Buffer.from("\0_import\0_export\0", "latin1");

interface ThinOptions {
  readonly cpuType: number;
  readonly thread?: boolean;
}

/** Build a minimal but structurally valid 64-bit little-endian thin Mach-O. */
const buildThinMacho = (options: ThinOptions): Buffer => {
  const segText = writeSegment64({
    name: "__TEXT",
    vmaddr: BASE,
    fileoff: 0,
    filesize: 0,
    prot: 5,
    nsects: 1,
  });
  const segLink = writeSegment64({
    name: "__LINKEDIT",
    vmaddr: 0x1_0000_8000n,
    fileoff: 0,
    filesize: 0,
    prot: 1,
    nsects: 0,
  });
  const extra = fixedCommands();
  const placeholderEntry = options.thread
    ? unixThreadArm64(0n)
    : mainCommand(0);
  const symtab = Buffer.alloc(24);
  const codeSig = Buffer.alloc(16);
  const commands = [
    segText,
    segLink,
    ...extra,
    placeholderEntry,
    symtab,
    codeSig,
  ];
  const sizeofcmds = commands.reduce((n, c) => n + c.length, 0);
  const textFileoff = 32 + sizeofcmds;
  const textSize = 16;
  const entryoff = textFileoff + 4;
  const symoff = textFileoff + textSize;
  const stroff = symoff + 2 * 16;
  const fileLen = stroff + STRINGS.length + 8;
  const exportAddr = BASE + BigInt(textFileoff);

  writeSection64(segText, {
    sect: "__text",
    seg: "__TEXT",
    addr: exportAddr,
    size: textSize,
    fileoff: textFileoff,
  });
  segText.writeBigUInt64LE(BigInt(symoff), 48);
  segLink.writeBigUInt64LE(BigInt(symoff), 40);
  segLink.writeBigUInt64LE(BigInt(fileLen - symoff), 48);
  if (options.thread)
    unixThreadArm64(BASE + BigInt(entryoff)).copy(placeholderEntry);
  else mainCommand(entryoff).copy(placeholderEntry);
  symtab.writeUInt32LE(0x2, 0);
  symtab.writeUInt32LE(24, 4);
  symtab.writeUInt32LE(symoff, 8);
  symtab.writeUInt32LE(2, 12);
  symtab.writeUInt32LE(stroff, 16);
  symtab.writeUInt32LE(STRINGS.length, 20);
  codeSig.writeUInt32LE(0x1d, 0);
  codeSig.writeUInt32LE(16, 4);
  codeSig.writeUInt32LE(stroff + STRINGS.length, 8);
  codeSig.writeUInt32LE(8, 12);

  const file = Buffer.alloc(fileLen);
  file.writeUInt32LE(0xfeed_facf, 0);
  file.writeUInt32LE(options.cpuType, 4);
  file.writeUInt32LE(0, 8);
  file.writeUInt32LE(2, 12);
  file.writeUInt32LE(commands.length, 16);
  file.writeUInt32LE(sizeofcmds, 20);
  file.writeUInt32LE(0x20_0085, 24);
  let p = 32;
  for (const c of commands) {
    c.copy(file, p);
    p += c.length;
  }
  file.writeUInt32LE(1, symoff);
  file.writeUInt8(0x01, symoff + 4);
  file.writeUInt16LE(0x0100, symoff + 6);
  file.writeUInt32LE(9, symoff + 16);
  file.writeUInt8(0x0f, symoff + 20);
  file.writeUInt8(1, symoff + 21);
  file.writeBigUInt64LE(exportAddr, symoff + 24);
  STRINGS.copy(file, stroff);
  return file;
};

/** Wrap two thin slices in a big-endian FAT (universal) container. */
const buildFatMacho = (first: Buffer, second: Buffer): Buffer => {
  const tableEnd = 8 + 2 * 20;
  const off0 = Math.ceil(tableEnd / 0x4000) * 0x4000;
  const off1 = Math.ceil((off0 + first.length) / 0x4000) * 0x4000;
  const file = Buffer.alloc(off1 + second.length);
  file.writeUInt32BE(0xcafe_babe, 0);
  file.writeUInt32BE(2, 4);
  const entry = (i: number, cpu: number, off: number, size: number): void => {
    const b = 8 + i * 20;
    file.writeUInt32BE(cpu, b);
    file.writeUInt32BE(0, b + 4);
    file.writeUInt32BE(off, b + 8);
    file.writeUInt32BE(size, b + 12);
    file.writeUInt32BE(14, b + 16);
  };
  entry(0, CPU_X86_64, off0, first.length);
  entry(1, CPU_ARM64, off1, second.length);
  first.copy(file, off0);
  second.copy(file, off1);
  return file;
};

const unwrap = (bytes: Buffer, opts = {}): ExecutableImage => {
  const result = parseMachoImage(bytes, opts);
  if (!result.ok)
    throw new Error(`unexpected failure: ${result.error.message}`);
  return result.value;
};

describe("parseMachoImage thin images", () => {
  it("projects header, segments, entry, dylib and symbols", () => {
    const image = unwrap(buildThinMacho({ cpuType: CPU_ARM64 }));
    expect(image.format).toBe("macho");
    expect(image.bits).toBe(64);
    expect(image.byte_order).toBe("little");
    expect(image.architecture).toBe("arm64");
    expect(image.machine_name).toBe("ARM64");
    expect(image.container.kind).toBe("thin");
    expect(image.image_offset).toBe(0);
    expect(image.segments.map((s) => s.name)).toEqual(["__TEXT", "__LINKEDIT"]);
    expect(image.sections.map((s) => s.name)).toEqual(["__TEXT,__text"]);
    const text = image.sections[0]!;
    expect(text.segment_name).toBe("__TEXT");
    expect(text.type).toBe("S_REGULAR");
    expect(text.executable).toBe(true);
    expect(text.writable).toBe(false);
    expect(image.entry_point.section_index).toBe(0);
    expect(image.entry_point.virtual_address).toBe(text.virtual_address + 4n);
    expect(image.macho?.dylibs).toEqual([
      {
        name: "/usr/lib/libTest.dylib",
        command: "LC_LOAD_DYLIB",
        current_version: "1.2.3",
        compatibility_version: "1.0.0",
      },
    ]);
    expect(image.libraries).toEqual([
      { name: "/usr/lib/libTest.dylib", kind: "needed" },
    ]);
    expect(image.macho?.uuid).toBe("30313233343536373839616263646566");
    expect(image.macho?.uses_chained_fixups).toBe(true);
    expect(image.macho?.code_signature).not.toBeNull();
    expect(image.overlay).toBeNull();
  });

  it("resolves two-level imports and defined exports from the nlist", () => {
    const image = unwrap(buildThinMacho({ cpuType: CPU_ARM64 }));
    expect(image.imports).toEqual([
      {
        library: "/usr/lib/libTest.dylib",
        name: "_import",
        ordinal: null,
        delay_loaded: false,
        weak: false,
        version: null,
      },
    ]);
    expect(image.exports).toEqual([
      {
        name: "_export",
        ordinal: null,
        address: image.sections[0]!.virtual_address,
        forwarder: null,
        kind: "function",
      },
    ]);
    expect(image.symbols).toHaveLength(2);
    expect(image.symbols.every((s) => s.table === "nlist")).toBe(true);
    expect(image.coverage).toEqual({
      imports: "complete",
      exports: "complete",
      symbols: "complete",
    });
  });

  it("decodes the LC_UNIXTHREAD program counter as the entry point", () => {
    const image = unwrap(buildThinMacho({ cpuType: CPU_ARM64, thread: true }));
    const text = image.sections[0]!;
    expect(image.entry_point.virtual_address).toBe(text.virtual_address + 4n);
    expect(image.entry_point.file_offset).toBe(text.file_offset + 4);
  });
});

describe("parseMachoImage FAT containers", () => {
  it("selects the first slice by default and reports the slice table", () => {
    const fat = buildFatMacho(
      buildThinMacho({ cpuType: CPU_X86_64 }),
      buildThinMacho({ cpuType: CPU_ARM64 }),
    );
    const image = unwrap(fat);
    expect(image.architecture).toBe("x86_64");
    expect(image.container.kind).toBe("fat");
    if (image.container.kind !== "fat") throw new Error("expected fat");
    expect(image.container.selected_index).toBe(0);
    expect(image.container.slices.map((s) => s.architecture)).toEqual([
      "x86_64",
      "arm64",
    ]);
    expect(image.image_offset).toBe(image.container.slices[0]!.file_offset);
    expect(image.image_size).toBe(image.container.slices[0]!.size);
    // Section offsets are absolute: inside the selected slice's file range.
    const text = image.sections[0]!;
    expect(text.file_offset).toBeGreaterThanOrEqual(image.image_offset);
    expect(text.file_offset + text.file_size).toBeLessThanOrEqual(
      image.image_offset + image.image_size,
    );
    expect(image.overlay).toBeNull();
  });

  it("selects a slice by architecture and by index", () => {
    const fat = buildFatMacho(
      buildThinMacho({ cpuType: CPU_X86_64 }),
      buildThinMacho({ cpuType: CPU_ARM64 }),
    );
    const byArch = unwrap(fat, { slice: { architecture: "arm64" } });
    expect(byArch.architecture).toBe("arm64");
    if (byArch.container.kind === "fat")
      expect(byArch.container.selected_index).toBe(1);
    const byIndex = unwrap(fat, { slice: { index: 1 } });
    expect(byIndex.architecture).toBe("arm64");
    expect(byIndex.image_offset).toBeGreaterThan(0);
  });
});

describe("parseMachoImage refusals", () => {
  it("rejects big-endian thin images as unsupported", () => {
    const bytes = Buffer.alloc(64);
    bytes.writeUInt32BE(0xfeed_facf, 0);
    const result = parseMachoImage(bytes, {});
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.kind).toBe("unsupported");
  });

  it("reports a truncated header as malformed", () => {
    const bytes = Buffer.alloc(10);
    bytes.writeUInt32LE(0xfeed_facf, 0);
    const result = parseMachoImage(bytes, {});
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.kind).toBe("malformed");
  });

  it("rejects an out-of-range FAT slice index as unsupported", () => {
    const fat = buildFatMacho(
      buildThinMacho({ cpuType: CPU_X86_64 }),
      buildThinMacho({ cpuType: CPU_ARM64 }),
    );
    const result = parseMachoImage(fat, { slice: { index: 9 } });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.kind).toBe("unsupported");
  });
});
