import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  CPU,
  codeSignatureCommand,
  machoImage,
} from "../artifacts/apple/MachoImage.fixture.js";
import {
  inspectBinaryHardeningReportSchema,
  type InspectBinaryHardeningInput,
} from "../domain/triage/inspectBinaryHardening.js";
import { analyzeInspectBinaryHardening } from "./InspectBinaryHardening.js";
import {
  TriageAnalysisFailure,
  type TriageAnalysisContext,
} from "./triageSupport.js";

const ctx = (bytes: Buffer): TriageAnalysisContext => ({
  sha256: createHash("sha256").update(bytes).digest("hex"),
});

const run = (
  bytes: Buffer,
  input: Partial<InspectBinaryHardeningInput> = {},
): ReturnType<typeof analyzeInspectBinaryHardening> =>
  analyzeInspectBinaryHardening(
    bytes,
    { path: "/artifacts/application", ...input },
    ctx(bytes),
  );

/** Validate the full report the service would see, artifact included. */
const validate = (bytes: Buffer, body: object): void => {
  const report = {
    ...body,
    artifact: {
      path: "/artifacts/application",
      sha256: createHash("sha256").update(bytes).digest("hex"),
      bytes: bytes.length,
    },
  };
  const parsed = inspectBinaryHardeningReportSchema.safeParse(report);
  if (!parsed.success) throw new Error(parsed.error.message);
};

// ---------------------------------------------------------------------------
// ELF builders
// ---------------------------------------------------------------------------

const PHOFF = 64;
const INTERP_OFF = 0x200;
const DYNSTR_OFF = 0x240;
const DYNSYM_OFF = 0x2a0;
const DYN_OFF = 0x300;
const NOTE_OFF = 0x380;
const SYMTAB_OFF = 0x3c0;
const SHSTR_OFF = 0x400;
const SHOFF = 0x500;
const ELF_TOTAL = 0x800;

const INTERP = "/lib64/ld-linux-x86-64.so.2\0";
const DYNSTR =
  "\0libc.so.6\0__stack_chk_fail\0__printf_chk\0printf\0/opt/lib\0";
const SHSTR =
  "\0.text\0.dynsym\0.dynstr\0.dynamic\0.note.gnu.property\0.symtab\0.shstrtab\0";

const writePhdr = (
  buf: Buffer,
  index: number,
  fields: readonly [type: number, flags: number, offset: number, size: number],
): void => {
  const [type, flags, offset, size] = fields;
  const base = PHOFF + index * 56;
  buf.writeUInt32LE(type, base);
  buf.writeUInt32LE(flags, base + 4);
  buf.writeBigUInt64LE(BigInt(offset), base + 8);
  buf.writeBigUInt64LE(BigInt(offset), base + 16);
  buf.writeBigUInt64LE(BigInt(size), base + 32);
  buf.writeBigUInt64LE(BigInt(size), base + 40);
};

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

const writeDynsym = (buf: Buffer, index: number, nameOffset: number): void => {
  const base = DYNSYM_OFF + index * 24;
  buf.writeUInt32LE(nameOffset, base);
  buf.writeUInt8(0x12, base + 4); // GLOBAL | FUNC
  buf.writeUInt16LE(0, base + 6); // SHN_UNDEF -> import
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

const writeGnuProperty = (
  buf: Buffer,
  propertyType: number,
  featureBits: number,
): void => {
  buf.writeUInt32LE(4, NOTE_OFF); // namesz
  buf.writeUInt32LE(16, NOTE_OFF + 4); // descsz
  buf.writeUInt32LE(5, NOTE_OFF + 8); // NT_GNU_PROPERTY_TYPE_0
  buf.write("GNU\0", NOTE_OFF + 12, "latin1");
  buf.writeUInt32LE(propertyType, NOTE_OFF + 16);
  buf.writeUInt32LE(4, NOTE_OFF + 20); // datasz
  buf.writeUInt32LE(featureBits, NOTE_OFF + 24);
};

/** A fully hardened ELF64: PIE, full RELRO, canary, NX, FORTIFY, CET or PAC/BTI. */
const buildHardenedElf = (
  machine = 62,
  property: { readonly type: number; readonly bits: number } = {
    type: 0xc0000002,
    bits: 0x3,
  },
): Buffer => {
  const buf = Buffer.alloc(ELF_TOTAL);
  buf.writeUInt32BE(0x7f454c46, 0);
  buf[4] = 2; // ELFCLASS64
  buf[5] = 1; // little-endian
  buf[6] = 1;
  buf.writeUInt16LE(3, 16); // ET_DYN
  buf.writeUInt16LE(machine, 18);
  buf.writeUInt32LE(1, 20);
  buf.writeBigUInt64LE(BigInt(PHOFF), 32);
  buf.writeBigUInt64LE(BigInt(SHOFF), 40);
  buf.writeUInt16LE(64, 52); // e_ehsize
  buf.writeUInt16LE(56, 54); // e_phentsize
  buf.writeUInt16LE(6, 56); // e_phnum
  buf.writeUInt16LE(64, 58); // e_shentsize
  buf.writeUInt16LE(8, 60); // e_shnum
  buf.writeUInt16LE(7, 62); // e_shstrndx
  writePhdr(buf, 0, [1, 5, 0, ELF_TOTAL]); // PT_LOAD R+X over the file
  writePhdr(buf, 1, [3, 4, INTERP_OFF, INTERP.length]); // PT_INTERP
  writePhdr(buf, 2, [2, 6, DYN_OFF, 96]); // PT_DYNAMIC
  writePhdr(buf, 3, [0x6474e551, 6, 0, 0]); // PT_GNU_STACK non-exec
  writePhdr(buf, 4, [0x6474e552, 4, DYN_OFF, 16]); // PT_GNU_RELRO
  writePhdr(buf, 5, [4, 4, NOTE_OFF, 32]); // PT_NOTE
  buf.write(INTERP, INTERP_OFF, "latin1");
  buf.write(DYNSTR, DYNSTR_OFF, "latin1");
  buf.write(SHSTR, SHSTR_OFF, "latin1");
  writeDynsym(buf, 1, 11); // __stack_chk_fail
  writeDynsym(buf, 2, 28); // __printf_chk
  writeDynsym(buf, 3, 41); // printf
  writeDyn(buf, 0, 1, 1); // DT_NEEDED libc.so.6
  writeDyn(buf, 1, 5, DYNSTR_OFF); // DT_STRTAB
  writeDyn(buf, 2, 10, DYNSTR.length); // DT_STRSZ
  writeDyn(buf, 3, 29, 48); // DT_RUNPATH -> /opt/lib
  writeDyn(buf, 4, 0x6ffffffb, 0x1); // DT_FLAGS_1 = DF_1_NOW
  writeDyn(buf, 5, 0, 0); // DT_NULL
  writeGnuProperty(buf, property.type, property.bits);
  writeShdr(buf, 0, [0, 0, 0n, 0n, 0, 0, 0, 0]);
  writeShdr(buf, 1, [1, 1, 0x6n, 0x1000n, 0, 0x40, 0, 0]); // .text
  writeShdr(buf, 2, [7, 11, 0x2n, BigInt(DYNSYM_OFF), DYNSYM_OFF, 96, 3, 24]); // .dynsym
  writeShdr(buf, 3, [
    15,
    3,
    0x2n,
    BigInt(DYNSTR_OFF),
    DYNSTR_OFF,
    DYNSTR.length,
    0,
    0,
  ]); // .dynstr
  writeShdr(buf, 4, [23, 6, 0x3n, BigInt(DYN_OFF), DYN_OFF, 96, 3, 16]); // .dynamic
  writeShdr(buf, 5, [32, 7, 0x2n, BigInt(NOTE_OFF), NOTE_OFF, 32, 0, 0]); // .note.gnu.property
  writeShdr(buf, 6, [51, 2, 0n, 0n, SYMTAB_OFF, 24, 3, 24]); // .symtab
  writeShdr(buf, 7, [59, 3, 0n, 0n, SHSTR_OFF, SHSTR.length, 0, 0]); // .shstrtab
  return buf;
};

/** A weak ELF64 executable with no section table: exec stack, RWX load, no RELRO. */
const buildWeakElf = (): Buffer => {
  const buf = Buffer.alloc(ELF_TOTAL);
  buf.writeUInt32BE(0x7f454c46, 0);
  buf[4] = 2;
  buf[5] = 1;
  buf[6] = 1;
  buf.writeUInt16LE(2, 16); // ET_EXEC
  buf.writeUInt16LE(62, 18);
  buf.writeUInt32LE(1, 20);
  buf.writeBigUInt64LE(BigInt(PHOFF), 32);
  buf.writeBigUInt64LE(0n, 40); // no section header table
  buf.writeUInt16LE(64, 52);
  buf.writeUInt16LE(56, 54);
  buf.writeUInt16LE(2, 56); // e_phnum
  buf.writeUInt16LE(64, 58);
  writePhdr(buf, 0, [1, 7, 0, ELF_TOTAL]); // PT_LOAD R+W+X
  writePhdr(buf, 1, [0x6474e551, 7, 0, 0]); // PT_GNU_STACK executable
  return buf;
};

// ---------------------------------------------------------------------------
// PE builder (header only, PE32+)
// ---------------------------------------------------------------------------

const PE_OFF = 0x80;
const PE_OPT = PE_OFF + 24;
const PE_OPT_SIZE = 240;

const buildPe = (
  dllCharacteristics: number,
  characteristics = 0x0022,
  securityDir = false,
): Buffer => {
  const buf = Buffer.alloc(0x400);
  buf.write("MZ", 0, "latin1");
  buf.writeUInt32LE(PE_OFF, 0x3c);
  buf.write("PE\0\0", PE_OFF, "latin1");
  buf.writeUInt16LE(0x8664, PE_OFF + 4); // AMD64
  buf.writeUInt16LE(0, PE_OFF + 6); // no sections
  buf.writeUInt16LE(PE_OPT_SIZE, PE_OFF + 20);
  buf.writeUInt16LE(characteristics, PE_OFF + 22);
  buf.writeUInt16LE(0x20b, PE_OPT); // PE32+
  buf.writeUInt32LE(0x1000, PE_OPT + 16); // entry rva
  buf.writeBigUInt64LE(0x1_4000_0000n, PE_OPT + 24); // image base
  buf.writeUInt32LE(0x1000, PE_OPT + 32); // section alignment
  buf.writeUInt32LE(0x200, PE_OPT + 36); // file alignment
  buf.writeUInt32LE(0x4000, PE_OPT + 56); // size of image
  buf.writeUInt32LE(0x200, PE_OPT + 60); // size of headers
  buf.writeUInt16LE(3, PE_OPT + 68); // subsystem
  buf.writeUInt16LE(dllCharacteristics, PE_OPT + 70);
  buf.writeUInt32LE(16, PE_OPT + 108); // NumberOfRvaAndSizes
  if (securityDir) {
    const base = PE_OPT + 112 + 4 * 8; // SECURITY directory (index 4)
    buf.writeUInt32LE(0x380, base); // file offset of the certificate table
    buf.writeUInt32LE(0x40, base + 4); // size
  }
  return buf;
};

// ---------------------------------------------------------------------------
// Mach-O builders
// ---------------------------------------------------------------------------

const MH_PIE = 0x200000;
const MH_NO_HEAP_EXECUTION = 0x1000000;
const MH_ALLOW_STACK_EXECUTION = 0x20000;

const restrictSegmentCommand = (): Uint8Array => {
  const bytes = new Uint8Array(72);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, 0x19, true); // LC_SEGMENT_64
  view.setUint32(4, 72, true);
  new TextEncoder().encodeInto("__RESTRICT", bytes.subarray(8, 24));
  return bytes;
};

const encryptionCommand = (cryptId: number): Uint8Array => {
  const bytes = new Uint8Array(24);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, 0x2c, true); // LC_ENCRYPTION_INFO_64
  view.setUint32(4, 24, true);
  view.setUint32(16, cryptId, true); // cryptid
  return bytes;
};

/** A code signature SuperBlob holding one CodeDirectory with CS_RUNTIME set. */
const runtimeSuperBlob = (): Buffer => {
  const blob = Buffer.alloc(64);
  blob.writeUInt32BE(0xfade0cc0, 0); // SuperBlob magic
  blob.writeUInt32BE(64, 4); // length
  blob.writeUInt32BE(1, 8); // count
  blob.writeUInt32BE(0, 12); // index[0].type = CSSLOT_CODEDIRECTORY
  blob.writeUInt32BE(20, 16); // index[0].offset
  blob.writeUInt32BE(0xfade0c02, 20); // CodeDirectory magic
  blob.writeUInt32BE(44, 24); // length
  blob.writeUInt32BE(0x20400, 28); // version
  blob.writeUInt32BE(0x10000, 32); // flags = CS_RUNTIME
  return blob;
};

const signedCodeCommand = (dataOff: number, dataSize: number): Uint8Array => {
  const bytes = new Uint8Array(16);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, 0x1d, true); // LC_CODE_SIGNATURE
  view.setUint32(4, 16, true);
  view.setUint32(8, dataOff, true);
  view.setUint32(12, dataSize, true);
  return bytes;
};

const setMachoFlags = (image: Uint8Array, flags: number): void => {
  new DataView(image.buffer, image.byteOffset).setUint32(24, flags, true);
};

const buildHardenedMacho = (): Buffer => {
  const superBlob = runtimeSuperBlob();
  const restrict = restrictSegmentCommand();
  const encryption = encryptionCommand(1);
  // Code signature command is last; its dataoff points just past the image.
  const base = machoImage({
    cpu: CPU.arm64e,
    commands: [restrict, encryption, signedCodeCommand(0, superBlob.length)],
  });
  const dataOff = base.length;
  const final = Buffer.concat([Buffer.from(base), superBlob]);
  const codeCommandOffset = 32 + restrict.length + encryption.length;
  final.writeUInt32LE(dataOff, codeCommandOffset + 8); // patch dataoff
  setMachoFlags(final, MH_PIE | MH_NO_HEAP_EXECUTION);
  return final;
};

const buildWeakMacho = (): Buffer => {
  const base = Buffer.from(
    machoImage({ cpu: CPU.x86_64, commands: [codeSignatureCommand()] }),
  );
  setMachoFlags(base, MH_ALLOW_STACK_EXECUTION);
  return base;
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("analyzeInspectBinaryHardening — ELF", () => {
  it("reports a fully hardened x86-64 ELF", async () => {
    const bytes = buildHardenedElf();
    const report = await run(bytes);
    expect(report.format).toBe("elf");
    expect(report.subject.format).toBe("elf");
    const elf = report.elf;
    expect(elf).not.toBeNull();
    expect(elf?.relro).toEqual({ value: "full", evidence_kind: "observed" });
    expect(elf?.pie).toEqual({ value: "pie", evidence_kind: "observed" });
    expect(elf?.nx).toEqual({ value: true, evidence_kind: "observed" });
    expect(elf?.stack_canary).toEqual({
      value: true,
      evidence_kind: "inferred",
    });
    expect(elf?.fortify?.fortified_count).toBe(1); // __printf_chk
    expect(elf?.fortify?.fortifiable_count).toBe(1); // the single fortifiable function printf
    expect(elf?.cet_ibt.value).toBe(true);
    expect(elf?.cet_shstk.value).toBe(true);
    expect(elf?.pac.value).toBe(false);
    expect(elf?.stripped.value).toBe(false);
    expect(elf?.runpath).toEqual(["/opt/lib"]);
    expect(elf?.rwx_segments).toEqual([]);
    expect(report.mitigations.evidence_kind).toBe("inferred");
    expect(report.mitigations.protections).toContainEqual({
      id: "relro",
      status: "enabled",
    });
    validate(bytes, report);
  });

  it("reports PAC and BTI from the aarch64 feature note", async () => {
    const bytes = buildHardenedElf(183, { type: 0xc0000000, bits: 0x3 });
    const report = await run(bytes);
    expect(report.elf?.pac.value).toBe(true);
    expect(report.elf?.bti.value).toBe(true);
    expect(report.elf?.cet_ibt.value).toBe(false);
  });

  it("reports a weak ELF without a section table", async () => {
    const bytes = buildWeakElf();
    const report = await run(bytes);
    const elf = report.elf;
    expect(elf?.relro.value).toBe("none");
    expect(elf?.pie.value).toBe("no-pie");
    expect(elf?.nx).toEqual({ value: false, evidence_kind: "observed" });
    expect(elf?.stack_canary.value).toBe(false);
    expect(elf?.fortify).toBeNull();
    expect(elf?.stripped.value).toBe(true);
    expect(elf?.rwx_segments).toHaveLength(2); // RWX PT_LOAD and the executable GNU_STACK
    expect(elf?.rwx_segments[0]?.type).toBe("PT_LOAD");
    expect(report.limitations.some((line) => line.includes("FORTIFY"))).toBe(
      true,
    );
    validate(bytes, report);
  });
});

describe("analyzeInspectBinaryHardening — PE", () => {
  it("reports a hardened PE from DllCharacteristics", async () => {
    // DYNAMIC_BASE | HIGH_ENTROPY_VA | NX_COMPAT | GUARD_CF
    const bytes = buildPe(0x0040 | 0x0020 | 0x0100 | 0x4000, 0x0022, true);
    const report = await run(bytes);
    expect(report.format).toBe("pe");
    const pe = report.pe;
    expect(pe?.dynamic_base).toEqual({
      value: true,
      evidence_kind: "observed",
    });
    expect(pe?.high_entropy_va.value).toBe(true);
    expect(pe?.nx_compat.value).toBe(true);
    expect(pe?.guard_cf.value).toBe(true);
    expect(pe?.no_seh.value).toBe(false);
    expect(pe?.isolation.value).toBe(true); // NO_ISOLATION not set
    expect(pe?.relocations_stripped.value).toBe(false);
    expect(pe?.authenticode_present.value).toBe(true);
    validate(bytes, report);
  });

  it("reports a weak PE with stripped relocations and no mitigations", async () => {
    const bytes = buildPe(0x0000, 0x0001); // RELOCS_STRIPPED
    const report = await run(bytes);
    const pe = report.pe;
    expect(pe?.dynamic_base.value).toBe(false);
    expect(pe?.nx_compat.value).toBe(false);
    expect(pe?.relocations_stripped.value).toBe(true);
    expect(pe?.authenticode_present.value).toBe(false);
    expect(pe?.gs_cookie.value).toBe(false);
    expect(report.mitigations.protections).toContainEqual({
      id: "aslr",
      status: "disabled",
    });
  });
});

describe("analyzeInspectBinaryHardening — Mach-O", () => {
  it("reports a hardened arm64e Mach-O with runtime and encryption", async () => {
    const bytes = buildHardenedMacho();
    const report = await run(bytes);
    expect(report.format).toBe("macho");
    const macho = report.macho;
    expect(macho?.pie.value).toBe(true);
    expect(macho?.no_heap_execution.value).toBe(true);
    expect(macho?.allow_stack_execution.value).toBe(false);
    expect(macho?.encrypted.value).toBe(true);
    expect(macho?.arm64e.value).toBe(true);
    expect(macho?.restrict_segment.value).toBe(true);
    expect(macho?.hardened_runtime).toEqual({
      value: true,
      evidence_kind: "observed",
    });
    validate(bytes, report);
  });

  it("reports a weak x86-64 Mach-O with an allowed executable stack", async () => {
    const bytes = buildWeakMacho();
    const report = await run(bytes);
    const macho = report.macho;
    expect(macho?.pie.value).toBe(false);
    expect(macho?.allow_stack_execution.value).toBe(true);
    expect(macho?.arm64e.value).toBe(false);
    expect(macho?.encrypted.value).toBe(false);
    // No parseable CodeDirectory -> hardened runtime is reported inferred.
    expect(macho?.hardened_runtime).toEqual({
      value: false,
      evidence_kind: "inferred",
    });
    expect(
      report.limitations.some((line) => line.includes("hardened-runtime")),
    ).toBe(true);
  });
});

describe("analyzeInspectBinaryHardening — refusals", () => {
  it("refuses content that is not an executable image", async () => {
    const bytes = Buffer.alloc(512, 0x41);
    await expect(run(bytes)).rejects.toBeInstanceOf(TriageAnalysisFailure);
  });
});
