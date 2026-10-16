import type { FormatValidator } from "./ScanEmbeddedContentReaders.js";
import {
  has,
  result,
  safe,
  u16be,
  u16le,
  u32be,
  u32le,
  u64be,
  u64le,
} from "./ScanEmbeddedContentReaders.js";

/**
 * Structural validators for executable and bytecode containers (PE, ELF,
 * thin and universal Mach-O, Dalvik DEX and Java class files). Each derives a
 * file-backed byte length from header tables where one exists, and rejects
 * offsets whose structure does not hold. `machoFat` and `javaClass` share the
 * `CA FE BA BE` magic and are written to be mutually exclusive.
 */

const pe: FormatValidator = (b, s) => {
  if (!has(b, s, 0x40)) return null;
  const lfanew = u32le(b, s + 0x3c);
  const peOff = s + lfanew;
  if (!has(b, peOff, 24) || u32be(b, peOff) !== 0x50_45_00_00) return null;
  const machine = u16le(b, peOff + 4);
  const sectionCount = u16le(b, peOff + 6);
  const optSize = u16le(b, peOff + 20);
  const optStart = peOff + 24;
  if (!has(b, optStart, optSize))
    return result(null, "high", `machine 0x${machine.toString(16)}`);
  const optMagic = has(b, optStart, 2) ? u16le(b, optStart) : 0;
  if (optMagic !== 0x10b && optMagic !== 0x20b)
    return result(null, "medium", "object or unrecognized optional header");
  let end = optStart + optSize;
  for (let i = 0; i < sectionCount && i < 96; i += 1) {
    const sh = optStart + optSize + i * 40;
    if (!has(b, sh, 40)) break;
    const rawPtr = u32le(b, sh + 20);
    if (rawPtr > 0) end = Math.max(end, rawPtr + u32le(b, sh + 16));
  }
  const certEnd = peSecurityEnd(b, optStart, optMagic);
  if (certEnd !== null) end = Math.max(end, certEnd);
  const size = end > s && end <= b.length ? end - s : null;
  return result(size, "high", `machine 0x${machine.toString(16)}`);
};

/** End of the PE certificate table (a file range, not an RVA), if declared. */
const peSecurityEnd = (
  b: Buffer,
  optStart: number,
  magic: number,
): number | null => {
  const dirBase = optStart + (magic === 0x20b ? 112 : 96) + 4 * 8;
  if (!has(b, dirBase, 8)) return null;
  const rva = u32le(b, dirBase);
  const dirSize = u32le(b, dirBase + 4);
  return rva > 0 && dirSize > 0 ? rva + dirSize : null;
};

interface ElfHeader {
  readonly s: number;
  readonly le: boolean;
  readonly is64: boolean;
  readonly phoff: number;
  readonly shoff: number;
  readonly phentsize: number;
  readonly phnum: number;
  readonly shentsize: number;
  readonly shnum: number;
}

const readElfHeader = (b: Buffer, s: number): ElfHeader | null => {
  if (!has(b, s, 0x18)) return null;
  const cls = b.readUInt8(s + 4);
  const data = b.readUInt8(s + 5);
  if (
    (cls !== 1 && cls !== 2) ||
    (data !== 1 && data !== 2) ||
    b.readUInt8(s + 6) !== 1
  )
    return null;
  const le = data === 1;
  const is64 = cls === 2;
  const empty = {
    s,
    le,
    is64,
    phoff: 0,
    shoff: 0,
    phentsize: 0,
    phnum: 0,
    shentsize: 0,
    shnum: 0,
  };
  if (!has(b, s, is64 ? 0x40 : 0x34)) return empty;
  const r16 = (o: number): number => (le ? u16le(b, s + o) : u16be(b, s + o));
  const rword = (o: number): number =>
    safe(
      is64
        ? le
          ? u64le(b, s + o)
          : u64be(b, s + o)
        : BigInt(le ? u32le(b, s + o) : u32be(b, s + o)),
    ) ?? 0;
  return {
    s,
    le,
    is64,
    phoff: rword(is64 ? 0x20 : 0x1c),
    shoff: rword(is64 ? 0x28 : 0x20),
    phentsize: r16(is64 ? 0x36 : 0x2a),
    phnum: r16(is64 ? 0x38 : 0x2c),
    shentsize: r16(is64 ? 0x3a : 0x2e),
    shnum: r16(is64 ? 0x3c : 0x30),
  };
};

const elf: FormatValidator = (b, s) => {
  const h = readElfHeader(b, s);
  if (h === null) return null;
  const header = h.is64 ? 0x40 : 0x34;
  const end = Math.max(
    header,
    h.phoff + h.phnum * h.phentsize,
    h.shoff + h.shnum * h.shentsize,
    elfSectionEnd(b, h),
  );
  const size = end > 0 && end <= b.length ? end : null;
  return result(size, "high", h.is64 ? "ELF64" : "ELF32");
};

/** Largest file-backed section end in the ELF section header table. */
const elfSectionEnd = (b: Buffer, h: ElfHeader): number => {
  const word = (o: number): number | null =>
    h.is64
      ? safe(h.le ? u64le(b, o) : u64be(b, o))
      : h.le
        ? u32le(b, o)
        : u32be(b, o);
  let end = 0;
  for (let i = 0; i < h.shnum && i < 0x4000; i += 1) {
    const sh = h.s + h.shoff + i * h.shentsize;
    if (!has(b, sh, h.is64 ? 0x28 : 0x18)) break;
    if ((h.le ? u32le(b, sh + 4) : u32be(b, sh + 4)) === 8) continue;
    const off = word(sh + (h.is64 ? 0x18 : 0x10));
    const sz = word(sh + (h.is64 ? 0x20 : 0x14));
    if (off !== null && sz !== null) end = Math.max(end, off + sz);
  }
  return end;
};

const MACHO_CPU_TYPES = new Set([
  7, 0x0100_0007, 12, 0x0100_000c, 0x0200_000c, 18, 0x0100_0012,
]);

const machoThin: FormatValidator = (b, s) => {
  if (!has(b, s, 4)) return null;
  const be = u32be(b, s);
  const map: Record<number, { le: boolean; is64: boolean }> = {
    0xcefa_edfe: { le: true, is64: false },
    0xcffa_edfe: { le: true, is64: true },
    0xfeed_face: { le: false, is64: false },
    0xfeed_facf: { le: false, is64: true },
  };
  const kind = map[be >>> 0];
  if (kind === undefined) return null;
  const hdr = kind.is64 ? 32 : 28;
  if (!has(b, s, hdr)) return null;
  const r32 = (o: number): number =>
    kind.le ? u32le(b, s + o) : u32be(b, s + o);
  const ncmds = r32(16);
  if (ncmds > 0x1_0000) return null;
  return result(
    machoThinEnd(b, { s, hdr, ncmds, le: kind.le }),
    "high",
    kind.is64 ? "64-bit" : "32-bit",
  );
};

interface MachoSpec {
  readonly s: number;
  readonly hdr: number;
  readonly ncmds: number;
  readonly le: boolean;
}

/** Largest file-backed end across LC_SEGMENT(_64)/LC_CODE_SIGNATURE commands. */
const machoThinEnd = (b: Buffer, spec: MachoSpec): number | null => {
  const { s, hdr, ncmds, le } = spec;
  const r32 = (o: number): number => (le ? u32le(b, o) : u32be(b, o));
  let cursor = s + hdr;
  let end = 0;
  for (let i = 0; i < ncmds; i += 1) {
    if (!has(b, cursor, 8)) return null;
    const cmd = r32(cursor);
    const cmdSize = r32(cursor + 4);
    if (cmdSize < 8 || !has(b, cursor, cmdSize)) return null;
    if (cmd === 0x1 && has(b, cursor, 56))
      end = Math.max(end, r32(cursor + 32) + r32(cursor + 36));
    else if (cmd === 0x19 && has(b, cursor, 72)) {
      const off = safe(le ? u64le(b, cursor + 40) : u64be(b, cursor + 40));
      const sz = safe(le ? u64le(b, cursor + 48) : u64be(b, cursor + 48));
      if (off !== null && sz !== null) end = Math.max(end, s + off + sz);
    } else if (cmd === 0x1d && has(b, cursor, 16))
      end = Math.max(end, s + r32(cursor + 8) + r32(cursor + 12));
    cursor += cmdSize;
  }
  return end > s ? end - s : null;
};

const machoFat: FormatValidator = (b, s) => {
  if (!has(b, s, 8)) return null;
  const magic = u32be(b, s) >>> 0;
  if (magic !== 0xcafe_babe && magic !== 0xcafe_babf) return null;
  const is64 = magic === 0xcafe_babf;
  const count = u32be(b, s + 4);
  if (count < 1 || count > 64) return null;
  const stride = is64 ? 32 : 20;
  let end = 0;
  for (let i = 0; i < count; i += 1) {
    const arch = s + 8 + i * stride;
    if (!has(b, arch, stride)) return null;
    if (i === 0 && !MACHO_CPU_TYPES.has(u32be(b, arch) >>> 0)) return null;
    const off = is64 ? safe(u64be(b, arch + 8)) : u32be(b, arch + 8);
    const sz = is64 ? safe(u64be(b, arch + 16)) : u32be(b, arch + 12);
    if (off !== null && sz !== null) end = Math.max(end, off + sz);
  }
  const size = end > s && end <= b.length ? end - s : null;
  return result(size, "high", `${count} slice${count === 1 ? "" : "s"}`);
};

const dex: FormatValidator = (b, s) => {
  if (!has(b, s, 0x70)) return null;
  for (let i = 4; i < 7; i += 1) {
    const c = b.readUInt8(s + i);
    if (c < 0x30 || c > 0x39) return null;
  }
  if (b.readUInt8(s + 7) !== 0) return null;
  if (u32le(b, s + 36) !== 0x70) return null;
  const size = u32le(b, s + 32);
  return result(
    size > 0 && size <= b.length ? size : null,
    "high",
    `version ${b.toString("latin1", s + 4, s + 7)}`,
  );
};

const javaClass: FormatValidator = (b, s) => {
  if (!has(b, s, 10)) return null;
  const nfat = u32be(b, s + 4);
  if (nfat >= 1 && nfat <= 64 && MACHO_CPU_TYPES.has(u32be(b, s + 8) >>> 0))
    return null;
  const major = u16be(b, s + 6);
  if (major < 43 || major > 255) return null;
  return result(null, "medium", `major version ${major}`);
};

export const EXECUTABLE_VALIDATORS = {
  pe,
  elf,
  machoThin,
  machoFat,
  dex,
  javaClass,
} as const;
