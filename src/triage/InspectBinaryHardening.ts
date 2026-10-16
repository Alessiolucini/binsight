import type { ExecutableImage } from "../domain/native/image/executableImage.js";
import { toHexAddress } from "../domain/triage/triageCommon.js";
import type {
  ElfHardening,
  HardeningEvidenceKind,
  HardeningFlag,
  InspectBinaryHardeningInput,
  InspectBinaryHardeningReport,
  MachoHardening,
  Mitigations,
  PeHardening,
  RwxSegment,
} from "../domain/triage/inspectBinaryHardening.js";
import {
  checkTriageCancelled,
  requireTriageImage,
  triageSubject,
  type TriageAnalysisContext,
} from "./triageSupport.js";

/** Longest list of writable-executable segments the report will enumerate. */
const MAX_RWX_SEGMENTS = 64;

const observed = (value: boolean): HardeningFlag => ({
  value,
  evidence_kind: "observed",
});

const inferred = (value: boolean): HardeningFlag => ({
  value,
  evidence_kind: "inferred",
});

const flag = (value: boolean, kind: HardeningEvidenceKind): HardeningFlag => ({
  value,
  evidence_kind: kind,
});

const CANARY_SYMBOLS = /stack_chk_(fail|guard)|__stack_smash_handler/u;
const SECURITY_COOKIE = /__(intel_)?security_cookie|__security_init_cookie/u;

/** True when any imported or defined symbol name matches the pattern. */
const hasSymbolMatching = (
  image: ExecutableImage,
  pattern: RegExp,
): boolean => {
  for (const entry of image.imports)
    if (entry.name !== null && pattern.test(entry.name)) return true;
  for (const symbol of image.symbols)
    if (pattern.test(symbol.name)) return true;
  return false;
};

/** glibc functions that have a `__*_chk` fortified counterpart. */
const FORTIFIABLE = new Set<string>([
  "memcpy",
  "memmove",
  "memset",
  "mempcpy",
  "strcpy",
  "stpcpy",
  "strncpy",
  "stpncpy",
  "strcat",
  "strncat",
  "sprintf",
  "snprintf",
  "vsprintf",
  "vsnprintf",
  "printf",
  "fprintf",
  "vprintf",
  "vfprintf",
  "gets",
  "fgets",
  "read",
  "pread",
  "pread64",
  "recv",
  "recvfrom",
  "readlink",
  "readlinkat",
  "getcwd",
  "getwd",
  "realpath",
  "ptsname_r",
  "wctomb",
  "mbstowcs",
  "wcrtomb",
  "wcscpy",
  "wcpcpy",
  "wcsncpy",
  "wcscat",
  "wcsncat",
  "wmemcpy",
  "wmemmove",
  "wmempcpy",
  "wmemset",
  "swprintf",
  "vswprintf",
  "fread",
  "fread_unlocked",
  "poll",
  "ppoll",
  "confstr",
  "getgroups",
  "getdomainname",
  "gethostname",
  "ttyname_r",
  "asprintf",
  "vasprintf",
  "dprintf",
  "vdprintf",
  "obstack_printf",
  "obstack_vprintf",
  "fwprintf",
  "wprintf",
  "syslog",
  "vsyslog",
  "explicit_bzero",
]);

const CHK_SUFFIX = /_chk$/u;
const LEADING_UNDERSCORES = /^_+/u;

/** Strip the fortify decoration to recover the underlying libc base name. */
const fortifyBaseName = (name: string): string =>
  name.replace(LEADING_UNDERSCORES, "").replace(CHK_SUFFIX, "");

const importNames = (image: ExecutableImage): readonly string[] =>
  image.imports
    .map((entry) => entry.name)
    .filter((name): name is string => name !== null);

/** FORTIFY accounting, or null when no symbol/import table is available. */
const elfFortify = (image: ExecutableImage): ElfHardening["fortify"] => {
  if (image.coverage.imports === "unavailable") return null;
  const names = importNames(image);
  const fortified = new Set<string>();
  const fortifiable = new Set<string>();
  for (const name of names) {
    const base = fortifyBaseName(name);
    if (CHK_SUFFIX.test(name)) {
      fortified.add(base);
      fortifiable.add(base);
    } else if (FORTIFIABLE.has(base)) fortifiable.add(base);
  }
  return {
    fortified_count: fortified.size,
    fortifiable_count: fortifiable.size,
    evidence_kind: "inferred",
  };
};

/** PIE classification from ELF type and the presence of a program interpreter. */
const elfPie = (image: ExecutableImage): ElfHardening["pie"] => {
  const details = image.elf;
  if (details === null) return { value: "no-pie", evidence_kind: "inferred" };
  if (details.e_type === 3)
    return details.interpreter !== null
      ? { value: "pie", evidence_kind: "observed" }
      : { value: "dso", evidence_kind: "observed" };
  return { value: "no-pie", evidence_kind: "observed" };
};

const elfRelro = (image: ExecutableImage): ElfHardening["relro"] => {
  const details = image.elf;
  if (details === null || details.gnu_relro === null)
    return { value: "none", evidence_kind: "observed" };
  return details.dynamic?.bind_now === true
    ? { value: "full", evidence_kind: "observed" }
    : { value: "partial", evidence_kind: "observed" };
};

const elfRwxSegments = (
  image: ExecutableImage,
): { readonly list: RwxSegment[]; readonly total: number } => {
  const all = image.segments.filter(
    (segment) => segment.readable && segment.writable && segment.executable,
  );
  const list = all.slice(0, MAX_RWX_SEGMENTS).map((segment) => ({
    index: segment.index,
    type: segment.type,
    file_offset: segment.file_offset,
    virtual_address: toHexAddress(segment.virtual_address),
  }));
  return { list, total: all.length };
};

const elfBlock = (image: ExecutableImage): ElfHardening => {
  const details = image.elf;
  const stack = details?.gnu_stack ?? { present: false, executable: false };
  const x86 = details?.x86_feature_1 ?? null;
  const arm = details?.aarch64_feature_1 ?? null;
  const rwx = elfRwxSegments(image);
  return {
    relro: elfRelro(image),
    stack_canary: inferred(hasSymbolMatching(image, CANARY_SYMBOLS)),
    nx: flag(!stack.executable, stack.present ? "observed" : "inferred"),
    pie: elfPie(image),
    rpath: [...(details?.dynamic?.rpath ?? [])],
    runpath: [...(details?.dynamic?.runpath ?? [])],
    fortify: elfFortify(image),
    cet_ibt: flag(x86 !== null && (x86 & 0x1) !== 0, "observed"),
    cet_shstk: flag(x86 !== null && (x86 & 0x2) !== 0, "observed"),
    pac: flag(arm !== null && (arm & 0x2) !== 0, "observed"),
    bti: flag(arm !== null && (arm & 0x1) !== 0, "observed"),
    stripped: flag(details?.has_symtab !== true, "observed"),
    rwx_segments: rwx.list,
    rwx_segment_coverage: {
      total: rwx.total,
      returned: rwx.list.length,
      truncated: rwx.total > rwx.list.length,
    },
  };
};

const IMAGE_FILE_RELOCS_STRIPPED = 0x0001;
const DLL_HIGH_ENTROPY_VA = 0x0020;
const DLL_DYNAMIC_BASE = 0x0040;
const DLL_FORCE_INTEGRITY = 0x0080;
const DLL_NX_COMPAT = 0x0100;
const DLL_NO_ISOLATION = 0x0200;
const DLL_NO_SEH = 0x0400;
const DLL_APPCONTAINER = 0x1000;
const DLL_GUARD_CF = 0x4000;
const DLL_EX_CET_COMPAT = 0x0001;

const peBlock = (image: ExecutableImage): PeHardening => {
  const details = image.pe;
  const dll = details?.dll_characteristics ?? 0;
  const characteristics = details?.characteristics ?? 0;
  const ex = details?.ex_dll_characteristics ?? null;
  const load = details?.load_config ?? null;
  const safeSeh =
    details !== null &&
    !details.pe32_plus &&
    load !== null &&
    load.se_handler_table !== null &&
    load.se_handler_count !== null &&
    load.se_handler_count > 0n &&
    (dll & DLL_NO_SEH) === 0;
  const gsCookie =
    load !== null &&
    load.security_cookie !== null &&
    load.security_cookie !== 0n;
  return {
    dynamic_base: observed((dll & DLL_DYNAMIC_BASE) !== 0),
    high_entropy_va: observed((dll & DLL_HIGH_ENTROPY_VA) !== 0),
    nx_compat: observed((dll & DLL_NX_COMPAT) !== 0),
    force_integrity: observed((dll & DLL_FORCE_INTEGRITY) !== 0),
    no_seh: observed((dll & DLL_NO_SEH) !== 0),
    guard_cf: observed((dll & DLL_GUARD_CF) !== 0),
    safe_seh: flag(safeSeh, "observed"),
    gs_cookie: flag(gsCookie, "observed"),
    cet_compat: flag(ex !== null && (ex & DLL_EX_CET_COMPAT) !== 0, "observed"),
    isolation: observed((dll & DLL_NO_ISOLATION) === 0),
    appcontainer: observed((dll & DLL_APPCONTAINER) !== 0),
    relocations_stripped: observed(
      (characteristics & IMAGE_FILE_RELOCS_STRIPPED) !== 0,
    ),
    authenticode_present: observed(details?.security_directory != null),
  };
};

const MH_ALLOW_STACK_EXECUTION = 0x20000;
const MH_PIE = 0x200000;
const MH_NO_HEAP_EXECUTION = 0x1000000;
const CPU_TYPE_ARM64 = 0x0100000c;
const CPU_SUBTYPE_ARM64E = 2;
const CPU_SUBTYPE_MASK = 0x00ffffff;
const CS_SUPERBLOB_MAGIC = 0xfade0cc0;
const CS_CODEDIRECTORY_MAGIC = 0xfade0c02;
const CS_RUNTIME = 0x10000;

/**
 * Hardened-runtime flag from the embedded CodeDirectory, when a code signature
 * is present and parseable. Returns null when no signature structure is found,
 * so the caller can mark the indicator inferred.
 */
const machoHardenedRuntime = (
  bytes: Buffer,
  image: ExecutableImage,
): boolean | null => {
  const range = image.macho?.code_signature ?? null;
  if (range === null) return null;
  const base = range.file_offset;
  if (base + 12 > bytes.length || range.size < 12) return null;
  if (bytes.readUInt32BE(base) !== CS_SUPERBLOB_MAGIC) return null;
  const count = bytes.readUInt32BE(base + 8);
  const limit = Math.min(count, 1024);
  for (let index = 0; index < limit; index += 1) {
    const entry = base + 12 + index * 8;
    if (entry + 8 > bytes.length) break;
    const blobOffset = base + bytes.readUInt32BE(entry + 4);
    if (blobOffset + 16 > bytes.length) continue;
    if (bytes.readUInt32BE(blobOffset) !== CS_CODEDIRECTORY_MAGIC) continue;
    return (bytes.readUInt32BE(blobOffset + 12) & CS_RUNTIME) !== 0;
  }
  return false;
};

const machoBlock = (bytes: Buffer, image: ExecutableImage): MachoHardening => {
  const details = image.macho;
  const flags = details?.flags ?? 0;
  const encryption = details?.encryption ?? null;
  const hardened = machoHardenedRuntime(bytes, image);
  const isArm64e =
    details !== null &&
    details.cpu_type === CPU_TYPE_ARM64 &&
    (details.cpu_subtype & CPU_SUBTYPE_MASK) === CPU_SUBTYPE_ARM64E;
  return {
    pie: observed((flags & MH_PIE) !== 0),
    allow_stack_execution: observed((flags & MH_ALLOW_STACK_EXECUTION) !== 0),
    no_heap_execution: observed((flags & MH_NO_HEAP_EXECUTION) !== 0),
    encrypted: observed(encryption !== null && encryption.crypt_id !== 0),
    hardened_runtime: hardened === null ? inferred(false) : observed(hardened),
    arm64e: observed(isArm64e),
    restrict_segment: observed(details?.has_restrict_segment === true),
    stack_chk: inferred(
      hasSymbolMatching(image, CANARY_SYMBOLS) ||
        hasSymbolMatching(image, SECURITY_COOKIE),
    ),
  };
};

const onOff = (enabled: boolean): "enabled" | "disabled" =>
  enabled ? "enabled" : "disabled";

const elfMitigations = (elf: ElfHardening): Mitigations["protections"] => [
  {
    id: "relro",
    status:
      elf.relro.value === "none"
        ? "disabled"
        : elf.relro.value === "partial"
          ? "partial"
          : "enabled",
  },
  { id: "stack-canary", status: onOff(elf.stack_canary.value) },
  { id: "nx", status: onOff(elf.nx.value) },
  {
    id: "pie",
    status:
      elf.pie.value === "pie"
        ? "enabled"
        : elf.pie.value === "dso"
          ? "unknown"
          : "disabled",
  },
  {
    id: "fortify",
    status:
      elf.fortify === null ? "unknown" : onOff(elf.fortify.fortified_count > 0),
  },
  { id: "cet", status: onOff(elf.cet_ibt.value || elf.cet_shstk.value) },
  { id: "pac-bti", status: onOff(elf.pac.value || elf.bti.value) },
];

const peMitigations = (pe: PeHardening): Mitigations["protections"] => [
  { id: "aslr", status: onOff(pe.dynamic_base.value) },
  { id: "high-entropy-aslr", status: onOff(pe.high_entropy_va.value) },
  { id: "dep-nx", status: onOff(pe.nx_compat.value) },
  { id: "safe-seh", status: onOff(pe.safe_seh.value || pe.no_seh.value) },
  { id: "control-flow-guard", status: onOff(pe.guard_cf.value) },
  { id: "gs-cookie", status: onOff(pe.gs_cookie.value) },
  { id: "cet", status: onOff(pe.cet_compat.value) },
  { id: "authenticode", status: onOff(pe.authenticode_present.value) },
];

const machoMitigations = (
  macho: MachoHardening,
): Mitigations["protections"] => [
  { id: "pie", status: onOff(macho.pie.value) },
  { id: "nx-stack", status: onOff(!macho.allow_stack_execution.value) },
  { id: "nx-heap", status: onOff(macho.no_heap_execution.value) },
  { id: "stack-canary", status: onOff(macho.stack_chk.value) },
  { id: "hardened-runtime", status: onOff(macho.hardened_runtime.value) },
  { id: "ptrauth", status: onOff(macho.arm64e.value) },
];

/** Authority caveats plus a caveat for every indicator that stays uncertain. */
const buildLimitations = (
  format: "elf" | "pe" | "macho",
  elf: ElfHardening | null,
  macho: MachoHardening | null,
): string[] => {
  const limitations = [
    "Hardening indicators are read from file headers, symbol tables and signature structures; they describe how the shipped file is marked, not proof that every function or code path is protected.",
    "An absent stack-canary symbol does not prove that every function is unprotected, and a present one does not prove universal coverage.",
    "NX (non-executable memory marking) and executable-stack are reported as separate indicators; neither implies the other.",
    "No target execution, no network access and no file writes occur; the file is read once into bounded memory.",
  ];
  if (format === "macho")
    limitations.push(
      "Mach-O code-signature structure is only read for the hardened-runtime flag; the certificate chain and OS trust are not evaluated, so presence is not validity.",
    );
  if (elf !== null && elf.fortify === null)
    limitations.push(
      "FORTIFY_SOURCE could not be assessed: no dynamic symbol or import table was available.",
    );
  if (elf !== null && elf.stripped.value)
    limitations.push(
      "The ELF has no symbol table; the stack-canary indicator is inferred from the dynamic imports that remain and may understate protection.",
    );
  if (elf !== null && !elf.nx.value && elf.nx.evidence_kind === "inferred")
    limitations.push(
      "No PT_GNU_STACK program header was present; the NX marking is inferred from the loader default rather than observed.",
    );
  if (macho !== null && macho.hardened_runtime.evidence_kind === "inferred")
    limitations.push(
      "No LC_CODE_SIGNATURE was present, so the hardened-runtime flag is reported as not observed rather than measured.",
    );
  return limitations;
};

/**
 * Report binary-hardening indicators for one ELF, PE or Mach-O image. Non
 * executable content is refused as an unsupported target. Pure, deterministic
 * and bounded: it only reads the already-parsed image model plus, for Mach-O,
 * the embedded CodeDirectory flags.
 */
export const analyzeInspectBinaryHardening = async (
  bytes: Buffer,
  input: InspectBinaryHardeningInput,
  context: TriageAnalysisContext,
): Promise<Omit<InspectBinaryHardeningReport, "artifact">> => {
  checkTriageCancelled(context.signal);
  const image = requireTriageImage(bytes, input.slice);
  checkTriageCancelled(context.signal);
  const elf = image.format === "elf" ? elfBlock(image) : null;
  const pe = image.format === "pe" ? peBlock(image) : null;
  const macho = image.format === "macho" ? machoBlock(bytes, image) : null;
  const protections =
    elf !== null
      ? elfMitigations(elf)
      : pe !== null
        ? peMitigations(pe)
        : macho !== null
          ? machoMitigations(macho)
          : [];
  return {
    subject: triageSubject(image),
    format: image.format,
    elf,
    pe,
    macho,
    mitigations: { evidence_kind: "inferred", protections },
    limitations: buildLimitations(image.format, elf, macho),
  };
};
