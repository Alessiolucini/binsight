import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import type {
  ElfDetails,
  ExecutableImage,
  ImageImport,
  ImageSection,
  ImageSymbol,
} from "../domain/native/image/executableImage.js";
import { parseEvidence } from "../domain/evidence.js";
import {
  AnalysisInputError,
  AnalysisOutputError,
} from "../domain/analysisErrorCore.js";
import { ok } from "../domain/result.js";
import { compareExecutablesReportSchema } from "../domain/triage/compareExecutables.js";
import { CompareExecutablesService } from "../application/triage/CompareExecutablesService.js";
import {
  compareExecutableImages,
  hardeningIndicators,
  type CompareSide,
} from "./CompareExecutables.js";

const sha = (bytes: Buffer): string =>
  createHash("sha256").update(bytes).digest("hex");

const section = (
  name: string,
  fileOffset: number,
  fileSize: number,
): ImageSection => ({
  index: 0,
  name,
  segment_name: null,
  type: null,
  file_offset: fileOffset,
  file_size: fileSize,
  virtual_address: BigInt(0x1000 + fileOffset),
  virtual_size: BigInt(fileSize),
  raw_flags: 0,
  readable: true,
  writable: false,
  executable: true,
});

const imp = (library: string | null, name: string | null): ImageImport => ({
  library,
  name,
  ordinal: null,
  delay_loaded: false,
  weak: false,
  version: null,
});

const symbol = (name: string): ImageSymbol => ({
  name,
  value: 0n,
  size: 0n,
  type: "function",
  binding: "global",
  defined: false,
  table: "dynsym",
});

const elfDetails = (overrides: Partial<ElfDetails>): ElfDetails => ({
  elf_class: 64,
  os_abi: 0,
  e_type: 3,
  machine: 62,
  e_flags: 0,
  interpreter: "/lib64/ld-linux-x86-64.so.2",
  gnu_stack: { present: true, executable: false },
  gnu_relro: { file_offset: 0, size: 16 },
  dynamic: {
    needed: [],
    soname: null,
    rpath: [],
    runpath: [],
    flags: null,
    flags_1: null,
    bind_now: true,
    has_debug_tag: false,
    text_relocations: false,
  },
  build_id: null,
  x86_feature_1: null,
  aarch64_feature_1: null,
  has_symtab: true,
  has_debug_info: false,
  comment: [],
  gnu_debuglink: null,
  ...overrides,
});

const image = (
  overrides: Partial<ExecutableImage> & { readonly elf?: ElfDetails | null },
): ExecutableImage => ({
  format: "elf",
  bits: 64,
  byte_order: "little",
  architecture: "x86_64",
  machine: 62,
  machine_name: "x86-64",
  image_offset: 0,
  image_size: 64,
  entry_point: { virtual_address: 0x1000n, file_offset: 0, section_index: 0 },
  sections: [],
  segments: [],
  imports: [],
  exports: [],
  libraries: [],
  symbols: [],
  coverage: { imports: "complete", exports: "complete", symbols: "complete" },
  overlay: null,
  container: { kind: "thin" },
  diagnostics: [],
  elf: elfDetails({}),
  pe: null,
  macho: null,
  ...overrides,
});

const side = (bytes: Buffer, img: ExecutableImage | null): CompareSide => ({
  identity: { path: `/artifacts/x`, sha256: sha(bytes), bytes: bytes.length },
  bytes,
  image: img,
});

const sidePath = (
  path: string,
  bytes: Buffer,
  img: ExecutableImage | null,
): CompareSide => ({
  identity: { path, sha256: sha(bytes), bytes: bytes.length },
  bytes,
  image: img,
});

describe("compareExecutableImages", () => {
  it("diffs imports, exports, libraries, sections, entropy and hardening by name", async () => {
    const baseBytes = Buffer.alloc(64, 0);
    const targetBytes = Buffer.from(
      Array.from({ length: 64 }, (_, index) => (index * 37) % 256),
    );
    const base = side(
      baseBytes,
      image({
        entry_point: {
          virtual_address: 0x1000n,
          file_offset: 0,
          section_index: 0,
        },
        imports: [
          imp("libc.so.6", "printf"),
          imp("libc.so.6", "__stack_chk_fail"),
          imp("libc.so.6", "__printf_chk"),
        ],
        exports: [
          {
            name: "old_export",
            ordinal: null,
            address: 0n,
            forwarder: null,
            kind: "function",
          },
        ],
        libraries: [{ name: "libc.so.6", kind: "needed" }],
        sections: [section(".text", 0, 16), section(".data", 16, 8)],
        symbols: [symbol("__stack_chk_fail")],
        elf: elfDetails({
          e_type: 3,
          interpreter: "/lib64/ld",
          has_symtab: true,
        }),
      }),
    );
    const target = side(
      targetBytes,
      image({
        entry_point: {
          virtual_address: 0x2000n,
          file_offset: 0,
          section_index: 0,
        },
        imports: [imp("libc.so.6", "printf"), imp("libm.so.6", "sqrt")],
        exports: [
          {
            name: "new_export",
            ordinal: null,
            address: 0n,
            forwarder: null,
            kind: "function",
          },
        ],
        libraries: [
          { name: "libc.so.6", kind: "needed" },
          { name: "libm.so.6", kind: "needed" },
        ],
        sections: [section(".text", 0, 16), section(".rodata", 16, 8)],
        symbols: [],
        elf: elfDetails({
          e_type: 2,
          interpreter: null,
          gnu_relro: null,
          gnu_stack: { present: true, executable: true },
          dynamic: null,
          has_symtab: false,
        }),
      }),
    );

    const report = await compareExecutableImages(base, target, 500, {});

    expect(report.identical).toBe(false);
    expect(report.format_changed.changed).toBe(false);
    expect(report.size_delta).toBe(0);
    expect(report.entry_point_changed).toEqual({
      changed: true,
      base: "0x1000",
      target: "0x2000",
    });
    expect(report.added_imports).toEqual([
      { library: "libm.so.6", name: "sqrt", ordinal: null },
    ]);
    expect(report.removed_imports).toContainEqual({
      library: "libc.so.6",
      name: "__stack_chk_fail",
      ordinal: null,
    });
    expect(report.added_exports).toEqual([
      { name: "new_export", ordinal: null },
    ]);
    expect(report.removed_exports).toEqual([
      { name: "old_export", ordinal: null },
    ]);
    expect(report.added_libraries).toEqual(["libm.so.6"]);
    expect(report.removed_libraries).toEqual([]);
    expect(report.added_sections).toEqual([".rodata"]);
    expect(report.removed_sections).toEqual([".data"]);

    expect(report.section_entropy_deltas).toHaveLength(1);
    const text = report.section_entropy_deltas[0]!;
    expect(text.name).toBe(".text");
    expect(text.base_entropy).toBe(0);
    expect(text.target_entropy).toBeGreaterThan(0);
    expect(text.delta).toBeCloseTo(text.target_entropy - text.base_entropy, 6);

    const changed = new Map(
      report.hardening_changes.map((entry) => [entry.indicator, entry]),
    );
    expect(changed.get("elf.pie")).toEqual({
      indicator: "elf.pie",
      base: "pie",
      target: "no-pie",
    });
    expect(changed.get("elf.relro")).toEqual({
      indicator: "elf.relro",
      base: "full",
      target: "none",
    });
    expect(changed.get("elf.nx")).toEqual({
      indicator: "elf.nx",
      base: "nx",
      target: "exec-stack",
    });
    expect(changed.get("elf.stripped")).toEqual({
      indicator: "elf.stripped",
      base: "no",
      target: "yes",
    });
    expect(changed.get("elf.stack_canary")).toEqual({
      indicator: "elf.stack_canary",
      base: "present",
      target: "not-observed",
    });
    expect(changed.get("elf.fortify")?.base).toBe("present");

    // The built report is schema-valid (compareExecutableImages parses it).
    expect(() => compareExecutablesReportSchema.parse(report)).not.toThrow();
  });
});

describe("compareExecutableImages edge cases", () => {
  it("reports only size, hash and format when one file is not an image", async () => {
    const baseBytes = Buffer.alloc(32, 1);
    const targetBytes = Buffer.alloc(40, 2);
    const base = side(baseBytes, image({}));
    const target = side(targetBytes, null);

    const report = await compareExecutableImages(base, target, 500, {});

    expect(report.format_changed).toEqual({
      changed: true,
      base: "elf",
      target: "file",
    });
    expect(report.size_delta).toBe(8);
    expect(report.added_imports).toEqual([]);
    expect(report.removed_imports).toEqual([]);
    expect(report.section_entropy_deltas).toEqual([]);
    expect(
      report.hardening_changes.every((entry) => entry.target === null),
    ).toBe(true);
    expect(
      report.limitations.some((note) =>
        note.includes("not a recognized ELF, PE or Mach-O image"),
      ),
    ).toBe(true);
  });

  it("marks identical files and empties every difference list", async () => {
    const bytes = Buffer.alloc(48, 7);
    const img = image({ sections: [section(".text", 0, 16)] });
    const report = await compareExecutableImages(
      side(bytes, img),
      side(bytes, img),
      500,
      {},
    );

    expect(report.identical).toBe(true);
    expect(report.size_delta).toBe(0);
    expect(report.entry_point_changed.changed).toBe(false);
    expect(report.hardening_changes).toEqual([]);
    expect(report.section_entropy_deltas[0]?.delta).toBe(0);
  });

  it("bounds each difference list to max_list and records coverage", async () => {
    const baseLibraries = Array.from({ length: 10 }, (_, index) => ({
      name: `libbase${index}.so`,
      kind: "needed" as const,
    }));
    const base = side(Buffer.alloc(16, 0), image({ libraries: baseLibraries }));
    const target = side(Buffer.alloc(16, 0), image({ libraries: [] }));

    const report = await compareExecutableImages(base, target, 3, {});

    expect(report.removed_libraries).toHaveLength(3);
    expect(report.removed_library_coverage).toEqual({
      total: 10,
      returned: 3,
      truncated: true,
    });
    expect(
      report.limitations.some((note) =>
        note.includes("reached the max_list bound"),
      ),
    ).toBe(true);
  });
});

describe("hardeningIndicators", () => {
  it("reads PE DLL-characteristics bits and Authenticode presence", () => {
    const pe = hardeningIndicators(
      image({
        format: "pe",
        elf: null,
        pe: {
          pe32_plus: true,
          machine: 0x8664,
          time_date_stamp: 0,
          characteristics: 0,
          subsystem: 3,
          dll_characteristics: 0x0040 | 0x0100 | 0x4000,
          image_base: 0x140000000n,
          size_of_image: 0x1000,
          size_of_headers: 0x400,
          checksum: 0,
          computed_checksum: 0,
          linker_version: "14.0",
          os_version: "6.0",
          subsystem_version: "6.0",
          data_directories: [],
          rich_header: null,
          load_config: null,
          tls_callbacks: null,
          debug_types: [],
          codeview: null,
          ex_dll_characteristics: null,
          security_directory: { file_offset: 100, size: 20 },
          managed: false,
          base_relocations: true,
          resources: false,
        },
      }),
    );
    expect(pe.get("pe.dynamic_base")).toBe("enabled");
    expect(pe.get("pe.nx_compat")).toBe("enabled");
    expect(pe.get("pe.guard_cf")).toBe("enabled");
    expect(pe.get("pe.high_entropy_va")).toBe("disabled");
    expect(pe.get("pe.authenticode")).toBe("present");
  });

  it("returns an empty map for a non-image file", () => {
    expect(hardeningIndicators(null).size).toBe(0);
  });
});

describe("CompareExecutablesService", () => {
  const identity = {
    id: "fixture",
    name: "fixture comparison seam",
    version: "1",
  };

  const buildReport = async () => {
    const baseBytes = Buffer.alloc(32, 0);
    const targetBytes = Buffer.alloc(40, 3);
    return compareExecutableImages(
      sidePath(
        "/artifacts/base",
        baseBytes,
        image({ sections: [section(".text", 0, 16)] }),
      ),
      sidePath(
        "/artifacts/target",
        targetBytes,
        image({ sections: [section(".text", 0, 16)] }),
      ),
      500,
      {},
    );
  };

  it("rejects a relative path and extra arguments before reading", async () => {
    let calls = 0;
    const service = new CompareExecutablesService({
      identity,
      compare: async () => {
        calls += 1;
        return ok(await buildReport());
      },
    });
    const relative = await service.compare({
      base_path: "base",
      target_path: "/artifacts/target",
    });
    const extra = await service.compare({
      base_path: "/artifacts/base",
      target_path: "/artifacts/target",
      nope: true,
    });
    expect(relative.ok).toBe(false);
    expect(extra.ok).toBe(false);
    if (!relative.ok) expect(relative.error).toBeInstanceOf(AnalysisInputError);
    expect(calls).toBe(0);
  });

  it("fails closed when the report changes a selected identity", async () => {
    const service = new CompareExecutablesService({
      identity,
      compare: async () => {
        const report = await buildReport();
        return ok({
          ...report,
          target: { ...report.target, path: "/artifacts/other" },
        });
      },
    });
    const result = await service.compare({
      base_path: "/artifacts/base",
      target_path: "/artifacts/target",
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(AnalysisOutputError);
  });

  it("builds derived, analyst-inference Evidence whose subject is the target", async () => {
    const service = new CompareExecutablesService({
      identity,
      compare: async () => ok(await buildReport()),
    });
    const result = await service.compare({
      base_path: "/artifacts/base",
      target_path: "/artifacts/target",
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const evidence = parseEvidence(result.value);
    expect(evidence.confidence).toBe("derived");
    expect(evidence.authority).toBe("analyst-inference");
    expect(evidence.subject?.local_path).toBe("/artifacts/target");
    expect(evidence.evidence_links).toEqual([]);
    expect(evidence.locations).toContainEqual({
      kind: "artifact-path",
      path: "/artifacts/base",
    });
  });
});
