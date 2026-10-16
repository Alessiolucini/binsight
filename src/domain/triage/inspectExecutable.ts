import { z } from "zod";
import {
  hexAddressSchema,
  refineOffsetsInside,
  triageListCoverageSchema,
  triagePathSchema,
  triageReportBase,
  triageSliceSchema,
} from "./triageCommon.js";

const nonNegative = z.number().int().nonnegative();

/** Structural list categories the caller can include; symbols are opt-in. */
export const inspectExecutableIncludeSchema = z.enum([
  "sections",
  "segments",
  "imports",
  "exports",
  "symbols",
  "libraries",
]);
export type InspectExecutableInclude = z.infer<
  typeof inspectExecutableIncludeSchema
>;

/** All structural lists except the symbol table, the include default. */
export const INSPECT_EXECUTABLE_DEFAULT_INCLUDE: readonly InspectExecutableInclude[] =
  ["sections", "segments", "imports", "exports", "libraries"];

/** Largest number of entries any one list may return. */
export const INSPECT_EXECUTABLE_MAX_LIST = 5000;

/** One explicit local executable plus which lists and how many entries to return. */
export const inspectExecutableInputSchema = z.strictObject({
  path: triagePathSchema,
  slice: triageSliceSchema,
  include: z
    .array(inspectExecutableIncludeSchema)
    .max(6)
    .default([...INSPECT_EXECUTABLE_DEFAULT_INCLUDE])
    .describe(
      'Structural lists to populate; defaults to all except "symbols".',
    ),
  max_list: z
    .number()
    .int()
    .min(1)
    .max(INSPECT_EXECUTABLE_MAX_LIST)
    .default(500)
    .describe("Maximum entries returned per list before truncation"),
});
export type InspectExecutableInput = z.infer<
  typeof inspectExecutableInputSchema
>;

/** Three-character rwx permission string; a cleared bit is a dash. */
const permissionsSchema = z
  .string()
  .regex(/^[r\x2d][w\x2d][x\x2d]$/u)
  .describe("Mapped permissions as r/w/x, a cleared bit shown as -");

const machineSchema = z.strictObject({
  value: nonNegative,
  name: z.string(),
});

const entryPointSchema = z.strictObject({
  virtual_address: hexAddressSchema.nullable(),
  file_offset: nonNegative.nullable(),
  section: z.string().nullable(),
});

const countsSchema = z.strictObject({
  sections: nonNegative,
  segments: nonNegative,
  imports: nonNegative,
  exports: nonNegative,
  symbols: nonNegative,
  libraries: nonNegative,
});

const sectionSchema = z.strictObject({
  index: nonNegative,
  name: z.string(),
  /** ELF sh_type or Mach-O section type name, null when the format has none. */
  type: z.string().nullable(),
  /** Mach-O owning segment; null for ELF and PE. */
  segment_name: z.string().nullable(),
  permissions: permissionsSchema,
  file_offset: nonNegative,
  file_size: nonNegative,
  virtual_address: hexAddressSchema,
  virtual_size: hexAddressSchema,
});

const segmentSchema = z.strictObject({
  index: nonNegative,
  name: z.string().nullable(),
  type: z.string(),
  permissions: permissionsSchema,
  file_offset: nonNegative,
  file_size: nonNegative,
  virtual_address: hexAddressSchema,
  memory_size: hexAddressSchema,
});

const importSchema = z.strictObject({
  library: z.string().nullable(),
  name: z.string().nullable(),
  ordinal: nonNegative.nullable(),
  delay_loaded: z.boolean(),
  weak: z.boolean(),
  version: z.string().nullable(),
});

const exportSchema = z.strictObject({
  name: z.string().nullable(),
  ordinal: nonNegative.nullable(),
  address: hexAddressSchema.nullable(),
  forwarder: z.string().nullable(),
  kind: z.enum(["function", "object", "unknown"]),
});

const librarySchema = z.strictObject({
  name: z.string(),
  kind: z.enum([
    "needed",
    "delay",
    "weak",
    "reexport",
    "upward",
    "lazy",
    "import",
  ]),
});

const symbolSchema = z.strictObject({
  name: z.string(),
  value: hexAddressSchema,
  size: hexAddressSchema,
  type: z.enum(["function", "object", "section", "file", "tls", "other"]),
  binding: z.enum(["local", "global", "weak", "other"]),
  defined: z.boolean(),
  table: z.enum(["dynsym", "symtab", "nlist", "coff"]),
});

const rangeSchema = z.strictObject({
  file_offset: nonNegative,
  size: nonNegative,
});

const fatSliceSchema = z.strictObject({
  cpu_type: nonNegative,
  cpu_subtype: nonNegative,
  architecture: z.string().min(1).nullable(),
  file_offset: nonNegative,
  size: nonNegative,
  align: nonNegative,
});

const containerSchema = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("thin") }),
  z.strictObject({
    kind: z.literal("fat"),
    selected_index: nonNegative,
    slices: z.array(fatSliceSchema),
  }),
]);

/** Compact ELF identity block layered over observed header fields. */
const elfDetailSchema = z.strictObject({
  elf_class: z.union([z.literal(32), z.literal(64)]),
  os_abi: nonNegative,
  e_type: nonNegative,
  machine: nonNegative,
  e_flags: nonNegative,
  interpreter: z.string().nullable(),
  soname: z.string().nullable(),
  rpath: z.array(z.string()),
  runpath: z.array(z.string()),
  bind_now: z.boolean(),
  text_relocations: z.boolean(),
  gnu_stack: z.strictObject({
    present: z.boolean(),
    executable: z.boolean(),
  }),
  gnu_relro: z.boolean(),
  build_id: z.string().nullable(),
  x86_feature_1: nonNegative.nullable(),
  aarch64_feature_1: nonNegative.nullable(),
  has_symtab: z.boolean(),
  has_debug_info: z.boolean(),
  gnu_debuglink: z.string().nullable(),
  comment: z.array(z.string()),
});

/** Compact PE identity block layered over observed header fields. */
const peDetailSchema = z.strictObject({
  pe32_plus: z.boolean(),
  machine: nonNegative,
  time_date_stamp: nonNegative,
  characteristics: nonNegative,
  subsystem: nonNegative,
  dll_characteristics: nonNegative,
  image_base: hexAddressSchema,
  size_of_image: nonNegative,
  size_of_headers: nonNegative,
  checksum: nonNegative,
  computed_checksum: nonNegative,
  linker_version: z.string(),
  os_version: z.string(),
  subsystem_version: z.string(),
  data_directories: z.array(
    z.strictObject({
      index: nonNegative,
      name: z.string(),
      rva: nonNegative,
      size: nonNegative,
    }),
  ),
  rich_header: z
    .strictObject({
      file_offset: nonNegative,
      xor_key: nonNegative,
      checksum_valid: z.boolean(),
      entry_count: nonNegative,
      entries: z.array(
        z.strictObject({
          product_id: nonNegative,
          build: nonNegative,
          count: nonNegative,
        }),
      ),
    })
    .nullable(),
  codeview: z
    .strictObject({
      signature: z.enum(["RSDS", "NB10"]),
      identifier: z.string(),
      age: nonNegative,
      pdb_path: z.string(),
    })
    .nullable(),
  load_config: z
    .strictObject({
      size: nonNegative,
      security_cookie: hexAddressSchema.nullable(),
      guard_flags: nonNegative.nullable(),
    })
    .nullable(),
  tls_callback_count: nonNegative.nullable(),
  debug_types: z.array(nonNegative),
  ex_dll_characteristics: nonNegative.nullable(),
  managed: z.boolean(),
  base_relocations: z.boolean(),
  resources: z.boolean(),
  security_directory: rangeSchema.nullable(),
});

/** Compact Mach-O identity block layered over observed load commands. */
const machoDetailSchema = z.strictObject({
  cpu_type: nonNegative,
  cpu_subtype: nonNegative,
  file_type: nonNegative,
  flags: nonNegative,
  uuid: z.string().nullable(),
  id_dylib: z.string().nullable(),
  source_version: z.string().nullable(),
  rpaths: z.array(z.string()),
  build_versions: z.array(
    z.strictObject({
      platform: nonNegative,
      minimum_os: z.string(),
      sdk: z.string(),
    }),
  ),
  encryption: z
    .strictObject({
      crypt_offset: nonNegative,
      crypt_size: nonNegative,
      crypt_id: nonNegative,
    })
    .nullable(),
  code_signature: rangeSchema.nullable(),
  has_restrict_segment: z.boolean(),
  uses_chained_fixups: z.boolean(),
  load_command_count: nonNegative,
});

export type InspectExecutableElf = z.infer<typeof elfDetailSchema>;
export type InspectExecutablePe = z.infer<typeof peDetailSchema>;
export type InspectExecutableMacho = z.infer<typeof machoDetailSchema>;

/** Unified structural view of one ELF/PE/Mach-O image, bounded per list. */
export const inspectExecutableReportSchema = z
  .strictObject({
    ...triageReportBase,
    format: z.enum(["elf", "pe", "macho"]),
    bits: z.union([z.literal(32), z.literal(64)]),
    byte_order: z.enum(["little", "big"]),
    architecture: z.string().min(1).nullable(),
    machine: machineSchema,
    entry_point: entryPointSchema,
    counts: countsSchema,
    sections: z.array(sectionSchema),
    sections_coverage: triageListCoverageSchema,
    segments: z.array(segmentSchema),
    segments_coverage: triageListCoverageSchema,
    imports: z.array(importSchema),
    imports_coverage: triageListCoverageSchema,
    exports: z.array(exportSchema),
    exports_coverage: triageListCoverageSchema,
    libraries: z.array(librarySchema),
    libraries_coverage: triageListCoverageSchema,
    symbols: z.array(symbolSchema),
    symbols_coverage: triageListCoverageSchema,
    overlay: rangeSchema.nullable(),
    container: containerSchema,
    elf: elfDetailSchema.nullable(),
    pe: peDetailSchema.nullable(),
    macho: machoDetailSchema.nullable(),
  })
  .superRefine((report, context) => {
    checkFormatDetail(report, context);
    checkCoverage(report, context);
    refineOffsetsInside(report.artifact.bytes, offsetsOf(report), context);
  });

export type InspectExecutableReport = z.infer<
  typeof inspectExecutableReportSchema
>;

const checkFormatDetail = (
  report: InspectExecutableReport,
  context: z.RefinementCtx,
): void => {
  const detailByFormat = {
    elf: report.elf,
    pe: report.pe,
    macho: report.macho,
  } as const;
  for (const [format, detail] of Object.entries(detailByFormat)) {
    const expected = format === report.format;
    if (expected === (detail === null))
      context.addIssue({
        code: "custom",
        path: [format],
        message: expected
          ? `The ${report.format} detail block must be present.`
          : `Only the ${report.format} detail block may be present.`,
      });
  }
};

const coverageEntries = (
  report: InspectExecutableReport,
): readonly {
  readonly key: string;
  readonly length: number;
  readonly coverage: z.infer<typeof triageListCoverageSchema>;
}[] => [
  {
    key: "sections",
    length: report.sections.length,
    coverage: report.sections_coverage,
  },
  {
    key: "segments",
    length: report.segments.length,
    coverage: report.segments_coverage,
  },
  {
    key: "imports",
    length: report.imports.length,
    coverage: report.imports_coverage,
  },
  {
    key: "exports",
    length: report.exports.length,
    coverage: report.exports_coverage,
  },
  {
    key: "libraries",
    length: report.libraries.length,
    coverage: report.libraries_coverage,
  },
  {
    key: "symbols",
    length: report.symbols.length,
    coverage: report.symbols_coverage,
  },
];

const checkCoverage = (
  report: InspectExecutableReport,
  context: z.RefinementCtx,
): void => {
  for (const { key, length, coverage } of coverageEntries(report)) {
    if (coverage.returned !== length)
      context.addIssue({
        code: "custom",
        path: [`${key}_coverage`, "returned"],
        message: `Returned count ${coverage.returned} disagrees with the ${length} emitted ${key}.`,
      });
    if (coverage.returned > coverage.total)
      context.addIssue({
        code: "custom",
        path: [`${key}_coverage`, "returned"],
        message: `Returned count ${coverage.returned} exceeds the total ${coverage.total}.`,
      });
    if (coverage.truncated !== coverage.returned < coverage.total)
      context.addIssue({
        code: "custom",
        path: [`${key}_coverage`, "truncated"],
        message: `Truncation flag disagrees with returned ${coverage.returned} of ${coverage.total}.`,
      });
  }
};

const offsetsOf = (
  report: InspectExecutableReport,
): readonly {
  readonly offset: number;
  readonly path: (string | number)[];
}[] => {
  const offsets: { offset: number; path: (string | number)[] }[] = [];
  if (report.entry_point.file_offset !== null)
    offsets.push({
      offset: report.entry_point.file_offset,
      path: ["entry_point", "file_offset"],
    });
  if (report.overlay !== null)
    offsets.push({
      offset: report.overlay.file_offset + report.overlay.size,
      path: ["overlay"],
    });
  for (const [index, section] of report.sections.entries())
    offsets.push({
      offset: section.file_offset + section.file_size,
      path: ["sections", index, "file_offset"],
    });
  for (const [index, segment] of report.segments.entries())
    offsets.push({
      offset: segment.file_offset + segment.file_size,
      path: ["segments", index, "file_offset"],
    });
  if (report.container.kind === "fat")
    for (const [index, slice] of report.container.slices.entries())
      offsets.push({
        offset: slice.file_offset + slice.size,
        path: ["container", "slices", index],
      });
  return offsets;
};
