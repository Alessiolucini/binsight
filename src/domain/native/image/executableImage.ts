/**
 * Format-neutral, I/O-free model of one executable image (ELF, PE/COFF or a
 * thin Mach-O slice). Each format parser owns the interpretation of its own
 * header structures and projects them here once; static analyzers consume
 * these parsed facts instead of re-reading raw headers.
 *
 * Addresses are bigint because 64-bit images routinely exceed 2^53. File
 * offsets and sizes are numbers because admitted inputs are bounded far below
 * that range.
 */

export type ImageFormat = "elf" | "pe" | "macho";
export type ImageByteOrder = "little" | "big";

/** Normalized architecture family; `null` when the machine is unrecognized. */
export type ImageArchitecture =
  | "x86"
  | "x86_64"
  | "arm"
  | "arm64"
  | "mips"
  | "powerpc"
  | "riscv"
  | "sparc"
  | "s390"
  | "loongarch"
  | "ia64"
  | null;

export interface ImagePermissions {
  readonly readable: boolean;
  readonly writable: boolean;
  readonly executable: boolean;
}

export interface ImageSection extends ImagePermissions {
  readonly index: number;
  /** ELF/PE section name, or Mach-O `segment,section`. */
  readonly name: string;
  /** Mach-O owning segment; null for ELF and PE. */
  readonly segment_name: string | null;
  /** Format-specific section type name (ELF sh_type, Mach-O section type), when known. */
  readonly type: string | null;
  readonly file_offset: number;
  /** Bytes backed by the file. Zero for NOBITS / zero-fill / uninitialized sections. */
  readonly file_size: number;
  readonly virtual_address: bigint;
  readonly virtual_size: bigint;
  /** ELF sh_flags (low 32 bits), PE Characteristics or Mach-O section flags. */
  readonly raw_flags: number;
}

export interface ImageSegment extends ImagePermissions {
  readonly index: number;
  /** Mach-O segment name; null for ELF program headers and PE. */
  readonly name: string | null;
  /** ELF p_type name such as PT_LOAD, or Mach-O load command name. */
  readonly type: string;
  readonly file_offset: number;
  readonly file_size: number;
  readonly virtual_address: bigint;
  readonly memory_size: bigint;
  readonly raw_flags: number;
}

export interface ImageImport {
  /** PE DLL name, Mach-O dylib install name from the two-level ordinal, or ELF verneed file. */
  readonly library: string | null;
  /** Imported symbol name; null for PE ordinal-only imports. */
  readonly name: string | null;
  readonly ordinal: number | null;
  readonly delay_loaded: boolean;
  readonly weak: boolean;
  /** ELF symbol version such as GLIBC_2.34, when declared. */
  readonly version: string | null;
}

export interface ImageExport {
  readonly name: string | null;
  readonly ordinal: number | null;
  readonly address: bigint | null;
  /** PE forwarder string such as `NTDLL.RtlAllocateHeap`. */
  readonly forwarder: string | null;
  readonly kind: "function" | "object" | "unknown";
}

export type ImageLibraryKind =
  | "needed"
  | "delay"
  | "weak"
  | "reexport"
  | "upward"
  | "lazy"
  | "import";

export interface ImageLibrary {
  readonly name: string;
  readonly kind: ImageLibraryKind;
}

export type ImageSymbolType =
  | "function"
  | "object"
  | "section"
  | "file"
  | "tls"
  | "other";
export type ImageSymbolBinding = "local" | "global" | "weak" | "other";

export interface ImageSymbol {
  readonly name: string;
  readonly value: bigint;
  readonly size: bigint;
  readonly type: ImageSymbolType;
  readonly binding: ImageSymbolBinding;
  readonly defined: boolean;
  /** Which table declared the symbol. */
  readonly table: "dynsym" | "symtab" | "nlist" | "coff";
}

export interface ImageEntryPoint {
  readonly virtual_address: bigint | null;
  readonly file_offset: number | null;
  /** Index into `sections`, or null when the entry is outside every section. */
  readonly section_index: number | null;
}

export interface ImageRange {
  readonly file_offset: number;
  readonly size: number;
}

export interface ElfDynamicFacts {
  readonly needed: readonly string[];
  readonly soname: string | null;
  readonly rpath: readonly string[];
  readonly runpath: readonly string[];
  readonly flags: number | null;
  readonly flags_1: number | null;
  /** DT_BIND_NOW, DF_BIND_NOW or DF_1_NOW was declared. */
  readonly bind_now: boolean;
  readonly has_debug_tag: boolean;
  readonly text_relocations: boolean;
}

export interface ElfDetails {
  readonly elf_class: 32 | 64;
  readonly os_abi: number;
  /** e_type value: 1 REL, 2 EXEC, 3 DYN, 4 CORE. */
  readonly e_type: number;
  readonly machine: number;
  readonly e_flags: number;
  readonly interpreter: string | null;
  /** PT_GNU_STACK presence and whether it requests an executable stack. */
  readonly gnu_stack: {
    readonly present: boolean;
    readonly executable: boolean;
  };
  readonly gnu_relro: ImageRange | null;
  readonly dynamic: ElfDynamicFacts | null;
  /** Lowercase hex NT_GNU_BUILD_ID descriptor. */
  readonly build_id: string | null;
  /** GNU_PROPERTY_X86_FEATURE_1_AND (bit0 IBT, bit1 SHSTK) when declared. */
  readonly x86_feature_1: number | null;
  /** GNU_PROPERTY_AARCH64_FEATURE_1_AND (bit0 BTI, bit1 PAC) when declared. */
  readonly aarch64_feature_1: number | null;
  readonly has_symtab: boolean;
  readonly has_debug_info: boolean;
  /** NUL-separated strings from `.comment`, deduplicated in first-seen order. */
  readonly comment: readonly string[];
  readonly gnu_debuglink: string | null;
}

export interface PeDataDirectory {
  readonly index: number;
  readonly name: string;
  readonly rva: number;
  readonly size: number;
}

export interface PeRichEntry {
  readonly product_id: number;
  readonly build: number;
  readonly count: number;
}

export interface PeRichHeader {
  /** File offset of the first XOR-masked `DanS` dword. */
  readonly offset: number;
  /** File offset just after the `Rich` marker and its XOR key. */
  readonly end_offset: number;
  readonly xor_key: number;
  readonly entries: readonly PeRichEntry[];
  /** Whether the XOR key equals the checksum recomputed over the DOS header, stub and entries. */
  readonly checksum_valid: boolean;
  /** Unmasked bytes from `DanS` through the last entry (pefile `clear_data`). */
  readonly clear_bytes: Buffer;
}

export interface PeLoadConfig {
  readonly size: number;
  readonly security_cookie: bigint | null;
  readonly se_handler_table: bigint | null;
  readonly se_handler_count: bigint | null;
  readonly guard_cf_check_function: bigint | null;
  readonly guard_cf_function_count: bigint | null;
  readonly guard_flags: number | null;
}

export interface PeCodeView {
  readonly signature: "RSDS" | "NB10";
  /** RSDS GUID in canonical text form, or NB10 timestamp as hex. */
  readonly identifier: string;
  readonly age: number;
  readonly pdb_path: string;
}

export interface PeDetails {
  readonly pe32_plus: boolean;
  readonly machine: number;
  readonly time_date_stamp: number;
  readonly characteristics: number;
  readonly subsystem: number;
  readonly dll_characteristics: number;
  readonly image_base: bigint;
  readonly size_of_image: number;
  readonly size_of_headers: number;
  readonly checksum: number;
  /** PE checksum recomputed with the pefile algorithm. */
  readonly computed_checksum: number;
  readonly linker_version: string;
  readonly os_version: string;
  readonly subsystem_version: string;
  readonly data_directories: readonly PeDataDirectory[];
  readonly rich_header: PeRichHeader | null;
  readonly load_config: PeLoadConfig | null;
  /** Virtual addresses of TLS callbacks; null when there is no TLS directory. */
  readonly tls_callbacks: readonly bigint[] | null;
  readonly debug_types: readonly number[];
  readonly codeview: PeCodeView | null;
  /** IMAGE_DLLCHARACTERISTICS_EX from debug type 20, when present. */
  readonly ex_dll_characteristics: number | null;
  /** The security directory is a file range, not an RVA. */
  readonly security_directory: ImageRange | null;
  readonly managed: boolean;
  readonly base_relocations: boolean;
  readonly resources: boolean;
}

export interface MachoDylib {
  readonly name: string;
  readonly command: string;
  readonly current_version: string;
  readonly compatibility_version: string;
}

export interface MachoBuildVersion {
  readonly platform: number;
  readonly minimum_os: string;
  readonly sdk: string;
}

export interface MachoEncryptionInfo {
  readonly crypt_offset: number;
  readonly crypt_size: number;
  readonly crypt_id: number;
}

export interface MachoDetails {
  readonly cpu_type: number;
  readonly cpu_subtype: number;
  readonly file_type: number;
  readonly flags: number;
  readonly load_commands: readonly {
    readonly command: number;
    readonly name: string;
    readonly offset: number;
    readonly size: number;
  }[];
  readonly uuid: string | null;
  readonly build_versions: readonly MachoBuildVersion[];
  readonly source_version: string | null;
  readonly dylibs: readonly MachoDylib[];
  readonly id_dylib: string | null;
  readonly rpaths: readonly string[];
  readonly encryption: MachoEncryptionInfo | null;
  readonly code_signature: ImageRange | null;
  readonly has_restrict_segment: boolean;
  readonly uses_chained_fixups: boolean;
}

export interface ImageFatSlice {
  readonly cpu_type: number;
  readonly cpu_subtype: number;
  readonly architecture: ImageArchitecture;
  readonly file_offset: number;
  readonly size: number;
  readonly align: number;
}

export type ImageContainer =
  | { readonly kind: "thin" }
  | {
      readonly kind: "fat";
      readonly slices: readonly ImageFatSlice[];
      readonly selected_index: number;
    };

/** Lists that hit a parser bound are truncated rather than silently complete. */
export interface ImageListCoverage {
  readonly imports: "complete" | "truncated" | "unavailable";
  readonly exports: "complete" | "truncated" | "unavailable";
  readonly symbols: "complete" | "truncated" | "unavailable";
}

export interface ExecutableImage {
  readonly format: ImageFormat;
  readonly bits: 32 | 64;
  readonly byte_order: ImageByteOrder;
  readonly architecture: ImageArchitecture;
  /** Format-native machine constant (e_machine, IMAGE_FILE_MACHINE, cputype). */
  readonly machine: number;
  readonly machine_name: string;
  /** File offset of this image inside the analyzed file (non-zero for FAT slices). */
  readonly image_offset: number;
  /** Byte length of this image inside the analyzed file. */
  readonly image_size: number;
  readonly entry_point: ImageEntryPoint;
  readonly sections: readonly ImageSection[];
  readonly segments: readonly ImageSegment[];
  readonly imports: readonly ImageImport[];
  readonly exports: readonly ImageExport[];
  readonly libraries: readonly ImageLibrary[];
  readonly symbols: readonly ImageSymbol[];
  readonly coverage: ImageListCoverage;
  /** Bytes after the last file range declared by headers, sections or segments. */
  readonly overlay: ImageRange | null;
  readonly container: ImageContainer;
  /** Non-fatal structural problems found while parsing, bounded in count. */
  readonly diagnostics: readonly string[];
  readonly elf: ElfDetails | null;
  readonly pe: PeDetails | null;
  readonly macho: MachoDetails | null;
}

/** Typed parse refusal; providers translate kinds into analysis errors. */
export interface ImageParseFailure {
  readonly kind: "unsupported" | "malformed" | "resource";
  readonly message: string;
}

/** Caller-selected Mach-O universal slice by architecture or declaration index. */
export interface ImageParseOptions {
  readonly slice?:
    | { readonly architecture: Exclude<ImageArchitecture, null> }
    | { readonly index: number };
}

/** Bounds shared by every format parser. */
export const IMAGE_PARSE_LIMITS = {
  sections: 65_535,
  segments: 65_535,
  loadCommands: 65_536,
  imports: 200_000,
  exports: 200_000,
  symbols: 400_000,
  libraries: 16_384,
  /** Longest string read from a string table or load command. */
  stringBytes: 4_096,
  diagnostics: 64,
  tlsCallbacks: 4_096,
} as const;
