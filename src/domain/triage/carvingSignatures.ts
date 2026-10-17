/**
 * BinSight-authored magic-byte signature table for embedded-content identification
 * (the `scan_embedded_content` tool). This is pure reference data: each entry
 * names a content family, the fixed byte prefixes that announce it, and the
 * key of the structural validator that confirms the match. The table never
 * extracts, decompresses or writes anything; it only lets the analyzer locate
 * candidate offsets, which a validator then accepts or rejects.
 *
 * Signatures are drawn from public format specifications (ELF, PE/COFF,
 * Mach-O, ZIP APPNOTE, RFC 1952 gzip, the .xz, zstd, bzip2, 7z, CAB, PNG,
 * JPEG/JFIF, PDF, SQLite, Dalvik, Java class, X.509/PKCS DER, SquashFS, cpio,
 * POSIX tar, U-Boot uImage and the Devicetree blob headers). Short or shared
 * magics (`MZ`, `CAFEBABE`, DER `SEQUENCE`) are deliberately listed and left
 * for the validator to disambiguate rather than reported on the magic alone.
 */

/** Content family an identified region is classified as. */
export type CarvingType =
  | "pe"
  | "elf"
  | "macho"
  | "macho_fat"
  | "zip"
  | "zip_central_directory"
  | "zip_end_of_central_directory"
  | "gzip"
  | "zlib"
  | "xz"
  | "zstd"
  | "bzip2"
  | "seven_zip"
  | "cab"
  | "png"
  | "jpeg"
  | "pdf"
  | "sqlite"
  | "dex"
  | "java_class"
  | "der_certificate"
  | "pem"
  | "pkcs12"
  | "squashfs"
  | "cpio"
  | "tar"
  | "uimage"
  | "dtb";

/** Every classifiable type, used to build the report's closed `type` enum. */
export const CARVING_TYPES = [
  "pe",
  "elf",
  "macho",
  "macho_fat",
  "zip",
  "zip_central_directory",
  "zip_end_of_central_directory",
  "gzip",
  "zlib",
  "xz",
  "zstd",
  "bzip2",
  "seven_zip",
  "cab",
  "png",
  "jpeg",
  "pdf",
  "sqlite",
  "dex",
  "java_class",
  "der_certificate",
  "pem",
  "pkcs12",
  "squashfs",
  "cpio",
  "tar",
  "uimage",
  "dtb",
] as const satisfies readonly CarvingType[];

/** Broad grouping used only for human-facing descriptions. */
export type CarvingCategory =
  | "executable"
  | "archive"
  | "compression"
  | "filesystem"
  | "image"
  | "document"
  | "database"
  | "certificate"
  | "firmware";

/** Key selecting the structural validator the analyzer runs for a candidate. */
export type CarvingValidatorKey =
  | "pe"
  | "elf"
  | "machoThin"
  | "machoFat"
  | "zipLocal"
  | "zipCentral"
  | "zipEocd"
  | "gzip"
  | "zlib"
  | "xz"
  | "zstd"
  | "bzip2"
  | "sevenZip"
  | "cab"
  | "png"
  | "jpeg"
  | "pdf"
  | "sqlite"
  | "dex"
  | "javaClass"
  | "derCertificate"
  | "pkcs12"
  | "squashfs"
  | "cpio"
  | "tar"
  | "uimage"
  | "dtb";

/** One fixed byte prefix to search for, and where the content actually begins. */
export interface CarvingPattern {
  /** Literal bytes to locate with an exact substring search. */
  readonly bytes: readonly number[];
  /** Offset of these bytes inside the content (non-zero for tar's `ustar`). */
  readonly magic_offset: number;
}

/** One entry of the magic table: a type, its prefixes, and a validator key. */
export interface CarvingSignature {
  readonly type: CarvingType;
  readonly category: CarvingCategory;
  readonly description: string;
  readonly patterns: readonly CarvingPattern[];
  readonly validator: CarvingValidatorKey;
}

const ascii = (text: string): number[] => [...text].map((c) => c.charCodeAt(0));

const at0 = (bytes: readonly number[]): CarvingPattern => ({
  bytes,
  magic_offset: 0,
});

/**
 * The complete signature table. Several entries intentionally share a prefix
 * (`macho_fat`/`java_class` both answer `CA FE BA BE`; `der_certificate`/
 * `pkcs12` both answer a DER `SEQUENCE`); their validators are mutually
 * exclusive, so at most one accepts any given offset.
 */
export const CARVING_SIGNATURES: readonly CarvingSignature[] = [
  {
    type: "pe",
    category: "executable",
    description: "DOS/PE (MZ) executable header",
    patterns: [at0(ascii("MZ"))],
    validator: "pe",
  },
  {
    type: "elf",
    category: "executable",
    description: "ELF executable or shared object",
    patterns: [at0([0x7f, 0x45, 0x4c, 0x46])],
    validator: "elf",
  },
  {
    type: "macho",
    category: "executable",
    description: "thin Mach-O image",
    patterns: [
      at0([0xcf, 0xfa, 0xed, 0xfe]),
      at0([0xce, 0xfa, 0xed, 0xfe]),
      at0([0xfe, 0xed, 0xfa, 0xcf]),
      at0([0xfe, 0xed, 0xfa, 0xce]),
    ],
    validator: "machoThin",
  },
  {
    type: "macho_fat",
    category: "executable",
    description: "universal (fat) Mach-O container",
    patterns: [at0([0xca, 0xfe, 0xba, 0xbe]), at0([0xca, 0xfe, 0xba, 0xbf])],
    validator: "machoFat",
  },
  {
    type: "zip",
    category: "archive",
    description: "ZIP local file header",
    patterns: [at0([0x50, 0x4b, 0x03, 0x04])],
    validator: "zipLocal",
  },
  {
    type: "zip_central_directory",
    category: "archive",
    description: "ZIP central directory file header",
    patterns: [at0([0x50, 0x4b, 0x01, 0x02])],
    validator: "zipCentral",
  },
  {
    type: "zip_end_of_central_directory",
    category: "archive",
    description: "ZIP end-of-central-directory record",
    patterns: [at0([0x50, 0x4b, 0x05, 0x06])],
    validator: "zipEocd",
  },
  {
    type: "gzip",
    category: "compression",
    description: "gzip-compressed stream (RFC 1952)",
    patterns: [at0([0x1f, 0x8b, 0x08])],
    validator: "gzip",
  },
  {
    type: "zlib",
    category: "compression",
    description: "zlib-compressed stream (RFC 1950)",
    patterns: [
      at0([0x78, 0x01]),
      at0([0x78, 0x5e]),
      at0([0x78, 0x9c]),
      at0([0x78, 0xda]),
    ],
    validator: "zlib",
  },
  {
    type: "xz",
    category: "compression",
    description: "XZ-compressed stream",
    patterns: [at0([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00])],
    validator: "xz",
  },
  {
    type: "zstd",
    category: "compression",
    description: "Zstandard-compressed frame",
    patterns: [at0([0x28, 0xb5, 0x2f, 0xfd])],
    validator: "zstd",
  },
  {
    type: "bzip2",
    category: "compression",
    description: "bzip2-compressed stream",
    patterns: [at0([0x42, 0x5a, 0x68])],
    validator: "bzip2",
  },
  {
    type: "seven_zip",
    category: "archive",
    description: "7-Zip archive",
    patterns: [at0([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])],
    validator: "sevenZip",
  },
  {
    type: "cab",
    category: "archive",
    description: "Microsoft Cabinet archive",
    patterns: [at0(ascii("MSCF"))],
    validator: "cab",
  },
  {
    type: "png",
    category: "image",
    description: "PNG image",
    patterns: [at0([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])],
    validator: "png",
  },
  {
    type: "jpeg",
    category: "image",
    description: "JPEG image",
    patterns: [at0([0xff, 0xd8, 0xff])],
    validator: "jpeg",
  },
  {
    type: "pdf",
    category: "document",
    description: "PDF document",
    patterns: [at0(ascii("%PDF-"))],
    validator: "pdf",
  },
  {
    type: "sqlite",
    category: "database",
    description: "SQLite 3 database",
    patterns: [at0(ascii("SQLite format 3\u0000"))],
    validator: "sqlite",
  },
  {
    type: "dex",
    category: "executable",
    description: "Dalvik DEX bytecode",
    patterns: [at0([0x64, 0x65, 0x78, 0x0a])],
    validator: "dex",
  },
  {
    type: "java_class",
    category: "executable",
    description: "Java class file",
    patterns: [at0([0xca, 0xfe, 0xba, 0xbe])],
    validator: "javaClass",
  },
  {
    type: "der_certificate",
    category: "certificate",
    description: "DER structure consistent with an X.509 certificate",
    patterns: [at0([0x30, 0x82])],
    validator: "derCertificate",
  },
  {
    type: "pkcs12",
    category: "certificate",
    description: "DER structure consistent with a PKCS#12 bag",
    patterns: [at0([0x30, 0x82])],
    validator: "pkcs12",
  },
  {
    type: "squashfs",
    category: "filesystem",
    description: "SquashFS filesystem",
    patterns: [at0(ascii("hsqs")), at0(ascii("sqsh"))],
    validator: "squashfs",
  },
  {
    type: "cpio",
    category: "archive",
    description: "cpio archive (ASCII header)",
    patterns: [
      at0(ascii("070701")),
      at0(ascii("070702")),
      at0(ascii("070707")),
    ],
    validator: "cpio",
  },
  {
    type: "tar",
    category: "archive",
    description: "POSIX tar archive",
    patterns: [
      { bytes: ascii("ustar\u0000"), magic_offset: 257 },
      { bytes: ascii("ustar  "), magic_offset: 257 },
    ],
    validator: "tar",
  },
  {
    type: "uimage",
    category: "firmware",
    description: "U-Boot legacy uImage",
    patterns: [at0([0x27, 0x05, 0x19, 0x56])],
    validator: "uimage",
  },
  {
    type: "dtb",
    category: "firmware",
    description: "Flattened Devicetree blob",
    patterns: [at0([0xd0, 0x0d, 0xfe, 0xed])],
    validator: "dtb",
  },
];

/** PEM armor labels scanned textually (not part of the binary magic table). */
export const PEM_BEGIN = ascii("-----BEGIN ");
