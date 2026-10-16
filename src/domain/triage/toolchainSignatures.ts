/**
 * REA-authored toolchain signature table.
 *
 * Every entry is a public, factual byte or structural marker emitted by a
 * compiler, linker, packer, protector, installer, language runtime or
 * bundler. The markers are documented from the producers themselves (section
 * names chosen by the tool, archive cookies, runtime symbol names, build-tool
 * structures) rather than copied from any third-party detection database. A
 * match only ever supports an inferred classification, never a verdict: the
 * presence of a marker is consistent with a tool having produced the file, and
 * is reported as such.
 */

export type ToolchainCategory =
  | "compiler"
  | "linker"
  | "packer"
  | "protector"
  | "installer"
  | "language"
  | "bundler";

export type ToolchainConfidence = "high" | "medium" | "low";

/** A packer or protector section-name marker, matched exactly or by prefix. */
export interface SectionSignature {
  /** Stable indicator id; matches aggregate under it across signatures. */
  readonly id: string;
  readonly name: string;
  readonly category: ToolchainCategory;
  readonly confidence: ToolchainConfidence;
  /** Section name to compare, case-sensitive. */
  readonly section: string;
  readonly match: "exact" | "prefix";
}

/** A byte or ASCII marker searched once across the whole file. */
export interface ContentSignature {
  readonly id: string;
  readonly name: string;
  readonly category: ToolchainCategory;
  readonly confidence: ToolchainConfidence;
  /** Human-readable marker label used in the reason text. */
  readonly label: string;
  /** Literal bytes to find; ASCII markers are their Latin-1 code units. */
  readonly bytes: readonly number[];
}

const ascii = (text: string): number[] => [...text].map((c) => c.charCodeAt(0));

/**
 * Section names a packer or protector assigns to its own output. Numbered
 * families (UPX0/UPX1/UPX2, .vmp0/.vmp1) are matched by prefix.
 */
export const SECTION_SIGNATURES: readonly SectionSignature[] = [
  {
    id: "upx",
    name: "UPX",
    category: "packer",
    confidence: "high",
    section: "UPX",
    match: "prefix",
  },
  {
    id: "aspack",
    name: "ASPack",
    category: "packer",
    confidence: "high",
    section: ".aspack",
    match: "exact",
  },
  {
    id: "aspack",
    name: "ASPack",
    category: "packer",
    confidence: "high",
    section: ".adata",
    match: "exact",
  },
  {
    id: "vmprotect",
    name: "VMProtect",
    category: "protector",
    confidence: "high",
    section: ".vmp",
    match: "prefix",
  },
  {
    id: "themida",
    name: "Themida/WinLicense",
    category: "protector",
    confidence: "high",
    section: ".themida",
    match: "exact",
  },
  {
    id: "themida",
    name: "Themida/WinLicense",
    category: "protector",
    confidence: "high",
    section: ".winlice",
    match: "exact",
  },
  {
    id: "themida",
    name: "Themida/WinLicense",
    category: "protector",
    confidence: "medium",
    section: ".boot",
    match: "exact",
  },
  {
    id: "enigma",
    name: "Enigma Protector",
    category: "protector",
    confidence: "high",
    section: ".enigma",
    match: "prefix",
  },
  {
    id: "mpress",
    name: "MPRESS",
    category: "packer",
    confidence: "high",
    section: ".MPRESS",
    match: "prefix",
  },
  {
    id: "petite",
    name: "Petite",
    category: "packer",
    confidence: "high",
    section: ".petite",
    match: "exact",
  },
  {
    id: "nspack",
    name: "NsPack",
    category: "packer",
    confidence: "high",
    section: ".nsp",
    match: "prefix",
  },
  {
    id: "pecompact",
    name: "PECompact",
    category: "packer",
    confidence: "high",
    section: ".pec",
    match: "prefix",
  },
  {
    id: "pelock",
    name: "PELock",
    category: "protector",
    confidence: "high",
    section: ".pelock",
    match: "exact",
  },
] as const;

/**
 * Byte and ASCII markers searched across the whole file. Grouped by the
 * producer that emits them; confidence reflects how specific the marker is.
 */
export const CONTENT_SIGNATURES: readonly ContentSignature[] = [
  // Packers that strip section headers and are only visible by content.
  {
    id: "upx",
    name: "UPX",
    category: "packer",
    confidence: "high",
    label: "UPX! magic",
    bytes: ascii("UPX!"),
  },
  {
    id: "upx",
    name: "UPX",
    category: "packer",
    confidence: "high",
    label: "UPX packer banner",
    bytes: ascii("the UPX executable packer"),
  },
  {
    id: "fsg",
    name: "FSG",
    category: "packer",
    confidence: "medium",
    label: "FSG! magic",
    bytes: ascii("FSG!"),
  },
  // Bundlers that wrap an interpreter and its program.
  {
    id: "pyinstaller",
    name: "PyInstaller",
    category: "bundler",
    confidence: "high",
    label: "PyInstaller MEI archive cookie",
    bytes: [0x4d, 0x45, 0x49, 0x0c, 0x0b, 0x0a, 0x0b, 0x0e],
  },
  {
    id: "pyinstaller",
    name: "PyInstaller",
    category: "bundler",
    confidence: "high",
    label: "_MEIPASS runtime path",
    bytes: ascii("_MEIPASS"),
  },
  {
    id: "py2exe",
    name: "py2exe",
    category: "bundler",
    confidence: "high",
    label: "PYTHONSCRIPT resource",
    bytes: ascii("PYTHONSCRIPT"),
  },
  {
    id: "nuitka",
    name: "Nuitka",
    category: "bundler",
    confidence: "high",
    label: "__nuitka symbol",
    bytes: ascii("__nuitka"),
  },
  {
    id: "nuitka",
    name: "Nuitka",
    category: "bundler",
    confidence: "medium",
    label: "Nuitka marker",
    bytes: ascii("Nuitka"),
  },
  {
    id: "node-sea",
    name: "Node.js SEA",
    category: "bundler",
    confidence: "high",
    label: "NODE_SEA_BLOB fuse",
    bytes: ascii("NODE_SEA_BLOB"),
  },
  {
    id: "node-sea",
    name: "Node.js SEA",
    category: "bundler",
    confidence: "high",
    label: "NODE_SEA_FUSE marker",
    bytes: ascii("NODE_SEA_FUSE"),
  },
  {
    id: "dotnet-apphost",
    name: ".NET apphost",
    category: "bundler",
    confidence: "high",
    label: ".NET apphost path placeholder",
    bytes: ascii("c3ab8ff13720e8ad9047dd39466b3c89"),
  },
  {
    id: "dotnet-singlefile",
    name: ".NET single-file bundle",
    category: "bundler",
    confidence: "high",
    label: "DOTNET_BUNDLE_EXTRACT_BASE_DIR",
    bytes: ascii("DOTNET_BUNDLE_EXTRACT_BASE_DIR"),
  },
  {
    id: "autoit",
    name: "AutoIt",
    category: "bundler",
    confidence: "high",
    label: "AU3!EA06 script marker",
    bytes: ascii("AU3!EA06"),
  },
  {
    id: "autoit",
    name: "AutoIt",
    category: "bundler",
    confidence: "high",
    label: "AU3!EA05 script marker",
    bytes: ascii("AU3!EA05"),
  },
  // Installers.
  {
    id: "nsis",
    name: "Nullsoft NSIS",
    category: "installer",
    confidence: "high",
    label: "NullsoftInst signature",
    bytes: ascii("NullsoftInst"),
  },
  {
    id: "nsis",
    name: "Nullsoft NSIS",
    category: "installer",
    confidence: "high",
    label: "Nullsoft Install System",
    bytes: ascii("Nullsoft Install System"),
  },
  {
    id: "inno",
    name: "Inno Setup",
    category: "installer",
    confidence: "high",
    label: "Inno Setup marker",
    bytes: ascii("Inno Setup"),
  },
  {
    id: "installshield",
    name: "InstallShield",
    category: "installer",
    confidence: "medium",
    label: "InstallShield marker",
    bytes: ascii("InstallShield"),
  },
  {
    id: "installanywhere",
    name: "InstallAnywhere",
    category: "installer",
    confidence: "medium",
    label: "InstallAnywhere marker",
    bytes: ascii("InstallAnywhere"),
  },
  // Language runtimes and their stripped-binary markers.
  {
    id: "go",
    name: "Go",
    category: "language",
    confidence: "high",
    label: "Go buildinfo magic",
    bytes: [
      0xff, 0x20, 0x47, 0x6f, 0x20, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x69, 0x6e,
      0x66, 0x3a,
    ],
  },
  {
    id: "go",
    name: "Go",
    category: "language",
    confidence: "high",
    label: "Go build ID note",
    bytes: ascii("Go build ID:"),
  },
  {
    id: "rust",
    name: "Rust",
    category: "language",
    confidence: "high",
    label: "rust_begin_unwind symbol",
    bytes: ascii("rust_begin_unwind"),
  },
  {
    id: "rust",
    name: "Rust",
    category: "language",
    confidence: "medium",
    label: "/rustc/ source path",
    bytes: ascii("/rustc/"),
  },
  {
    id: "delphi",
    name: "Embarcadero/Borland Delphi",
    category: "compiler",
    confidence: "high",
    label: "Borland\\Delphi registry path",
    bytes: ascii("Borland\\Delphi"),
  },
  {
    id: "delphi",
    name: "Embarcadero/Borland Delphi",
    category: "compiler",
    confidence: "medium",
    label: "Embarcadero marker",
    bytes: ascii("Embarcadero"),
  },
  {
    id: "delphi",
    name: "Embarcadero/Borland Delphi",
    category: "compiler",
    confidence: "medium",
    label: "FastMM allocator marker",
    bytes: ascii("FastMM"),
  },
  {
    id: "nim",
    name: "Nim",
    category: "language",
    confidence: "high",
    label: "NimMain entry symbol",
    bytes: ascii("NimMain"),
  },
  {
    id: "nim",
    name: "Nim",
    category: "language",
    confidence: "high",
    label: "nimFrame runtime symbol",
    bytes: ascii("nimFrame"),
  },
  {
    id: "zig",
    name: "Zig",
    category: "language",
    confidence: "medium",
    label: "/zig/lib/std path",
    bytes: ascii("/zig/lib/std"),
  },
  {
    id: "zig",
    name: "Zig",
    category: "language",
    confidence: "low",
    label: "ziglang marker",
    bytes: ascii("ziglang"),
  },
  {
    id: "mingw",
    name: "MinGW (GCC for Windows)",
    category: "compiler",
    confidence: "high",
    label: "Mingw-w64 runtime marker",
    bytes: ascii("Mingw-w64 runtime"),
  },
  {
    id: "mingw",
    name: "MinGW (GCC for Windows)",
    category: "compiler",
    confidence: "medium",
    label: "__mingw runtime symbol",
    bytes: ascii("__mingw_"),
  },
  {
    id: "clang",
    name: "Clang/LLVM",
    category: "compiler",
    confidence: "high",
    label: "clang version banner",
    bytes: ascii("clang version "),
  },
  {
    id: "clang",
    name: "Clang/LLVM",
    category: "compiler",
    confidence: "high",
    label: "Apple clang banner",
    bytes: ascii("Apple LLVM "),
  },
] as const;

/**
 * Documented subset of Rich-header product ids. The Rich header is emitted
 * only by the Microsoft Visual C/C++ linker; the product id identifies the
 * build tool and the low word is its build number. Only universally
 * documented anchors are named here; every other id is reported with its raw
 * value, and no Visual Studio marketing version is asserted from the build
 * number because the 16-bit build wraps across product generations.
 */
export const RICH_PRODUCT_IDS: Readonly<Record<number, string>> = {
  0x00: "unknown or padding entry",
  0x01: "imported object (legacy import record)",
} as const;

/** ASCII GCC/Clang `.comment` banners both record their producer and version. */
export const COMPILER_COMMENT_PATTERNS: readonly {
  readonly id: string;
  readonly name: string;
  readonly pattern: RegExp;
}[] = [
  { id: "gcc", name: "GCC", pattern: /GCC:\s*\([^)]*\)\s*[^\s,]+/u },
  {
    id: "clang",
    name: "Clang/LLVM",
    pattern: /(?:Apple\s+)?clang version\s+[^\s,]+/u,
  },
] as const;
