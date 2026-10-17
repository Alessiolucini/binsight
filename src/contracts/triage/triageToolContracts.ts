import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";
import {
  triageFileInputSchema,
  triageFileReportSchema,
} from "../../domain/triage/triageFile.js";
import {
  generateTriageReportInputSchema,
  generateTriageReportReportSchema,
} from "../../domain/triage/generateTriageReport.js";
import {
  compareBinariesInputSchema,
  compareBinariesReportSchema,
} from "../../domain/triage/compareBinaries.js";
import {
  inspectExecutableInputSchema,
  inspectExecutableReportSchema,
} from "../../domain/triage/inspectExecutable.js";
import {
  inspectBinaryHardeningInputSchema,
  inspectBinaryHardeningReportSchema,
} from "../../domain/triage/inspectBinaryHardening.js";
import {
  measureBinaryEntropyInputSchema,
  measureBinaryEntropyReportSchema,
} from "../../domain/triage/measureBinaryEntropy.js";
import {
  detectBinaryToolchainInputSchema,
  detectBinaryToolchainReportSchema,
} from "../../domain/triage/detectBinaryToolchain.js";
import {
  extractBinaryStringsInputSchema,
  extractBinaryStringsReportSchema,
} from "../../domain/triage/extractBinaryStrings.js";
import {
  identifyCryptoConstantsInputSchema,
  identifyCryptoConstantsReportSchema,
} from "../../domain/triage/identifyCryptoConstants.js";
import {
  classifyImportCapabilitiesInputSchema,
  classifyImportCapabilitiesReportSchema,
} from "../../domain/triage/classifyImportCapabilities.js";
import {
  scanBytePatternsInputSchema,
  scanBytePatternsReportSchema,
} from "../../domain/triage/scanBytePatterns.js";
import {
  computeSimilarityHashesInputSchema,
  computeSimilarityHashesReportSchema,
} from "../../domain/triage/computeSimilarityHashes.js";
import {
  inspectCodeSignatureInputSchema,
  inspectCodeSignatureReportSchema,
} from "../../domain/triage/inspectCodeSignature.js";
import {
  scanEmbeddedContentInputSchema,
  scanEmbeddedContentReportSchema,
} from "../../domain/triage/scanEmbeddedContent.js";
import {
  generateSbomInputSchema,
  generateSbomReportSchema,
} from "../../domain/triage/generateSbom.js";
import {
  recoverGoSymbolsInputSchema,
  recoverGoSymbolsReportSchema,
} from "../../domain/triage/recoverGoSymbols.js";
import {
  compareExecutablesInputSchema,
  compareExecutablesReportSchema,
} from "../../domain/triage/compareExecutables.js";

/** Dependency-free static intelligence tools, independent of native-analysis providers. */
export const TRIAGE_TOOL_CONTRACTS = [
  {
    name: "inspect_executable",
    ...toolContractMetadata("inspect_executable"),
    kind: "artifact-provider",
    description:
      "Returns a unified structural view of one local ELF, PE/COFF or Mach-O image projected from BinSight's shared parsed-image model: format, bits, byte_order, architecture, machine{value,name}, entry_point{virtual_address,file_offset,section}, total counts, and bounded sections/segments/imports/exports/libraries/symbols lists plus compact per-format elf/pe/macho detail blocks, overlay range, and thin/fat container with slices. Each list honors the caller's max_list bound and reports its own total/returned/truncated coverage; symbols are opt-in via include (default is all lists except symbols). It reads the selected file once (up to 256 MiB) WITHOUT executing the target, without network access, and without writing files; the inline report is bounded to 8 MiB (a typed resource error is raised if exceeded). It does NOT decompile, resolve relocations, evaluate code-signature or certificate trust, judge hardening, or prove the image loads or is unmodified. Non-executable bytes raise an unsupported-target error. Unknowns are reported as null (never omitted); parser truncation, omitted lists, universal-slice selection, and structural diagnostics are reported in each *_coverage and in limitations[].",
    inputSchema: inspectExecutableInputSchema,
    outputSchema: evidenceResultOf(inspectExecutableReportSchema),
    examples: [
      {
        title: "All structural lists (symbols excluded by default)",
        input: { path: "/artifacts/application" },
      },
      {
        title: "Imports and libraries only, more entries per list",
        input: {
          path: "/artifacts/application",
          include: ["imports", "libraries"],
          max_list: 2000,
        },
      },
      {
        title:
          "Select the arm64 slice of a universal Mach-O and include symbols",
        input: {
          path: "/artifacts/application",
          slice: "arm64",
          include: ["sections", "symbols"],
          max_list: 500,
        },
      },
    ],
  },
  {
    name: "inspect_binary_hardening",
    ...toolContractMetadata("inspect_binary_hardening"),
    kind: "artifact-provider",
    description:
      'Reports binary-hardening indicators for one ELF, PE/COFF or Mach-O image (checksec-style), reading the shipped file once into bounded memory without executing the target, without network access and without writing files. Returns one per-format block: ELF {relro, stack_canary, nx, pie, rpath, runpath, fortify, cet_ibt, cet_shstk, pac, bti, stripped, rwx_segments}; PE {dynamic_base, high_entropy_va, nx_compat, force_integrity, no_seh, guard_cf, safe_seh, gs_cookie, cet_compat, isolation, appcontainer, relocations_stripped, authenticode_present}; Mach-O {pie, allow_stack_execution, no_heap_execution, encrypted, hardened_runtime, arm64e, restrict_segment, stack_chk}. Each indicator carries evidence_kind "observed" (a header/structure bit) or "inferred" (a symbol or heuristic), alongside an always-inferred mitigations roll-up. It does NOT unpack, decrypt, evaluate certificate chains or OS trust, or prove per-function coverage. Non-executable input is refused as unsupported. Facts that cannot be assessed are null (e.g. fortify when no symbol table) or inferred flags, each matched by a limitations entry; input is capped at 256 MiB and the inline report at 8 MiB.',
    inputSchema: inspectBinaryHardeningInputSchema,
    outputSchema: evidenceResultOf(inspectBinaryHardeningReportSchema),
    examples: [
      {
        title:
          "Hardening of an executable (default, auto-detects ELF/PE/Mach-O)",
        input: { path: "/artifacts/application" },
      },
      {
        title: "A specific slice of a Mach-O universal binary",
        input: { path: "/artifacts/application", slice: "arm64" },
      },
    ],
  },
  {
    name: "measure_binary_entropy",
    ...toolContractMetadata("measure_binary_entropy"),
    kind: "artifact-provider",
    description:
      "Returns byte-level entropy statistics computed from the exact file snapshot: whole-file Shannon entropy (bits/byte), a Pearson chi-square against a uniform byte distribution, and the arithmetic mean byte value; when the bytes parse as an ELF, PE or Mach-O image, per-section entropy and chi-square over each section's file-backed bytes (SizeOfRawData for PE, section/sh file size elsewhere; uninitialized/NOBITS sections report 0); and, over a caller-sized grid of power-of-two blocks (block_size 256..1048576, default 4096; up to max_blocks, default 4096), the maximal consecutive runs of blocks at or above 7.2 bits (high) and at or below 1.0 bit (low). It does NOT decompress, unpack, decrypt, classify intent, extract keys or recover plaintext, and cannot distinguish compressed from encrypted data. It reads the file once (bounded at 256 MiB) without executing the target, without network and without writing files; CPU is bounded by the block/section limits and cooperative cancellation. Bounded lists (sections, high runs, low runs, blocks) each carry {total,returned,truncated} coverage; non-executable input yields subject format 'file' with empty sections; every unknown, clamp or truncation is stated in limitations.",
    inputSchema: measureBinaryEntropyInputSchema,
    outputSchema: evidenceResultOf(measureBinaryEntropyReportSchema),
    examples: [
      {
        title: "Default whole-file and per-section entropy profile",
        input: { path: "/artifacts/application" },
      },
      {
        title: "Coarser 64 KiB blocks, fewer blocks scanned",
        input: {
          path: "/artifacts/application",
          block_size: 65536,
          max_blocks: 1024,
        },
      },
    ],
  },
  {
    name: "detect_binary_toolchain",
    ...toolContractMetadata("detect_binary_toolchain"),
    kind: "artifact-provider",
    description:
      "Returns inferred compiler, packer, protector, installer, language and bundler identifications for one local ELF/PE/Mach-O or other file from a BinSight-authored table of public byte and structural markers: packer/protector section names, whole-file byte/ASCII markers (UPX, PyInstaller, Node SEA, AutoIt, NSIS, Inno Setup, Go, Rust, Delphi, Nim, Zig, MinGW, Clang), the Microsoft Rich header (MSVC) and GCC/Clang .comment banners. Each indicator carries id, category, confidence, evidence_kind=inferred and located match reasons bounded with coverage. It adds an entropy-assisted packed_indicator (likely_packed|not_observed|unknown) with whole-file entropy and entry-point section facts. Detection only: it never unpacks, decompresses or executes the target, uses no network and writes no files; the file is read once, bounded at 256 MiB. It does not assert Visual Studio versions, classify intent or prove a tool was used; an absent marker yields no indicator (absence is not proof), a non-image file reports subject=file with content markers only, and caveats are in limitations.",
    inputSchema: detectBinaryToolchainInputSchema,
    outputSchema: evidenceResultOf(detectBinaryToolchainReportSchema),
    examples: [
      {
        title: "Identify the toolchain of a shipped application",
        input: { path: "/artifacts/application" },
      },
      {
        title: "Classify a suspected packed Windows executable",
        input: { path: "/artifacts/sample.exe" },
      },
    ],
  },
  {
    name: "extract_binary_strings",
    ...toolContractMetadata("extract_binary_strings"),
    kind: "artifact-provider",
    description:
      "Recovers printable strings from one local file's raw bytes and tags each with inferred classifications. Returns strings[] {text, encoding (ascii|utf16le|utf8), file_offset, section (containing section of the default image slice, else null), length, tags[]}, a string_coverage {total,returned,truncated}, and tag_summary {tag:count} over the returned strings. Tags are BinSight regex inferences: url, ipv4, ipv6, domain, email, path_windows, path_posix, registry_key, guid, base64_blob, pem, jwt, user_agent, format_string, sql. The file is read once; it is never executed, no network, DNS or whois lookup is performed, and nothing is written. Strings are returned verbatim as file content and are not redacted; do not infer secrecy from a name. Guards: input is bounded to 256 MiB and scanned once per encoding; returned count is bounded by max_strings (coverage.truncated flags overflow) and returned text by max_total_bytes (exceeding it is a typed resource refusal with no partial result); a run over 8192 chars keeps its true length but capped text. Unknowns are explicit nulls (section null when unmapped or not an executable) each noted in limitations.",
    inputSchema: extractBinaryStringsInputSchema,
    outputSchema: evidenceResultOf(extractBinaryStringsReportSchema),
    examples: [
      {
        title: "Default ASCII + UTF-16LE extraction with inferred tags",
        input: { path: "/artifacts/application" },
      },
      {
        title: "Only network-indicator strings, UTF-8 included, deeper scan",
        input: {
          path: "/artifacts/application",
          min_length: 6,
          encodings: ["ascii", "utf16le", "utf8"],
          categories: ["url", "domain", "ipv4", "ipv6", "email"],
          max_strings: 5000,
        },
      },
    ],
  },
  {
    name: "identify_crypto_constants",
    ...toolContractMetadata("identify_crypto_constants"),
    kind: "artifact-provider",
    description:
      'Scans one local file for well-known cryptographic/hashing constant tables authored from public specifications: AES S-box, inverse S-box, Te0/Td0, Rcon; MD5 T-table and init; SHA-1/256/512 init and round constants (K prefix-anchored); CRC-32 reflected table and polynomials 0x04C11DB7/0xEDB88320; DES S-boxes; Blowfish P-array; ChaCha/Salsa20 "expand 32/16-byte k"; TEA/XTEA/XXTEA deltas; FNV/MurmurHash3/xxHash primes; DEFLATE base tables; standard and URL-safe Base64 alphabets plus a custom-alphabet heuristic; and P-256/secp256k1/Curve25519 parameters. Returns findings[] {algorithm, kind (sbox|iv|round_constant|table|magic|curve_param), evidence_kind=inferred, file_offset, resolved section, byte_order le|be|any, length}, a finding_coverage block, an algorithm_summary, and the file subject. Each match is observed bytes; algorithm attribution is inferred and shared constants may be reported under several algorithms. It does NOT prove the algorithm is reachable or used, does NOT extract key material or plaintext, and does NOT decrypt or unpack. It reads the file once (up to 256 MiB) without executing the target, without network access and without writing files; findings are bounded (256 per constant, 4096 total) with truncation signalled in finding_coverage. Non-executable input gives a "file" subject with null sections; every caveat is listed in limitations.',
    inputSchema: identifyCryptoConstantsInputSchema,
    outputSchema: evidenceResultOf(identifyCryptoConstantsReportSchema),
    examples: [
      {
        title: "Scan a shipped binary for crypto constants",
        input: { path: "/artifacts/application" },
      },
      {
        title: "Scan a suspected packed/obfuscated sample",
        input: { path: "/artifacts/sample.bin" },
      },
    ],
  },
  {
    name: "classify_import_capabilities",
    ...toolContractMetadata("classify_import_capabilities"),
    kind: "artifact-provider",
    description:
      "Classifies the import table of one local ELF, PE/COFF or Mach-O image against a versioned, BinSight-authored capability taxonomy, reporting capability classes (for example process creation, process injection, executable-memory allocation, socket and HTTP networking, cryptographic API use, filesystem writes, registry access, service persistence, debugger detection, privilege and token changes, input hooking, screen capture) each as imports consistent with a behavior, never as proof it occurs or is reachable. Returns each capability with a confidence tier, the supporting imports (bounded by max_support with coverage), the taxonomy_version, the examined import count, and whether runtime symbol resolution (GetProcAddress/dlsym and similar) is imported. Reads imports once (file up to 256 MiB) WITHOUT executing the target, without network access and without writing files; the report is bounded to 8 MiB. Imports resolved dynamically are not classified; an absent capability means no matching import was observed, not that the behavior is impossible. Non-executable bytes receive a typed unsupported-target failure.",
    inputSchema: classifyImportCapabilitiesInputSchema,
    outputSchema: evidenceResultOf(classifyImportCapabilitiesReportSchema),
    examples: [
      {
        title: "Classify an executable import table",
        input: { path: "/artifacts/application" },
      },
      {
        title: "Classify one slice with more supporting imports",
        input: {
          path: "/artifacts/application",
          slice: "arm64",
          max_support: 32,
        },
      },
    ],
  },
  {
    name: "scan_byte_patterns",
    ...toolContractMetadata("scan_byte_patterns"),
    kind: "artifact-provider",
    description:
      "Returns observed occurrences of caller-supplied byte patterns in one local file. Each match carries its pattern_id, file_offset with the containing executable section and virtual_address when the file is a recognized ELF/PE/Mach-O image (both null otherwise), matched length, and preview_hex of up to the first 32 matched bytes, plus match_coverage and per_pattern_counts that record per-pattern and global truncation. Patterns are hex (bytes, ?? / A? / ?0 nibble wildcards, [n] / [n-m] / [n-] jumps, (aa|bb) alternation), literal text (ASCII and/or UTF-16LE, optional case-insensitive), or a JavaScript regular expression without backreferences; overlapping occurrences are reported. It does NOT extract, decode, unpack, interpret matches semantically, assess reachability, or judge intent. It reads the file once (<=256 MiB) without executing the target, without network access, and without writing files; regex and jump work is bounded, and patterns that are malformed or exceed the jump bound are rejected with a typed input error. Absent section context is reported as null, never omitted.",
    inputSchema: scanBytePatternsInputSchema,
    outputSchema: evidenceResultOf(scanBytePatternsReportSchema),
    examples: [
      {
        title: "Locate MZ and ELF magic",
        input: {
          path: "/artifacts/application",
          patterns: [
            { id: "mz", type: "hex", value: "4D 5A" },
            { id: "elf", type: "hex", value: "7F 45 4C 46" },
          ],
        },
      },
      {
        title: "Find URLs and a wide marker string",
        input: {
          path: "/artifacts/application",
          patterns: [
            { id: "url", type: "regex", value: "https?://[\\w./-]+" },
            { id: "marker", type: "text", value: "Mozilla", wide: true },
          ],
          max_matches: 1000,
        },
      },
    ],
  },
  {
    name: "compute_similarity_hashes",
    ...toolContractMetadata("compute_similarity_hashes"),
    kind: "artifact-provider",
    description:
      "Returns deterministic similarity and identity hashes for one local file read once in memory: whole-file sha256 and md5 (node:crypto), tlsh (clean-room TLSH over the whole file; null under 50 bytes or too uniform), and ssdeep (clean-room CTPH/SpamSum). When the bytes are an executable image it adds imphash and imphash_sorted (pefile-exact PE import hash; delay imports excluded; ordinal-only imports resolved via the ws2_32/wsock32/oleaut32 tables else ord<N>), rich_pe_hash (MD5 of the PE Rich-header clear bytes), telfhash (TLSH over ELF .dynsym global STT_FUNC names after dropping leading .,_,str,mem and trailing 64), symhash (MD5 of the sorted Mach-O external-undefined symbol names), and per_section_sha256 over file-backed sections (bounded, with coverage). An optional slice selects one universal-binary architecture; import/symbol/section hashes then cover only that slice. It never executes the target, uses no network, writes no file, recovers no key or plaintext, and evaluates no trust; input is bounded to 256 MiB. Each hash whose inputs are absent is reported as null (never omitted) with a matching limitation, and a shared value is consistent with structural resemblance, not proof of shared provenance.",
    inputSchema: computeSimilarityHashesInputSchema,
    outputSchema: evidenceResultOf(computeSimilarityHashesReportSchema),
    examples: [
      {
        title: "Hash a shipped executable",
        input: { path: "/artifacts/application" },
      },
      {
        title: "Select one slice of a universal binary",
        input: { path: "/artifacts/application", slice: "arm64" },
      },
    ],
  },
  {
    name: "inspect_code_signature",
    ...toolContractMetadata("inspect_code_signature"),
    kind: "artifact-provider",
    description:
      "Parses an embedded code signature from one local PE or Mach-O file and reports its structure without evaluating trust. For PE Authenticode it returns the security-directory range, each WIN_CERTIFICATE entry (revision, type), the SignerInfo digest algorithm, the SpcSpOpusInfo program name, every X.509 certificate (subject, issuer, serial, validity via node:crypto) and the signer matched by issuer-and-serial, counter-signature/RFC 3161 timestamps, the nested-signature count, and an authentihash recomputed per the Authenticode spec with its stored value and whether they match. For Mach-O it decodes the SuperBlob index, each CodeDirectory (identifier, team id, flags, hash type, cd-hash), embedded XML entitlement keys, and DER-entitlements/requirements/CMS presence. It does NOT verify certificate chains, revocation or OS trust, extract key material, or judge validity; presence is not validity. It reads the file once, never executing the target, with no network and no file writes; lists are bounded with coverage, offsets are validated, and unknown structures are null with a limitation.",
    inputSchema: inspectCodeSignatureInputSchema,
    outputSchema: evidenceResultOf(inspectCodeSignatureReportSchema),
    examples: [
      {
        title: "Authenticode-signed PE",
        input: { path: "/artifacts/application" },
      },
      {
        title: "Universal Mach-O, arm64 slice",
        input: { path: "/artifacts/application", slice: "arm64" },
      },
    ],
  },
  {
    name: "scan_embedded_content",
    ...toolContractMetadata("scan_embedded_content"),
    kind: "artifact-provider",
    description:
      "Returns a binwalk-style map of content embedded in one local file: findings[] each with type (PE, ELF, thin/fat Mach-O, ZIP plus its central-directory and end-of-central-directory records, gzip, zlib, xz, zstd, bzip2, 7z, CAB, PNG, JPEG, PDF, SQLite, DEX, Java class, DER/PEM/PKCS12, SquashFS, cpio, tar, uImage, DTB), file_offset, a derived size or null, confidence (high/medium/low), a validated flag and a description; plus padding_runs[] of 0x00/0xff and a bounded entropy_profile[]. Regions are located by a BinSight-authored magic table and confirmed by bounded header/structure checks; sizes are derived only where a format declares one. It is identification only: it never extracts, decompresses a full stream, writes a file, spawns a process, uses the network or runs the target, and reads the bytes once (256 MiB input cap, single pass, capped candidate and finding counts, 8 MiB output cap). Unknowns are explicit: null size means no declared length, validated=false means a magic-only match, unrecognized regions carry no finding, findings/padding/entropy report truncation via coverage, and limitations state that identification is not proof of content and absence of a finding is not proof of absence.",
    inputSchema: scanEmbeddedContentInputSchema,
    outputSchema: evidenceResultOf(scanEmbeddedContentReportSchema),
    examples: [
      {
        title: "Map embedded content in an application binary",
        input: { path: "/artifacts/application" },
      },
      {
        title:
          "Scan a firmware blob with more findings and a finer entropy window",
        input: {
          path: "/artifacts/firmware.bin",
          max_findings: 2000,
          entropy_window: 4096,
        },
      },
    ],
  },
  {
    name: "generate_sbom",
    ...toolContractMetadata("generate_sbom"),
    kind: "artifact-provider",
    description:
      'Returns a component inventory of one local file plus optional CycloneDX-1.6 and SPDX-2.3-shaped documents, inline. Each component has name, version|null, type (library/application/module), source (go-buildinfo, cargo-auditable, binary-classifier), purl|null, evidence_kind (derived|inferred) and bounded file locations. Sources: Go build info, Rust cargo-auditable metadata, and a BinSight banner-signature table (OpenSSL, zlib, SQLite, libcurl, Node.js, BusyBox, Chrome). completeness is ALWAYS "partial": an absent source is not proof a component is absent, and static/vendored code may carry no recorded identity. Read once without executing the target, with no network, registry or vulnerability-DB access, and nothing is written; SBOM timestamps are fixed so identical bytes give identical output. Versions and purls are reported as observed, not validated. Guards: 256 MiB input, 8 MiB output, 128 MiB scan window, 4096-match and 20000-component caps with coverage/truncation flags. Unknowns stay explicit: null versions/purls and a per-source limitation naming why a source yielded nothing.',
    inputSchema: generateSbomInputSchema,
    outputSchema: evidenceResultOf(generateSbomReportSchema),
    examples: [
      {
        title: "Full inventory with both documents",
        input: { path: "/artifacts/application" },
      },
      {
        title: "CycloneDX only",
        input: { path: "/artifacts/application", format: "cyclonedx" },
      },
    ],
  },
  {
    name: "recover_go_symbols",
    ...toolContractMetadata("recover_go_symbols"),
    kind: "artifact-provider",
    description:
      "Returns Go function symbols recovered from the pclntab embedded in a (possibly stripped) ELF, PE or thin Mach-O: is_go, the header magic (go_version_magic), a pclntab block (file_offset, version 1.2/1.16/1.18/1.20, pointer_size, header-declared function_count), a bounded functions[] list (name, entry virtual address, mapped file_offset or null) with function_coverage, and heuristic package_names with package_coverage. It reads the file once without executing the target, without network access, and without writing files; a universal Mach-O requires selecting a thin slice. It does NOT disassemble, recover types/moduledata/typelinks/inlined frames, read non-pclntab symbol tables, or establish reachability or current validity; names are observed table bytes and packages are inferred name prefixes. Resource guards: 256 MiB input cap, max_functions (default 20000, max 200000) with the remainder reported through function_coverage, a 16 MiB structural-table budget, and an 8 MiB inline-output cap. Unknowns are explicit: no decodable table -> is_go false with empty lists and null magic/pclntab; a non-file-backed entry -> file_offset null; absence of a pclntab is not proof the file is not Go.",
    inputSchema: recoverGoSymbolsInputSchema,
    outputSchema: evidenceResultOf(recoverGoSymbolsReportSchema),
    examples: [
      {
        title: "Recover function names from a stripped Go ELF",
        input: { path: "/artifacts/application" },
      },
      {
        title:
          "Recover from one slice of a universal Go Mach-O with a smaller cap",
        input: {
          path: "/artifacts/application",
          slice: "arm64",
          max_functions: 5000,
        },
      },
    ],
  },
  {
    name: "compare_executables",
    ...toolContractMetadata("compare_executables"),
    kind: "artifact-provider",
    description:
      "Compares two local executables (base_path and target_path, both absolute; optional Mach-O slice applied to both; max_list 1-5000, default 500) and returns a by-name structural diff. Reports base and target identity (path, sha256, bytes), the target subject, identical, format_changed (base/target format family), size_delta, entry_point_changed (virtual addresses), and added/removed imports (library+name+ordinal), exports (name+ordinal), libraries and sections, per-section Shannon-entropy deltas for sections present in both, and inferred hardening_changes (ELF PIE/RELRO/NX/stack-canary/FORTIFY/stripped; PE DYNAMIC_BASE/NX/HIGH_ENTROPY_VA/GUARD_CF/FORCE_INTEGRITY/NO_SEH/Authenticode; Mach-O PIE/stack-exec/code-signature/encryption/restrict). Every list is bounded with its own coverage. It does NOT unpack, detect renames (a rename is one removal plus one addition), evaluate signature trust, or recover code or behavior. Both files are read once (<=256 MiB each) through the stable-snapshot reader and parsed in-process; neither file is run, and no network or temporary files are used; the complete report is capped at 8 MiB with a typed resource error if exceeded. A side that is not ELF/PE/Mach-O yields empty structural lists and a limitation, indicators that do not apply to a format are null, and any truncation is reported in that list's coverage.",
    inputSchema: compareExecutablesInputSchema,
    outputSchema: evidenceResultOf(compareExecutablesReportSchema),
    examples: [
      {
        title: "Diff two shipped builds of the same program",
        input: {
          base_path: "/artifacts/application-v1",
          target_path: "/artifacts/application-v2",
        },
      },
      {
        title: "Diff one slice of a universal binary with a tighter list cap",
        input: {
          base_path: "/artifacts/application-arm64-old",
          target_path: "/artifacts/application-arm64-new",
          slice: "arm64",
          max_list: 100,
        },
      },
    ],
  },
  {
    name: "triage_file",
    ...toolContractMetadata("triage_file"),
    kind: "artifact-provider",
    description:
      "Triage one local file in a single read-only pass, composing several static readers over one snapshot: file type and ELF/PE/Mach-O structure summary (architecture, entry point, import/export/library counts, overlay presence), SHA-256 and MD5, file and overlay Shannon entropy with a low/normal/high classification, compiler/packer/installer indicators with a packed indicator, coarse import-capability classes and whether runtime symbol resolution is imported, embedded code-signature presence, a string total with tag counts, and a next_probes list of deeper BinSight operations to run. Reads the file once (up to 256 MiB) WITHOUT executing the target, without network access and without writing files; the report is a bounded summary (8 MiB cap). Every classification is an inference, not proof of behavior; run the next_probes for complete paged evidence. Non-executable bytes are summarized as data rather than refused.",
    inputSchema: triageFileInputSchema,
    outputSchema: evidenceResultOf(triageFileReportSchema),
    examples: [
      {
        title: "Triage an unknown file in one call",
        input: { path: "/artifacts/application" },
      },
      {
        title: "Triage one slice of a universal binary",
        input: { path: "/artifacts/application", slice: "arm64" },
      },
    ],
  },
  {
    name: "generate_triage_report",
    ...toolContractMetadata("generate_triage_report"),
    kind: "artifact-provider",
    description:
      "Render a shareable GitHub-flavored Markdown triage report for one local file from the same one-call triage facets (file type, SHA-256 and MD5, structure summary, entropy, toolchain and packing indicators, import-capability classes, code-signature presence, string tag counts, and suggested next BinSight operations). Returns the Markdown document plus the identity fields it was built from. All rendered values are BinSight labels, hashes and numbers, not free-form target text. Reads the file once (up to 256 MiB) WITHOUT executing the target, without network access and without writing files; the tool returns the report inline and does not save it. The report restates static inferences, not proof of behavior.",
    inputSchema: generateTriageReportInputSchema,
    outputSchema: evidenceResultOf(generateTriageReportReportSchema),
    examples: [
      {
        title: "Generate a shareable triage report",
        input: { path: "/artifacts/application" },
      },
      {
        title: "Report on one universal-binary slice",
        input: { path: "/artifacts/application", slice: "arm64" },
      },
    ],
  },
  {
    name: "compare_binaries",
    ...toolContractMetadata("compare_binaries"),
    kind: "artifact-provider",
    description:
      "Compare two local files byte-for-byte and explain what changed, for any file type (firmware dumps, ECU calibration files, app or driver updates, data blobs), not only executables. Returns both files' SHA-256 and size, whether they are identical, the size delta, the count and fraction of changed bytes, the overall changed offset range, a summary (how many bytes were zeroed, filled with 0xFF, or otherwise modified), and a bounded list of contiguous changed regions — each with its file offset, length, a kind (zeroed/filled/modified) and before/after value samples read as little-endian words of the chosen width. Regions are coalesced by a caller gap and bounded by max_regions. Reads both files once (up to 256 MiB each) WITHOUT executing them, without network access and without writing files; the report is bounded to 8 MiB. It does no format-aware labeling: it reports where and how bytes differ, not named maps, fields or functions. Only the shorter length is compared; extra trailing bytes are reported as size_delta.",
    inputSchema: compareBinariesInputSchema,
    outputSchema: evidenceResultOf(compareBinariesReportSchema),
    examples: [
      {
        title: "Diff two firmware or calibration dumps",
        input: {
          base_path: "/artifacts/original.bin",
          target_path: "/artifacts/modified.bin",
        },
      },
      {
        title: "Diff two app builds, reporting 32-bit values",
        input: {
          base_path: "/artifacts/app-v1",
          target_path: "/artifacts/app-v2",
          word_size: 4,
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
