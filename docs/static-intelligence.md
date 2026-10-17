# Static intelligence suite

The static intelligence tools inspect one local ELF, PE/COFF or Mach-O file (and
some non-executable formats) with no external analysis engine, no network access
and no target execution. They run in-process, on any supported host, and return
Evidence with explicit observations, inferences and limitations.

They complement the deep-analysis providers (Hopper, Ghidra, IDA): use these for
fast, portable triage and structure, then open a provider session for
decompilation and cross-references.

## What you can ask

- "What does this binary import and export, and what sections does it have?"
- "Is it packed? What compiler or installer produced it?"
- "What is its exploit-mitigation posture (PIE, canary, NX, RELRO, CFG, ASLR)?"
- "What crypto constants and capabilities are present?"
- "What changed between these two builds?"
- "Give me a shareable triage report for this unknown file."

## Tools

| Tool                           | Purpose                                                                                                                                                                                     |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `triage_file`                  | One-call read-only triage: type, hashes, structure, entropy, packing, capabilities, signature, strings and suggested next steps.                                                            |
| `generate_triage_report`       | Render the triage facets as a shareable GitHub-flavored Markdown report.                                                                                                                    |
| `inspect_executable`           | Unified ELF/PE/Mach-O structure: sections, segments, imports, exports, libraries, symbols, entry point, overlay and per-format detail.                                                      |
| `inspect_binary_hardening`     | Cross-platform exploit-mitigation indicators for ELF, PE and Mach-O.                                                                                                                        |
| `measure_binary_entropy`       | File, per-section and per-block Shannon entropy with high/low runs and chi-square.                                                                                                          |
| `detect_binary_toolchain`      | Compiler, packer, protector, installer, language and bundler indicators, with a packed indicator.                                                                                           |
| `extract_binary_strings`       | ASCII/UTF-16/UTF-8 strings with offsets, sections and inferred IOC tags (URL, IP, path, registry key, GUID, …).                                                                             |
| `identify_crypto_constants`    | Well-known cryptographic constant tables (AES, SHA, MD5, CRC32, ChaCha, curves, …).                                                                                                         |
| `classify_import_capabilities` | Coarse capability classes inferred from the import table, stated as "imports consistent with".                                                                                              |
| `scan_byte_patterns`           | Search a file for caller-supplied byte, hex-wildcard, text and regex patterns.                                                                                                              |
| `compute_similarity_hashes`    | imphash, Rich-header hash, symhash, telfhash, ssdeep and TLSH similarity hashes.                                                                                                            |
| `inspect_code_signature`       | Parse Authenticode (PE) and Mach-O code-signature structure, without evaluating trust.                                                                                                      |
| `scan_embedded_content`        | Identify embedded files and padding by validated magic signatures (offsets only; no extraction).                                                                                            |
| `generate_sbom`                | Component inventory (CycloneDX / SPDX shapes) from embedded Go, Rust and binary-classifier metadata.                                                                                        |
| `recover_go_symbols`           | Recover function names from an embedded Go `pclntab`, including stripped binaries.                                                                                                          |
| `compare_executables`          | Diff two executables: imports, exports, sections, libraries, hardening and section entropy.                                                                                                 |
| `compare_binaries`             | Diff any two files byte-for-byte and explain what changed (firmware, calibration dumps, app/driver updates): changed regions, zeroed/0xFF-filled/modified, with before/after value samples. |

## CLI

```bash
# One-call triage of an unknown file
rea triage-file /path/to/sample --json

# A shareable Markdown report
rea generate-triage-report /path/to/sample --json

# Structure, hardening, packing, hashes
rea inspect-executable /path/to/sample --json
rea inspect-binary-hardening /path/to/sample --json
rea detect-binary-toolchain /path/to/sample --json
rea compute-similarity-hashes /path/to/sample --json

# Diff two builds
rea compare-executables /path/to/old /path/to/new --json
```

## MCP

```json
{ "name": "triage_file", "arguments": { "path": "/artifacts/application" } }
```

```json
{
  "name": "compare_executables",
  "arguments": {
    "base_path": "/artifacts/application-v1",
    "target_path": "/artifacts/application-v2"
  }
}
```

## What they do not do

- They do not execute, unpack, deobfuscate protected code, or defeat any
  protection; detection is reported as inference, never as a verdict.
- They do not evaluate certificate-chain or OS trust for a parsed signature.
- They do not reach the network or write files (except that you choose where to
  save the output of a tool that returns one).
- Classifications (packing, toolchain, capabilities, crypto, IOC tags) are
  inferences layered over observed bytes; an absent result means nothing was
  observed, not that the property is impossible.

Every tool reads the selected file once (up to 256 MiB), bounds its work, and
returns a report capped at 8 MiB with explicit `limitations`.
