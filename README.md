<div align="center">

# BinSight

### X-ray any binary. Static reverse-engineering intelligence for your AI agent — offline, cross-platform, with evidence.

**No Ghidra. No IDA. No internet. It never runs the file.**

[![MCP tool catalog](https://img.shields.io/badge/MCP-tool_catalog-5c4ee5?style=flat-square)](docs/mcp-contracts.md#generated-catalog)
[![license MIT](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](LICENSE)

Built on [REA (morluto/rea)](https://github.com/morluto/rea) · MIT

</div>

---

Point your AI agent (or your terminal) at any ELF, PE/Windows or Mach-O file and
ask what it is, what it does, and how it was built — and get an answer backed by
evidence, on **macOS, Windows or Linux**, without installing a disassembler and
without ever executing the target.

```text
You: Triage this unknown binary. Is it packed? What crypto does it use?
     Diff it against the previous version.

BinSight: UPX-packed (entropy 7.9), constants consistent with AES + SHA-256,
          Authenticode signature present, +3 network imports vs the prior build.
          — all static, all offline, with file offsets and evidence.
```

## Why

Great reverse-engineering tooling exists, but it's heavy: you need Ghidra, IDA or
Hopper to see imports and exports, `pwntools` on Linux for a hardening check,
macOS for `codesign`. BinSight puts **fast, portable, dependency-free static
triage** directly in your agent — so you can answer most questions in one call,
and only reach for the heavy tools when you actually need decompilation.

## What it adds (16 tools)

| Tool                               | What it answers                                                                                   |
| ---------------------------------- | ------------------------------------------------------------------------------------------------- |
| **`triage_file`**                  | One call: type, hashes, structure, entropy, packing, capabilities, signature, strings, next steps |
| **`generate_triage_report`**       | A shareable Markdown triage report                                                                |
| **`inspect_executable`**           | Sections, imports, exports, libraries, symbols, entry point, overlay — ELF/PE/Mach-O              |
| **`inspect_binary_hardening`**     | checksec for every OS: PIE, canary, NX, RELRO, CFG, ASLR, hardened runtime                        |
| **`measure_binary_entropy`**       | File / section / block Shannon entropy + chi-square                                               |
| **`detect_binary_toolchain`**      | Compiler, packer, installer, language (UPX, MSVC, PyInstaller, Go…)                               |
| **`extract_binary_strings`**       | ASCII/UTF-16 strings classified into IOCs (URL, IP, path, registry…)                              |
| **`identify_crypto_constants`**    | AES S-box, SHA/MD5, CRC32, ChaCha, curve parameters…                                              |
| **`classify_import_capabilities`** | Capabilities inferred from imports ("consistent with", never a verdict)                           |
| **`scan_byte_patterns`**           | Byte / hex-wildcard / text / regex search, no provider needed                                     |
| **`compute_similarity_hashes`**    | imphash, Rich hash, symhash, telfhash, ssdeep, TLSH                                               |
| **`inspect_code_signature`**       | Authenticode + Mach-O code signature — on any host                                                |
| **`scan_embedded_content`**        | binwalk-style embedded-file identification (offsets only)                                         |
| **`generate_sbom`**                | CycloneDX / SPDX component inventory from embedded metadata                                       |
| **`recover_go_symbols`**           | Function names from a stripped Go `pclntab`                                                       |
| **`compare_executables`**          | Diff two builds: imports, exports, sections, hardening, entropy                                   |

Every result separates **observations, inferences and unknowns**, carries file
offsets, and states its limitations. Detection only — nothing is unpacked,
decrypted, or executed.

## Quickstart

```bash
npx binsight triage-file /path/to/sample --json
npx binsight generate-triage-report /path/to/sample --json
npx binsight compare-executables /path/to/old /path/to/new --json
```

Register BinSight as an MCP server for your agent, then ask it to investigate a
feature and show the evidence:

```bash
npx binsight setup
```

BinSight supports the same agents as REA — see
[supported agents](docs/installation.md#supported-agents); other clients can use
[manual MCP registration](docs/installation.md#mcp-registry).

## Verified against the reference tools

BinSight's parsers and hashes are checked against the tools analysts already
trust: **imphash matches `pefile` byte-for-byte**, structure matches **LIEF /
readelf / otool**, and the hardening and packing results match **checksec** and
**Detect It Easy** on a real corpus of ELF, PE and Mach-O binaries.

## Documentation

- [Static intelligence suite](docs/static-intelligence.md): the 16 tools, with CLI and MCP examples.
- [Tool catalog](docs/mcp-contracts.md#generated-catalog): generated inventory of tools, providers and CLI commands.
- [Installation and setup](docs/installation.md): providers, agents and manual registration.

## Built on REA

BinSight builds on [REA](https://github.com/morluto/rea) and adds the static
intelligence suite above. REA is MIT-licensed; this project keeps that license
and attribution. **This is not an official REA release** — for REA itself, go to
[morluto/rea](https://github.com/morluto/rea).

## License

MIT. See [LICENSE](LICENSE). Portions © the REA authors.
