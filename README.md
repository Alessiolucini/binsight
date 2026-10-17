<div align="center">

# BinSight

### The AI X-ray for any file. Point it at a binary and ask: **what is it, what does it hide, and what changed?**

**Offline · cross-platform · with evidence. It never runs the file.**

[![MCP tool catalog](https://img.shields.io/badge/MCP-tool_catalog-5c4ee5?style=flat-square)](docs/mcp-contracts.md#generated-catalog)
[![license MIT](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](LICENSE)

Built on [REA (morluto/rea)](https://github.com/morluto/rea) · MIT

</div>

---

Most files are black boxes: an `.exe` you downloaded, a firmware dump, a driver,
a game, an ECU calibration, an app update. BinSight opens the box — **statically,
on your own machine, without ever running the file** — and answers the three
questions that matter, in plain language and with the evidence to back them up.

```text
You: What is this file? Is it hiding anything? And what changed vs the old version?

BinSight: PE/Windows x64, compiled with MSVC, UPX-packed (entropy 7.9),
          imports consistent with network + process injection, Authenticode
          signature present, and vs the previous build 3 regions changed —
          here are the offsets. All static, all offline, with evidence.
```

## The three questions

### 🔎 What is it?

`triage_file` and `inspect_executable` read ELF, PE/Windows and Mach-O (and raw
blobs) and tell you the type, architecture, entry point, imports/exports,
sections, hashes, and a compiler/packer fingerprint — **without starting Ghidra
or IDA**, on macOS, Windows or Linux.

### 🕵️ What does it hide?

`detect_binary_toolchain`, `measure_binary_entropy`, `classify_import_capabilities`,
`identify_crypto_constants`, `extract_binary_strings`, `inspect_code_signature`
and `scan_embedded_content` surface packing, high-entropy regions, imported
capabilities (network, process, crypto…), IOC strings, embedded files, and
whether a signature is real — reported as evidence and inference, never as a
verdict.

### 🔁 What changed?

`compare_binaries` diffs **any two files** byte-for-byte and explains the change
— which regions moved, what was zeroed or maxed out, the before/after values.
Works on app updates, drivers, firmware and ECU calibration dumps alike.
`compare_executables` adds import/export/section/hardening deltas for executables.

## All 17 tools

| Tool                               | What it answers                                                                                   |
| ---------------------------------- | ------------------------------------------------------------------------------------------------- |
| **`triage_file`**                  | One call: type, hashes, structure, entropy, packing, capabilities, signature, strings, next steps |
| **`generate_triage_report`**       | A shareable Markdown triage report                                                                |
| **`compare_binaries`**             | Diff **any** two files and explain what changed (firmware, ECU dumps, updates)                    |
| **`compare_executables`**          | Diff two executables: imports, exports, sections, hardening, entropy                              |
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

Every result separates **observations, inferences and unknowns**, carries file
offsets, and states its limitations. **Detection only** — nothing is unpacked,
decrypted, cracked or executed.

## Quickstart

```bash
npx binsight triage-file /path/to/file --json
npx binsight compare-binaries /path/to/old /path/to/new --json
npx binsight generate-triage-report /path/to/file --json
```

Register BinSight as an MCP server for your AI agent, then just ask it in plain
language ("what is this file, what does it hide, what changed?"):

```bash
npx binsight setup
```

BinSight supports the same agents as REA — see
[supported agents](docs/installation.md#supported-agents); other clients can use
[manual MCP registration](docs/installation.md#mcp-registry).

## Verified against the reference tools

BinSight's parsers and hashes are checked against the tools analysts already
trust: **imphash matches `pefile` byte-for-byte**, structure matches **LIEF /
readelf / otool**, and hardening and packing results match **checksec** and
**Detect It Easy** on a real corpus of ELF, PE and Mach-O binaries.

## Documentation

- [Static intelligence suite](docs/static-intelligence.md): the 17 tools, with CLI and MCP examples.
- [Tool catalog](docs/mcp-contracts.md#generated-catalog): generated inventory of tools, providers and CLI commands.
- [Installation and setup](docs/installation.md): providers, agents and manual registration.

## Built on REA

BinSight builds on [REA](https://github.com/morluto/rea) and adds the static
intelligence suite above. REA is MIT-licensed; this project keeps that license
and attribution. **This is not an official REA release** — for REA itself, go to
[morluto/rea](https://github.com/morluto/rea).

## License

MIT. See [LICENSE](LICENSE). Portions © the REA authors.
