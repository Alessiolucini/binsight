# BinSight in 60 seconds

Real, unedited output. Everything below is **static** — BinSight reads the file,
it never runs it — **offline**, on macOS / Windows / Linux, **without Ghidra or IDA**.

---

## 🔎 "What is this file?"

```bash
binsight triage-file ./sample.exe --json
```

A UPX-packed Windows binary, caught in one call:

```
type: pe  x86_64
packed: likely_packed
toolchain: UPX, MinGW (GCC for Windows)
file entropy: 6.98 bits/byte
```

BinSight read the type, architecture, **who compiled it, that it's packed**, and
its entropy — with no disassembler, in a single command.

---

## 🕵️ "Is it the same malware family? What's its fingerprint?"

```bash
binsight compute-similarity-hashes ./sample.exe --json
```

```
imphash: b3b3b59f7981590a22dc3fe2e580751e
```

That import hash is **byte-for-byte identical to `pefile`**, the reference tool
analysts trust — so you can cluster samples and match known families, offline.

---

## 🔁 "What changed between these two versions?"

```bash
binsight compare-binaries ./old.exe ./new.exe --json
```

```
changed: 47,677 bytes (19.54%)
regions: 467
range: 0x90 .. 0x3b93c
```

BinSight diffs **any** two files and tells you exactly where and how they differ.

### The headline example: a car ECU tune 🏎️

Two Bosch ME7.9.10 calibration dumps — a factory file and a tuned one — diffed
with the same command. BinSight found, with no ECU-specific database:

```
changed: 5,680 bytes (0.667%)  — all in the calibration area, firmware code untouched
87 changed regions
538 bytes raised to 0xFF (limits lifted)   577 bytes zeroed (checks disabled)

rev limiter:  6431 -> 7460 rpm   @ 0x981ec
rpm tables raised to ~7400-7700 rpm
```

A pure map tune, isolated to the byte — the kind of answer that normally needs a
€2,000 Windows tool. **No AI assistant does this. BinSight just did.**

---

## 📝 A shareable report, automatically

```bash
binsight generate-triage-report ./sample --json
```

returns a ready-to-paste Markdown report: type, hashes, structure, entropy,
packing, capabilities, signature, strings and suggested next steps.

---

## Or just ask your AI agent

With BinSight connected over MCP (`npx binsight setup`), skip the commands:

> _"What is this file, is it hiding anything, and what changed vs the old build?"_

and your agent runs the tools and answers — with the evidence.

---

Detection only. Nothing is unpacked, decrypted, cracked or executed. Every answer
separates observation from inference and states its limits. Built on
[REA](https://github.com/morluto/rea), MIT.
