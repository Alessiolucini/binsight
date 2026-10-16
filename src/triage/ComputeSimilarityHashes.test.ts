import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import type {
  ImageImport,
  ImageSymbol,
} from "../domain/native/image/executableImage.js";
import { computeSimilarityHashesReportSchema } from "../domain/triage/computeSimilarityHashes.js";
import { analyzeComputeSimilarityHashes } from "./ComputeSimilarityHashes.js";
import { computeImphashes } from "./simhash/imphash.js";
import { ssdeepHash } from "./simhash/ssdeep.js";
import { computeSymhash } from "./simhash/symhash.js";
import { computeTelfhash, telfhashSymbols } from "./simhash/telfhash.js";
import { tlshHash } from "./simhash/tlsh.js";

/** Deterministic pseudo-random buffer (shared with the recorded oracle values). */
const deterministicBuffer = (length: number): Buffer => {
  const buffer = Buffer.alloc(length);
  let state = 12345 >>> 0;
  for (let index = 0; index < length; index += 1) {
    state = (Math.imul(1103515245, state) + 12345) >>> 0;
    buffer[index] = (state >>> 16) & 0xff;
  }
  return buffer;
};

// TLSH / ssdeep values recorded from py-tlsh 5.0.0 and ppdeep over this buffer.
const DET_TLSH =
  "T1F601C597E62576B0656B80B906E93423EA4BEE980EDD52205E5201CBF23C7C2C108D2D";
const DET_SSDEEP =
  "12:bJQGl0Q0onoDGQ9Nwv9IBf990cKXCfRX8NoAd4o4b75TTfDm8h0C8pSX3TXr:b+GlL0ooDGQ9NOC7lMCPOaNDDm8M03Tb";
const DET_SHA256 =
  "129dc25c1eb7f1b355794ff2f1b038c3592eb898410567bb4e189c16d5afa72e";
const DET_MD5 = "7803758bd102ecdf2bd5ea5819a508d6";

const makeSymbol = (
  over: Partial<ImageSymbol> & { name: string },
): ImageSymbol => ({
  value: 0n,
  size: 0n,
  type: "function",
  binding: "global",
  defined: true,
  table: "dynsym",
  ...over,
});

const makeImport = (
  over: Partial<ImageImport> & { library: string },
): ImageImport => ({
  name: null,
  ordinal: null,
  delay_loaded: false,
  weak: false,
  version: null,
  ...over,
});

describe("tlsh", () => {
  it("reproduces the reference digest for a known buffer", () => {
    expect(tlshHash(deterministicBuffer(800))).toBe(DET_TLSH);
  });

  it("returns null for inputs shorter than 50 bytes", () => {
    expect(tlshHash(deterministicBuffer(49))).toBeNull();
  });

  it("returns null for uniform data that cannot be hashed", () => {
    expect(tlshHash(Buffer.alloc(500))).toBeNull();
  });
});

describe("ssdeep", () => {
  it("reproduces the reference digest for a known buffer", () => {
    expect(ssdeepHash(deterministicBuffer(800))).toBe(DET_SSDEEP);
  });

  it("emits the empty-input digest", () => {
    expect(ssdeepHash(Buffer.alloc(0))).toBe("3::");
  });
});

describe("imphash", () => {
  it("matches pefile over named, ordinal and delay imports", () => {
    const imports: ImageImport[] = [
      makeImport({ library: "WS2_32.dll", ordinal: 3 }),
      makeImport({ library: "OLEAUT32.dll", ordinal: 2 }),
      makeImport({ library: "FOO.dll", ordinal: 999 }),
      makeImport({ library: "KERNEL32.dll", name: "CreateFileA" }),
      makeImport({ library: "DELAY.dll", name: "Ignored", delay_loaded: true }),
    ];
    const { imphash, imphashSorted } = computeImphashes(imports);
    // ws2_32.closesocket,oleaut32.sysallocstring,foo.ord999,kernel32.createfilea
    expect(imphash).toBe("d2674d4580a8642c39fa6ba325bc41bc");
    expect(imphashSorted).not.toBeNull();
    expect(imphashSorted).not.toBe(imphash);
  });

  it("is null when no non-delay imports qualify", () => {
    expect(computeImphashes([]).imphash).toBeNull();
    expect(
      computeImphashes([
        makeImport({ library: "a.dll", name: "f", delay_loaded: true }),
      ]).imphash,
    ).toBeNull();
  });
});

describe("symhash", () => {
  it("hashes sorted external undefined symbol names", () => {
    const names = [
      "_printf",
      "_strlen",
      "_malloc",
      "___stack_chk_fail",
      "_fopen",
    ];
    expect(computeSymhash(names)).toBe("6dee623048c5c4d0cbbf941641af6fd9");
  });

  it("is order independent and null when empty", () => {
    expect(computeSymhash(["_b", "_a"])).toBe(computeSymhash(["_a", "_b"]));
    expect(computeSymhash([])).toBeNull();
  });
});

describe("telfhash", () => {
  const names = [
    "aes_encrypt",
    "connect_socket",
    "decrypt_block",
    "encode_frame",
    "handle_request",
    "init_context",
    "parse_header",
    "process_event",
    "read_config",
    "send_packet",
    "validate_token",
    "write_output",
  ];

  it("selects only global dynsym functions after noise filtering", () => {
    const symbols: ImageSymbol[] = [
      ...names.map((name) => makeSymbol({ name })),
      makeSymbol({ name: "_hidden_init" }),
      makeSymbol({ name: "strdup_helper" }),
      makeSymbol({ name: "memcpy_fast" }),
      makeSymbol({ name: "read_config64" }),
      makeSymbol({ name: "local_only", binding: "local" }),
      makeSymbol({ name: "a_global_object", type: "object" }),
      makeSymbol({ name: "from_symtab", table: "symtab" }),
    ];
    expect(telfhashSymbols(symbols)).toEqual([...names].sort());
    const result = computeTelfhash(symbols);
    expect(result.symbol_count).toBe(names.length);
    expect(result.hash).toBe(
      "T180C0809B0C7DBD1D1F574C94B565C55514C5D5450330053154015D7884E51C010C6757",
    );
  });

  it("is null without qualifying symbols", () => {
    expect(computeTelfhash([]).hash).toBeNull();
    expect(computeTelfhash([makeSymbol({ name: "_x" })]).hash).toBeNull();
  });
});

describe("analyzeComputeSimilarityHashes", () => {
  const context = (bytes: Buffer) => ({
    sha256: createHash("sha256").update(bytes).digest("hex"),
  });
  const validate = (
    bytes: Buffer,
    body: Awaited<ReturnType<typeof analyzeComputeSimilarityHashes>>,
  ) =>
    computeSimilarityHashesReportSchema.safeParse({
      ...body,
      artifact: {
        path: "/artifacts/sample",
        sha256: body.sha256,
        bytes: bytes.length,
      },
    });

  it("reports whole-file digests and null image hashes for non-executable content", async () => {
    const bytes = deterministicBuffer(800);
    const body = await analyzeComputeSimilarityHashes(
      bytes,
      { path: "/artifacts/sample" },
      context(bytes),
    );
    expect(body.subject.format).toBe("file");
    expect(body.sha256).toBe(DET_SHA256);
    expect(body.md5).toBe(DET_MD5);
    expect(body.tlsh).toBe(DET_TLSH);
    expect(body.ssdeep).toBe(DET_SSDEEP);
    expect(body.imphash).toBeNull();
    expect(body.imphash_sorted).toBeNull();
    expect(body.rich_pe_hash).toBeNull();
    expect(body.telfhash).toBeNull();
    expect(body.symhash).toBeNull();
    expect(body.per_section_sha256).toEqual([]);
    expect(
      body.limitations.some((note) => note.includes("not a recognized ELF")),
    ).toBe(true);
    expect(validate(bytes, body).success).toBe(true);
  });

  it("marks tlsh null with a limitation for short inputs", async () => {
    const bytes = deterministicBuffer(20);
    const body = await analyzeComputeSimilarityHashes(
      bytes,
      { path: "/artifacts/tiny" },
      context(bytes),
    );
    expect(body.tlsh).toBeNull();
    expect(body.limitations.some((note) => note.includes("tlsh is null"))).toBe(
      true,
    );
    expect(validate(bytes, body).success).toBe(true);
  });
});
