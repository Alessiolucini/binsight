import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { elf, pe } from "../domain/binaryTarget.fixture.js";
import { inspectCodeSignatureReportSchema } from "../domain/triage/inspectCodeSignature.js";
import { children, readIntegerHex, readNode, readOid } from "./codesign/der.js";
import { analyzeInspectCodeSignature } from "./InspectCodeSignature.js";
import type { TriageAnalysisContext } from "./triageSupport.js";

const context: TriageAnalysisContext = { sha256: "0".repeat(64) };

/** A stable self-signed certificate (serial 1122334455667788) generated with openssl. */
const CERT_DER = Buffer.from(
  "MIIDCTCCAfECCBEiM0RVZneIMA0GCSqGSIb3DQEBCwUAMEcxCzAJBgNVBAYTAlVTMRgwFgYDVQQKDA9SRUEgVHJpYWdlIFRlc3QxHjAcBgNVBAMMFVJFQSBDb2RlIFNpZ25pbmcgVGVzdDAeFw0yNjEwMTYyMTUyMzlaFw0zNjEwMTMyMTUyMzlaMEcxCzAJBgNVBAYTAlVTMRgwFgYDVQQKDA9SRUEgVHJpYWdlIFRlc3QxHjAcBgNVBAMMFVJFQSBDb2RlIFNpZ25pbmcgVGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMJ5Ev+d63SG+w4wBvB7YeH61xQFi4ipnMy947Njje52EExysu8U1Jr030m1srV+PPOPIJNL4JxsxnvcG+FUPmV3ImURolPEC+/NYozL+sfsUEVrJeZjtXp4xdzHKPwwXWHAn+YQ7/7muDEFIEYVeKvgPm4WLJhxRUnFKEwAT5qBzEdwLjRNtnbQ5rcyAsGHjDoq40YFsAI6FUn8qZyaviLOTg0Qd5O7WrhZKKpvG32845WIUwPOZANUa8GACer6Wgwih/Xz36JN1uthNj6qeEAtK0x6ZqcV/l+B9IJc04nkce+nwMA5JxowAyEcJcd6aAZN46pGJJvVEC8oY0Ou7tkCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEArSn307FvenCCNicLho5f8MJLk4ctatx/xUKCXy8oh7iNM1yetL4mZ2wJJItaJrn8MjoFqsEDf+ZZIkBU05ahgG511ao/2TcBEgseU8U3G+imjdNXNhrbT6IbM+qaAKda3XHOjjPWewKBUCLAZr/SQdL0/SOKzgis3qJrqJP/flyOyhQMAZZ+e+xlreAL7zFi2jqP6aMmFtcUFwDRS8RuA6P0crMzlwWbgcMoFZOSXY7sG3Pqhd6k8VZ/omsk2kCRDdDe33KWo/53d7O6RmrbwQLE76lo4LM6NetApRc43/FVMnyK+41tGtEm0nkqppOXodGk2YlFtn++1KGWDexYvQ==",
  "base64",
);

// ----- minimal DER encoder for building a synthetic PKCS#7 ------------------

const len = (n: number): Buffer => {
  if (n < 0x80) return Buffer.from([n]);
  const octets: number[] = [];
  let value = n;
  while (value > 0) {
    octets.unshift(value & 0xff);
    value >>>= 8;
  }
  return Buffer.from([0x80 | octets.length, ...octets]);
};
const tlv = (tag: number, content: Buffer): Buffer =>
  Buffer.concat([Buffer.from([tag]), len(content.length), content]);
const seq = (...parts: Buffer[]): Buffer => tlv(0x30, Buffer.concat(parts));
const set = (...parts: Buffer[]): Buffer => tlv(0x31, Buffer.concat(parts));
const ctx = (n: number, content: Buffer, constructed = true): Buffer =>
  tlv((constructed ? 0xa0 : 0x80) | n, content);
const octet = (content: Buffer): Buffer => tlv(0x04, content);
const nullValue = (): Buffer => tlv(0x05, Buffer.alloc(0));
const integer = (bytes: Buffer): Buffer => {
  const signed =
    (bytes[0] ?? 0) & 0x80 ? Buffer.concat([Buffer.from([0]), bytes]) : bytes;
  return tlv(0x02, signed);
};
const oid = (dotted: string): Buffer => {
  const parts = dotted.split(".").map(Number);
  const body: number[] = [40 * (parts[0] ?? 0) + (parts[1] ?? 0)];
  for (const arc of parts.slice(2)) {
    const stack: number[] = [arc & 0x7f];
    let value = arc >>> 7;
    while (value > 0) {
      stack.unshift((value & 0x7f) | 0x80);
      value >>>= 7;
    }
    body.push(...stack);
  }
  return tlv(0x06, Buffer.from(body));
};
const algId = (dotted: string): Buffer => seq(oid(dotted), nullValue());

const SHA256_OID = "2.16.840.1.101.3.4.2.1";

const utcTime = (text: string): Buffer =>
  tlv(0x17, Buffer.from(text, "latin1"));

/** A legacy PKCS#9 counter-signature with a signingTime, plus two nested signatures. */
const buildUnsignedAttrs = (): Buffer => {
  const counterSigner = seq(
    integer(Buffer.from([1])),
    seq(seq(), integer(Buffer.from([0x09]))),
    algId(SHA256_OID),
    ctx(0, seq(oid("1.2.840.113549.1.9.5"), set(utcTime("260101000000Z")))),
    algId("1.2.840.113549.1.1.1"),
    octet(Buffer.from([0x55])),
  );
  const counterSig = seq(oid("1.2.840.113549.1.9.6"), set(counterSigner));
  const nested = seq(
    oid("1.3.6.1.4.1.311.2.4.1"),
    set(seq(integer(Buffer.from([0]))), seq(integer(Buffer.from([0])))),
  );
  return ctx(1, Buffer.concat([counterSig, nested]));
};

/** Build a PKCS#7 SignedData whose SpcIndirectData carries `digest`. */
const buildPkcs7 = (digest: Buffer, unsignedAttrs?: Buffer): Buffer => {
  const serial = integer(Buffer.from("1122334455667788", "hex"));
  const digestInfo = seq(algId(SHA256_OID), octet(digest));
  const spcData = seq(oid("1.3.6.1.4.1.311.2.1.15"), ctx(0, Buffer.alloc(0)));
  const spcIndirect = seq(spcData, digestInfo);
  const encap = seq(oid("1.3.6.1.4.1.311.2.1.4"), ctx(0, octet(spcIndirect)));
  const programNameBmp = Buffer.from("Test Program", "utf16le").swap16();
  const opusInfo = seq(ctx(0, ctx(0, programNameBmp, false)));
  const opusAttr = seq(oid("1.3.6.1.4.1.311.2.1.12"), set(opusInfo));
  const signedAttrs = ctx(0, opusAttr);
  const signerInfo = seq(
    integer(Buffer.from([1])),
    seq(seq(), serial),
    algId(SHA256_OID),
    signedAttrs,
    algId("1.2.840.113549.1.1.1"),
    octet(Buffer.from([0, 1, 2, 3])),
    ...(unsignedAttrs === undefined ? [] : [unsignedAttrs]),
  );
  const signedData = seq(
    integer(Buffer.from([1])),
    set(algId(SHA256_OID)),
    encap,
    ctx(0, CERT_DER),
    set(signerInfo),
  );
  return seq(oid("1.2.840.113549.1.7.2"), ctx(0, signedData));
};

/** Wrap PKCS#7 in a WIN_CERTIFICATE and append it to the PE, setting the security directory. */
const signPe = (base: Buffer, pkcs7: Buffer): Buffer => {
  const certLength = 8 + pkcs7.length;
  const padded = Math.ceil(certLength / 8) * 8;
  const winCert = Buffer.alloc(padded);
  winCert.writeUInt32LE(certLength, 0);
  winCert.writeUInt16LE(0x0200, 4);
  winCert.writeUInt16LE(0x0002, 6);
  pkcs7.copy(winCert, 8);
  const final = Buffer.concat([base, winCert]);
  // Optional header is at e_lfanew + 24; PE32+ data directories start at +112.
  const optionalHeader = base.readUInt32LE(0x3c) + 24;
  const securityEntry = optionalHeader + 112 + 4 * 8;
  final.writeUInt32LE(base.length, securityEntry);
  final.writeUInt32LE(padded, securityEntry + 4);
  return final;
};

// ----- Mach-O SuperBlob fixture ---------------------------------------------

const be32 = (value: number): Buffer => {
  const buffer = Buffer.alloc(4);
  buffer.writeUInt32BE(value >>> 0, 0);
  return buffer;
};

const ENTITLEMENTS_XML =
  '<?xml version="1.0" encoding="UTF-8"?>\n' +
  '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n' +
  '<plist version="1.0"><dict>' +
  "<key>com.apple.security.cs.allow-jit</key><true/>" +
  "<key>get-task-allow</key><false/>" +
  "</dict></plist>";

interface BuiltSuperBlob {
  readonly superblob: Buffer;
  readonly cdHash: string;
}

const buildCodeDirectory = (): Buffer => {
  const ident = Buffer.from("com.test.app\0", "latin1");
  const team = Buffer.from("TEAMID123\0", "latin1");
  const headerSize = 52;
  const identOffset = headerSize;
  const teamOffset = identOffset + ident.length;
  const length = teamOffset + team.length;
  const cd = Buffer.alloc(length);
  cd.writeUInt32BE(0xfade0c02, 0);
  cd.writeUInt32BE(length, 4);
  cd.writeUInt32BE(0x20400, 8);
  cd.writeUInt32BE(0x00020002, 12); // adhoc | linker-signed
  cd.writeUInt32BE(0, 16); // hashOffset
  cd.writeUInt32BE(identOffset, 20);
  cd.writeUInt32BE(0, 24); // nSpecialSlots
  cd.writeUInt32BE(3, 28); // nCodeSlots
  cd.writeUInt32BE(0x4000, 32); // codeLimit
  cd.writeUInt8(32, 36); // hashSize
  cd.writeUInt8(2, 37); // hashType sha256
  cd.writeUInt8(0, 38);
  cd.writeUInt8(12, 39);
  cd.writeUInt32BE(0, 40); // spare2
  cd.writeUInt32BE(0, 44); // scatterOffset
  cd.writeUInt32BE(teamOffset, 48);
  ident.copy(cd, identOffset);
  team.copy(cd, teamOffset);
  return cd;
};

const buildSuperBlob = (): BuiltSuperBlob => {
  const cd = buildCodeDirectory();
  const requirements = Buffer.concat([be32(0xfade0c01), be32(8)]);
  const xml = Buffer.from(ENTITLEMENTS_XML, "utf8");
  const entitlements = Buffer.concat([
    be32(0xfade7171),
    be32(8 + xml.length),
    xml,
  ]);
  const derEnt = Buffer.concat([be32(0xfade7172), be32(8)]);
  const cmsBody = Buffer.from([1, 2, 3, 4, 5, 6]);
  const cms = Buffer.concat([
    be32(0xfade0b01),
    be32(8 + cmsBody.length),
    cmsBody,
  ]);
  const blobs = [cd, requirements, entitlements, derEnt, cms];
  const slots = [0, 2, 5, 7, 0x10000];
  const indexSize = 12 + blobs.length * 8;
  let offset = indexSize;
  const index: Buffer[] = [];
  for (const [position, blob] of blobs.entries()) {
    index.push(Buffer.concat([be32(slots[position] ?? 0), be32(offset)]));
    offset += blob.length;
  }
  const total = offset;
  const header = Buffer.concat([
    be32(0xfade0cc0),
    be32(total),
    be32(blobs.length),
  ]);
  const superblob = Buffer.concat([header, ...index, ...blobs]);
  return { superblob, cdHash: createHash("sha256").update(cd).digest("hex") };
};

/** A thin arm64 Mach-O with an LC_CODE_SIGNATURE pointing at an appended SuperBlob. */
const buildSignedMacho = (superblob: Buffer): Buffer => {
  const header = Buffer.alloc(32);
  header.writeUInt32LE(0xfeedfacf, 0);
  header.writeUInt32LE(0x0100000c, 4); // arm64
  header.writeUInt32LE(0, 8);
  header.writeUInt32LE(2, 12); // MH_EXECUTE
  header.writeUInt32LE(1, 16); // ncmds
  header.writeUInt32LE(16, 20); // sizeofcmds
  const command = Buffer.alloc(16);
  command.writeUInt32LE(0x1d, 0); // LC_CODE_SIGNATURE
  command.writeUInt32LE(16, 4);
  const image = Buffer.concat([header, command]);
  const dataoff = image.length;
  const withOffsets = Buffer.concat([image, superblob]);
  withOffsets.writeUInt32LE(dataoff, 32 + 8);
  withOffsets.writeUInt32LE(superblob.length, 32 + 12);
  return withOffsets;
};

const withArtifact = (body: object, bytes: number): unknown => ({
  ...body,
  artifact: { path: "/artifacts/app", sha256: "0".repeat(64), bytes },
});

describe("der walker", () => {
  it("reads a SEQUENCE and its children", () => {
    const encoded = seq(
      integer(Buffer.from([0x2a])),
      oid("1.2.840.113549.1.7.2"),
    );
    const node = readNode(encoded, 0);
    expect(node?.constructed).toBe(true);
    const kids = children(encoded, node!);
    expect(kids).toHaveLength(2);
    expect(readOid(encoded, kids[1]!)).toBe("1.2.840.113549.1.7.2");
  });

  it("drops the sign byte when decoding an INTEGER to hex", () => {
    const encoded = integer(Buffer.from("00ab", "hex"));
    expect(readIntegerHex(encoded, readNode(encoded, 0)!)).toBe("AB");
  });

  it("rejects indefinite-length encodings", () => {
    const indefinite = Buffer.from([0x30, 0x80, 0x00, 0x00]);
    expect(readNode(indefinite, 0)).toBeNull();
  });
});

describe("analyzeInspectCodeSignature — Mach-O", () => {
  it("parses the SuperBlob, CodeDirectory, entitlements and CMS", async () => {
    const { superblob, cdHash } = buildSuperBlob();
    const bytes = buildSignedMacho(superblob);
    const report = await analyzeInspectCodeSignature(
      bytes,
      { path: "/a" },
      context,
    );
    expect(report.present).toBe(true);
    expect(report.macho).not.toBeNull();
    const macho = report.macho!;
    expect(macho.superblob_present).toBe(true);
    expect(macho.blob_count).toBe(5);
    const cd = macho.code_directory!;
    expect(cd.identifier).toBe("com.test.app");
    expect(cd.team_id).toBe("TEAMID123");
    expect(cd.flags_decoded).toEqual(["adhoc", "linker-signed"]);
    expect(cd.hash_type_name).toBe("sha256");
    expect(cd.cd_hash).toBe(cdHash);
    expect(cd.cd_hash_truncated).toBe(cdHash.slice(0, 40));
    expect(macho.requirements_present).toBe(true);
    expect(macho.der_entitlements_present).toBe(true);
    expect(macho.cms_present).toBe(true);
    expect(macho.cms_size).toBe(14);
    expect(macho.entitlements?.keys).toEqual([
      "com.apple.security.cs.allow-jit",
      "get-task-allow",
    ]);
    expect(() =>
      inspectCodeSignatureReportSchema.parse(
        withArtifact(report, bytes.length),
      ),
    ).not.toThrow();
  });
});

describe("analyzeInspectCodeSignature — PE Authenticode", () => {
  it("computes an authentihash and parses the embedded certificate", async () => {
    const base = pe(0x8664);
    const unsigned = await analyzeInspectCodeSignature(
      base,
      { path: "/a" },
      context,
    );
    expect(unsigned.present).toBe(false);
    const computed = unsigned.pe!.authentihash!.computed;

    const digest = Buffer.from(computed, "hex");
    const signed = signPe(base, buildPkcs7(digest));
    const report = await analyzeInspectCodeSignature(
      signed,
      { path: "/a" },
      context,
    );
    expect(report.present).toBe(true);
    const peReport = report.pe!;
    expect(peReport.signature_present).toBe(true);
    expect(peReport.certificate_entries[0]?.certificate_type).toBe(
      "pkcs-signed-data",
    );
    expect(peReport.certificate_entries[0]?.revision).toBe("2.0");
    expect(peReport.certificate_entries[0]?.parsed_pkcs7).toBe(true);
    expect(peReport.authentihash?.algorithm).toBe("sha256");
    expect(peReport.authentihash?.stored).toBe(computed);
    expect(peReport.authentihash?.matches).toBe(true);
    expect(peReport.digest_algorithm).toBe("sha256");
    expect(peReport.program_name).toBe("Test Program");
    expect(peReport.certificate_count).toBe(1);
    expect(peReport.signer?.serial).toBe("1122334455667788");
    expect(peReport.signer?.subject).toBe(
      "C=US, O=REA Triage Test, CN=REA Code Signing Test",
    );
    expect(peReport.signer?.not_before).toBe("2026-10-16T21:52:39.000Z");
    expect(peReport.signer?.not_after).toBe("2036-10-13T21:52:39.000Z");
    expect(() =>
      inspectCodeSignatureReportSchema.parse(
        withArtifact(report, signed.length),
      ),
    ).not.toThrow();
  });

  it("parses counter-signature timestamps and counts nested signatures", async () => {
    const base = pe(0x8664);
    const unsigned = await analyzeInspectCodeSignature(
      base,
      { path: "/a" },
      context,
    );
    const digest = Buffer.from(unsigned.pe!.authentihash!.computed, "hex");
    const signed = signPe(base, buildPkcs7(digest, buildUnsignedAttrs()));
    const report = await analyzeInspectCodeSignature(
      signed,
      { path: "/a" },
      context,
    );
    const peReport = report.pe!;
    expect(peReport.nested_signature_count).toBe(2);
    expect(peReport.timestamps).toHaveLength(1);
    expect(peReport.timestamps[0]?.kind).toBe("authenticode-countersignature");
    expect(peReport.timestamps[0]?.time).toBe("2026-01-01T00:00:00Z");
  });
});

describe("analyzeInspectCodeSignature — non-signable inputs", () => {
  it("reports no signature for an ELF image", async () => {
    const report = await analyzeInspectCodeSignature(
      elf(2, 1, 0x3e),
      { path: "/a" },
      context,
    );
    expect(report.present).toBe(false);
    expect(report.pe).toBeNull();
    expect(report.macho).toBeNull();
    expect(report.subject.format).toBe("elf");
    expect(report.limitations.some((line) => line.includes("ELF"))).toBe(true);
  });

  it("reports no signature for non-executable bytes", async () => {
    const report = await analyzeInspectCodeSignature(
      Buffer.alloc(64, 0x41),
      { path: "/a" },
      context,
    );
    expect(report.present).toBe(false);
    expect(report.subject.format).toBe("file");
    expect(() =>
      inspectCodeSignatureReportSchema.parse(withArtifact(report, 64)),
    ).not.toThrow();
  });
});
