import { X509Certificate, createHash } from "node:crypto";
import type { ExecutableImage } from "../domain/native/image/executableImage.js";
import type {
  CodeSignatureCertificate,
  CodeSignatureTimestamp,
  PeAuthenticode,
  WinCertificateEntry,
} from "../domain/triage/inspectCodeSignature.js";
import {
  children,
  readIntegerHex,
  readNode,
  readOid,
  readString,
  readTime,
  Tag,
  TagClass,
  type DerNode,
} from "./codesign/der.js";

/** Authenticode and PKCS#7 object identifiers this parser recognizes. */
const OID = {
  signedData: "1.2.840.113549.1.7.2",
  spcIndirectData: "1.3.6.1.4.1.311.2.1.4",
  spcOpusInfo: "1.3.6.1.4.1.311.2.1.12",
  nestedSignature: "1.3.6.1.4.1.311.2.4.1",
  msTimestamp: "1.3.6.1.4.1.311.3.3.1",
  counterSignature: "1.2.840.113549.1.9.6",
  signingTime: "1.2.840.113549.1.9.5",
} as const;

/** Digest algorithm OIDs mapped to node:crypto hash names. */
const DIGEST_ALGORITHMS: ReadonlyMap<string, string> = new Map([
  ["1.3.14.3.2.26", "sha1"],
  ["2.16.840.1.101.3.4.2.1", "sha256"],
  ["2.16.840.1.101.3.4.2.2", "sha384"],
  ["2.16.840.1.101.3.4.2.3", "sha512"],
  ["1.2.840.113549.2.5", "md5"],
]);

const CERTIFICATE_TYPES: ReadonlyMap<number, string> = new Map([
  [0x0001, "x509"],
  [0x0002, "pkcs-signed-data"],
  [0x0003, "reserved"],
  [0x0004, "pkcs1-sign"],
]);

const MAX_CERT_ENTRIES = 64;
const MAX_CERTIFICATES = 256;
const MAX_TIMESTAMPS = 64;

interface Limited {
  push(message: string): void;
}

/** Parse the embedded Authenticode signature, reporting structure without any trust check. */
export const parsePeAuthenticode = (
  bytes: Buffer,
  image: ExecutableImage,
  limitations: Limited,
): PeAuthenticode => {
  const peOffset = bytes.readUInt32LE(0x3c);
  const optionalHeader = peOffset + 24;
  const pe32Plus = image.pe?.pe32_plus === true;
  const checksumOffset = optionalHeader + 64;
  const securityEntryOffset = optionalHeader + (pe32Plus ? 112 : 96) + 4 * 8;
  const securityDirectory = image.pe?.security_directory ?? null;
  const entries = readCertificateEntries(bytes, securityDirectory, limitations);
  const signaturePresent = entries.length > 0;

  let pkcs7: Pkcs7Facts = emptyPkcs7();
  const pkcs7Entry = entries.find(
    (entry) => entry.certificate_type === "pkcs-signed-data",
  );
  if (pkcs7Entry !== undefined) {
    const start = pkcs7Entry.file_offset + 8;
    const der = bytes.subarray(
      start,
      pkcs7Entry.file_offset + pkcs7Entry.length,
    );
    pkcs7 = parsePkcs7(der, limitations);
    if (pkcs7.parsed) Object.assign(pkcs7Entry, { parsed_pkcs7: true });
  }

  const algorithm = pkcs7.authentihashAlgorithm ?? "sha256";
  const computed = computeAuthentihash(bytes, algorithm, securityDirectory, {
    checksumOffset,
    securityEntryOffset,
  });
  const stored = pkcs7.storedAuthentihash;
  limitations.push(
    "The Authenticode signature structure is parsed; the certificate chain and OS trust are NOT evaluated. Presence is not validity.",
  );
  if (stored === null && signaturePresent)
    limitations.push(
      "A WIN_CERTIFICATE table is present but its SpcIndirectDataContent digest could not be parsed; the computed authentihash is reported without a stored value to compare.",
    );

  return {
    signature_present: signaturePresent,
    security_directory: securityDirectory,
    certificate_entries: entries,
    certificate_entry_coverage: {
      total: entries.length,
      returned: entries.length,
      truncated: false,
    },
    digest_algorithm: pkcs7.signerDigestAlgorithm,
    program_name: pkcs7.programName,
    signer: pkcs7.signer,
    certificate_count: pkcs7.certificates.length,
    certificates: pkcs7.certificates,
    certificate_coverage: pkcs7.certificateCoverage,
    timestamps: pkcs7.timestamps,
    timestamp_coverage: pkcs7.timestampCoverage,
    nested_signature_count: pkcs7.nestedCount,
    authentihash: {
      algorithm,
      computed,
      stored,
      matches: stored === null ? null : stored === computed,
    },
  };
};

/** Read the 8-byte-aligned WIN_CERTIFICATE entries in the security directory. */
const readCertificateEntries = (
  bytes: Buffer,
  directory: { readonly file_offset: number; readonly size: number } | null,
  limitations: Limited,
): WinCertificateEntry[] => {
  const entries: WinCertificateEntry[] = [];
  if (directory === null || directory.size < 8) return entries;
  const tableEnd = Math.min(
    directory.file_offset + directory.size,
    bytes.length,
  );
  let cursor = directory.file_offset;
  while (cursor + 8 <= tableEnd && entries.length < MAX_CERT_ENTRIES) {
    const length = bytes.readUInt32LE(cursor);
    if (length < 8 || cursor + length > tableEnd) break;
    const revision = bytes.readUInt16LE(cursor + 4);
    const type = bytes.readUInt16LE(cursor + 6);
    entries.push({
      file_offset: cursor,
      length,
      revision:
        revision === 0x0100 ? "1.0" : revision === 0x0200 ? "2.0" : "unknown",
      certificate_type: CERTIFICATE_TYPES.get(type) ?? "unknown",
      parsed_pkcs7: false,
    });
    cursor += length + ((8 - (length % 8)) % 8);
  }
  if (entries.length === MAX_CERT_ENTRIES)
    limitations.push(
      `Only the first ${String(MAX_CERT_ENTRIES)} WIN_CERTIFICATE entries were examined.`,
    );
  return entries;
};

/** Hash the PE per the Authenticode spec, excluding CheckSum, the security dir entry and the cert table. */
const computeAuthentihash = (
  bytes: Buffer,
  algorithm: string,
  certTable: { readonly file_offset: number; readonly size: number } | null,
  offsets: {
    readonly checksumOffset: number;
    readonly securityEntryOffset: number;
  },
): string => {
  const hash = createHash(algorithm);
  const certStart = certTable === null ? bytes.length : certTable.file_offset;
  const certEnd =
    certTable === null ? bytes.length : certTable.file_offset + certTable.size;
  hash.update(bytes.subarray(0, offsets.checksumOffset));
  hash.update(
    bytes.subarray(offsets.checksumOffset + 4, offsets.securityEntryOffset),
  );
  hash.update(bytes.subarray(offsets.securityEntryOffset + 8, certStart));
  if (certEnd < bytes.length) hash.update(bytes.subarray(certEnd));
  return hash.digest("hex");
};

interface Pkcs7Facts {
  parsed: boolean;
  signerDigestAlgorithm: string | null;
  authentihashAlgorithm: string | null;
  storedAuthentihash: string | null;
  programName: string | null;
  signer: CodeSignatureCertificate | null;
  certificates: CodeSignatureCertificate[];
  certificateCoverage: { total: number; returned: number; truncated: boolean };
  timestamps: CodeSignatureTimestamp[];
  timestampCoverage: { total: number; returned: number; truncated: boolean };
  nestedCount: number;
}

const emptyPkcs7 = (): Pkcs7Facts => ({
  parsed: false,
  signerDigestAlgorithm: null,
  authentihashAlgorithm: null,
  storedAuthentihash: null,
  programName: null,
  signer: null,
  certificates: [],
  certificateCoverage: { total: 0, returned: 0, truncated: false },
  timestamps: [],
  timestampCoverage: { total: 0, returned: 0, truncated: false },
  nestedCount: 0,
});

/** Walk a PKCS#7 SignedData ContentInfo and project the Authenticode facts. */
const parsePkcs7 = (der: Buffer, limitations: Limited): Pkcs7Facts => {
  const facts = emptyPkcs7();
  const contentInfo = readNode(der, 0);
  if (contentInfo === null || !contentInfo.constructed) return facts;
  const outer = children(der, contentInfo);
  const contentType = outer[0] === undefined ? null : readOid(der, outer[0]);
  const explicit = outer[1];
  if (contentType !== OID.signedData || explicit === undefined) return facts;
  const signedData = children(der, explicit)[0];
  if (signedData === undefined || !signedData.constructed) return facts;
  facts.parsed = true;
  const kids = children(der, signedData);
  readSignedDataContent(der, kids, facts);
  readCertificates(der, kids, facts, limitations);
  readSignerInfo(der, kids, facts, limitations);
  return facts;
};

/** Read encapContentInfo (SpcIndirectDataContent) for the stored authentihash. */
const readSignedDataContent = (
  der: Buffer,
  kids: readonly DerNode[],
  facts: Pkcs7Facts,
): void => {
  const encap = kids.find(
    (node) => node.tagClass === TagClass.universal && node.tag === Tag.sequence,
  );
  if (encap === undefined) return;
  const encapKids = children(der, encap);
  const eContentType =
    encapKids[0] === undefined ? null : readOid(der, encapKids[0]);
  const explicit = encapKids[1];
  if (eContentType !== OID.spcIndirectData || explicit === undefined) return;
  const octet = children(der, explicit)[0];
  if (octet === undefined) return;
  const indirect = readNode(der, octet.contentStart, octet.end);
  if (indirect === null) return;
  const digestInfo = children(der, indirect)[1];
  if (digestInfo === undefined) return;
  const digestKids = children(der, digestInfo);
  const algId = digestKids[0];
  const digest = digestKids[1];
  if (algId !== undefined) {
    const algOid = readOid(der, children(der, algId)[0] ?? algId);
    facts.authentihashAlgorithm =
      algOid === null ? null : (DIGEST_ALGORITHMS.get(algOid) ?? null);
  }
  if (digest !== undefined && digest.tag === Tag.octetString)
    facts.storedAuthentihash = der
      .subarray(digest.contentStart, digest.end)
      .toString("hex");
};

/** Summarize every embedded X.509 certificate via node:crypto, bounded in count. */
const readCertificates = (
  der: Buffer,
  kids: readonly DerNode[],
  facts: Pkcs7Facts,
  limitations: Limited,
): void => {
  const certs = kids.find(
    (node) => node.tagClass === TagClass.context && node.tag === 0,
  );
  if (certs === undefined) return;
  const nodes = children(der, certs);
  for (const node of nodes) {
    if (facts.certificates.length >= MAX_CERTIFICATES) break;
    const summary = summarizeCertificate(der.subarray(node.start, node.end));
    if (summary !== null) facts.certificates.push(summary);
  }
  const truncated = nodes.length > facts.certificates.length;
  facts.certificateCoverage = {
    total: nodes.length,
    returned: facts.certificates.length,
    truncated,
  };
  if (truncated)
    limitations.push(
      `Only ${String(MAX_CERTIFICATES)} of ${String(nodes.length)} embedded certificates were summarized.`,
    );
};

/** Project one certificate's naming and validity; chain trust is not evaluated. */
const summarizeCertificate = (der: Buffer): CodeSignatureCertificate | null => {
  try {
    const cert = new X509Certificate(der);
    return {
      subject: flatten(cert.subject),
      issuer: flatten(cert.issuer),
      serial: normalizeSerial(cert.serialNumber),
      not_before: toIso(cert.validFrom),
      not_after: toIso(cert.validTo),
    };
  } catch {
    return null;
  }
};

const flatten = (value: string): string =>
  value.replace(/\r?\n/gu, ", ").trim();

const normalizeSerial = (value: string): string => {
  const upper = value.replace(/[^0-9A-Fa-f]/gu, "").toUpperCase();
  const trimmed = upper.replace(/^0+(?=.)/u, "");
  return trimmed.length === 0 ? "0" : trimmed;
};

const toIso = (value: string): string | null => {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toISOString();
};

/** Read the first SignerInfo: digest algorithm, signer identity, opus name, timestamps and nested signatures. */
const readSignerInfo = (
  der: Buffer,
  kids: readonly DerNode[],
  facts: Pkcs7Facts,
  limitations: Limited,
): void => {
  const sets = kids.filter(
    (node) => node.tagClass === TagClass.universal && node.tag === Tag.set,
  );
  const signerSet = sets.at(-1);
  if (signerSet === undefined) return;
  const signerInfo = children(der, signerSet)[0];
  if (signerInfo === undefined) return;
  const si = children(der, signerInfo);
  const serial = readSignerSerial(der, si[1]);
  if (serial !== null)
    facts.signer =
      facts.certificates.find((cert) => cert.serial === serial) ?? null;
  const digestAlg = si.find(
    (node, index) =>
      index >= 2 &&
      node.tagClass === TagClass.universal &&
      node.tag === Tag.sequence,
  );
  if (digestAlg !== undefined) {
    const oid = readOid(der, children(der, digestAlg)[0] ?? digestAlg);
    facts.signerDigestAlgorithm =
      oid === null ? null : (DIGEST_ALGORITHMS.get(oid) ?? oid);
  }
  const signedAttrs = si.find(
    (node) => node.tagClass === TagClass.context && node.tag === 0,
  );
  if (signedAttrs !== undefined)
    facts.programName = readProgramName(der, signedAttrs);
  const unsignedAttrs = si.find(
    (node) => node.tagClass === TagClass.context && node.tag === 1,
  );
  if (unsignedAttrs !== undefined)
    readUnsignedAttributes(der, unsignedAttrs, facts, limitations);
};

/** Serial number from the SignerInfo issuerAndSerialNumber, matched against certificates. */
const readSignerSerial = (
  der: Buffer,
  sid: DerNode | undefined,
): string | null => {
  if (sid === undefined || !sid.constructed) return null;
  const serial = children(der, sid)[1];
  if (serial === undefined) return null;
  const hex = readIntegerHex(der, serial);
  return hex === null ? null : hex.replace(/^0+(?=.)/u, "");
};

/** SpcSpOpusInfo programName from the signed attributes, when present. */
const readProgramName = (der: Buffer, signedAttrs: DerNode): string | null => {
  for (const attr of children(der, signedAttrs)) {
    const parts = children(der, attr);
    const oid = parts[0] === undefined ? null : readOid(der, parts[0]);
    if (oid !== OID.spcOpusInfo || parts[1] === undefined) continue;
    const opus = children(der, parts[1])[0];
    if (opus === undefined) continue;
    const programName = children(der, opus).find(
      (node) => node.tagClass === TagClass.context && node.tag === 0,
    );
    if (programName === undefined) continue;
    const inner = children(der, programName)[0];
    if (inner === undefined) continue;
    const decoded =
      inner.tag === 0
        ? readString(der, { ...inner, tag: Tag.bmpString })
        : readString(der, { ...inner, tag: Tag.ia5String });
    if (decoded !== null) return decoded;
  }
  return null;
};

/** Count nested signatures and project counter-signature / RFC 3161 timestamps. */
const readUnsignedAttributes = (
  der: Buffer,
  unsignedAttrs: DerNode,
  facts: Pkcs7Facts,
  limitations: Limited,
): void => {
  let nested = 0;
  const timestamps: CodeSignatureTimestamp[] = [];
  for (const attr of children(der, unsignedAttrs)) {
    const parts = children(der, attr);
    const oid = parts[0] === undefined ? null : readOid(der, parts[0]);
    const values = parts[1];
    if (oid === null || values === undefined) continue;
    if (oid === OID.nestedSignature) nested += children(der, values).length;
    else if (oid === OID.counterSignature && timestamps.length < MAX_TIMESTAMPS)
      timestamps.push(readCounterSignature(der, values));
    else if (oid === OID.msTimestamp && timestamps.length < MAX_TIMESTAMPS)
      timestamps.push({
        kind: "rfc3161",
        time: findGeneralizedTime(der, values),
        signer: null,
        digest_algorithm: null,
      });
  }
  facts.nestedCount = nested;
  facts.timestamps = timestamps;
  facts.timestampCoverage = {
    total: timestamps.length,
    returned: timestamps.length,
    truncated: false,
  };
  if (nested > 0)
    limitations.push(
      `${String(nested)} nested signature(s) are counted but not individually parsed.`,
    );
};

/** Signing time from a legacy PKCS#9 counter-signature SignerInfo. */
const readCounterSignature = (
  der: Buffer,
  values: DerNode,
): CodeSignatureTimestamp => {
  const signerInfo = children(der, values)[0];
  let time: string | null = null;
  if (signerInfo !== undefined)
    for (const node of children(der, signerInfo)) {
      if (node.tagClass !== TagClass.context || node.tag !== 0) continue;
      for (const attr of children(der, node)) {
        const parts = children(der, attr);
        const oid = parts[0] === undefined ? null : readOid(der, parts[0]);
        if (oid !== OID.signingTime || parts[1] === undefined) continue;
        const value = children(der, parts[1])[0];
        if (value !== undefined) time = readTime(der, value);
      }
    }
  return {
    kind: "authenticode-countersignature",
    time,
    signer: null,
    digest_algorithm: null,
  };
};

/** First GeneralizedTime inside a bounded token, used for RFC 3161 genTime. */
const findGeneralizedTime = (der: Buffer, root: DerNode): string | null => {
  const stack: DerNode[] = [root];
  let budget = 8_192;
  while (stack.length > 0 && budget > 0) {
    const node = stack.pop();
    if (node === undefined) break;
    budget -= 1;
    if (
      node.tagClass === TagClass.universal &&
      node.tag === Tag.generalizedTime
    )
      return readTime(der, node);
    if (node.constructed)
      for (const child of children(der, node)) stack.push(child);
  }
  return null;
};
