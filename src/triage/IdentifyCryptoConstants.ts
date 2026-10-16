import type {
  CryptoFinding,
  IdentifyCryptoConstantsInput,
  IdentifyCryptoConstantsReport,
} from "../domain/triage/identifyCryptoConstants.js";
import {
  CRYPTO_SIGNATURES,
  type CryptoSignature,
} from "../domain/triage/cryptoSignatures.js";
import {
  checkTriageCancelled,
  loadTriageImage,
  triageLocation,
  triageSubject,
  yieldTriage,
  type TriageAnalysisContext,
} from "./triageSupport.js";
import type { ExecutableImage } from "../domain/native/image/executableImage.js";

/** Largest number of findings returned inline before the list is truncated. */
const MAX_FINDINGS = 4096;
/** Largest number of matches retained for any single constant. */
const PER_SIGNATURE_CAP = 256;
/** Length of a candidate custom Base64 alphabet. */
const BASE64_ALPHABET_LENGTH = 64;

interface RawMatch {
  readonly algorithm: string;
  readonly kind: CryptoFinding["kind"];
  readonly fileOffset: number;
  readonly byteOrder: CryptoFinding["byte_order"];
  readonly length: number;
}

/** Locate every occurrence of one signature, bounded per signature. */
const scanSignature = (
  bytes: Buffer,
  signature: CryptoSignature,
  into: RawMatch[],
): boolean => {
  const seen = new Set<number>();
  let found = 0;
  for (const variant of signature.variants) {
    const needle = variant.bytes;
    let position = 0;
    for (;;) {
      if (found >= PER_SIGNATURE_CAP) return true;
      const index = bytes.indexOf(needle, position);
      if (index < 0) break;
      position = index + needle.length;
      if (seen.has(index)) continue;
      seen.add(index);
      found += 1;
      into.push({
        algorithm: signature.algorithm,
        kind: signature.kind,
        fileOffset: index,
        byteOrder: variant.byteOrder,
        length: needle.length,
      });
    }
  }
  return false;
};

const isPrintable = (value: number): boolean => value >= 0x21 && value <= 0x7e;

/**
 * A genuine Base64 alphabet mixes letter cases and digits; requiring one of
 * each rejects incidental 64-byte sweeps of a contiguous ASCII range (such as
 * a ctype or glyph table) that are otherwise 64 unique printable bytes.
 */
const looksLikeAlphabet = (bytes: Buffer, start: number): boolean => {
  let upper = false;
  let lower = false;
  let digit = false;
  for (let index = start; index < start + BASE64_ALPHABET_LENGTH; index += 1) {
    const value = bytes[index] as number;
    if (value >= 0x41 && value <= 0x5a) upper = true;
    else if (value >= 0x61 && value <= 0x7a) lower = true;
    else if (value >= 0x30 && value <= 0x39) digit = true;
  }
  return upper && lower && digit;
};

/**
 * Flag runs of 64 consecutive unique printable bytes that mix upper-case,
 * lower-case and digit characters as a possible custom Base64 alphabet.
 * Offsets already matched by a known alphabet are skipped. One linear pass
 * keeps a window with no repeated byte.
 */
const scanCustomBase64 = (
  bytes: Buffer,
  known: ReadonlySet<number>,
  into: RawMatch[],
): boolean => {
  const lastSeen = new Int32Array(256).fill(-1);
  let start = 0;
  let found = 0;
  for (let index = 0; index < bytes.length; index += 1) {
    const value = bytes[index] as number;
    if (!isPrintable(value)) {
      start = index + 1;
      continue;
    }
    const previous = lastSeen[value] as number;
    if (previous >= start) start = previous + 1;
    lastSeen[value] = index;
    if (index - start + 1 >= BASE64_ALPHABET_LENGTH) {
      if (!known.has(start) && looksLikeAlphabet(bytes, start)) {
        if (found >= PER_SIGNATURE_CAP) return true;
        found += 1;
        into.push({
          algorithm: "Base64 (custom alphabet)",
          kind: "table",
          fileOffset: start,
          byteOrder: "any",
          length: BASE64_ALPHABET_LENGTH,
        });
      }
      start = index + 1;
    }
  }
  return false;
};

const toFinding = (
  match: RawMatch,
  image: ExecutableImage | null,
): CryptoFinding => ({
  algorithm: match.algorithm,
  kind: match.kind,
  evidence_kind: "inferred",
  file_offset: match.fileOffset,
  section: triageLocation(image, match.fileOffset).section,
  byte_order: match.byteOrder,
  length: match.length,
});

const compareMatches = (left: RawMatch, right: RawMatch): number =>
  left.fileOffset - right.fileOffset ||
  left.algorithm.localeCompare(right.algorithm) ||
  left.byteOrder.localeCompare(right.byteOrder);

const summarize = (
  findings: readonly CryptoFinding[],
): { algorithm: string; count: number }[] => {
  const counts = new Map<string, number>();
  for (const finding of findings)
    counts.set(finding.algorithm, (counts.get(finding.algorithm) ?? 0) + 1);
  return [...counts.entries()]
    .map(([algorithm, count]) => ({ algorithm, count }))
    .sort(
      (left, right) =>
        right.count - left.count ||
        left.algorithm.localeCompare(right.algorithm),
    );
};

const limitationsFor = (
  image: ExecutableImage | null,
  perSignatureCapped: boolean,
  globallyTruncated: boolean,
): string[] => {
  const notes = [
    "The presence of a constant is consistent with use of the algorithm; it does not prove the algorithm is reachable, invoked, or exercised at runtime.",
    "No key material, plaintext, or ciphertext is extracted or recovered.",
    "Matches are byte sequences from public specifications; constants shared between algorithms (for example the SHA-1 and MD5 initialization words, or the golden-ratio value used by TEA and several hash functions) may be reported under more than one algorithm.",
    "Word tables are searched in little- and big-endian encodings only; per-word byte swaps, 64-bit limb layouts for curve parameters, runtime-generated tables, and optimized DES SP-box layouts are not detected.",
    "A run of 64 consecutive unique printable bytes that mixes upper-case, lower-case and digit characters is reported as a possible custom Base64 alphabet; this is a heuristic that may flag unrelated data or miss alphabets without all three character classes.",
    "The file is read once in full and scanned without executing it, without network access, and without writing files.",
  ];
  if (image === null)
    notes.push(
      "The file is not a recognized executable image, so matches are reported by file offset with a null section.",
    );
  else
    notes.push(
      "Section names are resolved from the parsed image; for a universal binary only the default slice's sections are mapped, and matches outside it carry a null section.",
    );
  if (perSignatureCapped)
    notes.push(
      `At least one constant occurred more than ${PER_SIGNATURE_CAP} times; additional occurrences of that constant were not reported.`,
    );
  if (globallyTruncated)
    notes.push(
      `The finding list was truncated at ${MAX_FINDINGS}; see finding_coverage.`,
    );
  return notes;
};

/**
 * Scan a file for well-known cryptographic and hashing constant tables and
 * report each located constant with its file offset, section and the word byte
 * order matched. Matches are observed bytes; attribution is inferred.
 */
export const analyzeIdentifyCryptoConstants = async (
  bytes: Buffer,
  _input: IdentifyCryptoConstantsInput,
  context: TriageAnalysisContext,
): Promise<Omit<IdentifyCryptoConstantsReport, "artifact">> => {
  const image = loadTriageImage(bytes).image;
  const matches: RawMatch[] = [];
  let perSignatureCapped = false;
  for (const signature of CRYPTO_SIGNATURES) {
    if (scanSignature(bytes, signature, matches)) perSignatureCapped = true;
    await yieldTriage(context.signal);
  }
  checkTriageCancelled(context.signal);
  const knownBase64 = new Set(
    matches
      .filter((match) => match.algorithm.startsWith("Base64 ("))
      .map((match) => match.fileOffset),
  );
  if (scanCustomBase64(bytes, knownBase64, matches)) perSignatureCapped = true;
  matches.sort(compareMatches);
  const total = matches.length;
  const globallyTruncated = total > MAX_FINDINGS;
  const findings = matches
    .slice(0, MAX_FINDINGS)
    .map((match) => toFinding(match, image));
  return {
    subject: triageSubject(image),
    findings,
    finding_coverage: {
      total,
      returned: findings.length,
      truncated: globallyTruncated,
    },
    algorithm_summary: summarize(findings),
    limitations: limitationsFor(image, perSignatureCapped, globallyTruncated),
  };
};
