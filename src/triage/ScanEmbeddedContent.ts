import type {
  CarvingType,
  CarvingValidatorKey,
} from "../domain/triage/carvingSignatures.js";
import {
  CARVING_SIGNATURES,
  PEM_BEGIN,
} from "../domain/triage/carvingSignatures.js";
import type {
  EmbeddedFinding,
  EntropyPoint,
  PaddingRun,
  ScanEmbeddedContentInput,
  ScanEmbeddedContentReport,
} from "../domain/triage/scanEmbeddedContent.js";
import type { z } from "zod";
import type { triageListCoverageSchema } from "../domain/triage/triageCommon.js";
import {
  checkTriageCancelled,
  loadTriageImage,
  roundTo,
  shannonEntropy,
  triageSubject,
  yieldTriage,
} from "./triageSupport.js";
import type { TriageAnalysisContext } from "./triageSupport.js";
import { CARVING_VALIDATORS } from "./ScanEmbeddedContentFormats.js";

type Coverage = z.infer<typeof triageListCoverageSchema>;

/** Candidate offset for one signature, before structural validation. */
interface Candidate {
  readonly type: CarvingType;
  readonly validator: CarvingValidatorKey;
  readonly offset: number;
}

const CANDIDATES_PER_PATTERN = 200_000;
const TOTAL_CANDIDATE_CAP = 1_000_000;
const MIN_PADDING_RUN = 1024;
const MAX_PADDING_RUNS = 4096;
const MAX_ENTROPY_POINTS = 1024;
const MAX_PEM = 256;
const ZIP_VALIDATORS = new Set<CarvingValidatorKey>([
  "zipLocal",
  "zipCentral",
  "zipEocd",
]);
const CONFIDENCE_RANK: Record<EmbeddedFinding["confidence"], number> = {
  high: 0,
  medium: 1,
  low: 2,
};
const DESCRIPTIONS = new Map<CarvingType, string>(
  CARVING_SIGNATURES.map((signature) => [
    signature.type,
    signature.description,
  ]),
);

/**
 * Identify embedded content inside one local file by magic bytes and bounded
 * structural validation. Returns offsets, derived sizes where a format
 * declares them, a padding-run map and an entropy profile. It reads the bytes
 * once, never executes the target, never decompresses a full stream and never
 * writes a file; unknown sizes and unrecognized regions are reported as such.
 */
export const analyzeScanEmbeddedContent = async (
  bytes: Buffer,
  input: ScanEmbeddedContentInput,
  context: TriageAnalysisContext,
): Promise<Omit<ScanEmbeddedContentReport, "artifact">> => {
  const maxFindings = input.max_findings;
  const image = loadTriageImage(bytes).image;
  const scan = collectCandidates(bytes, context.signal);
  await yieldTriage(context.signal);

  const generic = validateGeneric(bytes, scan.list, context.signal);
  const zip = buildZipFindings(bytes, scan.list);
  const pem = scanPem(bytes, context.signal);
  await yieldTriage(context.signal);

  const all = [...generic, ...zip, ...pem];
  const ranked = rankFindings(all);
  const findings = ranked
    .slice(0, maxFindings)
    .sort((a, b) => a.file_offset - b.file_offset);

  const padding = await scanPadding(bytes, context);
  const entropy = await buildEntropyProfile(
    bytes,
    input.entropy_window,
    context,
  );

  return {
    subject: triageSubject(image),
    entropy_window: entropy.window,
    findings,
    findings_coverage: coverage(ranked.length, findings.length),
    padding_runs: padding.runs,
    padding_runs_coverage: coverage(padding.total, padding.runs.length),
    entropy_profile: entropy.points,
    entropy_profile_coverage: coverage(
      entropy.points.length,
      entropy.points.length,
    ),
    limitations: limitations(scan.truncated),
  };
};

const coverage = (total: number, returned: number): Coverage => ({
  total,
  returned,
  truncated: returned < total,
});

/** Locate every signature prefix in the file, bounded per pattern and overall. */
const collectCandidates = (
  bytes: Buffer,
  signal: AbortSignal | undefined,
): { readonly list: Candidate[]; readonly truncated: boolean } => {
  const list: Candidate[] = [];
  let truncated = false;
  for (const signature of CARVING_SIGNATURES) {
    for (const pattern of signature.patterns) {
      checkTriageCancelled(signal);
      const needle = Buffer.from(pattern.bytes);
      let from = 0;
      let found = 0;
      for (;;) {
        const pos = bytes.indexOf(needle, from);
        if (pos === -1) break;
        const offset = pos - pattern.magic_offset;
        if (offset >= 0)
          list.push({
            type: signature.type,
            validator: signature.validator,
            offset,
          });
        from = pos + 1;
        found += 1;
        if (
          found >= CANDIDATES_PER_PATTERN ||
          list.length >= TOTAL_CANDIDATE_CAP
        ) {
          truncated = true;
          break;
        }
      }
      if (list.length >= TOTAL_CANDIDATE_CAP) truncated = true;
    }
  }
  return { list, truncated };
};

/** Validate every non-ZIP candidate into a finding, dropping rejected offsets. */
const validateGeneric = (
  bytes: Buffer,
  candidates: readonly Candidate[],
  signal: AbortSignal | undefined,
): EmbeddedFinding[] => {
  const findings: EmbeddedFinding[] = [];
  const seen = new Set<string>();
  for (const [index, candidate] of candidates.entries()) {
    if (ZIP_VALIDATORS.has(candidate.validator)) continue;
    if ((index & 0x3fff) === 0) checkTriageCancelled(signal);
    const key = `${candidate.type}\u0000${candidate.offset}`;
    if (seen.has(key)) continue;
    const judged = CARVING_VALIDATORS[candidate.validator](
      bytes,
      candidate.offset,
    );
    if (judged === null) continue;
    seen.add(key);
    findings.push(finding(candidate.type, candidate.offset, judged));
  }
  return findings;
};

/** One judged region: everything a finding needs beyond its type and offset. */
interface Judged {
  readonly size: number | null;
  readonly confidence: EmbeddedFinding["confidence"];
  readonly validated: boolean;
  readonly detail: string | null;
}

const finding = (
  type: CarvingType,
  offset: number,
  judged: Judged,
): EmbeddedFinding => {
  const base = DESCRIPTIONS.get(type) ?? type;
  return {
    type,
    file_offset: offset,
    size: judged.size,
    confidence: judged.confidence,
    validated: judged.validated,
    description: judged.detail === null ? base : `${base} (${judged.detail})`,
  };
};

/**
 * Resolve ZIP structures: each end-of-central-directory that points back to a
 * real local header becomes one `zip` archive finding covering the whole
 * archive, and the local/central/EOCD records it subsumes are not repeated.
 * Structures outside any resolved archive are reported as fragments.
 */
const buildZipFindings = (
  bytes: Buffer,
  candidates: readonly Candidate[],
): EmbeddedFinding[] => {
  const byValidator = (key: CarvingValidatorKey): number[] =>
    candidates
      .filter(
        (c) =>
          c.validator === key &&
          CARVING_VALIDATORS[key](bytes, c.offset) !== null,
      )
      .map((c) => c.offset);
  const archives: { start: number; end: number }[] = [];
  const findings: EmbeddedFinding[] = [];
  for (const eocd of byValidator("zipEocd")) {
    const resolved = resolveZipArchive(bytes, eocd);
    if (resolved === null) continue;
    archives.push(resolved);
    const entries = bytes.readUInt16LE(eocd + 10);
    findings.push(
      finding("zip", resolved.start, {
        size: resolved.end - resolved.start,
        confidence: "high",
        validated: true,
        detail: `${entries} entr${entries === 1 ? "y" : "ies"}`,
      }),
    );
  }
  const covered = (offset: number): boolean =>
    archives.some((a) => offset >= a.start && offset < a.end);
  pushZipFragments(bytes, byValidator, covered, findings);
  return findings;
};

const resolveZipArchive = (
  bytes: Buffer,
  eocd: number,
): { start: number; end: number } | null => {
  if (eocd + 22 > bytes.length) return null;
  const cdSize = bytes.readUInt32LE(eocd + 12);
  const cdOffset = bytes.readUInt32LE(eocd + 16);
  const commentLen = bytes.readUInt16LE(eocd + 20);
  const start = eocd - cdSize - cdOffset;
  if (start < 0 || start + 4 > bytes.length) return null;
  if (bytes.readUInt32BE(start) !== 0x50_4b_03_04) return null;
  return { start, end: eocd + 22 + commentLen };
};

const pushZipFragments = (
  bytes: Buffer,
  byValidator: (key: CarvingValidatorKey) => number[],
  covered: (offset: number) => boolean,
  findings: EmbeddedFinding[],
): void => {
  for (const offset of byValidator("zipLocal"))
    if (!covered(offset))
      findings.push(
        finding("zip", offset, {
          size: null,
          confidence: "medium",
          validated: true,
          detail: "local file header fragment",
        }),
      );
  for (const offset of byValidator("zipCentral"))
    if (!covered(offset))
      findings.push(
        finding("zip_central_directory", offset, {
          size: null,
          confidence: "medium",
          validated: true,
          detail: "central directory fragment",
        }),
      );
  for (const offset of byValidator("zipEocd"))
    if (!covered(offset)) {
      const commentLen = bytes.readUInt16LE(offset + 20);
      findings.push(
        finding("zip_end_of_central_directory", offset, {
          size: 22 + commentLen,
          confidence: "medium",
          validated: true,
          detail: "unresolved archive",
        }),
      );
    }
};

/** Report PEM armored blocks found textually, with their label as detail. */
const scanPem = (
  bytes: Buffer,
  signal: AbortSignal | undefined,
): EmbeddedFinding[] => {
  const findings: EmbeddedFinding[] = [];
  const begin = Buffer.from(PEM_BEGIN);
  let from = 0;
  while (findings.length < MAX_PEM) {
    checkTriageCancelled(signal);
    const pos = bytes.indexOf(begin, from);
    if (pos === -1) break;
    from = pos + begin.length;
    const labelEnd = bytes.indexOf(Buffer.from("-----"), from);
    if (labelEnd === -1 || labelEnd - from > 64) continue;
    const label = bytes
      .toString("latin1", from, labelEnd)
      .replace(/[^\x20-\x7e]/gu, "");
    const endMarker = bytes.indexOf(
      Buffer.from(`-----END ${label}-----`),
      labelEnd,
    );
    const size =
      endMarker === -1 ? null : endMarker + 9 + label.length + 5 - pos;
    findings.push(
      finding("pem", pos, {
        size,
        confidence: "high",
        validated: true,
        detail: label === "" ? "armored block" : label,
      }),
    );
  }
  return findings;
};

/** Order findings so a bounded slice keeps the strongest, earliest evidence. */
const rankFindings = (
  findings: readonly EmbeddedFinding[],
): EmbeddedFinding[] =>
  [...findings].sort((a, b) => {
    if (a.validated !== b.validated) return a.validated ? -1 : 1;
    if (a.confidence !== b.confidence)
      return CONFIDENCE_RANK[a.confidence] - CONFIDENCE_RANK[b.confidence];
    return a.file_offset - b.file_offset;
  });

/** Map maximal runs of 0x00 or 0xff at least MIN_PADDING_RUN bytes long. */
const scanPadding = async (
  bytes: Buffer,
  context: TriageAnalysisContext,
): Promise<{ readonly runs: PaddingRun[]; readonly total: number }> => {
  const runs: PaddingRun[] = [];
  let total = 0;
  let index = 0;
  while (index < bytes.length) {
    if ((index & 0xff_ffff) === 0) await yieldTriage(context.signal);
    const value = bytes[index] as number;
    if (value !== 0x00 && value !== 0xff) {
      index += 1;
      continue;
    }
    let end = index + 1;
    while (end < bytes.length && bytes[end] === value) end += 1;
    if (end - index >= MIN_PADDING_RUN) {
      total += 1;
      if (runs.length < MAX_PADDING_RUNS)
        runs.push({ byte: value === 0 ? "00" : "ff", start: index, end });
    }
    index = end;
  }
  return { runs, total };
};

/** Sample Shannon entropy across the whole file, widening windows if needed. */
const buildEntropyProfile = async (
  bytes: Buffer,
  requested: number,
  context: TriageAnalysisContext,
): Promise<{ readonly points: EntropyPoint[]; readonly window: number }> => {
  if (bytes.length === 0) return { points: [], window: requested };
  const windows = Math.max(1, Math.ceil(bytes.length / requested));
  const window =
    windows <= MAX_ENTROPY_POINTS
      ? requested
      : Math.ceil(bytes.length / MAX_ENTROPY_POINTS);
  const points: EntropyPoint[] = [];
  for (let offset = 0; offset < bytes.length; offset += window) {
    if ((points.length & 0xff) === 0) await yieldTriage(context.signal);
    const end = Math.min(bytes.length, offset + window);
    points.push({
      offset,
      entropy: roundTo(shannonEntropy(bytes, offset, end), 3),
    });
  }
  return { points, window };
};

const limitations = (candidatesTruncated: boolean): string[] => {
  const notes = [
    "Regions are identified from observed magic bytes and bounded structural checks; identification is not extraction and no embedded content is decompressed or written out.",
    "A null size means the format does not declare a length in its header and the extent was not derived; it is not an observed length of zero.",
    "An unvalidated finding matched a magic signature but failed or lacked a deeper structural check, and may be a coincidental byte sequence rather than real content.",
    "The entropy profile is a sampled map and padding runs below the reporting threshold are omitted; unrecognized regions simply carry no finding and absence of a finding is not proof of absence.",
    "Reads are bounded (256 MiB input, one pass, capped candidate and finding counts) and the target is never executed; deeply nested or custom containers may go unrecognized.",
  ];
  if (candidatesTruncated)
    notes.push(
      "The per-signature candidate cap was reached, so some magic matches beyond the cap were not evaluated; narrow the input or treat the result as a partial map.",
    );
  return notes;
};
