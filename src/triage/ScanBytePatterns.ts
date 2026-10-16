import type {
  ScanByteMatch,
  ScanBytePatternCount,
  ScanBytePatternsInput,
  ScanBytePatternsReport,
} from "../domain/triage/scanBytePatterns.js";
import type { ExecutableImage } from "../domain/native/image/executableImage.js";
import { compilePattern } from "./ScanBytePatternsCompile.js";
import {
  checkTriageCancelled,
  loadTriageImage,
  triageLocation,
  triageSubject,
  yieldTriage,
  type TriageAnalysisContext,
} from "./triageSupport.js";

/** Matches examined between cooperative yields while one pattern is scanned. */
const YIELD_EVERY = 4096;

/** Shared scan state threaded through every pattern over one snapshot. */
interface ScanState {
  readonly haystack: string;
  readonly bytes: Buffer;
  readonly image: ExecutableImage | null;
  readonly matches: ScanByteMatch[];
  readonly globalBudget: number;
  readonly signal: AbortSignal | undefined;
}

/**
 * Scan one compiled pattern across the Latin-1 view, pushing up to the global
 * budget into `state.matches` while counting occurrences up to the per-pattern
 * cap. Overlapping occurrences are reported; preview hex is read from raw bytes.
 */
const scanPattern = async (
  id: string,
  regex: RegExp,
  state: ScanState,
): Promise<ScanBytePatternCount> => {
  regex.lastIndex = 0;
  let total = 0;
  let returned = 0;
  let truncated = false;
  let sinceYield = 0;
  for (
    let match = regex.exec(state.haystack);
    match !== null;
    match = regex.exec(state.haystack)
  ) {
    const start = match.index;
    const length = match[0].length;
    if (length === 0) {
      regex.lastIndex = start + 1;
      continue;
    }
    total += 1;
    if (state.matches.length < state.globalBudget) {
      const previewEnd = start + Math.min(32, length);
      state.matches.push({
        pattern_id: id,
        location: triageLocation(state.image, start),
        length,
        preview_hex: state.bytes.toString("hex", start, previewEnd),
      });
      returned += 1;
    }
    if (total >= state.globalBudget) {
      truncated = true;
      break;
    }
    regex.lastIndex = start + 1;
    sinceYield += 1;
    if (sinceYield >= YIELD_EVERY) {
      sinceYield = 0;
      await yieldTriage(state.signal);
    }
  }
  return { pattern_id: id, total, returned, truncated };
};

/**
 * Search one immutable file snapshot for caller-supplied byte, text and regex
 * patterns. Reads the file once (never executes it, no network, no writes),
 * reports observed occurrences with their executable-section context when the
 * file is a recognized image, and records truncation through coverage.
 */
export const analyzeScanBytePatterns = async (
  bytes: Buffer,
  input: ScanBytePatternsInput,
  context: TriageAnalysisContext,
): Promise<Omit<ScanBytePatternsReport, "artifact">> => {
  const image = loadTriageImage(bytes).image;
  const compiled = input.patterns.map((pattern) => compilePattern(pattern));
  const matches: ScanByteMatch[] = [];
  const state: ScanState = {
    haystack: bytes.toString("latin1"),
    bytes,
    image,
    matches,
    globalBudget: input.max_matches,
    signal: context.signal,
  };
  const perPatternCounts: ScanBytePatternCount[] = [];
  let totalFound = 0;
  let anyPatternTruncated = false;
  for (const pattern of compiled) {
    checkTriageCancelled(context.signal);
    const count = await scanPattern(pattern.id, pattern.regex, state);
    perPatternCounts.push(count);
    totalFound += count.total;
    anyPatternTruncated ||= count.truncated;
  }
  const limitations = [
    "Matches are observed byte occurrences in the file content; a reported match is consistent with the pattern's bytes being present and is not evidence of behavior, intent, or reachability.",
    "Occurrences are reported with overlap; scanning stops at the per-pattern and global match bounds, which match_coverage and per_pattern_counts record as truncation.",
    "Hex, text (ASCII and UTF-16LE) and regular-expression patterns are matched over the raw bytes read as Latin-1 (one byte per code unit); no other text encoding is decoded, and regular expressions see bytes rather than characters.",
    "Section attribution uses the parsed executable layout; when the file is not a recognized ELF, PE or Mach-O image, section and virtual_address are null.",
    "The file is read once, up to 256 MiB; the target is never executed, no network is used, and no files are written.",
  ];
  if (image === null)
    limitations.push(
      "The selected file is not a recognized executable image, so every match reports a null section and virtual_address.",
    );
  if (anyPatternTruncated)
    limitations.push(
      "One or more patterns reached the match bound; see per_pattern_counts.truncated for which counts are partial.",
    );
  return {
    subject: triageSubject(image),
    limitations,
    matches,
    match_coverage: {
      total: totalFound,
      returned: matches.length,
      truncated: matches.length < totalFound || anyPatternTruncated,
    },
    per_pattern_counts: perPatternCounts,
  };
};
