import type { ExecutableImage } from "../domain/native/image/executableImage.js";
import { sectionContainingOffset } from "../domain/native/image/imageReader.js";
import type {
  ExtractBinaryStringsInput,
  ExtractBinaryStringsReport,
  ExtractedString,
  StringEncoding,
  StringTag,
} from "../domain/triage/extractBinaryStrings.js";
import {
  checkTriageCancelled,
  loadTriageImage,
  triageSubject,
  yieldTriage,
  TriageAnalysisFailure,
  type TriageAnalysisContext,
} from "./triageSupport.js";
import {
  MAX_STRING_CHARS,
  scannerFor,
  type RawRun,
} from "./ExtractBinaryStringsScan.js";
import { tagString } from "./ExtractBinaryStringsTags.js";

/** Await the event loop between this many scanned bytes so long scans stay cooperative. */
const YIELD_INTERVAL_BYTES = 4 * 1024 * 1024;

/** Mutable accumulator kept bounded by `max_strings` and `max_total_bytes`. */
interface Collection {
  readonly strings: ExtractedString[];
  total: number;
  retainedBytes: number;
}

/** Immutable scan inputs plus the single mutable accumulator, passed as one value. */
interface ScanState {
  readonly bytes: Buffer;
  readonly input: ExtractBinaryStringsInput;
  readonly image: ExecutableImage | null;
  readonly categories: Set<StringTag> | null;
  readonly collection: Collection;
  readonly signal: AbortSignal | undefined;
}

/** Deduplicate the caller's encodings while preserving their order. */
const orderedEncodings = (
  encodings: readonly StringEncoding[],
): StringEncoding[] => [...new Set(encodings)];

/** Containing section name of the default image slice, or null when unmapped. */
const sectionNameFor = (
  image: ExecutableImage | null,
  fileOffset: number,
): string | null => {
  if (image === null) return null;
  const relative = fileOffset - image.image_offset;
  if (relative < 0 || relative >= image.image_size) return null;
  return sectionContainingOffset(image.sections, relative)?.name ?? null;
};

/** Retain one run, refusing when its text would cross the returned-bytes budget. */
const retain = (
  state: ScanState,
  run: RawRun,
  tags: StringTag[],
  section: string | null,
): void => {
  const { collection } = state;
  const maxTotalBytes = state.input.max_total_bytes;
  const entryBytes = Buffer.byteLength(run.text, "utf8");
  if (collection.retainedBytes + entryBytes > maxTotalBytes)
    throw new TriageAnalysisFailure(
      "resource",
      `returned string text would exceed the ${maxTotalBytes}-byte budget; lower max_strings or raise min_length, or raise max_total_bytes. No partial result is returned.`,
      { max_total_bytes: maxTotalBytes },
    );
  collection.strings.push({
    text: run.text,
    encoding: run.encoding,
    file_offset: run.file_offset,
    section,
    length: run.length,
    tags,
  });
  collection.retainedBytes += entryBytes;
};

/** Scan one encoding end to end, counting every match and retaining the earliest. */
const scanEncoding = async (
  state: ScanState,
  encoding: StringEncoding,
): Promise<void> => {
  checkTriageCancelled(state.signal);
  const { collection, categories } = state;
  let lastYield = 0;
  for (const run of scannerFor(encoding)(state.bytes, state.input.min_length)) {
    if (run.file_offset - lastYield >= YIELD_INTERVAL_BYTES) {
      await yieldTriage(state.signal);
      lastYield = run.file_offset;
    }
    let tags: StringTag[] | null = null;
    if (categories !== null) {
      tags = tagString(run.text);
      if (!tags.some((tag) => categories.has(tag))) continue;
    }
    collection.total += 1;
    if (collection.strings.length >= state.input.max_strings) continue;
    retain(
      state,
      run,
      tags ?? tagString(run.text),
      sectionNameFor(state.image, run.file_offset),
    );
  }
  await yieldTriage(state.signal);
};

/** Occurrence counts of each tag among the returned strings, present tags only. */
const summarizeTags = (
  strings: readonly ExtractedString[],
): Partial<Record<StringTag, number>> => {
  const summary: Partial<Record<StringTag, number>> = {};
  for (const entry of strings)
    for (const tag of entry.tags) summary[tag] = (summary[tag] ?? 0) + 1;
  return summary;
};

const buildLimitations = (
  image: ExecutableImage | null,
  input: ExtractBinaryStringsInput,
  encodings: readonly StringEncoding[],
  categories: readonly StringTag[] | null,
): string[] => {
  const notes = [
    "Tags are inferred classifications of observed bytes; a match is not proof of the value's purpose, validity, reachability, or secrecy.",
    "Strings are reported verbatim as file content and are not redacted; do not infer secrecy from a name or the surrounding text.",
    "No live resolution is performed: domains, URLs, addresses, and emails are not checked against DNS, whois, or any network service.",
    "Only common top-level domains are recognized for the domain tag, so a token such as name.dll may match it and an exotic TLD may be missed; base64_blob matches any sufficiently long base64-shaped run.",
    `Input is bounded to 256 MiB and scanned in one linear pass per encoding; a run longer than ${MAX_STRING_CHARS} characters keeps its true length but its text is capped. Returned text is bounded by max_total_bytes (${input.max_total_bytes}) and the count by max_strings (${input.max_strings}).`,
    "Language-specific string blobs (such as Go or Rust concatenated string tables) are not split into their constituent entries and may be reported as one long run.",
  ];
  if (encodings.includes("utf8"))
    notes.push(
      "UTF-8 scanning reports only runs containing at least one multi-byte code point; pure-ASCII text is recovered under the ascii encoding.",
    );
  if (categories !== null)
    notes.push(
      "A category filter is applied: only strings carrying one of the requested tags appear in the list, the counts, and the coverage total.",
    );
  if (image === null)
    notes.push(
      "The file has no recognized ELF, PE, or Mach-O header, so section attribution is null for every string.",
    );
  return notes;
};

/**
 * Recover printable strings from one file's bytes and tag each with inferred
 * classifications, without executing the file, using the network, or writing
 * any output. The file is read once; results are bounded and cooperative.
 */
export const analyzeExtractBinaryStrings = async (
  bytes: Buffer,
  input: ExtractBinaryStringsInput,
  context: TriageAnalysisContext,
): Promise<Omit<ExtractBinaryStringsReport, "artifact">> => {
  const image = loadTriageImage(bytes).image;
  const encodings = orderedEncodings(input.encodings);
  const categories = input.categories ?? null;
  const collection: Collection = { strings: [], total: 0, retainedBytes: 0 };
  const state: ScanState = {
    bytes,
    input,
    image,
    categories: categories === null ? null : new Set(categories),
    collection,
    signal: context.signal,
  };
  for (const encoding of encodings) await scanEncoding(state, encoding);
  return {
    subject: triageSubject(image),
    min_length: input.min_length,
    encodings,
    categories,
    strings: collection.strings,
    string_coverage: {
      total: collection.total,
      returned: collection.strings.length,
      truncated: collection.total > collection.strings.length,
    },
    tag_summary: summarizeTags(collection.strings),
    limitations: buildLimitations(image, input, encodings, categories),
  };
};
