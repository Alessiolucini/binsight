import type { ExecutableImage } from "../domain/native/image/executableImage.js";
import {
  ENTROPY_RUN_LIMIT,
  ENTROPY_SECTION_LIMIT,
  HIGH_ENTROPY_THRESHOLD,
  LOW_ENTROPY_THRESHOLD,
  type EntropyRun,
  type MeasureBinaryEntropyInput,
  type MeasureBinaryEntropyReport,
  type SectionEntropy,
} from "../domain/triage/measureBinaryEntropy.js";
import type { triageListCoverageSchema } from "../domain/triage/triageCommon.js";
import type { z } from "zod";
import {
  checkTriageCancelled,
  loadTriageImage,
  roundTo,
  triageSubject,
  yieldTriage,
} from "./triageSupport.js";
import type { TriageAnalysisContext } from "./triageSupport.js";

type Coverage = z.infer<typeof triageListCoverageSchema>;

/** Yield cadence: blocks between cooperative pauses, and bytes in the tail pass. */
const BLOCK_YIELD_STRIDE = 256;
const TAIL_YIELD_STRIDE = 4 * 1024 * 1024;

/**
 * Measure Shannon entropy and a uniform chi-square statistic over the whole
 * file, over each file-backed section when the bytes parse as an executable
 * image, and over a bounded grid of fixed-size blocks whose consecutive
 * high- and low-entropy runs are reported. Pure, deterministic and bounded:
 * the file is read once, nothing is executed, and no files or network are used.
 */
export const analyzeMeasureBinaryEntropy = async (
  bytes: Buffer,
  input: MeasureBinaryEntropyInput,
  context: TriageAnalysisContext,
): Promise<Omit<MeasureBinaryEntropyReport, "artifact">> => {
  const { block_size: blockSize, max_blocks: maxBlocks } = input;
  const length = bytes.length;
  const totalBlocks = length === 0 ? 0 : Math.ceil(length / blockSize);
  const scannedBlocks = Math.min(totalBlocks, maxBlocks);

  const fileCounts = new Uint32Array(256);
  const blockEntropies = new Float64Array(scannedBlocks);

  for (let block = 0; block < scannedBlocks; block += 1) {
    const start = block * blockSize;
    const end = Math.min(start + blockSize, length);
    const blockCounts = new Uint32Array(256);
    for (let index = start; index < end; index += 1) {
      const value = bytes[index] as number;
      blockCounts[value] = (blockCounts[value] as number) + 1;
      fileCounts[value] = (fileCounts[value] as number) + 1;
    }
    blockEntropies[block] = entropyFromCounts(blockCounts, end - start);
    if (block % BLOCK_YIELD_STRIDE === BLOCK_YIELD_STRIDE - 1)
      await yieldTriage(context.signal);
  }
  checkTriageCancelled(context.signal);

  // Complete the whole-file histogram over any bytes past the scanned grid.
  let processed = 0;
  for (let index = scannedBlocks * blockSize; index < length; index += 1) {
    const value = bytes[index] as number;
    fileCounts[value] = (fileCounts[value] as number) + 1;
    processed += 1;
    if (processed % TAIL_YIELD_STRIDE === 0) await yieldTriage(context.signal);
  }
  checkTriageCancelled(context.signal);

  const high = boundRuns(
    collectRuns(
      blockEntropies,
      (entropy) => entropy >= HIGH_ENTROPY_THRESHOLD,
      blockSize,
      length,
    ),
  );
  const low = boundRuns(
    collectRuns(
      blockEntropies,
      (entropy) => entropy <= LOW_ENTROPY_THRESHOLD,
      blockSize,
      length,
    ),
  );

  const loaded = loadTriageImage(bytes);
  const sections = await sectionEntropies(bytes, loaded.image, context);

  return {
    subject: triageSubject(loaded.image),
    block_size: blockSize,
    file_entropy: roundTo(entropyFromCounts(fileCounts, length)),
    file_chi_square: roundTo(chiSquareFromCounts(fileCounts, length)),
    mean: roundTo(meanFromCounts(fileCounts, length)),
    high_entropy_threshold: HIGH_ENTROPY_THRESHOLD,
    low_entropy_threshold: LOW_ENTROPY_THRESHOLD,
    section_entropy: sections.returned,
    section_coverage: sections.coverage,
    high_entropy_runs: high.returned,
    high_entropy_run_coverage: high.coverage,
    low_entropy_runs: low.returned,
    low_entropy_run_coverage: low.coverage,
    block_coverage: coverage(totalBlocks, scannedBlocks),
    limitations: limitations(
      loaded.image,
      sections.clamped,
      totalBlocks > scannedBlocks,
      high.coverage.truncated || low.coverage.truncated,
    ),
  };
};

/** Shannon entropy in bits per byte from a 256-bin histogram. */
export const entropyFromCounts = (
  counts: Uint32Array,
  total: number,
): number => {
  if (total <= 0) return 0;
  let entropy = 0;
  for (const count of counts) {
    if (count === 0) continue;
    const probability = count / total;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
};

/** Pearson chi-square of a histogram against a uniform byte distribution. */
export const chiSquareFromCounts = (
  counts: Uint32Array,
  total: number,
): number => {
  if (total <= 0) return 0;
  const expected = total / 256;
  let chi = 0;
  for (const count of counts) {
    const difference = count - expected;
    chi += (difference * difference) / expected;
  }
  return chi;
};

/** Arithmetic mean of the byte values represented by a histogram. */
export const meanFromCounts = (counts: Uint32Array, total: number): number => {
  if (total <= 0) return 0;
  let sum = 0;
  for (let value = 0; value < 256; value += 1)
    sum += value * (counts[value] as number);
  return sum / total;
};

const collectRuns = (
  entropies: Float64Array,
  inRun: (entropy: number) => boolean,
  blockSize: number,
  length: number,
): EntropyRun[] => {
  const makeRun = (
    startBlock: number,
    endBlock: number,
    sum: number,
  ): EntropyRun => {
    const blockCount = endBlock - startBlock;
    return {
      start: startBlock * blockSize,
      end: Math.min(endBlock * blockSize, length),
      block_count: blockCount,
      mean_entropy: roundTo(sum / blockCount),
    };
  };
  const runs: EntropyRun[] = [];
  let startBlock = -1;
  let sum = 0;
  for (let block = 0; block < entropies.length; block += 1) {
    const entropy = entropies[block] as number;
    if (inRun(entropy)) {
      if (startBlock < 0) {
        startBlock = block;
        sum = 0;
      }
      sum += entropy;
    } else if (startBlock >= 0) {
      runs.push(makeRun(startBlock, block, sum));
      startBlock = -1;
    }
  }
  if (startBlock >= 0) runs.push(makeRun(startBlock, entropies.length, sum));
  return runs;
};

const sectionEntropies = async (
  bytes: Buffer,
  image: ExecutableImage | null,
  context: TriageAnalysisContext,
): Promise<{
  readonly returned: SectionEntropy[];
  readonly coverage: Coverage;
  readonly clamped: boolean;
}> => {
  if (image === null)
    return { returned: [], coverage: coverage(0, 0), clamped: false };
  const total = image.sections.length;
  const returned: SectionEntropy[] = [];
  let clamped = false;
  for (const [index, section] of image.sections.entries()) {
    if (returned.length >= ENTROPY_SECTION_LIMIT) break;
    const start = image.image_offset + section.file_offset;
    const declared = section.file_size;
    const available = Math.max(0, Math.min(declared, bytes.length - start));
    if (available < declared) clamped = true;
    const counts = new Uint32Array(256);
    const safeStart = Math.min(Math.max(start, 0), bytes.length);
    for (let offset = safeStart; offset < safeStart + available; offset += 1) {
      const value = bytes[offset] as number;
      counts[value] = (counts[value] as number) + 1;
    }
    returned.push({
      name: section.name,
      file_offset: safeStart,
      size: available,
      entropy: roundTo(entropyFromCounts(counts, available)),
      chi_square: roundTo(chiSquareFromCounts(counts, available)),
    });
    if (index % BLOCK_YIELD_STRIDE === BLOCK_YIELD_STRIDE - 1)
      await yieldTriage(context.signal);
  }
  return {
    returned,
    coverage: coverage(total, returned.length),
    clamped,
  };
};

const boundRuns = (
  runs: readonly EntropyRun[],
): { readonly returned: EntropyRun[]; readonly coverage: Coverage } => ({
  returned: runs.slice(0, ENTROPY_RUN_LIMIT),
  coverage: coverage(runs.length, Math.min(runs.length, ENTROPY_RUN_LIMIT)),
});

const coverage = (total: number, returned: number): Coverage => ({
  total,
  returned,
  truncated: returned < total,
});

const limitations = (
  image: ExecutableImage | null,
  sectionsClamped: boolean,
  blocksTruncated: boolean,
  runsTruncated: boolean,
): string[] => {
  const notes = [
    "Entropy and chi-square are observed statistics computed from the exact file bytes, not a classification of file intent.",
    "Entropy cannot distinguish compressed data from encrypted data; both approach 8 bits per byte.",
    "High section or block entropy is consistent with packing, compression or encryption, but is not proof of any of them.",
    "No bytes are executed and no network or temporary files are used; the whole file is read once into memory, bounded at 256 MiB.",
  ];
  if (image === null)
    notes.push(
      "The file is not a recognized ELF, PE or Mach-O image, so no per-section entropy is reported.",
    );
  else if (image.container.kind === "fat")
    notes.push(
      "The file is a universal binary; per-section entropy covers only the first declared slice, while file-level entropy covers the whole file.",
    );
  if (sectionsClamped)
    notes.push(
      "One or more sections declared more file bytes than the artifact contains; entropy was measured only over the in-bounds portion.",
    );
  if (blocksTruncated)
    notes.push(
      "The block profile reached the max_blocks bound; blocks beyond it were not examined for runs, but file-level entropy still covers every byte.",
    );
  if (runsTruncated)
    notes.push(
      "The number of entropy runs exceeded the return bound; additional runs were omitted and are reflected in the run coverage.",
    );
  return notes;
};
