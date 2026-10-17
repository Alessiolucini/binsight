import type {
  CompareBinariesInput,
  CompareBinariesReport,
} from "../domain/triage/compareBinaries.js";
import { toHexAddress } from "../domain/triage/triageCommon.js";

type DiffBody = Omit<
  CompareBinariesReport,
  "base" | "target" | "subject" | "limitations"
>;

const CANCEL_STRIDE = 1 << 20;

const readWord = (buf: Buffer, offset: number, width: 1 | 2 | 4): number => {
  if (offset + width > buf.length) return 0;
  if (width === 1) return buf.readUInt8(offset);
  if (width === 2) return buf.readUInt16LE(offset);
  return buf.readUInt32LE(offset);
};

const regionKind = (
  target: Buffer,
  diffSet: (offset: number) => boolean,
  start: number,
  end: number,
): CompareBinariesReport["regions"][number]["kind"] => {
  let zeroed = true;
  let filled = true;
  for (let i = start; i <= end; i += 1) {
    if (!diffSet(i)) continue;
    const value = target[i] as number;
    if (value !== 0x00) zeroed = false;
    if (value !== 0xff) filled = false;
    if (!zeroed && !filled) return "modified";
  }
  return zeroed ? "zeroed" : filled ? "filled" : "modified";
};

const regionSamples = (
  base: Buffer,
  target: Buffer,
  region: { readonly start: number; readonly end: number },
  input: CompareBinariesInput,
): CompareBinariesReport["regions"][number]["samples"] => {
  const samples: CompareBinariesReport["regions"][number]["samples"] = [];
  const width = input.word_size;
  const first = region.start - (region.start % width);
  for (
    let off = first;
    off <= region.end && samples.length < input.samples_per_region;
    off += width
  ) {
    const before = readWord(base, off, width);
    const after = readWord(target, off, width);
    if (before !== after)
      samples.push({ offset: toHexAddress(off), before, after });
  }
  return samples;
};

/** Compare two byte buffers into a bounded, explained change report body. */
export const diffBinaries = (
  base: Buffer,
  target: Buffer,
  input: CompareBinariesInput,
  signal?: AbortSignal,
): DiffBody => {
  const compared = Math.min(base.length, target.length);
  const diffPositions: number[] = [];
  for (let i = 0; i < compared; i += 1) {
    if (i % CANCEL_STRIDE === 0) signal?.throwIfAborted();
    if (base[i] !== target[i]) diffPositions.push(i);
  }
  const changedBytes = diffPositions.length;
  const identical = changedBytes === 0 && base.length === target.length;
  if (changedBytes === 0)
    return {
      identical,
      size_delta: target.length - base.length,
      compared_bytes: compared,
      changed_bytes: 0,
      changed_ratio: 0,
      changed_range: null,
      summary: {
        region_count: 0,
        zeroed_bytes: 0,
        filled_bytes: 0,
        other_changed_bytes: 0,
      },
      regions: [],
      region_coverage: { total: 0, returned: 0, truncated: false },
    };

  const diffFlags = new Uint8Array(compared);
  let zeroed = 0;
  let filled = 0;
  let other = 0;
  for (const i of diffPositions) {
    diffFlags[i] = 1;
    const value = target[i] as number;
    if (value === 0x00) zeroed += 1;
    else if (value === 0xff) filled += 1;
    else other += 1;
  }
  const inDiff = (offset: number): boolean => diffFlags[offset] === 1;

  const bounds: { start: number; end: number }[] = [];
  let start = diffPositions[0] as number;
  let prev = start;
  for (let k = 1; k < diffPositions.length; k += 1) {
    const i = diffPositions[k] as number;
    if (i - prev <= input.region_gap) prev = i;
    else {
      bounds.push({ start, end: prev });
      start = prev = i;
    }
  }
  bounds.push({ start, end: prev });

  const returned = bounds.slice(0, input.max_regions);
  const regions = returned.map((region) => ({
    offset: toHexAddress(region.start),
    length: region.end - region.start + 1,
    kind: regionKind(target, inDiff, region.start, region.end),
    samples: regionSamples(base, target, region, input),
  }));

  return {
    identical,
    size_delta: target.length - base.length,
    compared_bytes: compared,
    changed_bytes: changedBytes,
    changed_ratio: changedBytes / compared,
    changed_range: {
      start: toHexAddress(diffPositions[0] as number),
      end: toHexAddress(diffPositions[diffPositions.length - 1] as number),
    },
    summary: {
      region_count: bounds.length,
      zeroed_bytes: zeroed,
      filled_bytes: filled,
      other_changed_bytes: other,
    },
    regions,
    region_coverage: {
      total: bounds.length,
      returned: regions.length,
      truncated: bounds.length > regions.length,
    },
  };
};
