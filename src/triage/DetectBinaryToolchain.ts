import type {
  ExecutableImage,
  ImageSection,
  PeRichHeader,
} from "../domain/native/image/executableImage.js";
import { compositeKey } from "../domain/unicodeCodePointOrder.js";
import {
  TOOLCHAIN_INDICATOR_LIMIT,
  TOOLCHAIN_MATCH_LIMIT,
  TOOLCHAIN_PACKED_REASON_LIMIT,
  type DetectBinaryToolchainInput,
  type DetectBinaryToolchainReport,
  type PackedIndicator,
  type ToolchainIndicator,
  type ToolchainMatch,
} from "../domain/triage/detectBinaryToolchain.js";
import {
  COMPILER_COMMENT_PATTERNS,
  CONTENT_SIGNATURES,
  RICH_PRODUCT_IDS,
  SECTION_SIGNATURES,
  type ToolchainCategory,
  type ToolchainConfidence,
} from "../domain/triage/toolchainSignatures.js";
import type { triageListCoverageSchema } from "../domain/triage/triageCommon.js";
import type { z } from "zod";
import {
  checkTriageCancelled,
  loadTriageImage,
  roundTo,
  triageLocation,
  triageSubject,
  yieldTriage,
} from "./triageSupport.js";
import type { TriageAnalysisContext } from "./triageSupport.js";

type Coverage = z.infer<typeof triageListCoverageSchema>;

/** Bytes between cooperative pauses while histogramming the whole file. */
const ENTROPY_YIELD_STRIDE = 8 * 1024 * 1024;
/** Whole-file entropy at or above which packing is inferred on its own. */
const VERY_HIGH_ENTROPY = 7.8;
/** Entropy that, with a writable+executable entry section, infers packing. */
const WRITABLE_ENTRY_ENTROPY = 7.0;

/** One marker contribution before matches are aggregated under an indicator. */
interface Contribution {
  readonly id: string;
  readonly name: string;
  readonly category: ToolchainCategory;
  readonly confidence: ToolchainConfidence;
  readonly match: ToolchainMatch;
}

/**
 * Identify the compiler, linker, packer, protector, installer, language and
 * bundler markers present in one file by a BinSight-authored signature table:
 * packer and protector section names, whole-file byte and ASCII markers, the
 * Microsoft Rich header, and GCC/Clang `.comment` banners. An entropy-assisted
 * packing assessment is layered on top. Detection only: the file is read once,
 * nothing is unpacked, decompressed or executed, and no network or temporary
 * files are used. Every identification is inferred from observed bytes.
 */
export const analyzeDetectBinaryToolchain = async (
  bytes: Buffer,
  _input: DetectBinaryToolchainInput,
  context: TriageAnalysisContext,
): Promise<Omit<DetectBinaryToolchainReport, "artifact">> => {
  const loaded = loadTriageImage(bytes);
  const image = loaded.image;
  const fileEntropy = await cooperativeFileEntropy(bytes, context);

  const contributions: Contribution[] = [];
  if (image !== null) contributions.push(...sectionContributions(image));
  contributions.push(...(await contentContributions(bytes, image, context)));
  if (image?.pe?.rich_header != null)
    contributions.push(...richContributions(image, image.pe.rich_header));
  if (image?.elf != null)
    contributions.push(...commentContributions(image.elf.comment));

  const { indicators, coverage } = aggregate(contributions);
  const packed = assessPacking(image, bytes, fileEntropy, indicators);

  return {
    subject: triageSubject(image),
    indicators,
    indicator_coverage: coverage,
    packed_indicator: packed,
    limitations: limitations(image, image?.pe?.rich_header ?? null, coverage),
  };
};

/** Shannon entropy in bits per byte over the whole file, yielding as it reads. */
export const cooperativeFileEntropy = async (
  bytes: Buffer,
  context: TriageAnalysisContext,
): Promise<number> => {
  const counts = new Uint32Array(256);
  for (let index = 0; index < bytes.length; index += 1) {
    const value = bytes[index] as number;
    counts[value] = (counts[value] as number) + 1;
    if (index % ENTROPY_YIELD_STRIDE === ENTROPY_YIELD_STRIDE - 1)
      await yieldTriage(context.signal);
  }
  checkTriageCancelled(context.signal);
  return roundTo(entropyFromCounts(counts, bytes.length));
};

const entropyFromCounts = (counts: Uint32Array, total: number): number => {
  if (total <= 0) return 0;
  let entropy = 0;
  for (const count of counts) {
    if (count === 0) continue;
    const probability = count / total;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
};

/** Packer and protector section-name markers in a parsed image. */
export const sectionContributions = (
  image: ExecutableImage,
): Contribution[] => {
  const found: Contribution[] = [];
  for (const section of image.sections)
    for (const signature of SECTION_SIGNATURES) {
      const hit =
        signature.match === "exact"
          ? section.name === signature.section
          : section.name.startsWith(signature.section);
      if (!hit) continue;
      found.push({
        id: signature.id,
        name: signature.name,
        category: signature.category,
        confidence: signature.confidence,
        match: {
          reason: `Section "${section.name}" matches the ${signature.name} ${signature.category} section-name marker.`,
          location: triageLocation(
            image,
            image.image_offset + section.file_offset,
          ),
        },
      });
    }
  return found;
};

/** Byte and ASCII markers found anywhere in the file. */
export const contentContributions = async (
  bytes: Buffer,
  image: ExecutableImage | null,
  context: TriageAnalysisContext,
): Promise<Contribution[]> => {
  const found: Contribution[] = [];
  for (const signature of CONTENT_SIGNATURES) {
    const offset = bytes.indexOf(Buffer.from(signature.bytes));
    if (offset !== -1)
      found.push({
        id: signature.id,
        name: signature.name,
        category: signature.category,
        confidence: signature.confidence,
        match: {
          reason: `Found the ${signature.name} marker (${signature.label}).`,
          location: triageLocation(image, offset),
        },
      });
    await yieldTriage(context.signal);
  }
  return found;
};

/** The Rich header is emitted only by the Microsoft Visual C/C++ linker. */
export const richContributions = (
  image: ExecutableImage,
  rich: PeRichHeader,
): Contribution[] => {
  const confidence: ToolchainConfidence = rich.checksum_valid
    ? "high"
    : "medium";
  const location = triageLocation(image, image.image_offset + rich.offset);
  const base: Omit<Contribution, "match"> = {
    id: "msvc",
    name: "Microsoft Visual C/C++ (MSVC)",
    category: "compiler",
    confidence,
  };
  const matches: Contribution[] = [
    {
      ...base,
      match: {
        reason: `A Rich header with ${rich.entries.length} build-tool entr${rich.entries.length === 1 ? "y" : "ies"} is present (checksum ${rich.checksum_valid ? "valid" : "mismatch"}); this structure is produced only by the MSVC linker.`,
        location,
      },
    },
  ];
  const ranked = [...rich.entries].sort((a, b) => b.count - a.count);
  for (const entry of ranked.slice(0, TOOLCHAIN_MATCH_LIMIT - 1)) {
    const role = RICH_PRODUCT_IDS[entry.product_id] ?? "Microsoft build tool";
    matches.push({
      ...base,
      match: {
        reason: `Rich entry product id ${entry.product_id} (${role}), build ${entry.build}, used ${entry.count} time${entry.count === 1 ? "" : "s"}.`,
        location,
      },
    });
  }
  return matches;
};

/** GCC and Clang record their producer and version in the ELF `.comment`. */
export const commentContributions = (
  comments: readonly string[],
): Contribution[] => {
  const found: Contribution[] = [];
  for (const comment of comments)
    for (const { id, name, pattern } of COMPILER_COMMENT_PATTERNS) {
      const banner = pattern.exec(comment)?.[0];
      if (banner === undefined) continue;
      found.push({
        id,
        name,
        category: "compiler",
        confidence: "high",
        match: {
          reason: `The .comment section records "${banner}".`,
          location: null,
        },
      });
    }
  return found;
};

const CONFIDENCE_RANK: Readonly<Record<ToolchainConfidence, number>> = {
  high: 3,
  medium: 2,
  low: 1,
};

/** Merge contributions into one indicator per id, bounding every list. */
export const aggregate = (
  contributions: readonly Contribution[],
): { indicators: ToolchainIndicator[]; coverage: Coverage } => {
  const byId = new Map<string, Contribution[]>();
  for (const contribution of contributions) {
    const group = byId.get(contribution.id);
    if (group === undefined) byId.set(contribution.id, [contribution]);
    else group.push(contribution);
  }
  const indicators = [...byId.values()]
    .map(buildIndicator)
    .sort(
      (a, b) =>
        CONFIDENCE_RANK[b.confidence] - CONFIDENCE_RANK[a.confidence] ||
        a.id.localeCompare(b.id),
    );
  const returned = indicators.slice(0, TOOLCHAIN_INDICATOR_LIMIT);
  return {
    indicators: returned,
    coverage: coverageOf(indicators.length, returned.length),
  };
};

const buildIndicator = (group: Contribution[]): ToolchainIndicator => {
  const head = group[0] as Contribution;
  const confidence = group.reduce<ToolchainConfidence>(
    (best, item) =>
      CONFIDENCE_RANK[item.confidence] > CONFIDENCE_RANK[best]
        ? item.confidence
        : best,
    "low",
  );
  const unique = dedupeMatches(group.map((item) => item.match));
  const returned = unique.slice(0, TOOLCHAIN_MATCH_LIMIT);
  return {
    id: head.id,
    name: head.name,
    category: head.category,
    confidence,
    evidence_kind: "inferred",
    matches: returned,
    match_coverage: coverageOf(unique.length, returned.length),
  };
};

const dedupeMatches = (
  matches: readonly ToolchainMatch[],
): ToolchainMatch[] => {
  const seen = new Set<string>();
  const unique: ToolchainMatch[] = [];
  for (const match of matches) {
    const key = compositeKey([match.location?.file_offset ?? -1, match.reason]);
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(match);
  }
  return unique.sort(
    (a, b) =>
      (a.location?.file_offset ?? Number.MAX_SAFE_INTEGER) -
        (b.location?.file_offset ?? Number.MAX_SAFE_INTEGER) ||
      a.reason.localeCompare(b.reason),
  );
};

/** Entropy-assisted packing assessment; never unpacks or executes. */
export const assessPacking = (
  image: ExecutableImage | null,
  bytes: Buffer,
  fileEntropy: number,
  indicators: readonly ToolchainIndicator[],
): PackedIndicator => {
  const entry = entryPointSection(image, bytes);
  const packers = indicators.filter(
    (indicator) =>
      indicator.category === "packer" || indicator.category === "protector",
  );
  const reasons: string[] = [];
  let status: PackedIndicator["status"];
  if (packers.length > 0) {
    status = "likely_packed";
    reasons.push(
      `A packer or protector indicator is present (${packers.map((p) => p.name).join(", ")}).`,
    );
  } else if (image !== null) {
    const writableEntry = entry !== null && entry.writable && entry.executable;
    if (writableEntry)
      reasons.push(
        `The entry point lies in a writable, executable section ("${entry.name}"), consistent with self-modifying or unpacking code.`,
      );
    if (fileEntropy >= VERY_HIGH_ENTROPY) {
      status = "likely_packed";
      reasons.push(
        `Whole-file entropy is ${fileEntropy} bits/byte, consistent with compression or encryption.`,
      );
    } else if (writableEntry && fileEntropy >= WRITABLE_ENTRY_ENTROPY) {
      status = "likely_packed";
      reasons.push(
        `Entry-section anomaly combined with high whole-file entropy (${fileEntropy} bits/byte).`,
      );
    } else {
      status = "not_observed";
      reasons.push(
        `Whole-file entropy (${fileEntropy} bits/byte) and the entry-point section are within the range of ordinary compiler output.`,
      );
    }
  } else {
    status = "unknown";
    reasons.push(
      `The file is not a recognized executable image; packing is assessed only from whole-file entropy (${fileEntropy} bits/byte).`,
    );
    if (fileEntropy >= VERY_HIGH_ENTROPY)
      reasons.push(
        "Whole-file entropy is very high, consistent with compression or encryption but not proof of packing.",
      );
  }
  return {
    status,
    evidence_kind: "inferred",
    file_entropy: fileEntropy,
    entry_point_section: entry,
    reasons: reasons.slice(0, TOOLCHAIN_PACKED_REASON_LIMIT),
  };
};

const entryPointSection = (
  image: ExecutableImage | null,
  bytes: Buffer,
): PackedIndicator["entry_point_section"] => {
  if (image === null || image.entry_point.section_index === null) return null;
  const section = image.sections[image.entry_point.section_index];
  if (section === undefined) return null;
  return {
    name: section.name,
    writable: section.writable,
    executable: section.executable,
    entropy: sectionEntropy(image, bytes, section),
  };
};

const sectionEntropy = (
  image: ExecutableImage,
  bytes: Buffer,
  section: ImageSection,
): number => {
  const start = image.image_offset + section.file_offset;
  const safeStart = Math.min(Math.max(start, 0), bytes.length);
  const available = Math.max(
    0,
    Math.min(section.file_size, bytes.length - safeStart),
  );
  const counts = new Uint32Array(256);
  for (let offset = safeStart; offset < safeStart + available; offset += 1) {
    const value = bytes[offset] as number;
    counts[value] = (counts[value] as number) + 1;
  }
  return roundTo(entropyFromCounts(counts, available));
};

const coverageOf = (total: number, returned: number): Coverage => ({
  total,
  returned,
  truncated: returned < total,
});

const limitations = (
  image: ExecutableImage | null,
  rich: PeRichHeader | null,
  coverage: Coverage,
): string[] => {
  const notes = [
    "Toolchain identifications are inferred from a BinSight-authored table of public byte and structural markers; a marker is consistent with a tool having produced the file and is not proof that it did.",
    "Detection only: no section, archive or packed region is unpacked, decompressed or executed; the file is read once (bounded at 256 MiB) with no network or temporary files.",
    "Markers can be stripped from a file a tool did produce and can be embedded by unrelated code or data, so an absent indicator is not proof the tool was not used.",
    "The packing assessment is an entropy-and-structure heuristic; entropy cannot distinguish compressed from encrypted data, and ordinary resources or media can raise whole-file entropy without packing.",
  ];
  if (image === null)
    notes.push(
      "The file is not a recognized ELF, PE or Mach-O image, so only whole-file content markers were scanned; no section, entry-point or Rich-header evidence is available.",
    );
  else if (image.container.kind === "fat")
    notes.push(
      "The file is a universal binary; section, entry-point and Rich evidence cover the selected slice, while content markers and entropy cover the whole file.",
    );
  if (rich !== null)
    notes.push(
      "Rich-header build numbers are reported as observed values; a specific Visual Studio marketing version is not asserted because the 16-bit build number is not unique across product generations.",
    );
  if (rich !== null && !rich.checksum_valid)
    notes.push(
      "The Rich header checksum did not validate; the MSVC identification is reported at reduced confidence.",
    );
  if (coverage.truncated)
    notes.push(
      "The number of distinct indicators exceeded the return bound; additional indicators were omitted and are reflected in the indicator coverage.",
    );
  return notes;
};
