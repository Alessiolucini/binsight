/**
 * Static similarity-hash triage: whole-file SHA-256/MD5/TLSH/ssdeep plus the
 * image-derived imphash, Rich-header hash, telfhash, symhash and per-section
 * SHA-256. Pure and deterministic; reads the one selected file once, never
 * executes it, uses no network and writes no files. Every identifier whose
 * inputs are absent is reported as null with a matching limitation.
 */

import { createHash } from "node:crypto";
import type {
  ExecutableImage,
  ImageArchitecture,
} from "../domain/native/image/executableImage.js";
import type {
  ComputeSimilarityHashesInput,
  ComputeSimilarityHashesReport,
  PerSectionDigest,
} from "../domain/triage/computeSimilarityHashes.js";
import { toHexAddress } from "../domain/triage/triageCommon.js";
import {
  checkTriageCancelled,
  loadTriageImage,
  triageSubject,
  yieldTriage,
  type TriageAnalysisContext,
} from "./triageSupport.js";
import { computeImphashes } from "./simhash/imphash.js";
import { ssdeepHash } from "./simhash/ssdeep.js";
import { computeSymhash } from "./simhash/symhash.js";
import { computeTelfhash } from "./simhash/telfhash.js";
import { tlshHash } from "./simhash/tlsh.js";

/** A single report retains at most this many per-section digests. */
const MAX_SECTIONS = 4096;

const sha256Hex = (bytes: Buffer): string =>
  createHash("sha256").update(bytes).digest("hex");

const md5Hex = (bytes: Buffer): string =>
  createHash("md5").update(bytes).digest("hex");

interface SectionDigests {
  readonly list: readonly PerSectionDigest[];
  readonly coverage: {
    readonly total: number;
    readonly returned: number;
    readonly truncated: boolean;
  };
}

/** SHA-256 of each file-backed section's on-disk bytes, bounded by MAX_SECTIONS. */
const perSectionDigests = (
  bytes: Buffer,
  image: ExecutableImage,
): SectionDigests => {
  const candidates = image.sections.filter(
    (section) =>
      section.file_size > 0 &&
      section.file_offset + section.file_size <= bytes.length,
  );
  const list = candidates
    .slice(0, MAX_SECTIONS)
    .map<PerSectionDigest>((section) => ({
      name: section.name,
      file_offset: section.file_offset,
      size: section.file_size,
      virtual_address:
        section.virtual_address > 0n
          ? toHexAddress(section.virtual_address)
          : null,
      sha256: sha256Hex(
        bytes.subarray(
          section.file_offset,
          section.file_offset + section.file_size,
        ),
      ),
    }));
  return {
    list,
    coverage: {
      total: candidates.length,
      returned: list.length,
      truncated: candidates.length > list.length,
    },
  };
};

interface ImageHashes {
  readonly imphash: string | null;
  readonly imphash_sorted: string | null;
  readonly rich_pe_hash: string | null;
  readonly telfhash: string | null;
  readonly symhash: string | null;
  readonly sections: SectionDigests;
}

const EMPTY_SECTIONS: SectionDigests = {
  list: [],
  coverage: { total: 0, returned: 0, truncated: false },
};

const imageHashes = (bytes: Buffer, image: ExecutableImage): ImageHashes => {
  const imph =
    image.format === "pe"
      ? computeImphashes(image.imports)
      : { imphash: null, imphashSorted: null };
  const rich = image.pe?.rich_header ?? null;
  const telf =
    image.format === "elf" ? computeTelfhash(image.symbols).hash : null;
  const sym =
    image.format === "macho"
      ? computeSymhash(
          image.imports
            .map((entry) => entry.name)
            .filter((name): name is string => name !== null),
        )
      : null;
  return {
    imphash: imph.imphash,
    imphash_sorted: imph.imphashSorted,
    rich_pe_hash: rich === null ? null : md5Hex(rich.clear_bytes),
    telfhash: telf,
    symhash: sym,
    sections: perSectionDigests(bytes, image),
  };
};

const AUTHORITY_LIMITATIONS = [
  "Similarity identifiers are derived from file content; a shared value is consistent with structural resemblance, not proof of shared authorship, provenance or behavior.",
  "No key material or plaintext is recovered; the whole file is read once (bounded to 256 MiB), the target is not executed, no network is used and no file is written.",
] as const;

const nullFieldLimitations = (
  image: ExecutableImage | null,
  hashes: ImageHashes,
  tlsh: string | null,
): string[] => {
  const notes: string[] = [];
  if (tlsh === null)
    notes.push(
      "tlsh is null: the file is shorter than 50 bytes or too uniform for a defined TLSH digest.",
    );
  if (hashes.imphash === null)
    notes.push(
      "imphash and imphash_sorted are null: the selected image is not a PE, or it declares no non-delay imports.",
    );
  if (hashes.rich_pe_hash === null)
    notes.push("rich_pe_hash is null: no PE Rich header is present.");
  if (hashes.telfhash === null)
    notes.push(
      "telfhash is null: no ELF .dynsym global functions survive filtering, or their joined names are too short for TLSH.",
    );
  if (hashes.symhash === null)
    notes.push(
      "symhash is null: the selected image is not a Mach-O, or it declares no external undefined symbols.",
    );
  if (image !== null && image.container.kind === "fat")
    notes.push(
      "Import-, symbol- and section-derived hashes cover only the selected universal-binary slice.",
    );
  return notes;
};

const toSlice = (
  slice: ComputeSimilarityHashesInput["slice"],
): Exclude<ImageArchitecture, null> | undefined => slice;

/** Compute every similarity identifier for one file; see the module contract. */
export const analyzeComputeSimilarityHashes = async (
  bytes: Buffer,
  input: ComputeSimilarityHashesInput,
  context: TriageAnalysisContext,
): Promise<Omit<ComputeSimilarityHashesReport, "artifact">> => {
  const loaded = loadTriageImage(bytes, toSlice(input.slice));
  const image = loaded.image;
  checkTriageCancelled(context.signal);
  const tlsh = tlshHash(bytes);
  await yieldTriage(context.signal);
  const ssdeep = ssdeepHash(bytes);
  await yieldTriage(context.signal);
  const hashes =
    image === null ? emptyImageHashes() : imageHashes(bytes, image);
  await yieldTriage(context.signal);
  const limitations: string[] = [...AUTHORITY_LIMITATIONS];
  if (image === null)
    limitations.push(
      `The file is not a recognized ELF, PE or Mach-O image (${loaded.failure.message}); only whole-file digests are reported.`,
    );
  limitations.push(...nullFieldLimitations(image, hashes, tlsh));
  return {
    subject: triageSubject(image),
    sha256: context.sha256,
    md5: md5Hex(bytes),
    imphash: hashes.imphash,
    imphash_sorted: hashes.imphash_sorted,
    rich_pe_hash: hashes.rich_pe_hash,
    telfhash: hashes.telfhash,
    symhash: hashes.symhash,
    tlsh,
    ssdeep,
    per_section_sha256: [...hashes.sections.list],
    per_section_coverage: hashes.sections.coverage,
    limitations,
  };
};

const emptyImageHashes = (): ImageHashes => ({
  imphash: null,
  imphash_sorted: null,
  rich_pe_hash: null,
  telfhash: null,
  symhash: null,
  sections: EMPTY_SECTIONS,
});
