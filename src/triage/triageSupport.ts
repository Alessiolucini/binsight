import type {
  ExecutableImage,
  ImageArchitecture,
  ImageParseFailure,
} from "../domain/native/image/executableImage.js";
import { sectionContainingOffset } from "../domain/native/image/imageReader.js";
import { parseExecutableImage } from "../domain/native/image/parseExecutableImage.js";
import type { z } from "zod";
import type {
  triageLocationSchema,
  triageSubjectSchema,
} from "../domain/triage/triageCommon.js";
import { toHexAddress } from "../domain/triage/triageCommon.js";

/** Shared context passed to every pure triage analyzer. */
export interface TriageAnalysisContext {
  readonly signal?: AbortSignal | undefined;
  /** SHA-256 of the exact snapshot bytes. */
  readonly sha256: string;
}

/** Expected analyzer refusal; the provider maps kinds to typed analysis errors. */
export class TriageAnalysisFailure extends Error {
  constructor(
    readonly kind: "unsupported" | "malformed" | "resource",
    message: string,
    readonly limits: Readonly<Record<string, number>> | null = null,
  ) {
    super(message);
    this.name = "TriageAnalysisFailure";
  }
}

/** Parsed executable image, or the reason the bytes are not one. */
export type TriageImage =
  | { readonly image: ExecutableImage; readonly failure: null }
  | { readonly image: null; readonly failure: ImageParseFailure };

/** Parse once per analysis; non-executable content is an observation, not an error. */
export const loadTriageImage = (
  bytes: Buffer,
  slice?: Exclude<ImageArchitecture, null>,
): TriageImage => {
  const parsed = parseExecutableImage(
    bytes,
    slice === undefined ? {} : { slice: { architecture: slice } },
  );
  return parsed.ok
    ? { image: parsed.value, failure: null }
    : { image: null, failure: parsed.error };
};

/** Require an executable image, refusing malformed and unrecognized content. */
export const requireTriageImage = (
  bytes: Buffer,
  slice?: Exclude<ImageArchitecture, null>,
): ExecutableImage => {
  const loaded = loadTriageImage(bytes, slice);
  if (loaded.image !== null) return loaded.image;
  throw new TriageAnalysisFailure(loaded.failure.kind, loaded.failure.message);
};

/** Evidence subject facts for an image or a plain file. */
export const triageSubject = (
  image: ExecutableImage | null,
): z.infer<typeof triageSubjectSchema> =>
  image === null
    ? { format: "file", architecture: null }
    : {
        format: image.format === "macho" ? "mach-o" : image.format,
        architecture: image.architecture,
      };

/** Position of one absolute file offset relative to the image's sections. */
export const triageLocation = (
  image: ExecutableImage | null,
  fileOffset: number,
): z.infer<typeof triageLocationSchema> => {
  if (image === null)
    return { file_offset: fileOffset, section: null, virtual_address: null };
  const relative = fileOffset - image.image_offset;
  const section =
    relative >= 0 && relative < image.image_size
      ? sectionContainingOffset(image.sections, relative)
      : undefined;
  return {
    file_offset: fileOffset,
    section: section?.name ?? null,
    virtual_address:
      section === undefined
        ? null
        : toHexAddress(
            section.virtual_address + BigInt(relative - section.file_offset),
          ),
  };
};

/** Cooperative cancellation point for long scans. */
export const checkTriageCancelled = (signal?: AbortSignal): void => {
  signal?.throwIfAborted();
};

/** Yield to the event loop between bounded chunks of CPU work. */
export const yieldTriage = async (signal?: AbortSignal): Promise<void> => {
  await new Promise<void>((resolve) => setImmediate(resolve));
  signal?.throwIfAborted();
};

/** Shannon entropy in bits per byte for a byte range. */
export const shannonEntropy = (
  bytes: Uint8Array,
  start = 0,
  end = bytes.length,
): number => {
  const length = end - start;
  if (length <= 0) return 0;
  const counts = new Uint32Array(256);
  for (let index = start; index < end; index += 1) {
    const value = bytes[index] as number;
    counts[value] = (counts[value] as number) + 1;
  }
  let entropy = 0;
  for (const count of counts) {
    if (count === 0) continue;
    const probability = count / length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
};

/** Round to a fixed number of decimals for stable report values. */
export const roundTo = (value: number, decimals = 4): number => {
  const factor = 10 ** decimals;
  return Math.round(value * factor) / factor;
};
