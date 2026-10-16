import * as zlib from "node:zlib";

/**
 * Bounds-checked numeric readers and shared types for the embedded-content
 * structural validators. Every validator receives the whole file and a
 * proposed start offset, reads only header fields and bounded tables, and
 * never decompresses a full stream, extracts a member or writes anything.
 */
export interface CandidateValidation {
  readonly validated: boolean;
  readonly size: number | null;
  readonly confidence: "high" | "medium" | "low";
  /** Extra detail appended to the signature description, or null. */
  readonly detail: string | null;
}

export type FormatValidator = (
  bytes: Buffer,
  start: number,
) => CandidateValidation | null;

const MAX = Number.MAX_SAFE_INTEGER;

/** True when [o, o + n) lies inside the buffer. */
export const has = (b: Buffer, o: number, n: number): boolean =>
  o >= 0 && n >= 0 && o + n <= b.length;

export const u16le = (b: Buffer, o: number): number => b.readUInt16LE(o);
export const u16be = (b: Buffer, o: number): number => b.readUInt16BE(o);
export const u32le = (b: Buffer, o: number): number => b.readUInt32LE(o);
export const u32be = (b: Buffer, o: number): number => b.readUInt32BE(o);
export const u64le = (b: Buffer, o: number): bigint => b.readBigUInt64LE(o);
export const u64be = (b: Buffer, o: number): bigint => b.readBigUInt64BE(o);

/** Convert a bigint length to a safe number, or null when out of range. */
export const safe = (value: bigint): number | null =>
  value >= 0n && value <= BigInt(MAX) ? Number(value) : null;

/** Build an accepting judgement; validators return null to reject instead. */
export const result = (
  size: number | null,
  confidence: "high" | "medium" | "low",
  detail: string | null = null,
): CandidateValidation => ({ validated: true, size, confidence, detail });

/** Decode a bounded prefix of a raw-deflate stream to confirm it is deflate. */
export const probeDeflate = (slice: Buffer): boolean => {
  try {
    const out = zlib.inflateRawSync(slice, {
      finishFlush: zlib.constants.Z_SYNC_FLUSH,
      maxOutputLength: 4096,
    });
    return out.length > 0;
  } catch (cause: unknown) {
    return (
      cause instanceof Error &&
      (cause as { code?: string }).code === "ERR_BUFFER_TOO_LARGE"
    );
  }
};
