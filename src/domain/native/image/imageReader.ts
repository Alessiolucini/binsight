import type {
  ImageByteOrder,
  ImageParseFailure,
  ImageRange,
  ImageSection,
} from "./executableImage.js";

/** Typed refusal thrown inside a format parser and converted to a Result at its boundary. */
export class ImageParseError extends Error {
  constructor(
    readonly kind: ImageParseFailure["kind"],
    message: string,
  ) {
    super(message);
    this.name = "ImageParseError";
  }
}

export const malformed = (message: string): ImageParseError =>
  new ImageParseError("malformed", message);

export const unsupported = (message: string): ImageParseError =>
  new ImageParseError("unsupported", message);

/** Bounds-checked, endian-aware integer and string reads over one image. */
export class ImageReader {
  readonly littleEndian: boolean;

  constructor(
    readonly bytes: Buffer,
    byteOrder: ImageByteOrder,
  ) {
    this.littleEndian = byteOrder === "little";
  }

  get length(): number {
    return this.bytes.length;
  }

  /** True when [offset, offset + size) lies inside the image. */
  contains(offset: number, size: number): boolean {
    return (
      Number.isSafeInteger(offset) &&
      Number.isSafeInteger(size) &&
      offset >= 0 &&
      size >= 0 &&
      offset + size <= this.bytes.length
    );
  }

  require(offset: number, size: number, what: string): void {
    if (!this.contains(offset, size))
      throw malformed(
        `${what} at file offset ${offset} (${size} bytes) is outside the ${this.bytes.length}-byte image`,
      );
  }

  u8(offset: number, what = "byte"): number {
    this.require(offset, 1, what);
    return this.bytes.readUInt8(offset);
  }

  u16(offset: number, what = "u16"): number {
    this.require(offset, 2, what);
    return this.littleEndian
      ? this.bytes.readUInt16LE(offset)
      : this.bytes.readUInt16BE(offset);
  }

  u32(offset: number, what = "u32"): number {
    this.require(offset, 4, what);
    return this.littleEndian
      ? this.bytes.readUInt32LE(offset)
      : this.bytes.readUInt32BE(offset);
  }

  i32(offset: number, what = "i32"): number {
    this.require(offset, 4, what);
    return this.littleEndian
      ? this.bytes.readInt32LE(offset)
      : this.bytes.readInt32BE(offset);
  }

  u64(offset: number, what = "u64"): bigint {
    this.require(offset, 8, what);
    return this.littleEndian
      ? this.bytes.readBigUInt64LE(offset)
      : this.bytes.readBigUInt64BE(offset);
  }

  /** Read a 4- or 8-byte unsigned word as bigint. */
  word(offset: number, bits: 32 | 64, what = "word"): bigint {
    return bits === 64
      ? this.u64(offset, what)
      : BigInt(this.u32(offset, what));
  }

  /** Read a 4- or 8-byte unsigned word that must fit a safe integer offset or size. */
  safeWord(offset: number, bits: 32 | 64, what = "word"): number {
    const value = this.word(offset, bits, what);
    if (value > BigInt(Number.MAX_SAFE_INTEGER))
      throw malformed(`${what} ${value} exceeds the supported integer range`);
    return Number(value);
  }

  slice(offset: number, size: number, what = "range"): Buffer {
    this.require(offset, size, what);
    return this.bytes.subarray(offset, offset + size);
  }

  /**
   * NUL-terminated string starting at `offset`, bounded by `limit` bytes and
   * the image end. Returns null when no terminator is found in bounds.
   */
  cString(
    offset: number,
    limit: number,
    encoding: "utf8" | "latin1" = "utf8",
  ): string | null {
    if (!Number.isSafeInteger(offset) || offset < 0 || offset >= this.length)
      return null;
    const end = Math.min(this.length, offset + limit);
    const terminator = this.bytes.indexOf(0, offset);
    if (terminator === -1 || terminator >= end) return null;
    return this.bytes.toString(encoding, offset, terminator);
  }

  /** Fixed-width field padded with NUL bytes, such as section names. */
  fixedString(offset: number, size: number, what = "name"): string {
    const field = this.slice(offset, size, what);
    const terminator = field.indexOf(0);
    return field.toString(
      "latin1",
      0,
      terminator === -1 ? field.length : terminator,
    );
  }
}

/** Run one format parser and convert typed refusals into a Result failure. */
export const captureImageParse = <T>(
  parse: () => T,
):
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly error: ImageParseFailure } => {
  try {
    return { ok: true, value: parse() };
  } catch (cause: unknown) {
    if (cause instanceof ImageParseError)
      return { ok: false, error: { kind: cause.kind, message: cause.message } };
    if (cause instanceof RangeError)
      return {
        ok: false,
        error: { kind: "malformed", message: cause.message },
      };
    throw cause;
  }
};

/** Bounded diagnostics collector shared by format parsers. */
export class ImageDiagnostics {
  readonly #messages: string[] = [];
  #dropped = 0;

  constructor(readonly limit: number) {}

  add(message: string): void {
    if (this.#messages.length < this.limit) this.#messages.push(message);
    else this.#dropped += 1;
  }

  list(): readonly string[] {
    return this.#dropped === 0
      ? [...this.#messages]
      : [
          ...this.#messages,
          `${this.#dropped} further diagnostics were omitted after the ${this.limit}-entry bound.`,
        ];
  }
}

/** Section whose file-backed bytes contain `offset`, if any. */
export const sectionContainingOffset = (
  sections: readonly ImageSection[],
  offset: number,
): ImageSection | undefined =>
  sections.find(
    (section) =>
      section.file_size > 0 &&
      offset >= section.file_offset &&
      offset < section.file_offset + section.file_size,
  );

/** Section whose virtual range contains `address`, if any. */
export const sectionContainingAddress = (
  sections: readonly ImageSection[],
  address: bigint,
): ImageSection | undefined =>
  sections.find(
    (section) =>
      section.virtual_size > 0n &&
      address >= section.virtual_address &&
      address < section.virtual_address + section.virtual_size,
  );

/** File offset for a virtual address inside a file-backed part of a section. */
export const fileOffsetForAddress = (
  sections: readonly ImageSection[],
  address: bigint,
): number | null => {
  const section = sectionContainingAddress(sections, address);
  if (section === undefined) return null;
  const delta = address - section.virtual_address;
  if (delta >= BigInt(section.file_size)) return null;
  return section.file_offset + Number(delta);
};

/** Bytes after the furthest declared file range, or null when nothing trails. */
export const overlayAfter = (
  imageSize: number,
  declaredEnds: Iterable<number>,
): ImageRange | null => {
  let end = 0;
  for (const value of declaredEnds)
    if (Number.isSafeInteger(value) && value > end) end = value;
  if (end >= imageSize) return null;
  return { file_offset: end, size: imageSize - end };
};
