/**
 * Minimal, bounds-checked DER (definite-length) walker used to read the
 * structure of embedded Authenticode PKCS#7 signatures without any trust
 * evaluation. It parses tag/length/value triples, iterates constructed
 * children, and decodes the few primitives this triage needs (object
 * identifiers, integers, times and strings). Indefinite lengths — illegal in
 * DER — are rejected, and every walk is bounded in depth and node count so a
 * crafted blob cannot drive unbounded work.
 */

export const DER_LIMITS = {
  /** Deepest constructed nesting any walk descends. */
  depth: 48,
  /** Most children any single container yields. */
  childrenPerNode: 8_192,
  /** Longest object identifier, in arc count, that is decoded. */
  oidArcs: 128,
} as const;

/** ASN.1 tag class. */
export const TagClass = {
  universal: 0,
  application: 1,
  context: 2,
  private: 3,
} as const;

/** Universal tag numbers this walker names. */
export const Tag = {
  boolean: 0x01,
  integer: 0x02,
  bitString: 0x03,
  octetString: 0x04,
  null: 0x05,
  oid: 0x06,
  utf8String: 0x0c,
  sequence: 0x10,
  set: 0x11,
  printableString: 0x13,
  ia5String: 0x16,
  utcTime: 0x17,
  generalizedTime: 0x18,
  bmpString: 0x1e,
} as const;

/** One parsed DER triple located inside a buffer. */
export interface DerNode {
  readonly tagClass: number;
  readonly constructed: boolean;
  /** Tag number; for universal types this is the ASN.1 type. */
  readonly tag: number;
  /** Offset of the first identifier byte. */
  readonly start: number;
  /** Offset of the first content byte. */
  readonly contentStart: number;
  /** Content length in bytes. */
  readonly length: number;
  /** Offset just past the content (`contentStart + length`). */
  readonly end: number;
}

const inside = (bytes: Buffer, offset: number, size: number): boolean =>
  offset >= 0 && size >= 0 && offset + size <= bytes.length;

/**
 * Read one triple at `offset`, bounded by `limit`. Returns null when the
 * bytes are not a well-formed definite-length triple inside the limit.
 */
export const readNode = (
  bytes: Buffer,
  offset: number,
  limit: number = bytes.length,
): DerNode | null => {
  const end = Math.min(limit, bytes.length);
  if (offset < 0 || offset + 2 > end) return null;
  const identifier = bytes[offset] as number;
  const tagClass = identifier >> 6;
  const constructed = (identifier & 0x20) !== 0;
  let tag = identifier & 0x1f;
  let cursor = offset + 1;
  if (tag === 0x1f) {
    tag = 0;
    for (let guard = 0; guard < 8; guard += 1) {
      if (cursor >= end) return null;
      const part = bytes[cursor] as number;
      cursor += 1;
      tag = (tag << 7) | (part & 0x7f);
      if ((part & 0x80) === 0) break;
      if (guard === 7) return null;
    }
  }
  if (cursor >= end) return null;
  const first = bytes[cursor] as number;
  cursor += 1;
  let length: number;
  if ((first & 0x80) === 0) length = first;
  else {
    const count = first & 0x7f;
    // Indefinite length (count === 0) is not valid DER; reject it.
    if (count === 0 || count > 4) return null;
    length = 0;
    for (let index = 0; index < count; index += 1) {
      if (cursor >= end) return null;
      length = length * 256 + (bytes[cursor] as number);
      cursor += 1;
    }
  }
  const contentStart = cursor;
  if (!Number.isSafeInteger(length) || contentStart + length > end) return null;
  return {
    tagClass,
    constructed,
    tag,
    start: offset,
    contentStart,
    length,
    end: contentStart + length,
  };
};

/** Iterate the immediate children of a constructed node, bounded by count. */
export const children = (bytes: Buffer, node: DerNode): DerNode[] => {
  const out: DerNode[] = [];
  if (!node.constructed) return out;
  let cursor = node.contentStart;
  while (cursor < node.end && out.length < DER_LIMITS.childrenPerNode) {
    const child = readNode(bytes, cursor, node.end);
    if (child === null || child.end <= cursor) break;
    out.push(child);
    cursor = child.end;
  }
  return out;
};

/** Decode an OBJECT IDENTIFIER node to its dotted-decimal string, or null. */
export const readOid = (bytes: Buffer, node: DerNode): string | null => {
  if (
    node.tagClass !== TagClass.universal ||
    node.tag !== Tag.oid ||
    node.length === 0 ||
    !inside(bytes, node.contentStart, node.length)
  )
    return null;
  const arcs: number[] = [];
  const first = bytes[node.contentStart] as number;
  arcs.push(Math.floor(first / 40), first % 40);
  let value = 0;
  for (let index = 1; index < node.length; index += 1) {
    if (arcs.length > DER_LIMITS.oidArcs) return null;
    const part = bytes[node.contentStart + index] as number;
    value = value * 128 + (part & 0x7f);
    if ((part & 0x80) === 0) {
      if (!Number.isSafeInteger(value)) return null;
      arcs.push(value);
      value = 0;
    }
  }
  return arcs.join(".");
};

/** Decode an INTEGER node to uppercase hex (two's-complement bytes, sign dropped). */
export const readIntegerHex = (bytes: Buffer, node: DerNode): string | null => {
  if (
    node.tagClass !== TagClass.universal ||
    node.tag !== Tag.integer ||
    node.length === 0 ||
    !inside(bytes, node.contentStart, node.length)
  )
    return null;
  let start = node.contentStart;
  const stop = node.end;
  // Drop a single leading 0x00 that only carries sign, keep genuine zero.
  while (start + 1 < stop && bytes[start] === 0x00) start += 1;
  const hex = bytes.subarray(start, stop).toString("hex").toUpperCase();
  return hex.length === 0 ? "0" : hex;
};

/** Decode a UTCTime / GeneralizedTime node to an ISO 8601 string, or null. */
export const readTime = (bytes: Buffer, node: DerNode): string | null => {
  if (
    node.tagClass !== TagClass.universal ||
    (node.tag !== Tag.utcTime && node.tag !== Tag.generalizedTime) ||
    !inside(bytes, node.contentStart, node.length)
  )
    return null;
  const text = bytes
    .subarray(node.contentStart, node.end)
    .toString("latin1")
    .trim();
  const utc = node.tag === Tag.utcTime;
  const match = utc
    ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/u.exec(text)
    : /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(?:\.\d+)?Z$/u.exec(text);
  if (match === null) return text.length === 0 ? null : text;
  const [, y, mo, d, h, mi, s] = match;
  const year = utc ? Number(y) + (Number(y) >= 50 ? 1900 : 2000) : Number(y);
  return `${String(year).padStart(4, "0")}-${mo}-${d}T${h}:${mi}:${s ?? "00"}Z`;
};

/** Decode a text-string node (UTF-8, IA5, printable, BMP) to a string, or null. */
export const readString = (bytes: Buffer, node: DerNode): string | null => {
  if (!inside(bytes, node.contentStart, node.length)) return null;
  const content = bytes.subarray(node.contentStart, node.end);
  if (node.tag === Tag.bmpString)
    return content.length % 2 === 0 ? swapUtf16(content) : null;
  if (
    node.tag === Tag.utf8String ||
    node.tag === Tag.ia5String ||
    node.tag === Tag.printableString
  )
    return content.toString(node.tag === Tag.utf8String ? "utf8" : "latin1");
  return null;
};

/** BMPString is UTF-16 big-endian; decode it after swapping to little-endian. */
const swapUtf16 = (content: Buffer): string => {
  const swapped = Buffer.allocUnsafe(content.length);
  for (let index = 0; index + 1 < content.length; index += 2) {
    swapped[index] = content[index + 1] as number;
    swapped[index + 1] = content[index] as number;
  }
  return swapped.toString("utf16le");
};
