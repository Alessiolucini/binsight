/**
 * BinSight-authored binary component classifiers. Each signature anchors on a short
 * ASCII literal that well-known projects embed in their own code or banners,
 * then confirms a version with a narrow window-local pattern. Matching a
 * signature is an inferred attribution of observed bytes, never proof that the
 * component is linked, reachable or current.
 */

import { compositeKey } from "../unicodeCodePointOrder.js";

/** Component kind a signature attributes a match to. */
export type ComponentSignatureType = "library" | "application";

/** One anchored classifier: a literal to locate, then a version confirmation. */
export interface ComponentSignature {
  /** Stable lowercase component identity reported as the component name. */
  readonly name: string;
  readonly type: ComponentSignatureType;
  /** purl type namespace used to build a package URL for a match. */
  readonly purl_type: string;
  /** ASCII literal located with a native byte search before confirmation. */
  readonly anchor: string;
  /** Bytes from the anchor start decoded as latin1 for the pattern. */
  readonly window: number;
  /** Anchored pattern; capture group 1 is the observed version. */
  readonly pattern: RegExp;
}

/** One confirmed classifier match at an absolute file offset. */
export interface ComponentHit {
  readonly name: string;
  readonly version: string;
  readonly type: ComponentSignatureType;
  readonly purl_type: string;
  readonly file_offset: number;
}

/** Bounded scan outcome; `truncated` when a match cap stopped collection. */
export interface ComponentScan {
  readonly hits: readonly ComponentHit[];
  readonly truncated: boolean;
}

/** Largest file prefix searched for classifier anchors. */
export const COMPONENT_SCAN_LIMIT_BYTES = 128 * 1024 * 1024;
/** Largest number of confirmed matches retained before truncation. */
export const COMPONENT_SCAN_MAX_HITS = 4096;
/** Largest number of anchor occurrences inspected per signature. */
const MAX_ANCHOR_OCCURRENCES = 100_000;

/**
 * Classifier table. Patterns are deliberately conservative: a semantic version
 * plus a project-specific framing word keeps random data from matching.
 */
export const COMPONENT_SIGNATURES: readonly ComponentSignature[] = [
  {
    name: "openssl",
    type: "library",
    purl_type: "generic",
    anchor: "OpenSSL ",
    window: 48,
    pattern: /^OpenSSL (\d+\.\d+\.\d+[a-z]?(?:-[0-9A-Za-z.+]+)?)(?= |$)/u,
  },
  {
    name: "zlib",
    type: "library",
    purl_type: "generic",
    anchor: "deflate ",
    window: 48,
    pattern: /^deflate (\d+\.\d+\.\d+(?:\.\d+)?) Copyright/u,
  },
  {
    name: "zlib",
    type: "library",
    purl_type: "generic",
    anchor: "zlib version ",
    window: 48,
    pattern: /^zlib version (\d+\.\d+\.\d+(?:\.\d+)?)/u,
  },
  {
    name: "sqlite",
    type: "library",
    purl_type: "generic",
    anchor: "SQLite version ",
    window: 48,
    pattern: /^SQLite version (\d+\.\d+\.\d+)/u,
  },
  {
    name: "curl",
    type: "library",
    purl_type: "generic",
    anchor: "libcurl/",
    window: 48,
    pattern: /^libcurl\/(\d+\.\d+\.\d+)/u,
  },
  {
    name: "node.js",
    type: "application",
    purl_type: "generic",
    anchor: "node.js/v",
    window: 48,
    pattern: /^node\.js\/v(\d+\.\d+\.\d+)/u,
  },
  {
    name: "busybox",
    type: "application",
    purl_type: "generic",
    anchor: "BusyBox v",
    window: 48,
    pattern: /^BusyBox v(\d+\.\d+\.\d+)/u,
  },
  {
    name: "chrome",
    type: "application",
    purl_type: "generic",
    anchor: "Chrome/",
    window: 48,
    pattern: /^Chrome\/(\d+\.\d+\.\d+\.\d+)/u,
  },
];

/**
 * Locate and confirm classifier matches in `bytes`, deduplicating identical
 * name/version/offset tuples and stopping at `COMPONENT_SCAN_MAX_HITS`. Only a
 * narrow latin1 window at each anchor is decoded, so the whole file is never
 * materialized as a string.
 */
export const scanComponentSignatures = (bytes: Buffer): ComponentScan => {
  const limit = Math.min(bytes.length, COMPONENT_SCAN_LIMIT_BYTES);
  const hits: ComponentHit[] = [];
  const seen = new Set<string>();
  let truncated = limit < bytes.length;
  for (const signature of COMPONENT_SIGNATURES) {
    const anchor = Buffer.from(signature.anchor, "latin1");
    if (anchor.length === 0) continue;
    let from = 0;
    let occurrences = 0;
    while (from <= limit - anchor.length) {
      const at = bytes.indexOf(anchor, from);
      if (at < 0 || at > limit - anchor.length) break;
      from = at + 1;
      occurrences += 1;
      if (occurrences > MAX_ANCHOR_OCCURRENCES) {
        truncated = true;
        break;
      }
      const end = Math.min(at + signature.window, bytes.length);
      const match = signature.pattern.exec(bytes.toString("latin1", at, end));
      const version = match?.[1];
      if (version === undefined) continue;
      const identity = compositeKey([signature.name, version, at]);
      if (seen.has(identity)) continue;
      if (hits.length >= COMPONENT_SCAN_MAX_HITS) {
        truncated = true;
        return { hits, truncated };
      }
      seen.add(identity);
      hits.push({
        name: signature.name,
        version,
        type: signature.type,
        purl_type: signature.purl_type,
        file_offset: at,
      });
    }
  }
  hits.sort((left, right) => left.file_offset - right.file_offset);
  return { hits, truncated };
};
