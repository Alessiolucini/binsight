/**
 * PE import hash (imphash) exactly reproducing pefile.get_imphash(): lowercase
 * library name with an .ocx/.sys/.dll extension stripped, ordinal-only imports
 * resolved through the standard ordinal tables (else `ord<N>`), each entry
 * joined as `library.function`, comma-joined and MD5-summed. Delay imports are
 * excluded. A sorted variant hashes the same entries in sorted order.
 */

import { createHash } from "node:crypto";
import type { ImageImport } from "../../domain/native/image/executableImage.js";
import { ORDINAL_TABLES } from "./ordinalTables.js";

const STRIP_EXTENSIONS = new Set(["ocx", "sys", "dll"]);

const md5 = (value: string): string =>
  createHash("md5").update(Buffer.from(value, "utf8")).digest("hex");

/** Lowercase the library and drop a trailing .ocx/.sys/.dll, as pefile does. */
const normalizeLibrary = (library: string): string => {
  const lower = library.toLowerCase();
  const dot = lower.lastIndexOf(".");
  if (dot >= 0 && STRIP_EXTENSIONS.has(lower.slice(dot + 1)))
    return lower.slice(0, dot);
  return lower;
};

/** Function token for one import: its name, or the ordinal-table / `ord<N>` form. */
const functionToken = (entry: ImageImport): string | null => {
  if (entry.name !== null && entry.name.length > 0)
    return entry.name.toLowerCase();
  if (entry.ordinal === null) return null;
  const table = ORDINAL_TABLES[(entry.library ?? "").toLowerCase()];
  const resolved = table?.[entry.ordinal];
  return (resolved ?? `ord${entry.ordinal}`).toLowerCase();
};

/** Ordered `library.function` tokens for every non-delay import. */
const importTokens = (imports: readonly ImageImport[]): string[] => {
  const tokens: string[] = [];
  for (const entry of imports) {
    if (entry.delay_loaded) continue;
    const func = functionToken(entry);
    if (func === null) continue;
    tokens.push(`${normalizeLibrary(entry.library ?? "")}.${func}`);
  }
  return tokens;
};

/** imphash and its sorted variant, or null for each when no imports qualify. */
export const computeImphashes = (
  imports: readonly ImageImport[],
): {
  readonly imphash: string | null;
  readonly imphashSorted: string | null;
} => {
  const tokens = importTokens(imports);
  if (tokens.length === 0) return { imphash: null, imphashSorted: null };
  const sorted = [...tokens].sort((left, right) =>
    left < right ? -1 : left > right ? 1 : 0,
  );
  return {
    imphash: md5(tokens.join(",")),
    imphashSorted: md5(sorted.join(",")),
  };
};
