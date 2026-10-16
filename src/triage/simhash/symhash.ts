/**
 * Mach-O symbol hash (symhash): the names of external, undefined symbols
 * (the nlist entries `nm` reports as `U`), sorted, comma-joined and MD5-summed.
 * These are the slice's imported symbols projected by the image parser.
 */

import { createHash } from "node:crypto";

/** symhash over the external undefined symbol names, or null when there are none. */
export const computeSymhash = (names: readonly string[]): string | null => {
  const filtered = names.filter((name) => name.length > 0);
  if (filtered.length === 0) return null;
  const sorted = [...filtered].sort((left, right) =>
    left < right ? -1 : left > right ? 1 : 0,
  );
  return createHash("md5")
    .update(Buffer.from(sorted.join(","), "utf8"))
    .digest("hex");
};
