/**
 * telfhash: a TLSH over the distinctive exported and imported function names of
 * an ELF's dynamic symbol table. Following the published algorithm, the global
 * STT_FUNC names from `.dynsym` are lowercased, compiler- and
 * architecture-noise names are dropped (leading `.`/`_`, `str`/`mem` prefixes,
 * `64` suffix), the survivors are de-duplicated, sorted and comma-joined, and
 * the result is TLSH-hashed.
 */

import type { ImageSymbol } from "../../domain/native/image/executableImage.js";
import { tlshHash } from "./tlsh.js";

const isNoise = (name: string): boolean =>
  name.startsWith(".") ||
  name.startsWith("_") ||
  name.startsWith("str") ||
  name.startsWith("mem") ||
  name.endsWith("64");

/** The cleaned, sorted, de-duplicated telfhash symbol names. */
export const telfhashSymbols = (
  symbols: readonly ImageSymbol[],
): readonly string[] => {
  const names = new Set<string>();
  for (const symbol of symbols) {
    if (
      symbol.table !== "dynsym" ||
      symbol.type !== "function" ||
      symbol.binding !== "global" ||
      symbol.name.length === 0
    )
      continue;
    const name = symbol.name.toLowerCase();
    if (!isNoise(name)) names.add(name);
  }
  return [...names].sort((left, right) =>
    left < right ? -1 : left > right ? 1 : 0,
  );
};

/** telfhash digest, or null when no qualifying symbols or the input is too short. */
export const computeTelfhash = (
  symbols: readonly ImageSymbol[],
): { readonly hash: string | null; readonly symbol_count: number } => {
  const names = telfhashSymbols(symbols);
  if (names.length === 0) return { hash: null, symbol_count: 0 };
  return {
    hash: tlshHash(Buffer.from(names.join(","), "utf8")),
    symbol_count: names.length,
  };
};
