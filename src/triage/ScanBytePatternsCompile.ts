import type { ScanBytePattern } from "../domain/triage/scanBytePatterns.js";
import { TriageAnalysisFailure } from "./triageSupport.js";

/**
 * Compiles caller patterns into global {@link RegExp} matchers over a Latin-1
 * view of the file (one code unit per byte). The hex grammar is a small YARA
 * subset; text is literal; regex is a JavaScript expression without
 * backreferences. Every matcher is byte-exact: ranges and classes are emitted
 * as `\xHH` escapes so raw bytes never reach the regex grammar.
 */
export interface CompiledPattern {
  readonly id: string;
  readonly regex: RegExp;
}

/** Largest fixed or ranged hex jump accepted; wider gaps are rejected. */
export const MAX_HEX_JUMP = 1_048_576;

const reject = (message: string): never => {
  throw new TriageAnalysisFailure("malformed", message);
};

const HEX_BYTE = /^[0-9a-fA-F]$/u;

const hexEscape = (byte: number): string =>
  `\\x${byte.toString(16).padStart(2, "0")}`;

/** Regex source matching a single byte under a nibble mask (0 bit = wildcard). */
const byteSource = (mask: number, value: number): string => {
  if (mask === 0) return "[\\s\\S]";
  if (mask === 0xff) return hexEscape(value);
  if (mask === 0xf0) {
    const high = value & 0xf0;
    return `[${hexEscape(high)}-${hexEscape(high | 0x0f)}]`;
  }
  const low = value & 0x0f;
  let members = "";
  for (let high = 0; high < 16; high += 1)
    members += hexEscape((high << 4) | low);
  return `[${members}]`;
};

const nibble = (char: string): number | "any" => {
  if (char === "?") return "any";
  return Number.parseInt(char, 16);
};

/** Compile one byte token from two adjacent nibble characters. */
const byteToken = (high: string, low: string): string => {
  const hi = nibble(high);
  const lo = nibble(low);
  const mask = (hi === "any" ? 0 : 0xf0) | (lo === "any" ? 0 : 0x0f);
  const value = ((hi === "any" ? 0 : hi) << 4) | (lo === "any" ? 0 : lo);
  return byteSource(mask, value);
};

interface ByteScan {
  readonly source: string;
  readonly nextIndex: number;
  readonly bytes: number;
}

/** Read a contiguous run of byte tokens (no jumps or groups) from `value`. */
const readBytes = (value: string, start: number): ByteScan => {
  let index = start;
  let source = "";
  let bytes = 0;
  while (index < value.length) {
    const char = value[index] as string;
    if (/\s/u.test(char)) {
      index += 1;
      continue;
    }
    if (char === "(" || char === "[" || char === ")" || char === "|") break;
    if (char !== "?" && !HEX_BYTE.test(char))
      reject(`Unexpected character '${char}' in hex pattern.`);
    const low = value[index + 1];
    if (low === undefined || (low !== "?" && !HEX_BYTE.test(low)))
      reject("Each hex byte needs exactly two nibbles (digits or '?').");
    source += byteToken(char, low as string);
    bytes += 1;
    index += 2;
  }
  return { source, nextIndex: index, bytes };
};

/** Compile a parenthesised alternation of byte-only sequences. */
const readAlternation = (
  value: string,
  openIndex: number,
): { readonly source: string; readonly nextIndex: number } => {
  const close = value.indexOf(")", openIndex);
  if (close === -1) reject("Unterminated '(' in hex pattern alternation.");
  const inner = value.slice(openIndex + 1, close);
  const alternatives = inner.split("|").map((alternative) => {
    const scan = readBytes(alternative, 0);
    if (scan.nextIndex !== alternative.length)
      reject(
        "Hex alternation branches may contain only bytes, not jumps or nested groups.",
      );
    if (scan.bytes === 0)
      reject("Hex alternation branches must each match at least one byte.");
    return scan.source;
  });
  if (alternatives.length < 2)
    reject("Hex alternation needs at least two '|'-separated branches.");
  return { source: `(?:${alternatives.join("|")})`, nextIndex: close + 1 };
};

const parseCount = (text: string): number => {
  if (!/^\d+$/u.test(text)) reject(`Invalid hex jump bound '${text}'.`);
  const count = Number.parseInt(text, 10);
  if (count > MAX_HEX_JUMP)
    reject(`Hex jump bound ${count} exceeds the ${MAX_HEX_JUMP}-byte limit.`);
  return count;
};

/** Compile a `[n]`, `[n-m]` or `[n-]` jump to a lazy any-byte quantifier. */
const readJump = (
  value: string,
  openIndex: number,
): { readonly source: string; readonly nextIndex: number } => {
  const close = value.indexOf("]", openIndex);
  if (close === -1) reject("Unterminated '[' in hex pattern jump.");
  const spec = value.slice(openIndex + 1, close).replace(/\s/gu, "");
  let source: string;
  if (/^\d+$/u.test(spec)) source = `[\\s\\S]{${parseCount(spec)}}`;
  else if (/^\d+-$/u.test(spec))
    source = `[\\s\\S]{${parseCount(spec.slice(0, -1))},}?`;
  else {
    const range = /^(\d+)-(\d+)$/u.exec(spec);
    if (range === null)
      reject(`Unsupported hex jump '[${spec}]'; use [n], [n-m] or [n-].`);
    const min = parseCount((range as RegExpExecArray)[1] as string);
    const max = parseCount((range as RegExpExecArray)[2] as string);
    if (min > max)
      reject(`Hex jump [${spec}] has a minimum greater than its maximum.`);
    source = `[\\s\\S]{${min},${max}}?`;
  }
  return { source, nextIndex: close + 1 };
};

/** Compile a hex pattern to regex source, rejecting unbounded or empty forms. */
export const compileHexSource = (value: string): string => {
  let index = 0;
  let source = "";
  let byteCount = 0;
  let lastWasJump = false;
  let sawToken = false;
  while (index < value.length) {
    const char = value[index] as string;
    if (/\s/u.test(char)) {
      index += 1;
      continue;
    }
    if (char === "[") {
      if (!sawToken) reject("A hex pattern may not begin with a jump.");
      const jump = readJump(value, index);
      source += jump.source;
      index = jump.nextIndex;
      lastWasJump = true;
      continue;
    }
    if (char === "(") {
      const alternation = readAlternation(value, index);
      source += alternation.source;
      index = alternation.nextIndex;
      byteCount += 1;
      lastWasJump = false;
      sawToken = true;
      continue;
    }
    if (char === ")" || char === "|")
      reject(`Unexpected '${char}' outside a hex alternation group.`);
    const scan = readBytes(value, index);
    if (scan.nextIndex === index)
      reject(`Unexpected character '${char}' in hex pattern.`);
    source += scan.source;
    byteCount += scan.bytes;
    index = scan.nextIndex;
    lastWasJump = false;
    sawToken = true;
  }
  if (!sawToken || byteCount === 0)
    reject("A hex pattern must match at least one concrete byte.");
  if (lastWasJump) reject("A hex pattern may not end with a jump.");
  return source;
};

const bytesToSource = (buffer: Buffer): string => {
  let source = "";
  for (const byte of buffer) source += hexEscape(byte);
  return source;
};

/** Compile a literal text pattern over its requested ASCII and/or UTF-16LE forms. */
export const compileTextSource = (pattern: ScanBytePattern): string => {
  const wideOn = pattern.wide ?? false;
  const asciiOn = pattern.ascii ?? !wideOn;
  const parts: string[] = [];
  if (asciiOn) parts.push(bytesToSource(Buffer.from(pattern.value, "latin1")));
  if (wideOn) parts.push(bytesToSource(Buffer.from(pattern.value, "utf16le")));
  if (parts.length === 0)
    reject("A text pattern needs at least one of ascii or wide enabled.");
  return parts.length === 1 ? (parts[0] as string) : `(?:${parts.join("|")})`;
};

const BACKREFERENCE = /\\[1-9]|\\k</u;

/** Validate and build a caller regex; rejects backreferences and invalid syntax. */
export const compileCallerRegex = (pattern: ScanBytePattern): RegExp => {
  if (BACKREFERENCE.test(pattern.value))
    reject("Backreferences are not supported in regex patterns.");
  try {
    return new RegExp(pattern.value, pattern.nocase === true ? "gi" : "g");
  } catch (cause: unknown) {
    return reject(
      `Invalid regular expression: ${cause instanceof Error ? cause.message : String(cause)}`,
    );
  }
};

/** Compile one caller pattern into a global matcher, or throw a typed refusal. */
export const compilePattern = (pattern: ScanBytePattern): CompiledPattern => {
  if (pattern.type === "regex")
    return { id: pattern.id, regex: compileCallerRegex(pattern) };
  const source =
    pattern.type === "hex"
      ? compileHexSource(pattern.value)
      : compileTextSource(pattern);
  const flags = pattern.type === "text" && pattern.nocase === true ? "gi" : "g";
  return { id: pattern.id, regex: new RegExp(source, flags) };
};
