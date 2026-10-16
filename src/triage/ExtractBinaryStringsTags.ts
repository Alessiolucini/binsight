import type { StringTag } from "../domain/triage/extractBinaryStrings.js";

/**
 * Inferred classification of one observed string. Every tag is a bounded,
 * backtracking-free pattern match over the recovered text, not a judgement
 * about whether the value is secret, valid, reachable, or live.
 */

/** Common public and private TLD labels recognized for the `domain` tag. */
const DOMAIN_TLDS = [
  "com",
  "net",
  "org",
  "io",
  "gov",
  "edu",
  "mil",
  "info",
  "biz",
  "xyz",
  "dev",
  "app",
  "cloud",
  "co",
  "me",
  "tv",
  "us",
  "uk",
  "de",
  "fr",
  "ru",
  "cn",
  "jp",
  "br",
  "in",
  "top",
  "site",
  "online",
  "club",
  "local",
  "lan",
  "internal",
  "onion",
].join("|");

/** Ordered so the report lists tags deterministically. */
const DETECTORS: readonly {
  readonly tag: StringTag;
  readonly pattern: RegExp;
}[] = [
  {
    tag: "url",
    pattern: /(?:https?|ftps?|file|wss?):\/\/[^\s"'<>]+/iu,
  },
  {
    tag: "ipv4",
    pattern:
      /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/u,
  },
  {
    tag: "ipv6",
    pattern:
      /(?:\b(?:[0-9a-f]{1,4}:){6}[0-9a-f]{1,4}\b)|(?:[0-9a-f]{0,4}::[0-9a-f:]{2,})/iu,
  },
  {
    tag: "domain",
    pattern: new RegExp(
      String.raw`\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:${DOMAIN_TLDS})\b`,
      "iu",
    ),
  },
  {
    tag: "email",
    pattern: /\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,24}\b/iu,
  },
  {
    tag: "path_windows",
    pattern:
      /(?:\b[a-z]:\\[^\r\n"<>|]+)|(?:\\\\[^\\\r\n"<>|]+\\[^\r\n"<>|]+)/iu,
  },
  {
    tag: "path_posix",
    pattern: /(?:\/[A-Za-z0-9._+-]+){2,}\/?/u,
  },
  {
    tag: "registry_key",
    pattern:
      /\b(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|HK(?:LM|CU|CR|CC|U))\\[^\r\n]+/iu,
  },
  {
    tag: "guid",
    pattern:
      /\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?/iu,
  },
  {
    tag: "base64_blob",
    pattern: /[A-Za-z0-9+/]{24,}={0,2}/u,
  },
  {
    tag: "pem",
    pattern: /-----BEGIN [A-Z0-9 ]+-----/u,
  },
  {
    tag: "jwt",
    pattern:
      /\beyJ[A-Za-z0-9_-]{2,}\.eyJ[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\b/u,
  },
  {
    tag: "user_agent",
    pattern:
      /(?:\bMozilla\/\d)|(?:\b(?:curl|wget|python-requests|go-http-client|okhttp|libwww-perl|libcurl)\/\d)|User-Agent:/iu,
  },
  {
    tag: "format_string",
    pattern:
      /%(?:\d+\$)?[-+ 0#]*(?:\d+|\*)?(?:\.(?:\d+|\*))?(?:hh|h|ll|l|L|q|j|z|t)?[diouxXeEfFgGaAcspn]/u,
  },
  {
    tag: "sql",
    pattern:
      /(?:\bselect\b[\s\S]{0,400}?\bfrom\b)|(?:\binsert\s+into\b)|(?:\bupdate\b[\s\S]{0,400}?\bset\b)|(?:\bdelete\s+from\b)|(?:\b(?:create|drop|alter)\s+(?:table|index|database|view)\b)/iu,
  },
] as const;

/** The inferred tags for one string, in a stable report order; empty when none match. */
export const tagString = (text: string): StringTag[] => {
  const tags: StringTag[] = [];
  for (const { tag, pattern } of DETECTORS)
    if (pattern.test(text)) tags.push(tag);
  return tags;
};
