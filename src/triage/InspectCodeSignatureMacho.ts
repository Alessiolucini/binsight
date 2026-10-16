import { createHash } from "node:crypto";
import { parseXmlPropertyList } from "../domain/propertyListKeys.js";
import type { ExecutableImage } from "../domain/native/image/executableImage.js";
import { toHexAddress } from "../domain/triage/triageCommon.js";
import type {
  MachoCodeDirectory,
  MachoCodeSignature,
  MachoEntitlements,
  MachoSignatureBlob,
} from "../domain/triage/inspectCodeSignature.js";

const MAGIC = {
  superBlob: 0xfade0cc0,
  codeDirectory: 0xfade0c02,
  requirements: 0xfade0c01,
  requirement: 0xfade0c00,
  blobWrapper: 0xfade0b01,
  entitlements: 0xfade7171,
  derEntitlements: 0xfade7172,
} as const;

/** CodeDirectory hash type constants mapped to node:crypto hash names. */
const HASH_TYPES: ReadonlyMap<number, string> = new Map([
  [1, "sha1"],
  [2, "sha256"],
  [3, "sha256"],
  [4, "sha384"],
  [5, "sha512"],
]);

/** SuperBlob slot indices, named where known. */
const SLOTS: ReadonlyMap<number, string> = new Map([
  [0, "code-directory"],
  [1, "info"],
  [2, "requirements"],
  [3, "resource-dir"],
  [4, "application"],
  [5, "entitlements"],
  [7, "der-entitlements"],
  [0x10000, "cms-signature"],
]);

/** CS_* flag bits reported when set. */
const CS_FLAGS: readonly (readonly [number, string])[] = [
  [0x00000001, "valid"],
  [0x00000002, "adhoc"],
  [0x00000004, "get-task-allow"],
  [0x00000008, "installer"],
  [0x00000100, "hard"],
  [0x00000200, "kill"],
  [0x00000800, "restrict"],
  [0x00001000, "enforcement"],
  [0x00002000, "require-lv"],
  [0x00010000, "runtime"],
  [0x00020000, "linker-signed"],
];

const MAX_BLOBS = 256;
const MAX_ENTITLEMENT_BYTES = 4 * 1024 * 1024;
const MAX_ENTITLEMENT_KEYS = 512;

interface Limited {
  push(message: string): void;
}

/** Parse the embedded Mach-O code signature structurally; no trust is evaluated. */
export const parseMachoCodeSignature = (
  bytes: Buffer,
  image: ExecutableImage,
  limitations: Limited,
): MachoCodeSignature | null => {
  const range = image.macho?.code_signature ?? null;
  if (range === null) return null;
  const base = range.file_offset;
  const empty = buildEmpty(range);
  if (
    !within(bytes, base, 12) ||
    bytes.readUInt32BE(base) !== MAGIC.superBlob
  ) {
    limitations.push(
      "LC_CODE_SIGNATURE is present but its data does not begin with a CSMAGIC_EMBEDDED_SIGNATURE SuperBlob.",
    );
    return empty;
  }
  const superLength = bytes.readUInt32BE(base + 4);
  const count = bytes.readUInt32BE(base + 8);
  const limit = Math.min(base + superLength, bytes.length);
  const blobs: MachoSignatureBlob[] = [];
  const codeDirectories: MachoCodeDirectory[] = [];
  let entitlements: MachoEntitlements | null = null;
  let derEntitlements = false;
  let requirements = false;
  let cmsPresent = false;
  let cmsSize = 0;
  const total = count;
  for (let index = 0; index < count && blobs.length < MAX_BLOBS; index += 1) {
    const entryOffset = base + 12 + index * 8;
    if (!within(bytes, entryOffset, 8)) break;
    const slot = bytes.readUInt32BE(entryOffset);
    const blobOffset = base + bytes.readUInt32BE(entryOffset + 4);
    if (!within(bytes, blobOffset, 8)) continue;
    const magic = bytes.readUInt32BE(blobOffset);
    const blobLength = bytes.readUInt32BE(blobOffset + 4);
    blobs.push({
      slot: SLOTS.get(slot) ?? `slot-${toHexAddress(slot)}`,
      magic: toHexAddress(magic),
      file_offset: blobOffset,
      size: blobLength,
    });
    if (magic === MAGIC.codeDirectory) {
      const cd = parseCodeDirectory(bytes, blobOffset, limit);
      if (cd !== null) codeDirectories.push(cd);
    } else if (magic === MAGIC.requirements || magic === MAGIC.requirement)
      requirements = true;
    else if (magic === MAGIC.blobWrapper) {
      cmsPresent = true;
      cmsSize = blobLength;
    } else if (magic === MAGIC.entitlements)
      entitlements = parseEntitlements(
        bytes,
        blobOffset,
        blobLength,
        limitations,
      );
    else if (magic === MAGIC.derEntitlements) derEntitlements = true;
  }
  limitations.push(
    "The Mach-O code signature structure is parsed; the certificate chain and OS trust are NOT evaluated. Presence is not validity.",
  );
  return {
    code_signature: range,
    superblob_present: true,
    blob_count: total,
    blobs,
    blob_coverage: {
      total,
      returned: blobs.length,
      truncated: blobs.length < total,
    },
    code_directory: codeDirectories[0] ?? null,
    alternate_code_directory_count: Math.max(0, codeDirectories.length - 1),
    entitlements,
    der_entitlements_present: derEntitlements,
    requirements_present: requirements,
    cms_present: cmsPresent,
    cms_size: cmsSize,
  };
};

const buildEmpty = (range: {
  readonly file_offset: number;
  readonly size: number;
}): MachoCodeSignature => ({
  code_signature: range,
  superblob_present: false,
  blob_count: 0,
  blobs: [],
  blob_coverage: { total: 0, returned: 0, truncated: false },
  code_directory: null,
  alternate_code_directory_count: 0,
  entitlements: null,
  der_entitlements_present: false,
  requirements_present: false,
  cms_present: false,
  cms_size: 0,
});

/** Decode one CodeDirectory blob and compute its own cd_hash. */
const parseCodeDirectory = (
  bytes: Buffer,
  offset: number,
  limit: number,
): MachoCodeDirectory | null => {
  if (!within(bytes, offset, 44)) return null;
  const length = bytes.readUInt32BE(offset + 4);
  const end = offset + length;
  if (length < 44 || end > limit) return null;
  const version = bytes.readUInt32BE(offset + 8);
  const flags = bytes.readUInt32BE(offset + 12);
  const identOffset = bytes.readUInt32BE(offset + 20);
  const nSpecialSlots = bytes.readUInt32BE(offset + 24);
  const nCodeSlots = bytes.readUInt32BE(offset + 28);
  const codeLimit = bytes.readUInt32BE(offset + 32);
  const hashSize = bytes.readUInt8(offset + 36);
  const hashType = bytes.readUInt8(offset + 37);
  const teamOffset = version >= 0x20200 ? bytes.readUInt32BE(offset + 48) : 0;
  const hashName = HASH_TYPES.get(hashType) ?? null;
  const digest =
    hashName === null
      ? ""
      : createHash(hashName).update(bytes.subarray(offset, end)).digest("hex");
  return {
    file_offset: offset,
    version: toHexAddress(version),
    identifier: readCString(bytes, offset + identOffset, end),
    team_id:
      teamOffset === 0 ? null : readCString(bytes, offset + teamOffset, end),
    flags,
    flags_decoded: CS_FLAGS.filter(([bit]) => (flags & bit) !== 0).map(
      ([, name]) => name,
    ),
    hash_type: hashType,
    hash_type_name: hashName,
    hash_size: hashSize,
    n_code_slots: nCodeSlots,
    n_special_slots: nSpecialSlots,
    code_limit: codeLimit,
    cd_hash: digest,
    cd_hash_truncated: digest.slice(0, 40),
  };
};

/** Decode the embedded XML entitlements plist via the shared property-list decoder. */
const parseEntitlements = (
  bytes: Buffer,
  offset: number,
  length: number,
  limitations: Limited,
): MachoEntitlements | null => {
  const end = Math.min(offset + length, bytes.length);
  const xmlBytes = bytes.subarray(offset + 8, end);
  if (xmlBytes.length === 0) return null;
  if (xmlBytes.length > MAX_ENTITLEMENT_BYTES) {
    limitations.push(
      `Embedded entitlements (${String(xmlBytes.length)} bytes) exceed the ${String(MAX_ENTITLEMENT_BYTES)}-byte decode bound and were not parsed.`,
    );
    return {
      file_offset: offset,
      format: "xml",
      keys: [],
      key_coverage: { total: 0, returned: 0, truncated: false },
      plist: null,
    };
  }
  let value: unknown = null;
  try {
    value = parseXmlPropertyList(xmlBytes.toString("utf8")).value;
  } catch {
    limitations.push(
      "Embedded XML entitlements were present but could not be decoded as a property list.",
    );
  }
  const allKeys =
    typeof value === "object" && value !== null && !Array.isArray(value)
      ? Object.keys(value as Record<string, unknown>)
      : [];
  const keys = allKeys.slice(0, MAX_ENTITLEMENT_KEYS);
  return {
    file_offset: offset,
    format: "xml",
    keys,
    key_coverage: {
      total: allKeys.length,
      returned: keys.length,
      truncated: keys.length < allKeys.length,
    },
    plist: value,
  };
};

const within = (bytes: Buffer, offset: number, size: number): boolean =>
  offset >= 0 && size >= 0 && offset + size <= bytes.length;

const readCString = (
  bytes: Buffer,
  offset: number,
  end: number,
): string | null => {
  if (offset < 0 || offset >= end || offset >= bytes.length) return null;
  const stop = Math.min(end, bytes.length);
  const terminator = bytes.indexOf(0, offset);
  if (terminator === -1 || terminator >= stop) return null;
  return bytes.toString("utf8", offset, terminator);
};
