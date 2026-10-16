import { z } from "zod";
import {
  hexAddressSchema,
  refineOffsetsInside,
  triageListCoverageSchema,
  triagePathSchema,
  triageReportBase,
  triageSliceSchema,
} from "./triageCommon.js";

/** Lowercase hex of any length, used for digests whose width depends on the algorithm. */
const hexBytesSchema = z.string().regex(/^[0-9a-f]*$/u);

const nonNegative = z.number().int().nonnegative();

/** A byte range inside the analyzed file. */
const fileRangeSchema = z.strictObject({
  file_offset: nonNegative,
  size: nonNegative,
});

/** One X.509 certificate summarized from its parsed fields; no trust is evaluated. */
export const codeSignatureCertificateSchema = z.strictObject({
  subject: z.string(),
  issuer: z.string(),
  /** Serial number as uppercase hexadecimal without a leading sign. */
  serial: z.string().regex(/^[0-9A-F]+$/u),
  not_before: z.string().nullable(),
  not_after: z.string().nullable(),
});

/** A counter-signature or RFC 3161 timestamp token, parsed structurally only. */
export const codeSignatureTimestampSchema = z.strictObject({
  kind: z.enum(["authenticode-countersignature", "rfc3161"]),
  /** Signing time in ISO 8601, or the raw token value when it cannot be normalized. */
  time: z.string().nullable(),
  signer: z.string().nullable(),
  digest_algorithm: z.string().nullable(),
});

/** One WIN_CERTIFICATE entry framing a PKCS#7 blob in the PE security directory. */
export const winCertificateEntrySchema = z.strictObject({
  file_offset: nonNegative,
  length: nonNegative,
  /** WIN_CERT_REVISION constant, e.g. "1.0" or "2.0", or "unknown" when unrecognized. */
  revision: z.string(),
  /** WIN_CERT_TYPE name such as pkcs-signed-data, x509, pkcs1-sign, or unknown. */
  certificate_type: z.string(),
  parsed_pkcs7: z.boolean(),
});

/** Observed Authenticode structure plus a computed authentihash; trust is not checked. */
export const peAuthenticodeSchema = z.strictObject({
  signature_present: z.boolean(),
  security_directory: fileRangeSchema.nullable(),
  certificate_entries: z.array(winCertificateEntrySchema),
  certificate_entry_coverage: triageListCoverageSchema,
  /** SignerInfo digestAlgorithm name, or null when it was not parsed. */
  digest_algorithm: z.string().nullable(),
  /** SpcSpOpusInfo programName when present. */
  program_name: z.string().nullable(),
  /** The certificate matching the SignerInfo issuer and serial, when found. */
  signer: codeSignatureCertificateSchema.nullable(),
  certificate_count: nonNegative,
  certificates: z.array(codeSignatureCertificateSchema),
  certificate_coverage: triageListCoverageSchema,
  timestamps: z.array(codeSignatureTimestampSchema),
  timestamp_coverage: triageListCoverageSchema,
  nested_signature_count: nonNegative,
  authentihash: z
    .strictObject({
      algorithm: z.string(),
      computed: hexBytesSchema,
      /** The digest stored in SpcIndirectDataContent, when parsed. */
      stored: hexBytesSchema.nullable(),
      matches: z.boolean().nullable(),
    })
    .nullable(),
});

/** One Mach-O CodeDirectory, decoded structurally. */
export const machoCodeDirectorySchema = z.strictObject({
  file_offset: nonNegative,
  /** CodeDirectory version as a hex string, e.g. 0x20400. */
  version: hexAddressSchema,
  identifier: z.string().nullable(),
  team_id: z.string().nullable(),
  flags: nonNegative,
  /** Decoded CS_* flag names present in `flags`. */
  flags_decoded: z.array(z.string()),
  hash_type: nonNegative,
  hash_type_name: z.string().nullable(),
  hash_size: nonNegative,
  n_code_slots: nonNegative,
  n_special_slots: nonNegative,
  code_limit: nonNegative,
  /** Digest of the CodeDirectory blob under its own hash type (full width). */
  cd_hash: hexBytesSchema,
  /** First 20 bytes of the CodeDirectory digest, as codesign reports CandidateCDHash. */
  cd_hash_truncated: hexBytesSchema,
});

/** One SuperBlob index entry located by slot and magic. */
export const machoSignatureBlobSchema = z.strictObject({
  slot: z.string(),
  magic: hexAddressSchema,
  file_offset: nonNegative,
  size: nonNegative,
});

/** Embedded entitlements decoded from the XML blob; DER entitlements are reported as presence only. */
export const machoEntitlementsSchema = z.strictObject({
  file_offset: nonNegative,
  format: z.literal("xml"),
  /** Top-level plist keys when the entitlements are a dictionary. */
  keys: z.array(z.string()),
  key_coverage: triageListCoverageSchema,
  /** Parsed plist value, or null when the XML could not be decoded. */
  plist: z.unknown(),
});

/** Observed Mach-O embedded code signature; certificate chain and OS trust are not evaluated. */
export const machoCodeSignatureSchema = z.strictObject({
  code_signature: fileRangeSchema,
  superblob_present: z.boolean(),
  blob_count: nonNegative,
  blobs: z.array(machoSignatureBlobSchema),
  blob_coverage: triageListCoverageSchema,
  code_directory: machoCodeDirectorySchema.nullable(),
  alternate_code_directory_count: nonNegative,
  entitlements: machoEntitlementsSchema.nullable(),
  der_entitlements_present: z.boolean(),
  requirements_present: z.boolean(),
  cms_present: z.boolean(),
  cms_size: nonNegative,
});

/** One explicit local file whose embedded signature structure is parsed without trust evaluation. */
export const inspectCodeSignatureInputSchema = z.strictObject({
  path: triagePathSchema,
  slice: triageSliceSchema,
});

/** Bounded, trust-free signature observation. A missing signature is `present: false`, never an error. */
export const inspectCodeSignatureReportSchema = z
  .strictObject({
    ...triageReportBase,
    present: z.boolean(),
    pe: peAuthenticodeSchema.nullable(),
    macho: machoCodeSignatureSchema.nullable(),
  })
  .superRefine((report, context) => {
    refineOffsetsInside(report.artifact.bytes, collectOffsets(report), context);
  });

export type CodeSignatureCertificate = z.infer<
  typeof codeSignatureCertificateSchema
>;
export type CodeSignatureTimestamp = z.infer<
  typeof codeSignatureTimestampSchema
>;
export type WinCertificateEntry = z.infer<typeof winCertificateEntrySchema>;
export type PeAuthenticode = z.infer<typeof peAuthenticodeSchema>;
export type MachoCodeDirectory = z.infer<typeof machoCodeDirectorySchema>;
export type MachoSignatureBlob = z.infer<typeof machoSignatureBlobSchema>;
export type MachoEntitlements = z.infer<typeof machoEntitlementsSchema>;
export type MachoCodeSignature = z.infer<typeof machoCodeSignatureSchema>;
export type InspectCodeSignatureInput = z.infer<
  typeof inspectCodeSignatureInputSchema
>;
export type InspectCodeSignatureReport = z.infer<
  typeof inspectCodeSignatureReportSchema
>;

/** Every file offset a report asserts, for the shared bounds check. */
const collectOffsets = (
  report: z.infer<typeof inspectCodeSignatureReportSchema>,
): { readonly offset: number; readonly path: (string | number)[] }[] => {
  const offsets: { offset: number; path: (string | number)[] }[] = [];
  const { pe, macho } = report;
  if (pe !== null) {
    if (pe.security_directory !== null)
      offsets.push({
        offset: pe.security_directory.file_offset,
        path: ["pe", "security_directory", "file_offset"],
      });
    for (const [index, entry] of pe.certificate_entries.entries())
      offsets.push({
        offset: entry.file_offset,
        path: ["pe", "certificate_entries", index, "file_offset"],
      });
  }
  if (macho !== null) {
    offsets.push({
      offset: macho.code_signature.file_offset,
      path: ["macho", "code_signature", "file_offset"],
    });
    for (const [index, blob] of macho.blobs.entries())
      offsets.push({
        offset: blob.file_offset,
        path: ["macho", "blobs", index, "file_offset"],
      });
    if (macho.code_directory !== null)
      offsets.push({
        offset: macho.code_directory.file_offset,
        path: ["macho", "code_directory", "file_offset"],
      });
    if (macho.entitlements !== null)
      offsets.push({
        offset: macho.entitlements.file_offset,
        path: ["macho", "entitlements", "file_offset"],
      });
  }
  return offsets;
};
