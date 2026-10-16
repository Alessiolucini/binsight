import type {
  InspectCodeSignatureInput,
  InspectCodeSignatureReport,
} from "../domain/triage/inspectCodeSignature.js";
import {
  checkTriageCancelled,
  loadTriageImage,
  triageSubject,
  yieldTriage,
  type TriageAnalysisContext,
} from "./triageSupport.js";
import { parseMachoCodeSignature } from "./InspectCodeSignatureMacho.js";
import { parsePeAuthenticode } from "./InspectCodeSignaturePe.js";

/**
 * Parse an embedded code signature — PE Authenticode or a Mach-O code
 * signature SuperBlob — into its structure without evaluating certificate
 * chains or operating-system trust. The analyzer reads the selected file once;
 * it never executes the target, resolves a network, or writes files.
 */
export const analyzeInspectCodeSignature = async (
  bytes: Buffer,
  input: InspectCodeSignatureInput,
  context: TriageAnalysisContext,
): Promise<Omit<InspectCodeSignatureReport, "artifact">> => {
  checkTriageCancelled(context.signal);
  const loaded = loadTriageImage(bytes, input.slice);
  const image = loaded.image;
  const limitations: string[] = [];
  const collector = { push: (message: string) => limitations.push(message) };

  if (image === null) {
    limitations.push(
      `The file is not a recognized PE or Mach-O image (${loaded.failure.message}); embedded code signatures are a PE Authenticode / Mach-O concept and none was examined.`,
    );
    return finalize(null, { pe: null, macho: null }, false, limitations);
  }

  if (image.format === "pe") {
    await yieldTriage(context.signal);
    const pe = parsePeAuthenticode(bytes, image, collector);
    return finalize(
      { ...triageSubject(image) },
      { pe, macho: null },
      pe.signature_present,
      limitations,
    );
  }

  if (image.format === "macho") {
    await yieldTriage(context.signal);
    const macho = parseMachoCodeSignature(bytes, image, collector);
    return finalize(
      { ...triageSubject(image) },
      { pe: null, macho },
      macho !== null,
      limitations,
    );
  }

  limitations.push(
    "ELF images carry no standardized embedded code signature; no signature structure was examined.",
  );
  return finalize(
    { ...triageSubject(image) },
    { pe: null, macho: null },
    false,
    [...limitations],
  );
};

/** Assemble the report body with a consistent subject and shared caveats. */
const finalize = (
  subject: InspectCodeSignatureReport["subject"] | null,
  blocks: {
    pe: InspectCodeSignatureReport["pe"];
    macho: InspectCodeSignatureReport["macho"];
  },
  present: boolean,
  limitations: string[],
): Omit<InspectCodeSignatureReport, "artifact"> => ({
  subject: subject ?? { format: "file", architecture: null },
  present,
  pe: blocks.pe,
  macho: blocks.macho,
  limitations: [
    ...limitations,
    "Only signature structure is reported: certificate validity, revocation and OS trust policy are not checked, and no key material is extracted.",
  ],
});
