import { observeMzWindowsHeader } from "../../dosMz.js";
import { readFatContainerHeader } from "../../apple/machoContainer.js";
import { err, type Result } from "../../result.js";
import type {
  ExecutableImage,
  ImageParseFailure,
  ImageParseOptions,
} from "./executableImage.js";
import { parseElfImage } from "./elfImage.js";
import { parseMachoImage } from "./machoImage.js";
import { parsePeImage } from "./peImage.js";

/** Executable container family recognized from leading bytes alone. */
export type ExecutableFormatGuess =
  | { readonly format: "elf" }
  | { readonly format: "pe"; readonly pe_offset: number }
  | { readonly format: "macho" }
  | { readonly format: "macho-fat" }
  | { readonly format: null };

const MACHO_MAGICS: readonly number[] = [
  0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe,
];

/** Classify by magic numbers; structural validity is decided by the format parser. */
export const detectExecutableFormat = (
  bytes: Buffer,
): ExecutableFormatGuess => {
  if (bytes.length >= 4 && bytes.readUInt32BE(0) === 0x7f454c46)
    return { format: "elf" };
  if (bytes.length >= 4 && MACHO_MAGICS.includes(bytes.readUInt32BE(0)))
    return { format: "macho" };
  const fat = readFatContainerHeader(bytes, bytes.length);
  if (fat.state === "parsed" || fat.state === "malformed")
    return { format: "macho-fat" };
  if (bytes.length >= 2 && bytes.readUInt16LE(0) === 0x5a4d) {
    const observed = observeMzWindowsHeader(bytes);
    if (observed.state === "declared" && observed.signature === "PE")
      return { format: "pe", pe_offset: observed.offset };
  }
  return { format: null };
};

/**
 * Parse one ELF, PE/COFF or Mach-O image (selecting one slice of a universal
 * binary) into the shared format-neutral model.
 */
export const parseExecutableImage = (
  bytes: Buffer,
  options: ImageParseOptions = {},
): Result<ExecutableImage, ImageParseFailure> => {
  const guess = detectExecutableFormat(bytes);
  switch (guess.format) {
    case "elf":
      return parseElfImage(bytes);
    case "pe":
      return parsePeImage(bytes, guess.pe_offset);
    case "macho":
    case "macho-fat":
      return parseMachoImage(bytes, options);
    case null:
      return err({
        kind: "unsupported",
        message:
          "The file is not an ELF, PE/COFF or Mach-O executable image recognized by its header.",
      });
  }
};
