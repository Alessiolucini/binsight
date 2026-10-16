/**
 * Classic LC_SYMTAB nlist decoding into the shared import, export and symbol
 * models. Modern dyld binaries may carry only chained-fixup imports and an
 * export trie; this reader reports only what the nlist table declares and the
 * image parser marks the coverage accordingly.
 */

import { IMAGE_PARSE_LIMITS } from "./executableImage.js";
import type {
  ImageExport,
  ImageImport,
  ImageSection,
  ImageSymbol,
  ImageSymbolType,
} from "./executableImage.js";
import type { ImageReader } from "./imageReader.js";
import type { MachoSymtab } from "./machoImageCommands.js";

const N_STAB = 0xe0;
const N_TYPE = 0x0e;
const N_EXT = 0x01;
const N_UNDF = 0x0;
const N_ABS = 0x2;
const N_SECT = 0xe;
const N_WEAK_REF = 0x0040;
const N_WEAK_DEF = 0x0080;

export interface NlistTables {
  readonly imports: ImageImport[];
  readonly exports: ImageExport[];
  readonly symbols: ImageSymbol[];
  readonly importsTruncated: boolean;
  readonly exportsTruncated: boolean;
  readonly symbolsTruncated: boolean;
}

export interface NlistContext {
  readonly reader: ImageReader;
  readonly bits: 32 | 64;
  readonly symtab: MachoSymtab;
  readonly dylibNames: readonly string[];
  readonly sections: readonly ImageSection[];
}

/** One decoded nlist record. */
interface Nlist {
  readonly name: string;
  readonly type: number;
  readonly sect: number;
  readonly desc: number;
  readonly value: bigint;
}

const readNlist = (context: NlistContext, base: number): Nlist => {
  const { reader, bits, symtab } = context;
  const strx = reader.u32(base, "nlist n_strx");
  const type = reader.u8(base + 4, "nlist n_type");
  const sect = reader.u8(base + 5, "nlist n_sect");
  const desc = reader.u16(base + 6, "nlist n_desc");
  const value = reader.word(base + 8, bits, "nlist n_value");
  const name =
    strx === 0
      ? ""
      : (reader.cString(symtab.stroff + strx, IMAGE_PARSE_LIMITS.stringBytes) ??
        "");
  return { name, type, sect, desc, value };
};

const libraryFor = (context: NlistContext, desc: number): string | null => {
  const ordinal = (desc >> 8) & 0xff;
  return ordinal >= 1 && ordinal <= context.dylibNames.length
    ? (context.dylibNames[ordinal - 1] ?? null)
    : null;
};

const symbolTypeOf = (
  context: NlistContext,
  record: Nlist,
): ImageSymbolType => {
  if ((record.type & N_STAB) !== 0) return "other";
  const kind = record.type & N_TYPE;
  if (kind === N_ABS) return "object";
  if (kind !== N_SECT) return "other";
  const section = context.sections[record.sect - 1];
  return section !== undefined && section.executable ? "function" : "object";
};

const pushSymbol = (
  context: NlistContext,
  record: Nlist,
  symbols: ImageSymbol[],
): void => {
  const ext = (record.type & N_EXT) !== 0;
  const weak = (record.desc & (N_WEAK_REF | N_WEAK_DEF)) !== 0;
  symbols.push({
    name: record.name,
    value: record.value,
    size: 0n,
    type: symbolTypeOf(context, record),
    binding: ext ? (weak ? "weak" : "global") : "local",
    defined: (record.type & N_TYPE) !== N_UNDF,
    table: "nlist",
  });
};

/** Decode every nlist record into imports, exports and symbols, bounded. */
export const readNlistSymbols = (context: NlistContext): NlistTables => {
  const { symtab, bits } = context;
  const width = bits === 64 ? 16 : 12;
  const imports: ImageImport[] = [];
  const exports: ImageExport[] = [];
  const symbols: ImageSymbol[] = [];
  const tables: Mutable = {
    importsTruncated: false,
    exportsTruncated: false,
    symbolsTruncated: false,
  };
  for (let i = 0; i < symtab.nsyms; i++) {
    if (symbols.length >= IMAGE_PARSE_LIMITS.symbols) {
      tables.symbolsTruncated = true;
      break;
    }
    const record = readNlist(context, symtab.symoff + i * width);
    pushSymbol(context, record, symbols);
    const ext = (record.type & N_EXT) !== 0;
    const stab = (record.type & N_STAB) !== 0;
    if (!ext || stab) continue;
    if ((record.type & N_TYPE) === N_UNDF)
      classifyImport(context, record, imports, tables);
    else classifyExport(record, exports, tables);
  }
  return { imports, exports, symbols, ...tables };
};

interface Mutable {
  importsTruncated: boolean;
  exportsTruncated: boolean;
  symbolsTruncated: boolean;
}

const classifyImport = (
  context: NlistContext,
  record: Nlist,
  imports: ImageImport[],
  tables: Mutable,
): void => {
  if (imports.length >= IMAGE_PARSE_LIMITS.imports) {
    tables.importsTruncated = true;
    return;
  }
  imports.push({
    library: libraryFor(context, record.desc),
    name: record.name,
    ordinal: null,
    delay_loaded: false,
    weak: (record.desc & N_WEAK_REF) !== 0,
    version: null,
  });
};

const classifyExport = (
  record: Nlist,
  exports: ImageExport[],
  tables: Mutable,
): void => {
  if (exports.length >= IMAGE_PARSE_LIMITS.exports) {
    tables.exportsTruncated = true;
    return;
  }
  exports.push({
    name: record.name,
    ordinal: null,
    address: record.value,
    forwarder: null,
    kind: "function",
  });
};
