import type {
  ElfDetails,
  MachoDetails,
  PeDetails,
} from "../domain/native/image/executableImage.js";
import type {
  InspectExecutableElf,
  InspectExecutableMacho,
  InspectExecutablePe,
} from "../domain/triage/inspectExecutable.js";
import { toHexAddress } from "../domain/triage/triageCommon.js";

/** Project the parsed ELF facts into the compact report block. */
export const elfDetailBlock = (details: ElfDetails): InspectExecutableElf => {
  const dynamic = details.dynamic;
  return {
    elf_class: details.elf_class,
    os_abi: details.os_abi,
    e_type: details.e_type,
    machine: details.machine,
    e_flags: details.e_flags,
    interpreter: details.interpreter,
    soname: dynamic?.soname ?? null,
    rpath: dynamic === null ? [] : [...dynamic.rpath],
    runpath: dynamic === null ? [] : [...dynamic.runpath],
    bind_now: dynamic?.bind_now ?? false,
    text_relocations: dynamic?.text_relocations ?? false,
    gnu_stack: {
      present: details.gnu_stack.present,
      executable: details.gnu_stack.executable,
    },
    gnu_relro: details.gnu_relro !== null,
    build_id: details.build_id,
    x86_feature_1: details.x86_feature_1,
    aarch64_feature_1: details.aarch64_feature_1,
    has_symtab: details.has_symtab,
    has_debug_info: details.has_debug_info,
    gnu_debuglink: details.gnu_debuglink,
    comment: [...details.comment],
  };
};

/** Project the parsed PE facts into the compact report block. */
export const peDetailBlock = (
  details: PeDetails,
  maxList: number,
): InspectExecutablePe => ({
  pe32_plus: details.pe32_plus,
  machine: details.machine,
  time_date_stamp: details.time_date_stamp,
  characteristics: details.characteristics,
  subsystem: details.subsystem,
  dll_characteristics: details.dll_characteristics,
  image_base: toHexAddress(details.image_base),
  size_of_image: details.size_of_image,
  size_of_headers: details.size_of_headers,
  checksum: details.checksum,
  computed_checksum: details.computed_checksum,
  linker_version: details.linker_version,
  os_version: details.os_version,
  subsystem_version: details.subsystem_version,
  data_directories: details.data_directories
    .filter((directory) => directory.rva > 0 || directory.size > 0)
    .map((directory) => ({
      index: directory.index,
      name: directory.name,
      rva: directory.rva,
      size: directory.size,
    })),
  rich_header:
    details.rich_header === null
      ? null
      : {
          file_offset: details.rich_header.offset,
          xor_key: details.rich_header.xor_key,
          checksum_valid: details.rich_header.checksum_valid,
          entry_count: details.rich_header.entries.length,
          entries: details.rich_header.entries
            .slice(0, maxList)
            .map((entry) => ({
              product_id: entry.product_id,
              build: entry.build,
              count: entry.count,
            })),
        },
  codeview:
    details.codeview === null
      ? null
      : {
          signature: details.codeview.signature,
          identifier: details.codeview.identifier,
          age: details.codeview.age,
          pdb_path: details.codeview.pdb_path,
        },
  load_config:
    details.load_config === null
      ? null
      : {
          size: details.load_config.size,
          security_cookie:
            details.load_config.security_cookie === null
              ? null
              : toHexAddress(details.load_config.security_cookie),
          guard_flags: details.load_config.guard_flags,
        },
  tls_callback_count:
    details.tls_callbacks === null ? null : details.tls_callbacks.length,
  debug_types: [...details.debug_types],
  ex_dll_characteristics: details.ex_dll_characteristics,
  managed: details.managed,
  base_relocations: details.base_relocations,
  resources: details.resources,
  security_directory:
    details.security_directory === null
      ? null
      : {
          file_offset: details.security_directory.file_offset,
          size: details.security_directory.size,
        },
});

/** Project the parsed Mach-O facts into the compact report block. */
export const machoDetailBlock = (
  details: MachoDetails,
): InspectExecutableMacho => ({
  cpu_type: details.cpu_type,
  cpu_subtype: details.cpu_subtype,
  file_type: details.file_type,
  flags: details.flags,
  uuid: details.uuid,
  id_dylib: details.id_dylib,
  source_version: details.source_version,
  rpaths: [...details.rpaths],
  build_versions: details.build_versions.map((version) => ({
    platform: version.platform,
    minimum_os: version.minimum_os,
    sdk: version.sdk,
  })),
  encryption:
    details.encryption === null
      ? null
      : {
          crypt_offset: details.encryption.crypt_offset,
          crypt_size: details.encryption.crypt_size,
          crypt_id: details.encryption.crypt_id,
        },
  code_signature:
    details.code_signature === null
      ? null
      : {
          file_offset: details.code_signature.file_offset,
          size: details.code_signature.size,
        },
  has_restrict_segment: details.has_restrict_segment,
  uses_chained_fixups: details.uses_chained_fixups,
  load_command_count: details.load_commands.length,
});
