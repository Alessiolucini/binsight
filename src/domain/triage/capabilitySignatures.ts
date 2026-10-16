/**
 * REA-authored, versioned taxonomy mapping imported API names to coarse
 * capability classes. Entries describe what an import is *consistent with*;
 * they are inferences over observed imports, never a behavioral verdict. The
 * API lists are factual, well-documented platform symbols from public SDK
 * references (Win32, POSIX libc, macOS frameworks). No third-party rule text
 * is reproduced.
 */

/** Bump when rule ids, labels, or matched APIs change in a way callers observe. */
export const CAPABILITY_TAXONOMY_VERSION = "1";

/** One capability class and the exact API basenames consistent with it. */
export interface CapabilityRule {
  readonly id: string;
  readonly label: string;
  /** Exact imported symbol basenames (lowercased, Win32 A/W suffix stripped). */
  readonly apis: readonly string[];
}

/** API basenames whose presence indicates dynamic symbol resolution at runtime. */
export const DYNAMIC_RESOLUTION_APIS: readonly string[] = [
  "getprocaddress",
  "ldrgetprocedureaddress",
  "dlopen",
  "dlsym",
  "loadlibrary",
  "loadlibraryex",
];

/** Curated capability rules; matched case-insensitively against import basenames. */
export const CAPABILITY_RULES: readonly CapabilityRule[] = [
  {
    id: "process:create",
    label: "process creation consistent with imports",
    apis: [
      "createprocess",
      "createprocessasuser",
      "shellexecute",
      "shellexecuteex",
      "winexec",
      "fork",
      "posix_spawn",
      "execve",
      "execvp",
      "system",
    ],
  },
  {
    id: "process:inject",
    label: "process injection consistent with imports",
    apis: [
      "writeprocessmemory",
      "createremotethread",
      "createremotethreadex",
      "ntcreatethreadex",
      "queueuserapc",
      "setthreadcontext",
      "virtualallocex",
      "virtualprotectex",
      "mach_vm_write",
      "task_for_pid",
      "ptrace",
    ],
  },
  {
    id: "memory:executable",
    label: "executable memory allocation consistent with imports",
    apis: [
      "virtualalloc",
      "virtualprotect",
      "ntprotectvirtualmemory",
      "mprotect",
      "mmap",
    ],
  },
  {
    id: "net:socket",
    label: "raw socket networking consistent with imports",
    apis: [
      "socket",
      "connect",
      "send",
      "recv",
      "wsastartup",
      "wsasocket",
      "wsaconnect",
      "bind",
      "listen",
      "accept",
    ],
  },
  {
    id: "net:http",
    label: "HTTP client networking consistent with imports",
    apis: [
      "internetopen",
      "internetopenurl",
      "internetconnect",
      "httpopenrequest",
      "httpsendrequest",
      "winhttpopen",
      "winhttpconnect",
      "winhttpsendrequest",
      "urldownloadtofile",
      "curl_easy_init",
      "curl_easy_perform",
    ],
  },
  {
    id: "net:dns",
    label: "DNS resolution consistent with imports",
    apis: ["getaddrinfo", "gethostbyname", "dnsquery", "res_query", "res_init"],
  },
  {
    id: "crypto:api",
    label: "cryptographic API use consistent with imports",
    apis: [
      "cryptacquirecontext",
      "cryptencrypt",
      "cryptdecrypt",
      "cryptgenkey",
      "bcryptencrypt",
      "bcryptdecrypt",
      "bcryptgeneratesymmetrickey",
      "cccrypt",
      "ccryptorcreate",
      "evp_encryptinit_ex",
      "evp_decryptinit_ex",
      "aes_set_encrypt_key",
    ],
  },
  {
    id: "fs:write",
    label: "filesystem writes consistent with imports",
    apis: [
      "writefile",
      "createfile",
      "movefile",
      "copyfile",
      "deletefile",
      "fopen",
      "fwrite",
      "open",
      "unlink",
      "rename",
    ],
  },
  {
    id: "registry:access",
    label: "Windows registry access consistent with imports",
    apis: [
      "regopenkeyex",
      "regcreatekeyex",
      "regsetvalueex",
      "regqueryvalueex",
      "regdeletekey",
      "regdeletevalue",
    ],
  },
  {
    id: "persistence:service",
    label: "service installation consistent with imports",
    apis: [
      "createservice",
      "openscmanager",
      "startservice",
      "changeserviceconfig2",
    ],
  },
  {
    id: "anti-analysis:debugger-check",
    label: "debugger detection consistent with imports",
    apis: [
      "isdebuggerpresent",
      "checkremotedebuggerpresent",
      "ntqueryinformationprocess",
      "outputdebugstring",
    ],
  },
  {
    id: "privilege:token",
    label: "privilege/token manipulation consistent with imports",
    apis: [
      "adjusttokenprivileges",
      "openprocesstoken",
      "lookupprivilegevalue",
      "setuid",
      "seteuid",
      "setgid",
    ],
  },
  {
    id: "input:hook",
    label: "input hooking consistent with imports",
    apis: [
      "setwindowshookex",
      "getasynckeystate",
      "getkeystate",
      "registerrawinputdevices",
    ],
  },
  {
    id: "screen:capture",
    label: "screen capture consistent with imports",
    apis: ["bitblt", "getdc", "createcompatiblebitmap", "cgdisplaycreateimage"],
  },
];
