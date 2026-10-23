# Related Toyota firmware and DENSO TEN sources

This integrates the supplied `../related-firmware/` investigation into the existing CA01 work. Large downloads, selected source trees, PDFs and captured sites remain there, outside Git. `evidence/ca01-related-source-integration.json` records original URLs, local paths, sizes, hashes, nested package identities, all 63 selected-source file hashes, line-level contracts and verification corrections. The imported report is retained unchanged as an original research artifact.

## Independently checked facts

All five entries in `DOWNLOAD_MANIFEST.json` match their actual sizes and SHA-256 values. The **230,096,727-byte** official DENSO TEN archive has SHA-256 `d6d4a2cfae85b86209c4ae61d399238e6db63282c2f50df04aeb8378f96ebe5c`; all **95 ZIP entries** pass CRC checks. Its four selected middleware packages contain **63 regular files**, each independently compared byte-for-byte with `selected-source/`.

The version-defining file is `linux-kernel-3.10.101-ltsi_3.10+svnr836-r0/Makefile`, whose VERSION/PATCHLEVEL/SUBLEVEL/EXTRAVERSION fields establish **3.10.101-ltsi**. This is distinct from the earlier source tree's **2.6.35.7**. The archive also contains an `eglibc_2.19-r0.tar.xz` package. Package identity or kernel-generation differences do not establish the installed CA01 kernel, userspace ABI, board configuration or binary compatibility.

The supplied `hardware-source-comparison.json` accidentally captured `net/Makefile` as `new_kernel_makefile`. Its stated kernel version is correct, but that excerpt was not proof; the actual root Makefile and hash are now recorded. The report's `libmmap_hw.so` is **not** an established missing dependency in our 89-name recovered-set inventory. Its generic candidate grouping is not evidence that the archive supplies compatible EGL/GLES or security libraries. Keyword matches such as `CAN` are not a recovered CAN message contract.

## Useful source contracts, with limits

Paths below are relative to `../related-firmware/selected-source/`.

| Module | Verified interface | CA01/QEMU implication |
|---|---|---|
| `Evoproxy_1.6.18` | `ep_main.c:32-40`: queues `/toevoproxy` and `/fromevoproxy`; session-bus `org.alps.evolution`, object `/org/alps/evolution/hli`, interface `org.alps.evolution.hli`, method `SendMessage`, signal `IncomingMessage` | Concrete IPC reference for a future isolated, self-authored fixture. No match to an original CA01 service has been established. |
| `evo_hli_rca13` | `include/BT-CMD.xml:1-28`: matching D-Bus object/interface, `av` message schema and Bluetooth status request/confirmation | Useful Bluetooth schema; not the original Toyota GUI or proof of compatible IPC. |
| `evo_socket_adapter_rca13` | `include/alps_socket_layer_common.h:41`: `/var/tmp/alps_sock_serv`; client code uses `AF_UNIX`/`SOCK_STREAM` | An isolated mock could implement this endpoint once a genuine CA01 caller is matched. No socket adapter was run. |
| `evo_bvd_rca13` | `include/bvd_if_dev.h:29-33`: magic `'B'`, commands70/71/72; control device `bvd_if_cdev`; TTY commands73/74 | Kernel virtual-device expectations, not ordinary QEMU user-mode device support. No host driver was loaded. |

These are source-level Bluetooth/ALPS interface references. A lexical comparison of function-definition candidates against 1,144 currently unresolved strong/weak import names found no matching providers in the four modules. This is not a compiled export audit and does not exclude useful adaptation later. Generic POSIX calls are consumers of standard runtime APIs, not replacement implementations.

**No new complete firmware executable or verified missing-library provider was obtained.** The recovered inventory remains 59 files, including21 ARM executables and20 shared libraries. Fresh trace counts remain HMI17, Display47, Repro18 unresolved names. `libsecurity.so`, core vendor IPC/display services, `libGLES_CM.so` and `libOpenVG.so` remain blockers. The newer package is not installed into either working QEMU rootfs.

## Documented version families

The four downloaded PDFs were converted to text and their filename tables inspected. URLs and complete PDF hashes are in the integration evidence.

| Bulletin snapshot | Base Entune Audio | Other documented variants |
|---|---|---|
| 2017 | `15TBDANA-CA01_1117.kwi` | CA01 Plus/Premium2204 |
| 2018 | `15TBDANA-CA01_1127.kwi` | CA01 Plus/Premium2215 (see original table for exact model mapping) |
| 2019 revision | `15TBDANA-CA01_1134.kwi` | `15TDDANA`2246/3246 and `15TDANNA`2244/3244 |
| 2020 | `15TBDANA-CA01_1134.kwi` | `15TDDANA`2247/3247 and `15TDANNA`2247/3247 |

These are bulletin references, not downloaded firmware comparisons. Only the original base1127 KWI is present and analyzed. Do not treat Plus/Premium, CA01/CA02 or regional variants as interchangeable. No component delta, shared-library identity, new image signature or runtime compatibility has been measured without those bytes.

## Regional research provenance

The imported report covers USA, Canada, Japan, UK/Europe, China, DENSO and DENSO TEN. USA/Canada capture files and lookup diagnostics are retained in `site-inspection/`; other regional leads are report observations, not independently verified compatible downloads. Recorded 403 responses, sign-in redirects or form failures describe those acquisition attempts and do not prove global unavailability. TIS HTML/sign-in responses are not firmware despite a final HTTP200. No login state tokens or captured browser pages were copied into Git.

DENSO TEN's17-generation archive is an actual verified download. The separate NA/JP TCU URLs have only recorded HEAD status200 and were not downloaded or shown to match this head unit. DENSO corporate source-download failures and regional product names do not establish CA01 compatibility.

## Development order

1. Keep current 1127 originals, verified recoveries and working ARMEL renderer baseline unchanged.
2. Map selected source interfaces to actual recovered binary imports, constants and observed callers before attempting a service adaptation. Preserve the trace-only runner's standard-interpreter and isolation checks.
3. Obtain legitimate additional firmware/rootfs material containing missing libraries; compare container/component hashes, architecture, SONAMEs, symbols and versions offline.
4. Only after a proven interface match, build a separate mocked service/graphics experiment. No complete Toyota GUI, original kernel boot, radio hardware interaction or authentication success is implied by these source references.
