from pathlib import Path
import json,hashlib
repo=Path('/home/starlight/projects/rav4-radio/ca01-development-kit');root=repo.parent/'related-firmware';out=Path('/tmp/ca01-consolidation-20261022')
r=json.loads((out/'related-verification/verified-related.json').read_text())
for f in r['downloaded_files']:
 name=Path(f['local_path']).name
 f['source_url']=('https://www.denso-ten.com/support/source/oem/17/OSS_SOFT_PACK.zip' if name.endswith('.zip') else 'https://static.nhtsa.gov/odi/tsbs/2020/MC-10173804-9999.pdf' if name=='T-SB-0024-20.pdf' else json.loads((root/'bulletin-downloads.json').read_text())['bulletins'][name.removesuffix('.pdf')]['url'])
r['scope']='Independent offline validation of supplied related-firmware materials; no new firmware acquired, no selected middleware executed, no ABI compatibility inferred.'
r['source_materials']=[dict(path=str(p),size=p.stat().st_size,sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in sorted(root.rglob('*')) if p.is_file() and p.suffix in ('.json','.md','.html','.js','.txt') and 'selected-source' not in p.parts]
contracts=[('Evoproxy_1.6.18/Evoproxy_1.6.18/ep_main.c',32,40,'POSIX queues /toevoproxy and /fromevoproxy; org.alps.evolution session bus IPC'),('evo_hli_rca13/evo_hli/include/BT-CMD.xml',1,28,'D-Bus SendMessage and IncomingMessage av schema; Bluetooth request/confirmation'),('evo_socket_adapter_rca13/evo_socket_adapter/include/alps_socket_layer_common.h',41,41,'/var/tmp/alps_sock_serv'),('evo_socket_adapter_rca13/evo_socket_adapter/src/alps_socket_layer_client.c',127,177,'AF_UNIX SOCK_STREAM client'),('evo_bvd_rca13/evo_bvd/include/bvd_if_dev.h',29,33,'BVD ioctl magic B commands70-72'),('evo_bvd_rca13/evo_bvd/src/bvd_if_dev.c',480,481,'bvd_if_cdev control node'),('evo_bvd_rca13/evo_bvd/include/bvd_tty_dev.h',27,28,'GET_TIOCM73 SET_MODEM_STATUS74')]
r['source_contracts']=[]
for file,start,end,meaning in contracts:
 p=root/'selected-source'/file;data=p.read_bytes();lines=data.decode(errors='replace').splitlines()
 r['source_contracts'].append(dict(local_path=str(p),sha256=hashlib.sha256(data).hexdigest(),start_line=start,end_line=end,observation=meaning,excerpt='\n'.join(lines[start-1:end])))
r['accuracy_corrections']=[dict(field='hardware-source-comparison.json.new_kernel_makefile',finding='Contains net/Makefile, not the version-defining root Makefile. Actual root Makefile independently confirms3.10.101-ltsi.'),dict(field='RESEARCH_REPORT.md libmmap_hw.so',finding='Not in current89 missing library names or file dependency records; not an established CA01 requirement.'),dict(field='evo-inspection.json CAN matches',finding='Substring hits do not establish CAN protocol support; verified contracts in selected modules are Bluetooth IPC/virtual-device interfaces.'),dict(field='hardware-source-comparison.json missing_generic_candidates',finding='Name-based candidate grouping is not evidence the archive provides those SONAMEs or an ABI-compatible implementation.')]
r['integration_effect']=dict(new_complete_firmware_files=0,new_verified_missing_library_providers=0,recovered_files=59,arm_elfs=41,runtime_missing={'PROC_HMI':17,'PROC_DISPLAY':47,'PROC_REPRO':18})
(repo/'evidence/ca01-related-source-integration.json').write_text(json.dumps(r,indent=2)+'\n')
(repo/'docs/CA01_RELATED_FIRMWARE_AND_SOURCES.md').write_text('''# Related Toyota firmware and DENSO TEN sources

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
''')
for file,section in [
 ('docs/CA01_DEPENDENCY_INVENTORY.md','The newer DENSO TEN17-generation source archive adds verified Bluetooth IPC/device references but **zero verified providers** for the current missing library inventory. `libmmap_hw.so` is not an observed requirement. See [related firmware/source integration](CA01_RELATED_FIRMWARE_AND_SOURCES.md).'),
 ('docs/CA01_HARDWARE_INTERFACES.md','The newer source archive defines Evo Bluetooth POSIX-queue, D-Bus, Unix-socket and BVD control/TTY interfaces. These belong to selected newer source modules and have **not** been matched to the original CA01 binaries or board. See [line-level contracts and compatibility limits](CA01_RELATED_FIRMWARE_AND_SOURCES.md).'),
 ('docs/CA01_GUI_EMULATION_READINESS.md','The newer source modules are Bluetooth/IPC references, not demonstrated replacements for missing Toyota OpenVG/GLES/display libraries. The working software diagnostic remains the graphics baseline. See [related source verification](CA01_RELATED_FIRMWARE_AND_SOURCES.md).'),
 ('SYSTEM_INVENTORY.md','The verified DENSO TEN17 archive and63 selected source files are inventoried outside Git with hashes and original URLs. Linux3.10.101-ltsi and Evo Bluetooth interfaces are useful comparison sources, not a replacement CA01 rootfs or established ABI match. See [source recovery and related-firmware inventory](docs/CA01_RELATED_FIRMWARE_AND_SOURCES.md).')]:
 p=repo/file;p.write_text(p.read_text()+'\n## Related-source integration\n\n'+section+'\n')
p=repo/'README.md';s=p.read_text();needle='- [Security-library acquisition search and installed tooling](docs/CA01_LIBSECURITY_SEARCH.md)';assert needle in s;s=s.replace(needle,needle+'\n- [Related firmware versions, newer DENSO TEN sources and verified interfaces](docs/CA01_RELATED_FIRMWARE_AND_SOURCES.md)');p.write_text(s)
p=repo/'.gitignore';p.write_text(p.read_text()+'*.zip\nrelated-firmware/\n')
print('Integrated source provenance,63file index,verified interfaces,bulletin comparison and accuracy corrections. No vendor source/archive copied into Git.')
