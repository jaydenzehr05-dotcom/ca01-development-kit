from pathlib import Path
repo=Path('/home/starlight/projects/rav4-radio/ca01-development-kit')
p=repo/'README.md';s=p.read_text().replace('# CA01 development kit — first milestone','# CA01 development kit — firmware research and local ARM emulation',1)
s=s.replace('This kit provides a working firmware inspector and a compiled, read-only ARM\nLinux probe. It is an initial development deliverable, not a Google Maps app or\nan installable Toyota update. Launching our own executable on the physical radio\nis the next unresolved dependency.', '''This repository consolidates the firmware inspector, verified partial recovery,
updater/security research, dependency tools, and isolated ARM emulation work.
The original source archives, original firmware, proprietary recovered bytes,
Linux root filesystems and rendered images remain outside Git.

## Current verified local capabilities

- **59 complete recovered files**, including **41 ARM ELF files**: 21 executables
  and 20 shared libraries. Every original recovered size/hash was rechecked.
  Additional Kernel/Audio/Driver/Voice fragments retain explicit partial status.
- Recovered original `PROC_REPRO`, BIOS files and updater call graphs establish
  64,000-byte AES-prefix processing and SHA-256/RSA-PSS interfaces. `libsecurity.so`,
  exact key/mode provisioning and successful authentication remain unresolved.
- Debian ARMEL and ARMhf QEMU environments work locally. ARMEL is the relevant
  soft-float baseline for the recovered binaries; this is not a booted CA01 OS.
- Bubblewrap dependency tracing is offline, read-only, and restricted to approved
  dynamic ARMEL targets. Standard-interpreter validation rejects static/custom
  loader targets before QEMU. Constructor/main guards confirm trace-only behavior.
- Fresh loader traces: **PROC_HMI 17**, **PROC_DISPLAY 47**, **PROC_REPRO 18**
  unresolved library names. These runtime observations differ from the recovery-only
  inventory (89 missing names across all 41 files).
- A self-authored ARM EGL/GLES software test renders **800 × 480**; all
  **384,000 pixels** match the expected pattern. The stock Toyota GUI has not run.
- The combined automated suite passes **71 tests**. No radio access or flashing.

Start with [consolidation verification](docs/CA01_LOCAL_CONSOLIDATION.md),
[recovered dependencies](docs/CA01_DEPENDENCY_INVENTORY.md),
[loader/graphics setup](docs/CA01_ARM_LOADER_AND_GRAPHICS.md), and
[security interfaces](docs/CA01_SECURITY_INTERFACES.md).

The small self-authored probes in `build/` are retained intentional Unicorn
fixtures with their C sources/build scripts. `dist/CA01-development-kit.zip` is
an unchanged **historical first-milestone package**, not this consolidated checkout.
Older test counts below describe those historical milestones.''')
a=s.index('## Next development milestone');b=s.index('## Original source archive downloads',a)
s=s[:a]+'''## Next development priorities

1. Obtain a legitimate additional firmware/rootfs source that contains missing
   vendor libraries, especially `libsecurity.so` and core `libipas_*` services.
2. Map the legacy OpenVG/GLES1 and Fujitsu Ten display/IPC interfaces against
   the working self-authored software-renderer baseline.
3. Keep original applications in loader-trace mode until dependencies, ABI and
   hardware-service isolation are established. No complete CA01 boot, stock GUI,
   signature acceptance or physical-radio recovery has been demonstrated.

'''+s[b:]
p.write_text(s)
# Keep earlier milestones as evidence, with an unmistakable current pointer.
for name in ['CA01_ARM_LINUX_PHASE1.md','CA01_ARM_LINUX_PHASE2.md','CA01_GUI_EMULATION_READINESS.md']:
 p=repo/'docs'/name;s=p.read_text();head,tail=s.split('\n',1)
 s=head+'\n\n> Historical milestone. The current integrated results are in\n> [local consolidation](CA01_LOCAL_CONSOLIDATION.md) and\n> [loader/graphics verification](CA01_ARM_LOADER_AND_GRAPHICS.md).\n'+tail
 if name=='CA01_ARM_LINUX_PHASE2.md':
  s=s.replace('/tmp/ca01-middleware-research/recovered','../system-audit/ca01-updater-independent-20261022')
  s=s.replace('--output ../system-audit/gui-emulation/compatibility.json','--output ../system-audit/gui-emulation/NEW-compatibility.json')
 if name=='CA01_GUI_EMULATION_READINESS.md':
  s=s.replace('from 61 current recovered-directory files (some duplicates/other file types).','from the historical directory scan. The canonical manifest now records exactly 59 complete recovered files; other directory entries are metadata, not additional recovered files.')
 p.write_text(s)
p=repo/'docs/CA01_ARM_LOADER_AND_GRAPHICS.md';s=p.read_text().replace('The complete main-checkout test suite passed: **38 tests**, including 14 new sandbox/staging/parser tests.','The initial main-checkout suite passed 38 tests. After integration with the research suite and four interpreter-validation regressions, the combined suite passes **71 tests** (18 sandbox tests).')
s=s.replace('It only supports loader-trace mode for the three named targets.','It only supports loader-trace mode for the three named targets. Every executable and approved target must declare exactly `/lib/ld-linux.so.3` in a bounded, validated PT_INTERP record; static/custom-loader targets are rejected before any staging or execution.')
s=s.replace('All changes from this pass remain local and uncommitted; no Git push or physical-radio access occurred.','Both efforts are integrated into local main; see [consolidation verification](CA01_LOCAL_CONSOLIDATION.md). No Git push or physical-radio access occurred.')
p.write_text(s)
p=repo/'SYSTEM_INVENTORY.md';s=p.read_text();n='## What is available';s=s.replace(n,'''## Current recovered/runtime inventory

The integrated collection has 59 complete recovered files (21 ARM executables,
20 ARM shared libraries and 18 other files). See the hash-verified
[dependency inventory](docs/CA01_DEPENDENCY_INVENTORY.md) and
[local consolidation](docs/CA01_LOCAL_CONSOLIDATION.md). The recovery-only set
is missing 89 requested library names; the installed ARMEL environment supplies
some system dependencies. Fresh isolated traces leave HMI 17, Display 47 and
Repro 18 unresolved names. No complete radio or stock GUI boot is established.

'''+n)
p.write_text(s)
p=repo/'docs/CA01_MISSING_EXECUTABLES_AUDIT.md';s=p.read_text();h,t=s.split('\n',1)
s=h+'\n\n> Initial source-manifest audit, retained for provenance. Later recovery found\n> both BIOS files and the original updater; see [current recovery status](CA01_MISSING_EXECUTABLES.md).\n> The middleware pathname records are now confirmed removal entries, not recovered executables.\n'+t
s=s.replace('likely deployment target, executable type NOT independently checked','removal entry processed by PROC_REPRO before archive replacement; executable itself not recovered')
p.write_text(s)
p=repo/'docs/CA01_FORMAT_IDENTIFICATION.md';s=p.read_text();h,t=s.split('\n',1)
s=h+'\n\n> Historical raw-component signature scan. Later validated suffix decoding recovered\n> 59 complete files and PROC_REPRO analysis confirmed AES-prefix handling.\n> See [current format research](CA01_UPDATE_FORMAT_RESEARCH.md).\n'+t
s=s.replace('Bottom line: no proprietary middleware executables were recovered. High-entropy payloads remain unidentified; no evidence sufficient to name compression/encryption algorithm.','At this initial raw scan no proprietary middleware executables had been recovered and the transform was unidentified. That limitation was later narrowed by validated DEFLATE suffix recovery and the original updater’s AES calls; encrypted-prefix parameters remain unresolved.')
p.write_text(s)
p=repo/'.gitignore';s=p.read_text();s+='''
# Keep vendor firmware, recovered libraries, runtimes and generated images local.
*.kwi
*.tgz
*.tar.gz
*.tar.xz
*.so
*.so.*
*.ppm
*.png
*rootfs/
recovered/
system-audit/
''';p.write_text(s)
