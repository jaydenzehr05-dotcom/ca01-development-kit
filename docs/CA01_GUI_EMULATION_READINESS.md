# CA01 GUI emulation feasibility (recovered firmware audit)

> Historical milestone. The current integrated results are in
> [local consolidation](CA01_LOCAL_CONSOLIDATION.md) and
> [loader/graphics verification](CA01_ARM_LOADER_AND_GRAPHICS.md).

The recovered ARM executables are not sufficient to emulate a complete head unit today.

The `tools/ca01_gui_dependency_audit.py` script inventories DT_NEEDED libraries with readelf. The local machine-readable report is stored **outside Git** under `../system-audit/gui-emulation/dependencies.json`; it enumerates all 41 recovered ELF binaries from the historical directory scan. The canonical manifest now records exactly 59 complete recovered files; other directory entries are metadata, not additional recovered files.

| Executable | Declared shared libraries | Found within recovered-folder inventory | Not in recovered folder |
|---|---:|---:|---:|
| `PROC_HMI` | 31 | 7 | 24 |
| `PROC_DISPLAY` | 69 | 14 | 55 |
| `PROC_REPRO` | 30 | 6 | 24 |

Across all recovered ELFs, 109 distinct libraries are required and 89 do not have a same-basename file in the scanned recovered directory. **This is not the number of permanently missing proprietary files.** The inventory includes ordinary system libraries (libc, libm, etc.) obtainable from a compatible ARM Linux rootfs, and could omit differently named or externally stored existing libraries. It does not assess recursive transitive loading or runtime `dlopen`.

Critical GUI libraries missing from the scanned recovery set include `libEGL.so`, `libGLES_CM.so`, `libOpenVG.so`, along with numerous Fujitsu Ten `libipas_*` libraries. The original programs may require proprietary GLES/OpenVG GPU drivers, display controller integration, peripheral services, IPC, CAN bus messages, touchscreen events and fixed filesystem layouts.

**Current status:** We can analyze ELF code and perform limited synthetic ARM emulation; we have not booted an original CA01 Linux filesystem or rendered the production GUI. Software rendering and ABI stubs may enable an eventual demonstration of some screens, but would be a partial simulation rather than proof of full radio operation.

**Next realistic milestones:** (1) merge Codex's isolated recovered-file metadata/tools without affecting its branch; (2) construct a compatible ARM EABI rootfs in a throwaway sandbox and inventory basic runtime libraries; (3) resolve missing proprietary libraries or implement narrowly scoped stubs; (4) use QEMU user mode for nonhardware code where dependencies permit, reserving QEMU-system/Unicorn peripheral models for later. Never run vendor binaries on the host directly or connect real radio hardware.

No firmware was modified or flashed.

## Related-source integration

The newer source modules are Bluetooth/IPC references, not demonstrated replacements for missing Toyota OpenVG/GLES/display libraries. The working software diagnostic remains the graphics baseline. See [related source verification](CA01_RELATED_FIRMWARE_AND_SOURCES.md).
