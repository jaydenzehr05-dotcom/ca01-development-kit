# Running REA and Ghidra in the CA01 workspace

All commands below are local and read-only with respect to the vehicle.
They assume the original firmware and vendor source archives have been
obtained legally and kept outside Git.

## Toolchain installed in WSL

Workspace: `/home/starlight/projects/rav4-radio/`.

- REA source checkout: `rea-reference`, version 6.7.0, pinned initially at
  commit `0281d10`. Dependencies installed and CLI built.
- Node.js 24.18.0: `tools/node-v24.18.0-linux-x64/`.
- Ghidra 12.1.4: `tools/ghidra_12.1.4_PUBLIC/`.
- Temurin JDK 21.0.13: `tools/jdk-21.0.13+9/`.
- Zig 0.13.0: isolated `.venv` under the development kit.
- Unblob 26.6.4: same isolated Python environment.

Ghidra/JDK release archives were SHA-256 verified before extraction.
The checked-out REA requires **Ghidra 12.1.x**, not 12.2.

## REA command wrapper

Use `tools/rea_ca01.sh` from this Git repository. It sets the workspace
paths for Ghidra, Java and Node, without changing Windows or global WSL
defaults. For example:

```sh
tools/rea_ca01.sh doctor --provider ghidra --format json
tools/rea_ca01.sh analyze build/ca01-hw-probe-arm --provider ghidra --format json
tools/rea_ca01.sh decompile build/ca01-hw-probe-arm 0x203ec --provider ghidra --format json
```

The provider-specific REA doctor returned `healthy=true`, and both native
analysis and Ghidra decompilation of the **valid ARM ELF** succeeded.
REA's broader environment health can still report missing optional providers,
which does not invalidate the explicitly healthy Ghidra provider.

REA does not automatically decode proprietary CA01 KWI update sections.
REA+Unblob extracted no recognizable standard nested files from the
substantial `1127` components. A raw boot component is not a normal ELF,
so use the explicit Ghidra survey rather than assuming a valid entry point.

## Ghidra raw boot survey

```sh
tools/ghidra/run_boot_ghidra.sh
```

This imports the boot component as raw ARM with an **assumed** base/address
mapping, prints string locations and heuristic function counts, and discards
the temporary project. It doesn't execute the firmware, install firmware or
verify boot acceptance. Results:
`../system-audit/ghidra-boot-survey.txt` or
`evidence/ghidra-boot-survey.txt`.

## Hardware probe build, testing and evidence

```sh
ZIG=/absolute/path/to/zig sh build_hw_probe.sh
.venv/bin/python -m unittest discover -s tests -p 'test_*.py' -v
python3 tools/ca01_source_contracts.py \
  --archive /path/to/OSS_SOFT_PACK.tgz \
  --output /path/to/vendor-driver-contracts.json
```

The mock test suite validates input handling and restricts syscalls. It
does not prove safety on the actual radio. In particular, a read-only
`/proc/asic` access could have hardware register side effects in an
unverified device configuration. **The default build disables those reads.**
Review the handlers before enabling them in a bench environment.

## What is *not* installed / working yet

- A CA01 production kernel configuration, original proprietary middleware,
  verified userspace services, or complete installed root filesystem.
- A validated factory-radio driver/device map.
- A proved bootloader signing acceptance or hardware recovery method.
- A stock-radio boot or full hardware emulation.
- A safe installer for use in the vehicle.

Keep the original firmware, vendor archives, large toolchain and any future
storage dumps **out of this Git repository**.
