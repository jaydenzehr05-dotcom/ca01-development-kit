# CA01 decompiled binary outputs

These are Ghidra C-like reconstructions, not original source. Canonical firmware
remains unchanged. Functions/addresses/errors and code-body versus import-thunk
counts are in the manifests. No factory GUI startup is claimed.

## System runtime

- [decompiled.c](/home/starlight/projects/rav4-radio/system-audit/ca01-critical-decompilation-20261023/sysc1127-verified/decompiled.c)
- [functions.tsv](/home/starlight/projects/rav4-radio/system-audit/ca01-critical-decompilation-20261023/sysc1127-verified/functions.tsv)
- [manifest.json](/home/starlight/projects/rav4-radio/system-audit/ca01-critical-decompilation-20261023/sysc1127-verified/manifest.json)

## System supervisor

- [decompiled.c](/home/starlight/projects/rav4-radio/system-audit/ca01-critical-decompilation-20261023/system1127-verified/decompiled.c)
- [functions.tsv](/home/starlight/projects/rav4-radio/system-audit/ca01-critical-decompilation-20261023/system1127-verified/functions.tsv)
- [manifest.json](/home/starlight/projects/rav4-radio/system-audit/ca01-critical-decompilation-20261023/system1127-verified/manifest.json)

## Display broad pass

- [decompiled.c](/home/starlight/projects/rav4-radio/system-audit/ca01-critical-decompilation-20261023/display1134/decompiled.c)
- [functions.tsv](/home/starlight/projects/rav4-radio/system-audit/ca01-critical-decompilation-20261023/display1134/functions.tsv)
- [manifest.json](/home/starlight/projects/rav4-radio/system-audit/ca01-critical-decompilation-20261023/display1134/manifest.json)

## Display focused startup/file/queues

- [decompiled.c](/home/starlight/projects/rav4-radio/system-audit/ca01-critical-decompilation-20261023/display1134-focused/decompiled.c)
- [functions.tsv](/home/starlight/projects/rav4-radio/system-audit/ca01-critical-decompilation-20261023/display1134-focused/functions.tsv)
- [manifest.json](/home/starlight/projects/rav4-radio/system-audit/ca01-critical-decompilation-20261023/display1134-focused/manifest.json)

[Findings and remaining gaps](/home/starlight/projects/rav4-radio/ca01-development-kit/docs/CA01_CRITICAL_BINARY_DECOMPILATION.md)

The first sysc1127/system1127 exports are exploratory; use the -verified exports above. projects/ contains saved disposable Ghidra analysis databases.
