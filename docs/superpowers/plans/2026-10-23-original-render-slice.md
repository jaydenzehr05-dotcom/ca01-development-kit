# CA01 original ARM rendering implementation plan

Goal: execute hash-verified original HMI graphics instructions against real ARMEL Mesa, integrate the measured descriptor/token and callback lifecycle, and capture independently validated pixels. This is a bounded rendering slice, not full PROC_HMI startup or factory menus.

Architecture: keep existing startup fail-closed at ipasz.conf. Extend the existing display model with one authoritative descriptor and window validator. A self-authored ARMEL fixture linked at0x10000000 maps the verified original ELF into private memory, binds known imports to real Mesa or explicitly logged display-service models, and calls a fixed whitelist of original functions. All other imports fail loudly. Run only inside offline Bubblewrap/QEMU with a read-only firmware input. Source files remain unchanged; only private process relocation/import slots are bound.

Steps:
- Add failing tests for descriptor layout, distinct token/handle mapping, invalid/duplicate/zero handles, allocation/cleanup and pending presentation.
- Extend src/ca01_gui_compat.* and reuse validation in both EGL boundaries; preserve the canonical IPC queue.
- Implement a bounded native original-render fixture plus a hash-gated Python launcher. Assert original GL initialization, original rectangle geometry, clear/draw calls and frame submission reach actual ARMEL Mesa. Fail on unknown imports or invalid buffer tokens.
- Test both original resolutions, negative allocation/callback paths, lifecycle cleanup and exact pixel expectations. Record which input state is fixture supplied.
- Trace the next full scene/startup blocker, inspect original resource loaders for concrete filenames/formats, and pursue feasible authentic recovery without invented files.
- Run the complete regressions and existing graphics audit, preserve execution evidence, request an independent review and leave changes local unless a new push is authorized.

Constraints: no vehicle access, firmware modification, security-validation changes, fabricated services, or synthetic-menu claims. No new remote push is authorized by this handoff. No additional generic renderer: new pixels must include original HMI geometry/GL-call instructions.

Ruling: use a fixed high executable base, because QEMU placed its default PIE at0x400000 inside the original HMI mapping. MAP_FIXED_NOREPLACE now rejects collisions; no mapping is overwritten.
