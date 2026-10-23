# CA01 updater investigation plan

User specification: /mnt/c/Users/fathe/.codex/attachments/0c7d7287-dec0-45d0-8d7e-ab718f5b87c8/Pasted text.txt

Scope: read-only independent research of CA01_1127 component decoding and installation; prioritize actual middleware executable recovery. No hardware, flashing, signing bypass, main-tree writes or remote pushes. Isolated research/ca01-firmware-updater based on0b242fc. Other session's boot emulator and untracked files remain outside this worktree.

- [x] Baseline structure, metadata and19automatedtests verified.
- [x] Source archaeology with exact paths/lines and confidence-labeled source call graph.
- [x] Independent binary/compression/leading-transform investigation; recover bytes only with validated decoder.
- [x] Public primary-source/tool comparison; no private uploads.
- [x] Test-first reproducible inspector: exact offsets/raw header fields, hashes, windows, fixed pathname observations, bounded stream checks and evidence. Separate observations from unknown semantics.
- [x] Integrate three requested reports and machine-readable evidence; rerun all tests and check original hashes unchanged; local research commit only.

Tool design: extend existing narrow CA01 structural inspector without editing it. Read input bytes only; JSON goes to stdout or exclusively created report path; no extraction/install/firmware rewriting. Codec probes use bounded output and require decoder EOF, not just magic bytes. Never label signature-sized blobs as verified signatures or arbitrary disassembly as real functions.

Results: actual PROC_REPRO recovered;59 complete files/41ARM ELFs; missing rma1_hwreg/vigilancer andlibsecurity.so prevent full decoder/target recovery. Research tools verified with40tests before incorporating the other session's already-published five boot-emulation tests. Review correction: preserve DEFLATE stored-block alignment. Main publication e30031d was explicitly authorized during research and succeeded; new research is committed locally only.
