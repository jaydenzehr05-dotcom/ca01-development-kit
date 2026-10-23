# Security-library acquisition follow-up

`libsecurity.so` remains unrecovered. This pass installed an independent DEFLATE inspection tool, tested previously unexamined stored-block boundaries, identified the structure of Audio's leading partial ELF, searched exact security API names in both source archives, and located the real official newer-firmware link. No new complete firmware file was obtained, no target code ran, and nothing was pushed.

## Installed and verified tool

[Mark Adler's infgen](https://github.com/madler/infgen) 3.6 is installed at:

`/home/starlight/projects/rav4-radio/tools/infgen-3.6-1e36c3d/infgen`

Source commit: `1e36c3da205ce3da7df1abd1f1c765a3cf49b267`. The private installation contains its source, license, build/hash manifest and self-test. No global packages were changed. Compilation succeeded with one upstream signedness warning in PNG handling.

Controlled gzip, zlib and raw-DEFLATE tests matched the expected output lengths; a truncated gzip stream was rejected. Infgen also independently agreed with the Middleware, Kernel and Audio suffix stream lengths. A synthetic zero history and alignment prelude were used solely for these diagnostics. Their added bytes are **not firmware recovery**, and infgen does not verify the missing gzip CRC or any firmware signature.

## What the search established

- The two original source archives contain no exact tested security API/library marker across **121,852 regular members**, **95 nested archives**, and **1,630,558,215 scanned bytes**. Search patterns and archive-by-archive coverage are recorded in `evidence/ca01-libsecurity-tool-validation.json`. This does not identify stripped unnamed code or prove absence from the installed radio.
- [Local recovery checks](CA01_LIBSECURITY_LOCAL_SEARCH.md) found no earlier usable stored-block continuation. Audio's leading partial ELF has a complete 26-entry section table, but its executable code and dynamic symbol strings are before the available bytes. The filename remains unknown. Root review independently checked all section records and known-byte flags.
- [Official/public-source checks](CA01_LIBSECURITY_PUBLIC_SEARCH.md) found the original Toyota 1134 calibration hyperlink embedded in the bulletin PDF. It requires sign-in in this environment. The public consumer metadata API returned access/service errors; no newer image was downloaded.

## Remaining useful input

A legitimately obtained complete installed filesystem backup, or another official CA01 firmware package that actually contains the library, would materially advance the search. A newer update might still omit it; acquisition does not establish library presence or compatibility. The available encrypted/missing prefix cannot be reconstructed merely by installing another file-carving tool. No library, ELF header, key, or decrypted prefix has been fabricated.

Scripts and responses are preserved under `system-audit/ca01-libsecurity-search-20261022/` in the local RAV4 project. Full structural evidence and hashes are linked above; raw firmware remains outside Git.
