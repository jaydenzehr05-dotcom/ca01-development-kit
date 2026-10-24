# Missing CA01 provider/configuration search — 2026-10-23T21:58:48.915893+00:00

## Result

No new copy of `libipas_apc.so`, `ipasz.conf`, or `libsecurity.so` was recovered.
No replacement library, invented configuration, firmware execution or vehicle access was used.
The existing repository and concurrent exporter/startup work were not modified by this search.

## Expanded local scope

Unlike previous selected-source/filename searches, this pass recursively opened nested TAR/GZIP/XZ/ZIP members and searched their file contents and TAR member names. It examined 254,933 regular-file/container visits totaling 3,500,886,819 bytes. Counts include compressed containers as well as expanded members and are not unique source-file counts. All three archives completed, with zero parser errors and zero size-limit skips. Max archive recursion is four; recognized nested archives use listed suffixes or ZIP magic, so arbitrary renamed formats are not ruled out.

| Archive | File/container visits | Bytes searched |
|---|---:|---:|
| `20130619_LE2355.tgz` | 33,803 | 392,724,662 |
| `OSS_SOFT_PACK.tgz` | 88,082 | 1,238,150,582 |
| `DENSO_TEN_17_OSS_SOFT_PACK.zip` | 133,048 | 1,870,011,575 |

Exact case-insensitive search patterns: `libipas_apc`, `ipasz.conf`, `libsecurity.so`, `rq_apc_Cnct`, `rq_apc_AppInfNsw`, `fd_uif_SetUieInf`. Number of archive matches: 0.
Archive SHA-256 values and exact scope are in `ca01-missing-archive-search.json`.

## Firmware check

Six 1134 partial regions contain 32,179,391 decoded bytes, of which 31,698,656 are explicitly known in the masks. All 18 target-string matches are wholly known and fall inside existing complete recovered entries. The `ipasz.conf` strings are inside `libipas_sysc.so` and `libipas_sysp.so`, not a configuration file. APC/security matches are inside existing consumers such as `PROC_UIEIF`, `PROC_SPC`, `PROC_REPRO` and `PROC_SYSTEM`; no new provider was found. The scanned complete 1127 ELF dynamic symbol tables provide no definitions for the three named API targets. This does not infer that any missing file is absent from encrypted prefixes or the installed radio.

## Public acquisition check

The official DENSO TEN 13t and 17 source pages were fetched again; their source links point to the same three archives already held and scanned. The 17 package is a newer-generation reference, not proof of CA01 ABI compatibility.

- https://www.denso-ten.com/jp/support/source/oem/13t/index.html
- https://www.denso-ten.com/support/source/oem/17/index.html

The original 2017 Toyota bulletin names `15TBDANA-CA01_1117.kwi`. Its embedded link is `/t3Portal/calibration/15TBDANA-CA01_1117`. A fresh HEAD request redirected to Toyota's TIS HTML portal, not firmware; the HTTP 200 is not a successful firmware download. Session query strings were discarded from the saved probe report. Exact-name public searches produced no verified downloadable candidate; this is not a proof that no public copy exists.

- https://static.nhtsa.gov/odi/tsbs/2017/MC-10115270-9999.pdf
- https://techinfo.toyota.com/t3Portal/calibration/15TBDANA-CA01_1117

## Next evidence that would unlock recovery

1. Obtain another legitimately accessible same-family update (1117 or an applicable service/recovery package) for offline component comparison. It might expose different file bytes; it is not guaranteed to contain unchanged factory files.
2. Obtain an authorized read-only factory filesystem image or file export from a matching spare/bench unit. Prioritize actual `ipasz.conf` plus launch directory/init files and `libipas_apc.so`/`libsecurity.so` with recursive dependencies. No hardware extraction was performed or authorized here.
3. Verify any candidate against ARM EABI, DT_NEEDED/exports, hashes, version and board provenance before using it. Newer Linux/AGL source or a same-named unrelated library does not establish a match.

## Verification

The recursive scanner passed a synthetic ZIP -> gzip TAR -> exact target-content/provenance test. Partial scanning verified mask coverage and mapped every match into a previously recovered complete entry. Report assertions check all three archives completed, zero scan errors/skips, six partial regions and no defined target exports. These are acquisition/static-analysis checks, not an original firmware startup test.
