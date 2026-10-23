# Public-source search for the CA01 security library

No `libsecurity.so` or additional firmware image was obtained in this bounded
search. It did identify the actual official download path, replacing the older
guessed filename URL, and the consumer portal's published metadata endpoints.

## Exact official firmware path

[Toyota T-SB-0024-20, page 8](https://static.nhtsa.gov/odi/tsbs/2020/MC-10173804-9999.pdf)
names base-audio `15TBDANA-CA01_1134.kwi`. Decompressing the downloaded PDF's
object streams recovered its original link annotation:
`/t3Portal/calibration/15TBDANA-CA01_1134`.
Resolving it on [Toyota's technical-information host](https://techinfo.toyota.com/t3Portal/calibration/15TBDANA-CA01_1134)
returned HTTP 302 to Toyota login and ultimately HTML. No login was attempted.
This proves a real bulletin link exists; it does not prove anonymous access or
that the firmware file has been withdrawn.

The same bulletin links Audio Plus `15TDDANA-CA01_2247` and Premium Audio
`15TDANNA-CA01_2247`, plus corresponding CA02 variants. Those are possible
family-comparison targets, not established substitutes or compatible libraries.
Their binaries were not downloaded.

## Consumer portal inspection

The public [Toyota firmware portal](https://www.toyota.com/firmware-updates)
and its update page loaded successfully. Reading their linked JavaScript
identified ordinary unauthenticated year/model lookup URLs under
`/content/sdp/us/en/toyota/softwareupdates/`:

- `vehicle_garage.model.json`: vehicle selection metadata.
- `software_update.model.json`: firmware metadata; frontend checks `firmwareUrl`.

Using the published query fields `division=toyota`, `vehicle=RAV4`,
`modelYear=2016`, and `navigationType=without navigation`, the selector returned
HTTP 502 and the firmware endpoint returned HTTP 403 with XML `AccessDenied`.
The same endpoint and query schema were also checked for model years 2014 and
2015; both returned HTTP 403 XML `AccessDenied`. These were bounded year-variant
checks, not a change of host or authentication route.
No VIN, credentials, hidden endpoint enumeration, or access-control workaround
was used. These results limit this acquisition attempt; they do not establish
that the update is unavailable to other clients or through normal dealer access.

## API provenance search

Separate exact searches for `sysSecStartUp`, `sysUserRsaPrvKeyNonCrt`, and
`sysRsaDecPbcKeyInit` returned no results. `sysAesKey` returned an unrelated Go
constant. Searches combining `libsecurity.so` with Renesas or Fujitsu found no
applicable documentation; an OSF/FreeBSD security-library reference was unrelated.
No official API header, vendor attribution, key-storage architecture, or software
replacement was established. Search coverage is bounded and is not proof that
such documents do not exist.

Machine-readable URLs, query outcomes, SHA-256 values, and exact PDF annotations
are in `evidence/ca01-libsecurity-public-search.json`. Downloaded bulletin,
public page/JavaScript copies, and response bodies are under
`/tmp/ca01-libsecurity-public`. Requests were bounded to 100 MiB for the firmware
endpoint and 5 MB for documents/pages; no firmware executable was run.

The repository README records the original 1127 acquisition URL as
`https://www.toyota.com/firmware-download/15TBDANA-CA01_1127.kwi`. That provenance
was checked locally; the already-held file was not downloaded again. The consumer
query field names and values follow the frontend JavaScript, with year/model
selection rather than fabricated VIN data.
