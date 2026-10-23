# CA01 security interfaces: fresh static follow-up

Fresh Ghidra 12.1.4 analysis of independently recovered `06-PROC_REPRO`
(SHA-256 `47a48311b513bffaa3c8f41e9c3ebcc05ae3525e8efe069c714f5e8341fbb771`)
changes one earlier conclusion: **streaming continuation chunks are not fed to
SHA256 by this helper.** No target executable or hardware was run. Exact
instructions are retained in `evidence/ca01-security-interfaces.json`.

## Signed extent correction

At `0xdec0`, the mode argument is saved in r6. `0xdf14` compares it with 1;
`0xdf18` branches directly to `0xdfd0`, which returns zero through the epilogue.
There is no SHA update on that path. The streaming driver `0xe7ec` calls this
mode for later chunks, writes the returned buffer, and separately reads the
last 256 bytes for mode 2 (`0xeb14`), which calls the SHA finalizer/PSS verifier.
Mode 0 initializes and updates SHA256 using the decrypted initial prefix.
Consequently, on the large-component branch, this particular PSS check covers
the returned plaintext of the encrypted prefix, not every clear continuation
chunk. The memory helper `0xa9bc` similarly feeds only its returned prefix length
to SHA256 when input exceeds 64,000 bytes. For small inputs it subtracts the
256-byte signature before hashing; boundary cases split a signature across the
prefix and suffix. This finding does not resolve all boundary cases or exclude
nested hashes, signed manifests, or validation elsewhere in the system.

The earlier call-graph phrase “later hash update” for `0xdec0` mode 1 was
incorrect. Initial-prefix decoding, continuation passthrough, and final-signature
verification are the three actual modes observed here.

## Register-level API reconstruction

These describe register preparation at the call sites, not recovered vendor C
headers. Ghidra's speculative extra arguments must not be treated as prototypes.

| Call site | Imported call | Established values |
|---|---|---|
| `0x1e8a4` | `sysAesKey` | r0=`0x7d7b8`, r1=key selector, r2=`0xa34fa93c` for wrapper mode 0 or `0x28acfb69` for mode 1 |
| `0x1e8c8` | `sysAesInit` | r0=`0x7d578`, r1=`0x7c12776f`, r2=`0x7d7b8` |
| `0x1e840` | `sysAesExec` | r0=context `0x7d578`, r1=input pointer, r2=input byte count, r3=output pointer, stack[0]=returned-length pointer, stack[4]=operation token |
| `0x1e850` | `sysAesFinish` | r0=context `0x7d578`, called after execution even on error; its return is discarded |
| `0x1e95c` | `sysRsaPbcKeyInit` | r0=`0x7ca8c` (literal at `0x1e9bc`), r1=RSA selector |
| `0x1e99c` | `sysRsaDecPbcKeyInit` | r0=`0x7d4dc`, r1=`0x7ca8c`, r2=`0x1e` for wrapper mode 2 or `0xe70ecc7d` for mode 1, r3=0 |
| `0x1ea48` | `sysSha256Update` | r0=context `0x7d638`, r1=data pointer, r2=byte count |
| `0x1e9e4` | `sysSha256Final` | r0=stack output buffer, r1=context `0x7d638` |
| `0x1ea00` | `sysRsaPssVerify` | r0=context `0x7d4dc`, r1=SHA output buffer, r2=signature pointer |

AES-exec wrapper mode 0 selects `0x2ad0367e`, mode 1 selects `0xe70ecc7d`.
The updater's observed decrypt path uses mode 0. The shared token
`0xe70ecc7d` also occurs in RSA context initialization, so naming it an AES
cipher mode, encryption flag, or padding standard would be premature.
`0x1e870` saves `{r3,lr}` and does not prepare a fifth stack argument to
`sysAesKey`; the decompiler's fifth parameter is therefore not supported.
r3 retains the wrapper mode because it was used in comparisons; whether the
library consumes it is unknown. Similarly `sysSha256Update`'s decompiled extra
arguments are residual register/stack values, not established parameters.
The public-key object address `0x7ca8c` is a storage pointer, not key bytes.
Context sizes cannot be inferred merely by subtracting neighboring addresses.

## Key lifecycle and error behavior

`0x1e750` independently skips each disable operation for selector `0xff`.
Otherwise it invokes `sysSecRsaKeyDisable` or `sysSecAesKeyDisable`; return
`-3` is tolerated, `-2` becomes `-4`, and other nonzero disable returns become
`-1`. The RSA call still has the selector in r0, even though the untyped
Ghidra decompilation prints no argument. Whether the library reads it is not
proved. These are lifecycle calls, not evidence of successful irreversible
key revocation. The surrounding state machine reads metadata bytes 0 and 1
for these disable controls; bytes 2 and 3 are the separately documented
verification/decryption selectors.

Most crypto wrappers preserve `-1`, map `-2` to `-4`, and preserve other return
values. The caller explicitly permits `0x210000` from AES setup and then still
executes AES; this is a tolerated status, not a successful signature or a
bypass. Positive errors can trigger `sysSecErrRecovery` before retrying setup.
The unknown library defines their actual meaning.

## Hardware limits and complementary consumers

The recovered ELF inventory has three consumers of this security API:
`PROC_REPRO`, `PROC_SYSTEM`, and `libnavi_if.so`. The latter imports private-key
RSA initialization (`sysRsaDecPrvKeyInit`) plus `sysRsaExec`; `PROC_SYSTEM`
imports security startup/shutdown and serial/version queries. No recovered ELF
provides these symbols. Shared API usage and key-slot selectors make the missing
security library an important next target, but do not prove that the keys reside
in hardware. Neither a device node, ioctl ABI, silicon key store, IV, AES cipher
mode, nor a working software replacement has been established from these calls.

### New complementary result: caller-supplied RSA key construction

A fresh import/decompilation of `libnavi_if.so` recovered its named export
`AWN_Navisec_RSA_Decription` at ELF relative address `0x152d4`
(Ghidra analysis address `0x252d4`, with image base `0x10000`). All addresses
in this subsection use that Ghidra image base. This is an original exported symbol,
including its spelling. After checking its caller-supplied descriptors, it calls:

```text
sysSecStartUp()
sysUserRsaPrvKeyNonCrt(key_object,
    key_descriptor + 0x10, key_descriptor + 0x310,
    key_descriptor + 0x210,
    word_at_0x710, word_at_0x720, word_at_0x71c)
sysRsaDecPrvKeyInit(rsa_context, key_object, 0xe70ecc7d)
sysRsaExec(rsa_context, input_pointer, input_u16_length,
    output_pointer, output_length_pointer)
sysSecFinish()
```

The key-construction call is at `0x25358`; its three pointer offsets and three
stack words are confirmed by ARM instructions at `0x25330–0x25354`. The import
`sysUserRsaPrvKeyNonCrt` was missed by searches restricted to `sysSec`/`sysRsa`.
The operation descriptor supplies input at offset 0, output at offset 4, a
16-bit input length at offset 8 and output-length storage at offset 10.
The function permits input lengths 1 through 256. The key descriptor must begin
with words `0xffffffff` and `1`. Names of individual key fields (modulus,
exponent, etc.) cannot be assigned confidently from this call alone.

This is concrete evidence that the security API accepts a private-key object
built from caller-provided data in a navigation workflow. It does not recover
those values or connect them to the updater's slot-selected keys, but it rules
out assuming from API names alone that every operation requires hardware-resident
keys. The shared `0xe70ecc7d` token also appears in this private-key RSA path.
No navigation operation, key extraction, firmware decryption, or signature
verification was executed.
