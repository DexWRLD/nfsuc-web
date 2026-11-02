# Graphics initialization graph

Ordinary provenance only. `0x00686000` is not on this chain. Nothing here was executed. Direct3D was not implemented.

## Legend

| edge | meaning |
| --- | --- |
| solid | proven ordinary edge |
| dashed | possible / incomplete |
| dotted | indirect |
| red label | missing initialization or external/protected |

## Flag `0x01311E1C`

```
PE image (.data virtual tail)
        |
        | value 0
        v
[0x01311E1C] ----READ----> 0x0072E5D0  (cmp with 1; else call 0x009773B0)
      ^  |
      |  +----READ----> 0x00722D60  (cmp with 2 after xchg)
      |
      | DEFINITE xchg writers (ordinary .text)
      |
      +-- 0x00722D70  mov eax,1 ; xchg [ecx],eax     value := 1
      |     function 0x00722D60 HIGH unreachable
      |     no E8 caller, no absolute pointer in allowed sections
      |
      +-- 0x00729977  mov eax,2 ; xchg [ecx],eax     value := 2
      |     inside 0x00729750 MEDIUM
      |     called from 0x0072E454 inside 0x0072E340 (after factory work)
      |
      +-- 0x00B4F997  xor eax,eax ; xchg [ecx],eax   value := 0
            leaf 0x00B4F990, .rdata table 0x00B62BD0
```

Compared values observed: `0` (image), `1` (gate before `0x0072E340`), `2` (post-path wait in `0x00722D60`).

## Object `0x01318170`

```
.bss/.data virtual tail (file bytes absent -> mapped 0)
        |
        | ADDRESS_TAKEN (123 sites), no absolute WRITE
        v
ECX = 0x01318170  --proven-->  call 0x0072E5D0   (from 0x00766773)
        |
        +--> 0x0072E5D0  mov esi, ecx
        +--> 0x0072E340  mov ebx, ecx
                |
                + WRITE [ebx+0x10] = Direct3DCreate9 result
                + many READ/WRITE of +0x14, +0x54, +0x4B8, +0x4C0..
```

Minimum observed field span on the graphics methods: through offset `0x534` (1332). Exact allocation size is not proven beyond that. No dependence on `0x00686000`.

## Outer caller `0x00766730`

```
[0x01385FA0] --READ--> push ; call [0x00B611D4]     dotted, PE target 0x008A9F58 (not a map entry)
[0x01882C34] --READ--> index
fs:[0x2C]    --READ--> TEB TLS array
        |
        v
TLS slot = [TEB + index*4]
        | WRITE [slot+4], [slot+0xC]
        | call 0x00977300
        | mov ecx, 0x01318170
        v
call 0x0072E5D0
```

TLS on this entry: required before the factory if this outer function is the root. Direct entry at `0x0072E5D0` does not itself read the TLS index on the path to `Direct3DCreate9`.

## Create method `0x0072E340`

```
[0x00B615C4] --READ--> ESI
        | dotted call esi  (three times; PE value 0x008AA3AE is mid-instruction)
        v
call 0x0072DD00 / 0x0072DCA0
        | [0x00CEA3F0] zero => skip indirect body   proven PE zero
        v
push 0x20 ; call 0x0087A79C  (Direct3DCreate9)
        | EAX -> [ebx+0x10]
        v
further ordinary methods; call 0x00729750 (sets flag to 2)
```

## Wait helper `0x009773B0`

```
arg0 -> [arg0] -> push 1 ; call [0x00B61188]
```

Not a loop. Callers spin by re-reading `0x01311E1C` and calling this between reads.

## Slot summary

| slot | PE value | ordinary writers | notes |
| --- | --- | --- | --- |
| `0x00B615C4` | `0x008AA3AE` | none | mid-`je` displacement; not a CFG instruction start |
| `0x00B611D4` | `0x008A9F58` | none | not a function-map entry |
| `0x00B61188` | `0x008AB180` | none | not a function-map entry |
| `0x00CEA3F0` | `0` | none | zero path skips the call |
| `0x01882C34` | `0` (BSS) | none | 605 absolute reads; TLS index shape |

## Enterability

Required for a legitimate call of high-confidence `0x0072E5D0` that reaches `Direct3DCreate9`:

| requirement | class |
| --- | --- |
| `[0x01311E1C] == 1` | writer exists at `0x00722D60`, but that function has no ordinary caller or data pointer → `EXTERNAL_DEPENDENCY` / `UNKNOWN` how it is entered |
| `ECX == 0x01318170` (or an equivalent object) | address is PE-known static; fields are zero → `PE_INITIALIZED` address, `MISSING` field state |
| `[0x00B615C4]` callable target | PE value is not a valid entry → `UNKNOWN` / not dispatchable |
| `Direct3DCreate9` | `IMPORT` not implemented (not required to *analyze* enterability; required to finish the call) |
| TLS index / TEB | needed for outer `0x00766730`, not for the `0x0072E5D0` prefix itself → `TLS_OPTIONAL_ON_PREFIX` for the high function, `TLS_REQUIRED_BEFORE_FACTORY` for the outer medium root |

`Direct3DCreate9` frontier enterable: **NO**.
