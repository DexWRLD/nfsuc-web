# `0x00686000`

Ordinary `.text` calls this address. The bytes at the address are not an ordinary function. Nothing in this note replaces the call with `malloc` or any other helper.

## Where `0x009EB870` stops

`0x009EB870` does not call `0x00686000`. Its body is:

```
009EB870 push esi
009EB871 mov esi, dword ptr [esp + 0x10]
009EB875 push esi
009EB876 call 0x9e9460
009EB87B mov ecx, dword ptr [esp + 0x10]
009EB87F mov edx, dword ptr [eax]
```

`0x009E9460` loads `0x0189DA88`. If that dword is 0 it executes `xor eax, eax` / `ret`. `0x009EB870` then reads `[eax]`. The call from `0x009E9340` is `0x009EB870(0x248, 0x00C30EAC, 0, 0)`. The 0x248 size is an argument of `0x009EB870`, not an argument of `0x00686000`.

`0x0189DA88` has one ordinary store, `0x009E9414` (`mov dword ptr [0x0189DA88], eax`). Its only direct caller is `0x00810291`. In `0x008101B0` that call is after:

```
00810245 mov eax, dword ptr [0xcd3a54]
0081024A push eax
0081024B push 0xbbbfc8
00810250 push 4
00810259 call 0x686000
0081025E mov edi, eax
00810260 add esp, 0xc
```

On the nonzero path, `0x0081027A` stores `0x00BBB460` at offset 0 of the returned block and `0x00810291` publishes the pointer. The block `0x009E9160` later receives is that pointer, once this call has returned one.

## Call shape at the helper

The instruction at `0x00810259` is `E8 A2 5D E7 FF`. Destination `0x0081025E + 0xFFE75DA2 = 0x00686000`. The caller removes 12 bytes. EAX is saved, compared with zero, and used as a pointer. The same shape appears at high-confidence sites, including reachable `0x00772413`:

```
00772407 push 0
00772409 push 0xbaea38
0077240E push 0x9c6c
00772413 call 0x686000
00772418 mov esi, eax
0077241A add esp, 0xc
00772421 test esi, esi
```

Three caller-cleaned stack arguments. The last push is a small integer or a larger constant. Another push is often a `.rdata` address. EAX is treated as a pointer. This is a behavioral signature only. The `malloc` thunk is `0x0087B6F8`, one argument, and it is not this address.
