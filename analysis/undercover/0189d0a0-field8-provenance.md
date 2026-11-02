# `[0x0189D0A0+8]`

`0x009E4B49` reads `[edx + eax*4 - 4]` with EDX taken from `[object+8]`. While that field is 0 and the count is 0, the address is `0xFFFFFFFC`.

## The store

`0x009E46A1` is `mov dword ptr [ecx+8], eax`. The preceding call is `0x009DC250`, with ECX equal to `[0x0189BEEC]` and a size of `argument * 4`. `0x009B2D31` passes ECX = `0x0189D0A0` into the helper that reaches `0x009E4640`.

`0x009DC250` adds 4 and calls `0x009DC310`. The size-bearing call under that function is `0x009DBE50`:

```
call dword ptr [0x0189D198]
add esp, 4
```

The Phase 11 leaf stores `0x009E77D0` at `0x0189D198`. `0x009E77D0` calls `0x009E9460`. `0x009E9460` returns 0 when `[0x0189DA88]` is 0 and otherwise calls through that pointer. `0x009E77D0` then reads `[eax]`, so a zero factory pointer does not produce the block stored at `[object+8]`.

## Same helper, not the same call

`0x009E4640` does not call `0x00686000`. None of the 249 direct callers is that function. The field path and the `0x009EB870` path meet at `0x0189DA88`. The only ordinary store to `0x0189DA88` uses EAX from `call 0x00686000` in `0x008101B0`. Both initialization problems stop on that call. They do not stop on two different helpers.
