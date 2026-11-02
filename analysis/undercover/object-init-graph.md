# Object initialization graph

Edges are direct calls or a value a caller stores. Nothing here was taken from a protected section.

```
0x008101B0
    call 0x0055FF30          ; bytes at the target are not a function
    call 0x00686000          ; bytes at the target are not a function
    call 0x009E9410
        -> writes EAX to 0x0189DA88
0x009E9420
    reads 0x0189DA88
    call 0x009E9340
        call 0x009EB870(0x248, 0x00C30EAC, 0, 0)
            call 0x009E9460
                requires 0x0189DA88
        call 0x009E9160(ecx = returned block)
            writes dword 0x00C30E68 at offset 0
            writes the second argument at offset 0x58
            call 0x009E8AD0
                writes 0x0189D198 .. 0x0189D270
                including 0x0189D1A4 = 0x009E78C0
                and 0x0189D198 = 0x009E77D0
            mov eax, esi
        mov [0x0189DA84], eax
0x009B2D31
    mov ecx, 0x0189D0A0
    call 0x009B67C0
        call 0x009E4640
            call 0x009DC250 with ecx = [0x0189BEEC]
                call 0x009DC310
                    reaches 0x009DBE50
                        call [0x0189D198]
            mov [object+8], eax
0x0099DCD0
    reads 0x0189D1A4
    mov ecx, 0x0189D0A0
    call 0x009B6290
        call 0x009E4B10
            reads [object+0] and [object+8]
```

## Order of the callback leaf

Inside `0x009E9160` the call to `0x009E8AD0` is at `0x009E9305`. The `mov eax, esi` / `ret 8` is at `0x009E9313`. The caller `0x009E9340` stores EAX at `0x009E9396`, after that call returns. The leaf therefore runs during `0x009E9160`, after that function has stored offset 0 and offset `0x58`, and before `0x009E9340` publishes the pointer.

`0x009E9340` calls `0x009EB870` before `0x009E9160`. The block exists before the leaf runs. The leaf does not create it.

## What was not executed

`0x009E9160` does not allocate. Its ECX is the pointer `0x009EB870` returned, and that return requires `[0x0189DA88]`. The only writer of `0x0189DA88` is `0x009E9414`, called only from `0x00810291`. Reaching that store executes `call 0x00686000`. Those bytes are `E8` to an address outside the image, and the map labels the site low confidence. No ordinary instruction stores a replacement prologue there.

`0x009E75A0` writes zeros to the same three dwords the image already contains. Running it does not give `0x009E4B10` a pointer.

No harness store was made to `0x0189DA84`, `0x0189DA88`, `0x0189D0A0`, or `0x0189BEEC`.
