# `0x0189D0A0`

The address is passed in ECX. Ordinary code takes that address 219 times and then calls a helper. No site writes the dword at `0x0189D0A0` with an absolute `mov`. The bytes are in the zero-filled tail of `.data`, so the initial value of every field is 0.

This is an in-place object, and it is the base of a larger structure. It is not a slot that holds a pointer to an object. The first 12 bytes are one record. The same record shape is repeated at `+0x0C`, `+0x18`, `+0x24`, and `+0x30`.

## Record at offset 0

| Offset | Size | Access | Where | Initial value | Writer |
| --- | --- | --- | --- | --- | --- |
| `+0x00` | dword | read | `0x009E4B10`, `0x009E4560`, `0x009E4820`, `0x009E4890` | 0 | `0x009E4820` and `0x009E4890` store a reduced count. `0x009E75A0` and `0x009E4BB0` store 0 |
| `+0x04` | dword | read/write | `0x009E4640`, `0x009E4BB0`, `0x009E4C30` | 0 | `0x009E4640` stores its stack argument. `0x009E4C30` uses it as a byte length (`shl 2`) |
| `+0x08` | dword | read as a pointer | `0x009E4B49` | 0 | `0x009E46A1` and `0x009E4C03` store EAX |

`0x009E4B10` is the function that faulted in Phase 11. With the stack argument 0 it computes `count - 0`. If that difference is not greater than 0 it calls `[0x0189D1A4]`. It then loads EDX from `[object+8]` and executes

`mov eax, dword ptr [edx + eax*4 - 4]`

With count 0 and argument 0, EAX is 0, so the address is `[pointer - 4]`. `0x009DC250` is the function that returns a block plus 4 and stores the requested size in the dword immediately before the returned pointer. The `-4` is that header. The fault address `0xFFFFFFFC` is that header read while `[object+8]` is still 0.

## How `+0x08` is written

`0x009B2D31` is `mov ecx, 0x0189D0A0` followed by `call 0x009B67C0`. That helper calls `0x009E4640` on the base. `0x009E4640` stores its argument at `+0x04`, calls `0x009DC250` with ECX equal to `[0x0189BEEC]` and a size of `argument * 4`, and stores the return value at `+0x08`.

`0x009DC250` adds 4 to the size and calls `0x009DC310`. `0x009DC310` is a 271-instruction high-confidence function. It calls `memset`. The size-bearing call under it is `0x009DBE50`, whose body is

`call dword ptr [0x0189D198]`
`add esp, 4`

`0x0189D198` is the first slot the Phase 11 leaf writes, and the stored value is `0x009E77D0`. That function calls `0x009E9460`, which returns 0 when `[0x0189DA88]` is 0 and otherwise calls through that object's pointer table at `+0x1C`.

## Other observed fields

`0x009E7540` calls `0x009E75A0` at offsets 0, `0x0C`, `0x18`, `0x24`, `0x30`, and `0x40`. `0x009E75A0` writes 0 to `+0`, `+4`, and `+8` of whatever it receives. That matches the current image. It does not install a pointer.

`0x009B67C0` also calls `0x009E4C80` at `+0x0C`, `+0x18`, `+0x24`, and `+0x30`, and writes a byte at `+0x98`, a dword at `+0x94`, and a byte at `+0x99`. `0x009B9160` reads dwords at `+0x70` and `+0x74`.

Direct field stores in the 24 instructions after each `mov reg, 0x0189D0A0` were counted. There are none. Every one of those sites passes the address in ECX. The forward slice does not follow a pointer that was saved to the stack and reloaded, so the field writes above were recovered by disassembling the helpers.
