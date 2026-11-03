# Phase 54 connected browser startup probe

Baseline dddf195, main 12 ahead of local origin/main. The earlier audit remains untracked. The source image is SHA-256 verified by the Phase 53 builder. The Wasm is generated locally in web/dist with the same command as Phase 53. No source executable or compiled diagnostic is committed.

## Ordinary caller and state graph

The recorded direct chain is 0x008104E9 in 0x008101B0 → 0x009E9420 → 0x009E9340 → 0x009E9160, then 0x009E9305 → 0x009E8AD0. The last function takes no arguments, reads no globals, writes 49 callback dwords in the ordinary zero-filled data tail, and returns with plain RET. These are static globals. Evidence establishes an ordinary direct caller, with no proof of a static constructor registration or when the original executable reaches it. The browser probe still enters that leaf directly, then invokes the startup-related root with the historical harness inputs in the same module instance.

## Browser trace

The initializer reproduced 49 writes, [0x0189D1A4] = 0x009E78C0, EIP 0x00DEC0DE and ESP 0x0300F000. The root has a diagnostic cdecl stack with arguments 0 and 2. Within the root, the calls below are executed by lifted guest code. The host does not invoke the intermediate bodies.

| Callsite | Target | Contract and observed continuation |
|---|---|---|
| 0x0099DCEB | 0x009E78C0 through [0x0189D1A4] | Three cdecl arguments 0x00C1875C, 0x00C19840, 0x1F8. Reads zero CoreImpl pointer at 0x0189DA84, returns EAX zero, caller pops 12 argument bytes. |
| 0x0099DD10 | 0x009B6290 | ECX=0x0189D0A0 and index zero on stack. Thiscall RET 4 contract, no return reached. |
| 0x009B629E | 0x009E4B10 | Passes the same receiver and index. Thiscall RET 4 contract, no return reached. |
| 0x009E4B32 | 0x009E78C0 through [0x0189D1A4] | Three cdecl arguments 0x00C30AB4, 0x00C30938, 0x10A. Zero CoreImpl branch returns EAX zero, caller pops 12 bytes. |

The actual browser trace is 0x0099DCD0 → 0x009E78C0 → 0x009B6290 → 0x009E4B10 → 0x009E78C0, four unique functions and a maximum four active frames. Instruction 0x009E4B49 attempts MOV EAX,[EDX+EAX*4-4]. EDX is the zero [object+8] backing pointer, EAX is zero after count minus index, and the effective address is 0xFFFFFFFC. The bounded bridge records that address and traps. The inspector displays the fault.

The mapped globals use original 32-bit VAs and zero-filled initial state from the recorded PE data tail. The bridge uses aligned Wasm dwords, a bounded stack window, and the initializer's original slot writes. There is no arbitrary heap fixture. The prefix is cut at the next unsupported continuation and the dispatcher admits only the observed target. The condition helpers cover the flags consumed by this probe. No general x86 runtime or whole-image loader is supplied.

## Missing producer

At 0x009E46A1, MOV [ECX+8],EAX publishes the block to the receiver. The ordinary caller at 0x009B2D31 supplies 0x0189D0A0. 0x009E4640 obtains the block via 0x009DC250 → 0x009DC310 → 0x009DBE50, which dispatches through slot 0x0189D198 to 0x009E77D0. 0x009E9460 depends on [0x0189DA88]; its ordinary producer is rooted in the allocator-shaped 0x00686000 call from 0x008101B0. Field +8 is an indexed backing storage pointer in the observed consumer. Object constructor ordering and a valid allocator-backed instance remain unresolved. Classification is missing ordinary object state with an opaque upstream dependency.

## Validation and metrics

TypeScript, frontend build, Wasm build and the 53-test Node and Edge HTTPS batch passed, including exact prefix trace, guest-stack return, fault address and authentic video/cache regression. Historical native counts remain 84 unique, 50 enterable and 358 runs. Browser evidence now covers five distinct addresses including the standalone initializer, and one connected four-function prefix ending in a fault. No additional original object producer, full boot or authentic gameplay frame was verified.
