# External-helper cut

`0x00686000` stays an unavailable protected or external dependency. This pass does not lift it, execute it, or replace it. `0x0055FF30` stays unknown.

The measurement uses the reachable high-confidence call graph. A direct edge exists only when a function's own control-flow walk reaches an `E8` whose target is `0x00686000`. A call that merely sits in the address gap before the next discovered function is not an edge. Phase 13 counted 249 `E8` sites and 44 of those sites whose span owner is a reachable high-confidence function. Of those 44 sites, 42 are inside the control-flow graph of 19 functions. Two sites remain in a span the walk does not enter.

Path class is bounded. Callees are classified before callers. A function is `MUST_REACH_EXTERNAL_HELPER` when every walk to a return hits the helper or a callee that already must hit it. It is `MAY_REACH_EXTERNAL_HELPER` when some walk hits that set and some return does not. A cycle is not treated as a forced hit. This is not symbolic execution.

## Counts

| set | functions |
| --- | --- |
| reachable high-confidence, excluding import thunks | 6,498 |
| CFG-confirmed direct callers | 19 |
| `MUST_REACH_EXTERNAL_HELPER` | 11 |
| `MAY_REACH_EXTERNAL_HELPER` | 31 |
| `NO_PATH_TO_EXTERNAL_HELPER` | 6,456 |

Forty-two functions have a path to the helper. Twenty-three of them do not call it themselves. The other 6,456 reachable high-confidence functions have no direct-call path to it.

`MUST` functions, all direct callers except `0x00782570`:

| function | class | sites inside its CFG |
| --- | --- | --- |
| `0x007111E0` | MUST | 1 |
| `0x0075F3D0` | MUST | 1 |
| `0x00762560` | MUST | 1 |
| `0x007632E0` | MUST | 1 |
| `0x007723E0` | MUST | 1 |
| `0x0077A610` | MUST | 1 |
| `0x00780D60` | MUST | 2 |
| `0x00782570` | MUST | 0, through a callee |
| `0x007F9710` | MUST | 1 |
| `0x0081F9F0` | MUST | 1 |
| `0x00830380` | MUST | 16 |

`0x00830380` is the heavy caller: sixteen sites, and every returning walk hits one. `0x0072C2A0` is the opposite shape, a `MAY` function with eight sites and a walk back to a return that skips them.

## The former 102-function frontier

All 102 functions in the closure rooted at `0x0099DCD0` are `NO_PATH_TO_EXTERNAL_HELPER`. None calls `0x00686000`, and none calls a function that does.

That does not make the closure a usable initialization frontier. Phase 11 entered four functions and faulted at `0x009E4B49` because `[0x0189D0A0+8]` is 0. Phase 12 and 13 showed that the ordinary store of that field, and the store of `0x0189DA88`, follow `call 0x00686000` in code that is outside this 102. The call graph of the 102 is clean. The object state the executed path needs is not. The prefix that ran is the useful part. The rest of the closure waits on an indirect slot or on that object field. It was not retried, and it is not the primary frontier.

## Largest closures with no path to the helper

These are direct-call closures inside the 6,456. Import names come from thunk edges recorded in the function map. "Indirect" here is the count in the root function only. A closure can still reach an indirect call, an unknown target, or a protected edge further down. None of these twenty is runnable as a whole.

| root | functions | depth | root indirects | unknown targets | imports in the closure |
| --- | --- | --- | --- | --- | --- |
| `0x009DA970` | 755 | 36 | 3 | 7 | memset, memcpy, memmove, strlen, strcmp, strcpy, sprintf |
| `0x009BBEC0` | 479 | 31 | 0 | 4 | memset, memcpy, strcmp, memmove, strlen, strcpy |
| `0x0099E270` | 478 | 31 | 0 | 4 | same family |
| `0x0099DE70` | 476 | 30 | 1 | 4 | same family |
| `0x009BFF30` | 467 | 28 | 0 | 4 | same family |
| `0x0099DE30` | 465 | 29 | 0 | 4 | same family |
| `0x0099DE50` | 465 | 29 | 0 | 4 | same family |
| `0x009BF760` | 463 | 28 | 0 | 4 | same family |
| `0x009BF360` | 462 | 28 | 0 | 4 | same family |
| `0x0099F120` | 461 | 28 | 0 | 4 | same family |
| `0x0099F170` | 461 | 28 | 0 | 4 | same family |
| `0x009BAC90` | 461 | 28 | 0 | 4 | same family |
| `0x009BACD0` | 461 | 28 | 0 | 4 | same family |
| `0x0099E410` | 437 | 23 | 0 | 3 | same family |
| `0x009A0730` | 436 | 23 | 1 | 2 | same family |
| `0x009C87D0` | 432 | 23 | 4 | 3 | same family |
| `0x0099EF00` | 430 | 23 | 2 | 3 | same family |
| `0x009B2F50` | 413 | 24 | 1 | 5 | adds memcmp, vsprintf |
| `0x0099F9F0` | 399 | 21 | 1 | 2 | same family |
| `0x009BF990` | 389 | 24 | 0 | 3 | adds sprintf |

`0x009DA970` is the Phase 10 protected closure. Independence from `0x00686000` does not remove that protected edge. The largest closure whose recorded imports are only helpers the runtime already implements is still `0x0099DCD0` at 102 functions. Phase 10 counted 141 indirect calls in it. It is not runnable.

The closures that are runnable now are the ones Phase 10 already executed, and both stay outside the helper cut:

| root | functions | why it can run | helper |
| --- | --- | --- | --- |
| `0x00B01EB0` | 19 | no imports, no indirects, no protected edges | no path |
| `0x00968D10` | 31 | the imports it reaches are implemented; the returning path enters 6 functions | no path |

No larger closure cleared that bar. They were not executed again.

## `0x0055FF30`

Four call sites. The high-confidence owners `0x00794690` and `0x00794C10` are not reachable. The medium owners are `0x00793A30` and `0x008101B0`. None of the four is in the reachable high-confidence graph, and none is on the Direct3DCreate9 prefix below. This target does not independently block the frontiers measured here. It stays unknown and unimplemented.
