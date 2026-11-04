# Phase 77 handoff — C initializer / `_initterm_e` gate

Phase 76 executed a host-scheduled bounded prefix of original CRT startup at `0x0087BB3D` through SEH, FS owner token, and `InterlockedCompareExchange`, stopping at `0x0087BBB4 → 0x0087C232`. Read `runtime-phase76.md`, `crt-startup-contract-phase76.json`, `crt-startup-execution-phase76.json`, and `crt-bootstrap-execution-phase76.json`.

## Preserve

- Ordinary 14-body module hash unchanged; diagnostic module remains opt-in and outside Git.
- Compatibility routing stays exact-callsite / unchanged operand / name-record gated.
- Cookie + NT_TIB32 + startup state/owner transitions already proven must not be short-circuited by pre-setting globals.
- `Sleep` / `InterlockedExchange` remain unimplemented until a reviewed path requires them.
- Original PE entry and loader binding remain unverified / false.

## Next bounded target

1. Review stub `0x0087C232` and legacy cell `0x00B613B4` (`_initterm_e`) ABI from authenticated bytes and Microsoft docs.
2. Do **not** invent a generic walker. Prefer the smallest exact contract that can invoke authenticated table `[0x00B63DC4,0x00B63DD4)` in order.
3. First non-null entry `0x0087BCB3` requires PE-header reads, then `__set_app_type` and `_encode_pointer(-1)`. Modern `_set_app_type` docs do not automatically prove the double-underscore export. No identity encoding.
4. Only after all required non-null C entries return successfully may C++ `[0x00B61730,0x00B63DC0)` be considered.
5. Stop at the first unsupported service, branch, or instruction. Do not skip to Apt.

## Safety

No PE-entry reconstruction, import-cell patches, protected unpacking, commercial payloads in Git, LAN widening, Unicorn retuning, graphics, or full-game Play.

## Reproduction

```text
python tools/uc_unified_build.py ^
  "C:/Games/Need For Speed Undercover/nfs.exe" ^
  "C:/Users/999/.nfsuc-web/authorized-startup" ^
  --crt-cookie-output "<outside-git-diagnostic-dir>"
```

Select the diagnostic module in Play Development Preview → Execution inspector → Compatibility CRT. Local commits only after validation; no fetch/push unless explicitly requested.
