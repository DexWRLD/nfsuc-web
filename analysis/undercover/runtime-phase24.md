# Runtime Phase 24 — Opaque Graphics Boundary Contracts

Protected targets `0x007A51B0` / `0x004A26B0` treated as **opaque**. No bodies recovered.

## Ordinary callers of `0x007A51B0`

- Count: **160**
- Dominant ABI: cdecl-like; cleanup `add esp, 0x14..0x20`; paired globals `0x017A9xxx` + `0x01278xxx`; size arg ∈ {1,4,8,12,16,20,28,32}
- Return: overwhelmingly **UNUSED** (void-like)

## Ordinary callers of `0x004A26B0`

- Count: **2** — renderer vector publication only

## METHOD ordinary prefixes

### METHOD_148 `0x007AD2D0`
- ABI: thiscall; no stack args; ret
- Reads: [this+0xC], renderer 0x017AA798, [renderer+0x19C], [renderer+0x118], [renderer+0x158]
- Record: {'id': 'SUBMIT_RECORD_148', 'size': 8, 'fields': {'+0x00': '[this+0xC] ASSOCIATED field / handle', '+0x04': 'uint32 1 or 2 from renderer LOD/visibility gate'}}
- Boundary args: ['arg0 size=8', 'arg1 &SUBMIT_RECORD_148', 'arg2 global 0x01278700', 'arg3 global 0x017A9684', 'arg4 this (iface)']
- Input/output: PARTIAL_VISIBLE_CONTRACT / NO_VISIBLE_OUTPUT

### METHOD_14C `0x007ADC20`
- ABI: thiscall; no stack args; ret
- Reads: [this+0xC], VT+0x68 float compare vs const
- Record: {'id': 'SUBMIT_RECORD_14C', 'size': 8, 'fields': {'+0x00/+0x04': 'includes [this+0xC] and selector 1|2 from VT+0x68 compare'}}
- Boundary args: ['arg0 size=8', 'arg1 record*', 'arg2 global 0x01278740', 'arg3 global 0x017A9BCC', 'arg4 this']
- Input/output: PARTIAL_VISIBLE_CONTRACT / NO_VISIBLE_OUTPUT

### METHOD_154 `0x007ADCC0`
- ABI: thiscall; no stack args; ret
- Reads: [this+0xC]
- Record: {'id': 'SUBMIT_RECORD_154', 'size': 4, 'fields': {'+0x00': '[this+0xC]'}}
- Boundary args: ['arg0 size=4', 'arg1 record*', 'arg2 global 0x012787B0', 'arg3 global 0x017A95D4', 'arg4 this', 'extra stack slot used for record materialization']
- Input/output: PARTIAL_VISIBLE_CONTRACT / NO_VISIBLE_OUTPUT

## Call-shape clusters

- **SUBMIT_SHAPE_A**: args=5 size=0x00000008 paired=True n=20 eg ['0x007A86E0', '0x007A9095', '0x007AACCD', '0x007AB32A', '0x007ABBB7']
- **SUBMIT_SHAPE_B**: args=5 size=0x00000008 paired=True n=9 eg ['0x007A8785', '0x007AC1CA', '0x007AC849', '0x007AD068', '0x007AD0BA']
- **SUBMIT_SHAPE_C**: args=5 size=0x00000004 paired=True n=8 eg ['0x007A87DC', '0x007A8846', '0x007A88BD', '0x007AC892', '0x007ACFB6']
- **SUBMIT_SHAPE_D**: args=0 size=? paired=False n=5 eg ['0x007A8804', '0x007AAAA3', '0x007AB623', '0x007AC6BB', '0x007ACF83']
- **SUBMIT_SHAPE_E**: args=5 size=0x00000004 paired=True n=2 eg ['0x007A887D', '0x007AE678']
- **SUBMIT_SHAPE_F**: args=6 size=0x00000001 paired=True n=10 eg ['0x007A88E4', '0x007A8904', '0x007A8924', '0x007A8944', '0x007A8964']
- **SUBMIT_SHAPE_G**: args=5 size=0x00000001 paired=True n=4 eg ['0x007A8A1C', '0x007A8A39', '0x007A8A56', '0x007B13A9']
- **SUBMIT_SHAPE_H**: args=8 size=0x0000000C paired=True n=4 eg ['0x007AAB15', '0x007ACF5A', '0x007AD72A', '0x007ADD53']
- **SUBMIT_SHAPE_I**: args=6 size=0x00000004 paired=True n=34 eg ['0x007AAB5A', '0x007AAB8A', '0x007AB65A', '0x007AB68A', '0x007AB6EA']
- **SUBMIT_SHAPE_J**: args=7 size=0x00000008 paired=True n=29 eg ['0x007AABC4', '0x007AABF4', '0x007AAC8E', '0x007AB55B', '0x007AB6C4']
- **SUBMIT_SHAPE_K**: args=5 size=0x00000014 paired=True n=3 eg ['0x007AB2AC', '0x007ABAAF', '0x007B0C7B']
- **SUBMIT_SHAPE_L**: args=6 size=0x00000004 paired=True n=6 eg ['0x007AB2DA', '0x007ABADA', '0x007AC24A', '0x007AD75A', '0x007AD7DA']
- **SUBMIT_SHAPE_M**: args=5 size=0x0000001C paired=True n=1 eg ['0x007AB4DB']
- **SUBMIT_SHAPE_N**: args=5 size=0x00000020 paired=True n=2 eg ['0x007AB809', '0x007AB986']
- **SUBMIT_SHAPE_O**: args=5 size=0x00000010 paired=True n=2 eg ['0x007ABA1D', '0x007B0FF8']
- **SUBMIT_SHAPE_P**: args=5 size=0x0000000C paired=True n=2 eg ['0x007ABB52', '0x007AC30C']
- **SUBMIT_SHAPE_Q**: args=6 size=0x00000004 paired=False n=1 eg ['0x007ABD6A']
- **SUBMIT_SHAPE_R**: args=5 size=0x0000000C paired=True n=11 eg ['0x007ABF2F', '0x007AC7A5', '0x007AC91D', '0x007AC96D', '0x007AC9B7']
- **SUBMIT_SHAPE_S**: args=5 size=0x00000014 paired=True n=2 eg ['0x007AC0E4', '0x007AC576']
- **SUBMIT_SHAPE_T**: args=7 size=0x00000008 paired=True n=1 eg ['0x007AC604']
- **SUBMIT_SHAPE_U**: args=8 size=0x0000000C paired=True n=3 eg ['0x007AD42B', '0x007AD48B', '0x007AD4EB']
- **SUBMIT_SHAPE_V**: args=6 size=0x00000008 paired=True n=1 eg ['0x007AECD2']

## Architecture decisions

- GRAPHICS_ARCHITECTURE: **ORDINARY_FRONTEND_PROTECTED_BACKEND**
- SAFE_RUNTIME_SEAM: **NO_MEANINGFUL_RENDER_SEAM**
- FIRST_FRAME: **FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND**
- D3D9 justified: **False**
- Backend adapter justified: **False**
- Further protected-backend analysis needed: **NO**

## Frame correlation

{'classification': 'NO_COMMON_ROOT_FOUND', 'frame_state_correlation': 'NO_RELATION_FOUND', 'shared_absolutes': [], 'note': 'METHOD_14x submit prefixes share no absolute globals with Present 0x00752AF0. Renderer global appears in methods only. Presentation remains raw-DEVICE; draw submission is opaque frontend→protected backend.', 'relationship_raw_vs_submit': 'NO_RELATION_FOUND', 'distinction': 'SHARED_CALL_GRAPH=no; SHARED_FRAME_STATE=no among inventoried absolutes'}

## Recommended Phase 25

EXPAND CPU/RUNTIME FIRST — first-frame draw path is blocked by protected submit. Ordinary work should focus on non-graphics runtime islands / Present-only host harness, not further protected-backend recovery.

---
**FIRST-FRAME PATH IS BLOCKED BY PROTECTED BACKEND**

