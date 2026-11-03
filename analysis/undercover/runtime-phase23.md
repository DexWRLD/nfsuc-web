# Runtime Phase 23 — Renderer Vector Insertion & Interface Provenance

Primary direction: Draw consumer ← vector element ← insertion ← iface construction ← vtable ← methods.

## A. Vector insertion sites

- Count: **2** (confidence **STRONG**)
- Strongest: **INSERT_SITE_A**
- Classic inlined `end+=8` push_back sites in ordinary .text: **0**
- Insert primitive `0x004A26B0`: body **ENCRYPTED_OR_INVALID** (encrypted .text island)

### INSERT_SITE_A — `0x007A40D0` (VECTOR_INSERT_STRONG)
- Range: ['0x007A415F', '0x007A416C']
- Renderer: ECX/EDI = renderer this (caller 0x007B3F71 with ECX=renderer)
- +0x00: {'reg': 'EBX', 'provenance': 'FACTORY_DERIVED_POINTER', 'path': 'arg0 VT+0x04 then VT+0x34 -> EBX', 'detail': 'mov ecx,[esp+0x20]; call [eax+4]; call [eax+0x34]; mov ebx,eax'}
- +0x04: {'reg': 'ESI', 'provenance': 'ORDINARY_CONSTRUCTOR_RETURN', 'ctor': '0x007A1A20', 'vtable_write': 'mov [esi], 0xBB1AAC after ctor', 'alloc': 'pool via 0x004AC400 on renderer+0x25C or global 0x012A78A0'}
- ABI: `push ESI(+0x04); push EBX(+0x00); lea ecx,[edi+0x50]; call 0x4A26B0`

### INSERT_SITE_B — `0x007AF900` (VECTOR_INSERT_STRONG)
- Range: ['0x007AFC3E', '0x007AFC67']
- Renderer: EDI holds renderer (vector at edi+0x50)
- +0x00: {'reg': 'EAX from [esp+0x20]', 'provenance': 'CALLER_SUPPLIED_POINTER', 'detail': 'push esi; push eax; mov ecx, &vector; call insert'}
- +0x04: {'reg': 'ESI', 'provenance': 'ORDINARY_CONSTRUCTOR_RETURN', 'ctor': '0x007A1A20', 'pre_call': 'VT+0x200 on new iface before insert'}
- ABI: `push ESI(+0x04); push EAX(+0x00); ecx=&(edi+0x50)`

## B. Vector mutation routines

- `0x007A45B0` — **VECTOR_CLEAR** — zeros begin/end/capacity; calls reserve helper
- `0x004A2AA0` — **VECTOR_REALLOC** — capacity ensure used on temp vectors (VT 0xBB1914 wrapper) and ctor-adjacent inits
- `0x007A6510` — **VECTOR_ERASE** — size=(end-begin); lea ecx,&vector; falls into/calls erase helper 0x4A1FF0
- `0x007A06E0` — **VECTOR_CLEAR** — walk begin..end; VT+0 push1 deleting dtor on [elem+4]; end=begin
- `0x007A0C10` — **VECTOR_CLEAR** — same owned teardown as dtor loop without freeing buffer

## C. Element +0x00

- Classification: **ASSOCIATED_OBJECT_POINTER** (STRONG)
- Not a boolean for `0x0079E4A0` filters.
- Role subtype: UNKNOWN_SUBTYPE

## D. Element +0x04

- **ENGINE_GFX_IFACE_00** — ORDINARY_CONSTRUCTOR 0x007A1A20 -> vtable 0x00BB1AAC

## E. Insertion callers

- Site A caller: `0x007B3F71` (renderer method path in `0x007B36A0` band)
- Site B: internal to `0x007AF900`

## F–H. Interface instances / constructors / lifecycle

- Construction: **ORDINARY_CONSTRUCTED** via `0x007A1A20`
- Final vtable: `0x00BB1AAC` (**STATIC**)
- Allocation: {'primary': '0x004AC400 against renderer+0x25C pool', 'fallback_global': '0x012A78A0', 'class': 'ORDINARY_ALLOCATOR_WRAPPER'}
- Ownership: **OWNED_ENGINE_OBJECT**

## I–J. Vtable publication

- Static table `0x00BB1AAC` in `.rdata`
- Vtable pointer writes observed: 3
- Classification: STATIC (not dynamic/import/protected table)

## K–M. Method slots / implementations / backend

- `0x00000148` `ENGINE_GFX_METHOD_148` → `0x007AD2D0` (**ORDINARY_TEXT_TARGET**)
  - submit `0x7A51B0`: True (ENCRYPTED_ENTRY_JMP)
  - terminus: **PROTECTED_BOUNDARY**
- `0x0000014C` `ENGINE_GFX_METHOD_14C` → `0x007ADC20` (**ORDINARY_TEXT_TARGET**)
  - submit `0x7A51B0`: True (ENCRYPTED_ENTRY_JMP)
  - terminus: **PROTECTED_BOUNDARY**
- `0x00000154` `ENGINE_GFX_METHOD_154` → `0x007ADCC0` (**ORDINARY_TEXT_TARGET**)
  - submit `0x7A51B0`: True (ENCRYPTED_ENTRY_JMP)
  - terminus: **PROTECTED_BOUNDARY**

Deepest chain: `ENGINE_GFX_IFACE_00 -> METHOD_14x -> submit_0x7A51B0[ENCRYPTED] -> PROTECTED_BOUNDARY`

## N. Raw-device relationship

- NO_RELATION_FOUND_IN_METHODS
- Raw-device Draw: **NO**; ordinary D3D9 wrapper: **NO**

## O. Renderer ctor/dtor ownership

- Ctor vector: {'site': '0x007B50DB..0x007B50E6', 'push': '0x0A', 'ecx': 'lea ecx,[esi+0x50]', 'call': '0x007A45B0', 'behavior': 'zeros +0x50/+0x54/+0x58 then calls reserve 0x6CA7C0', 'initial_elements_inserted': False, 'reserve_body': 'ENCRYPTED_OR_INVALID'}
- Dtor vector: {'walk': 'edi=begin; while edi!=end; iface=[edi+4]; if iface: VT+0(push 1)', 'then': 'end=begin (0x007A077A)', 'buffer_free': 'later heap free of begin storage (existing Phase22)', 'element_cleanup': 'VIRTUAL_DELETING_DTOR'}

## P. `0x00686030`

- {'va': '0x00686030', 'classification': 'EXTERNAL_PROTECTED_FREE_HELPER', 'abi_observed': 'cdecl; push ptr; call; add esp,4', 'body_class': 'ENCRYPTED_OR_INVALID', 'body_bytes': '0dbb6f13c788c7c6c85652bc0f7f4997', 'note': 'Unresolved sibling of frozen 0x00686000; used on renderer scalar-deleting paths (e.g. 0x007A2FA0) and other object teardown. Not implemented.', 'caller_count': 799, 'callers_sample': ['0x006E5AC9', '0x006EA9E1', '0x006FAC3F', '0x006FAC45', '0x00701BC0', '0x00701C1C', '0x00701C81', '0x00701D37', '0x0070AA62', '0x0070DE60', '0x00710728', '0x00710808'], 'not_automatically_equivalent_to': '0x00686000'}

## Q. Allocation provenance

- {
  "renderer_vector_buffer": {
    "via": "0x006CA7C0",
    "class": "PROTECTED_ALLOCATOR",
    "body": "ENCRYPTED_OR_INVALID"
  },
  "interface_object": {
    "via": "0x004AC400 / 0x012A78A0",
    "class": "ORDINARY_ALLOCATOR_WRAPPER"
  },
  "submit_helper": {
    "va": "0x007A51B0",
    "class": "ENCRYPTED_ENTRY_JMP",
    "bytes": "6affe9e289c9ff64"
  },
  "insert_helper": {
    "va": "0x004A26B0",
    "class": "ENCRYPTED_OR_INVALID",
    "bytes": "ddf1c58a6f91cf00"
  }
}

## R. angr consensus

- {'UC': 'MIXED_INTERFACE_PUBLICATION', 'ANGR': 'ORDINARY_INTERFACE_PUBLICATION_VISIBLE', 'CONSENSUS': 'UC=MIXED_INTERFACE_PUBLICATION; ANGR=ORDINARY_INTERFACE_PUBLICATION_VISIBLE', 'angr_materially_helped': True, 'strongest_angr_finding': {'va': '0x0079E4A0', 'role': 'selector', 'note': 'coherent decompile'}}

## S. Interface graph v2

- Written to `analysis/undercover/renderer-interface-graph.json`

## T–V. Publication / boundary / seam

- INTERFACE_PUBLICATION: **MIXED_INTERFACE_PUBLICATION**
- GRAPHICS_BOUNDARY: **PROTECTED_ENGINE_BACKEND_BOUNDARY**
- POST_INIT_SEAM: **PARTIAL_POST_INIT_SEAM**
- D3D9 justified: **False**
- Engine backend adapter justified: **False**

## W. First-frame estimate

- BEST_CASE: **UNBOUNDED**
- LIKELY: **UNBOUNDED**

## X. Recommended Phase 24

EXPAND POST-INIT GRAPHICS ANALYSIS — resolve encrypted .text islands that host vector insert/submit without unpacking SecuROM sections; map submit queue globals (0x017A9684 / 0x01278700 family) and any post-decrypt ordinary continuations

---

**EXPAND POST-INIT GRAPHICS ANALYSIS**

