# NFS Undercover PC: static graphics investigation
Date: 2026-11-03. Target: nfs.exe, /nfs.exe, PE32 little-endian x86, base 0x00400000.
SHA256: 6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd.

## A. Executive summary

The target matched before investigation. This session retrieved 70 function addresses (69 returned decompilation, one was not defined), inspected selected complete disassemblies, and checked relevant references, imports and bounded static data. Counts describe retrieval, not proof that all decompiled paths are correct. No game code was executed; no Ghidra edits, scripts, patching, decryption, unpacking or protected implementation reconstruction occurred. This report concerns Undercover only. The implementation project was not inspected or changed.

Newly established:
- Graphics object storage extends through byte +0x534: minimum extent 0x535 bytes, not a proven exact allocation/sizeof.
- Requested and capability configurations share selected field offsets, but represent different values and are not interchangeable.
- Configuration +0x48 is AA tier; graphics-object +0x48 is the separate performance setting.
- AA fallback at 0x00729848–0x00729854 is c & (((int32)c > 0) - 1). For supported tiers 0..3 it produces zero, not tier-minus-one.
- Device creation uses vtable +0x40 twice: flags 0x40 first, then flags 0x20 and type 1 on a nonzero first result. Both use output address 0x013C6510.
- Presentation parameters occupy engine +0x130..+0x167. VSync nonzero selects interval 1; zero selects 0x80000000.
- Read-only references verify callback calls to message pumping, device-status checking, buffer processing, input processing and shutdown.
- Cleanup reaches another opaque/bad-instruction boundary at 0x0071E380. Its implementation was not pursued.

Status remains FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND. Device initialization evidence does not prove successful rendering or a runtime-ready recompilation.

Evidence labels: CONFIRMED = exact instructions/data/references; STRONGLY SUPPORTED = converging interpretation with a missing conclusive link; HYPOTHESIS = plausible but incomplete; BLOCKED = unavailable within current permitted inspection. A table may confirm storage while leaving its proposed semantic type only strongly supported. “Not established” does not mean absent.

## B. Graphics-object field map

Base G = 0x01318170. DWORD fields unless stated. Later-use function addresses identify retrieved functions; instruction addresses identify verified assembly. This is an observed layout, not a complete recovered class. Unlisted later writers remain unestablished.

|Offset|Address|Proposed type / initial value|Initializer|Later writers / readers|Confidence|
|---|---|---|---|---|---|
|+00|01318170|buffer-begin pointer = 0189BB18|007279CD|Window title reads [G] at 0072E51F; destructor uses begin/capacity|Storage CONFIRMED; string-like ownership STRONGLY SUPPORTED|
|+04|01318174|buffer-end pointer = 0189BB18|007279D4|Destructor buffer representation|Storage CONFIRMED; role STRONGLY SUPPORTED|
|+08|01318178|buffer-capacity/end pointer = 0189BB19|007279DB|00727B60 uses [G+08]-[G]|Storage CONFIRMED; role STRONGLY SUPPORTED|
|+10|01318180|interface pointer = 0|00727A49|0072E3C2 stores wrapper return; consumed by mode/caps/device calls; released 00727F9C|IDirect3D9 interpretation STRONGLY SUPPORTED|
|+14|01318184|D3DEngine pointer|00727AFF|0x1B8 allocation at 00727ACF, constructor 00724F90 at 00727AEA; many readers|Allocation call/ownership CONFIRMED; allocator opaque|
|+18|01318188|0, later window-like handle|00727A4F|0072E544 stores return; input setup reads global at 0073056B|Storage CONFIRMED; HWND STRONGLY SUPPORTED|
|+1C..+38|0131818C..013181A8|rectangle/state region; no constructor assignment established|Not established|Window continuation passes G+1C and G+2C to indirect calls|Region use CONFIRMED; detailed type HYPOTHESIS|
|+3C|013181AC|DWORD windowed flag = 0|00727A4C|Copied as bool to engine+198 at 00727B0C; rectangle and multisample readers|Storage CONFIRMED; Windowed STRONGLY SUPPORTED|
|+40|013181B0|status flag = 0|00727B3B|0072E5D0 stores result of 0071DD00 masked to byte|CONFIRMED storage; semantics unresolved|
|+44|013181B4|DWORD = 0|00727A52|No further semantic attribution|CONFIRMED|
|+48|013181B8|performance level = 0|00727A55|Registry g_PerformanceLevel store 0071E0C6; getter/setter selector 0xD|CONFIRMED|
|+4C|013181BC|scaled brightness/gamma setting|00727AA7|Getter/setter selector 0xB; calls 007530E0|Storage CONFIRMED; gamma role STRONGLY SUPPORTED|
|+50|013181C0|capability PCDisplayConfig* = 0|00727ACC|0072980C allocation result; 0072980F initializes; destructor frees 00727B97|CONFIRMED|
|+54|013181C4|requested PCDisplayConfig*|00727B19|Preset copy 00727B26; registry, clamping and setter; destructor frees 00727BA0|CONFIRMED|
|+58|013181C8|DWORD = 100|00727A8F|Role unestablished|CONFIRMED storage|
|+5C|013181CC|DWORD = 1|00727A96|Role unestablished|CONFIRMED storage|
|+60|013181D0|DWORD = 1|00727A99|Role unestablished|CONFIRMED storage|
|+64|013181D4|adapter ordinal = 0|00727A9C|Passed to IDirect3D9-shaped calls and CreateDevice path|STRONGLY SUPPORTED semantic type|
|+68..|013181D8..|adapter-identifier output region|Not established|0072B7D0 passes G+68 to vtable +14|STRONGLY SUPPORTED|
|+494|01318604|hardware identifier used for preset selection|Not established|00723610 compares against identifier tables|CONFIRMED use; exact hardware field unresolved|
|+4B4,+4B5,+4B6|01318624..26|three bytes = 0|00727AAA,00727AB0,00727AB6|Roles unresolved|CONFIRMED storage|
|+4B8|01318628|DWORD = 0; safe-mode override|00727ABC|0076CA20 recognizes safemode and sets global; 0072E340 selects preset|STRONGLY SUPPORTED meaning|
|+4BC|0131862C|byte = 0|00727AC6|00723A00 conditional indirect input/message call|CONFIRMED storage/use|
|+4C0/+4C4|01318630/34|DWORD pair 8,0|00727A19/00727A2F|Callback slot B615C4, IDs 3A at startup /3B cleanup|CONFIRMED|
|+4C8/+4CC|01318638/3C|DWORD pair 8,0|00727A1F/00727A35|Same callback, IDs 34/35|CONFIRMED|
|+4D0/+4D4|01318640/44|DWORD pair 18,0|00727A25/00727A3B|Same callback, IDs 32/33|CONFIRMED|
|+4E8/+4EC/+4F0|01318658/5C/60|three DWORD pointers = 0|007279E8/EE/F4|Destructor frees storage with 0xC-byte element stride|CONFIRMED; vector-like STRONGLY SUPPORTED|
|+4F8|01318668|float = 0|00727A41|0072E3E7 stores aspect-like result; 007237B0 compares mode width/height ratio|CONFIRMED storage; aspect STRONGLY SUPPORTED|
|+4FC|0131866C|byte = 0|00727B2B|0072E5D0 stores success of query type 9|CONFIRMED|
|+500..+52B|01318670..0131869B|embedded synchronization wrapper|LEA 00727A01, call 00727A0C|00977E20 initializes; destructor 00977400 at 00727BCA|CONFIRMED region; OS primitive unresolved|
|+530|013186A0|atomic DWORD = 0|00727B33/00727B39|0072E050 sets 1 on render thread; 00752AF0 reads global|CONFIRMED|
|+534|013186A4|byte = 1|00727B3E|0072E5D0 derives from requested +1C and +34|CONFIRMED|

Constructor is ECX-based, with EBP=ECX at 007279C7. The maximum direct member access is a byte at +534. Embedded wrapper 00977E20 initializes DWORDs through its +28, and byte +24, within the listed region.

Destructor 00727B60: frees +50 (00727B97), frees +54 (00727BA0), calls engine destructor 00725110 (00727BB1), frees engine (00727BB7), destroys embedded synchronization wrapper (00727BCA), frees 0xC-stride vector storage (00727C18), then conditionally frees title-like buffer (00727C43). All allocator/free implementations remain opaque. This destructor is separate from live-device shutdown.

## C. PCDisplayConfig layout

33 DWORDs = 0x84 bytes. Requested preset starts at 0x00BAAA48. Capabilities are separately allocated at 00729801, stored at G+50 at 0072980C. Both use identical offsets for fields explicitly handled by clamp 0071D7E0. This does not prove every remaining offset has the same semantic interpretation.

Registry strings are static evidence of setting names, not proof that unresolved indirect calls actually resolve to registry APIs. Stores listed below follow success tests in 0071DE60.

|Offset|Size|Meaning / setting name|Source instruction or supporting function|Confidence|
|---|---|---|---|---|
|00|4|unnamed quality/mode, getter/setter ID 7|00727D39; caps set to 2 at 00725C3E|CONFIRMED storage; name unresolved|
|04,08|4 each|unnamed capability-limited settings|00725C49,00725C4C; 0071D7E0|CONFIRMED storage|
|0C|4|derived reflection flag|00727D93; 00729750/00727FB0 derive from +2C|CONFIRMED relation|
|10|4|g_RoadReflectionEnable|0071DF46; setter 00727D2C|CONFIRMED|
|14|4|unnamed capability-limited setting|00725C4F; 0071D7E0|CONFIRMED storage|
|18|4|unnamed quality flag, ID 10|00727D5F; cap 1 at 00725C43|CONFIRMED storage|
|1C|4|g_SmokeEnable|0071E066; cap derived from engine+20 bit 17 at 00725C01|CONFIRMED|
|20|4|unnamed setting, ID 0x12|00727DAD|CONFIRMED storage|
|24|4|unnamed setting, ID 0x11|00727DA0; cap 1 at 00725C52|CONFIRMED storage|
|28|4|unnamed setting, ID 0xC|00727D6C; cap 1 at 00725C55|CONFIRMED storage|
|2C|4|g_WorldLodLevel|0071DF76; setter 00727D06; derived reflection controls in 00729750|CONFIRMED|
|30|4|not mapped|No semantic claim|BLOCKED|
|34|4|g_WorldFXLevel|0071DF16; setter 00727E1B|CONFIRMED|
|38|4|g_CarEffects, clamped 0..3|0071DECE,0071DEE6; setter 00727E34|CONFIRMED|
|3C|4|not mapped|No semantic claim|BLOCKED|
|40|4|unnamed setting, ID 0x1C|00727E4D|CONFIRMED storage|
|44|4|g_CarLodLevel|0071DFA6; setter 00727D1F|CONFIRMED|
|48|4|g_FSAALevel, tier 0..3|0071DFD6; setter 00727CEC; sample lookup 00722FF3|CONFIRMED|
|4C|4|g_RainEnable|0071E006; setter 00727D45|CONFIRMED|
|50|4|g_TextureFiltering|0071E036; setter 00727CD3; caps writes 00725C17/2B|CONFIRMED|
|54|4|unnamed setting, ID 9|00727D52; cap 1 at 00725C46|CONFIRMED storage|
|58|4|g_ShadowEnable|0071E142; cap 0 or 3 at 00725BF1|CONFIRMED|
|5C|4|derived reflection level, ID 0x18|00727DEE; 00727FB0|CONFIRMED relation|
|60|4|g_CarDamageDetail|0071E096; setter 00727DFB; capability value from CPUID bit at 00725C7E|CONFIRMED|
|64|4|g_ShaderDetailLevel, clamped 0..1|0071E171; setter 00727C8B|CONFIRMED|
|68|4|g_AudioDetail|0071E1BB; setter 00727C7E|CONFIRMED|
|6C|4|g_Width|0071E268; setter 00727DBA; presentation reads 00722F38|CONFIRMED|
|70|4|g_Height|0071E298; setter 00727DC7; presentation reads 00722F3D|CONFIRMED|
|74|4|g_Refresh|0071E2C8; mode selector 007237B0|CONFIRMED|
|78|4|FirstTime / preset-reset trigger|0071E1D0; 0072E340 tests and replaces requested preset|CONFIRMED storage; trigger STRONGLY SUPPORTED|
|7C|4|g_VSyncOn|0071E0F6; setter 00727CF9; interval store 00722FDE|CONFIRMED|
|80|4|not mapped|No semantic claim|BLOCKED|

g_PerformanceLevel is NOT config+48: 0071E0C6 writes [EBP+48] where EBP is the graphics object. g_Brightness also has a registry key; exact loader destination was not recovered here. g_AudioMode's exact destination remains unestablished.

0071D7E0 clamps requested fields to capability values. Inspected offsets: 00,04,08,0C,10,14,18,24,28,2C,48,4C,50,54,58,60,1C. Comparisons at 18,28,4C,54 and1C use unsigned values in the retrieved code; others use signed minima. It does not clamp every DWORD, nor does it copy the entire structure.

00723610 chooses preset index 0/1/2 from G+494 identifier tables, with an opaque system-info adjustment; a nonzero supplied override immediately selects 0. In 0072E340, requested +78 !=0 OR G+4B8 !=0 causes a complete 0x84-byte preset copy AFTER settings loading. This can overwrite loaded values.

00729750 / 00727FB0 transform requested +2C into (+5C,+0C): 0 -> (0,0), 1 -> (1,0), other -> (2,1). This relationship is confirmed even though the intuitive setting names do not explain it.

## D. Startup call graph

Arrows below are ordinary direct calls unless marked callback/indirect. Prior-session constructor wrapper evidence is retained and distinguished from new assembly retrieval.

1. Static initializer pointer 00B62C10 -> wrapper 00B4FB60 [prior verified]. Wrapper supplies ECX=01318170 and calls constructor at 00B4FB65; callback-shaped destructor registration is at 00B4FB6A/6F. Exact CRT dispatcher remains BLOCKED.
2. 0076CA20 -> 009782D0 at 0076CB45, with callback address 00766730 pushed at 0076CB40. Thread wrapper stores callback/argument state and calls 00AE5068, then resumes through unresolved slot B61114. Confirmed thread abstraction; exact imported thread-creation API unresolved.
3. Callback 00766730 initializes TLS/thread identity, then calls 0072E5D0 at 00766773. The callback is not defined as a Ghidra function; bounded bytes and existing call xrefs establish these sites.
4. 0072E5D0 waits until [01311E1C]==1; repeated calls to 009773B0 at 0072E5FD. That helper invokes unresolved slot B61188 with (*arg,1). Do not label it SleepEx conclusively.
5. 0072E612 -> 0072E340. If AL !=0, 0072E621 -> 007297D0; otherwise skips the later initialization block.
6. 0072E340: callback registrations B615C4; 0072E3B9 -> 0087A79C (SDK argument 0x20), result stored G+10 at 0072E3C2; 0072E3DA -> 0072B7D0; no modes produces the error path. 0072E410 loads settings; optional preset reset; 0072E454 applies derived settings; 0072E46A selects mode; class-registration-shaped call at 0072E4DA; window-creation-shaped call at 0072E53D; return stored at 0072E544.
7. 007297D0: allocate capabilities (00729801); initialize (0072980F -> 00725BB0); clamp (0072981E -> 0071D7E0); device attempt (00729836 -> 00725200); on nonzero result adjust AA then retry at 0072986A.
8. Resource initialization: 00729872 -> 00768590; query creation at 00729891; query issue at 0072989D; gamma 0072989F -> 0075F240; additional manager calls 007298E8,007298F5,007298FA,007298FF,00729904; 1x1 texture creation at 00729927; fill helper 0072993D; buffer-manager allocation 0072994E and constructor 00729968.
9. 0072996D loads 2; 00729972 loads address 01311E1C; 00729977 XCHG publishes state 2. This proves publication ordering in instructions, not that device creation succeeded.
10. Back in startup: input initialization 0072E65F -> 007304D0; query type9 at 0072E676; feature flags and 0072E6D3 -> 00731B30.

Callback loop edges verified by xrefs:
- 007667B3 and 00766819 -> 00723A00, message-pump-shaped routine.
- 007667FB -> 0071E630, device vtable+0C status query; return stored engine+194.
- Status comparison against 0x88760869 precedes 00766807 -> 0072E5C0 (previously verified forwarding to 0072E050).
- Negative HRESULT skips the ordinary success-side resource-processing block.
- 00766833 -> 007661A0, queued buffer work; 00766890 -> 00730450, input-edge processing.
- 00766931 -> 00727F40 on callback exit.

The signaled-object/queue logic uses globals 013C6564, 01797020..38 and unresolved synchronization slots. Do not flatten this into a verified complete frame scheduler. A complete call chain from callback to the protected submission backend has not been proven.

## E. Win32 API findings

Confirmed imported symbols include CreateWindowExA (EXTERNAL:000000F7), RegisterClassExA (F8), UpdateWindow (F6), DestroyWindow (E5), ShowWindow (00000108), plus ordinary event/thread APIs. Their existence does not establish the identity of historical B615xx slots.

Prior verified slots:
- B6157C -> static 008AA540; 0072E53D prepares 12 arguments matching CreateWindowExA. STRONGLY SUPPORTED identity; no reliable slot-to-import connection.
- B61578 -> static 008AA530; 0072E547 explicitly passes one EAX value. UpdateWindow is HYPOTHESIS; ShowWindow is not supported by its two-argument signature.
- The one-argument target has a conflicting apparent stack contract beyond Ghidra's defined body. Do not use the misleading static target as a working Win32 adapter.

Window class preparation: 0072E487 writes size 0x30; 0072E48F writes style 0x40; 0072E497 writes callback address 0072B170; 0072E4CE supplies class-name address 00BABB28 ("GameFrame"). The registration-shaped indirect call is 0072E4DA through B61580. 0072B170 is not defined as a function; its bounded entry bytes show stack arguments and message dispatch, but a complete WndProc implementation was not recovered.

Twelve window-call values (semantic parameter names remain conditional on API identity):
exstyle=0; class="GameFrame"; title=[G]; style=ESI; x=rect.left; y=rect.top; width=right-left; height=bottom-top; parent=0; menu=0; instance=prior ECX value; parameter=0.
Push addresses respectively: 0072E53C,537,536,535,534,533,532,52B,528,527,522,521.

0072DF90 initializes rectangle origin to (100,100), derives dimensions from selected mode when G+3C==0 or requested +6C/+70 otherwise, then forms right/bottom. It calls unresolved style helpers 0072DDC0/0072DE20 and indirect B6155C. Exact style bits and adjusted final dimensions are BLOCKED at those dependencies; 0x80C00000 occurs as an input, not a proven final style.

G+18 is written with the EAX result regardless of a visible immediate null test in that continuation. Subsequent indirect operations use G+18 and rectangle output pointers. The caller's apparent success AL at the end does not establish successful CreateWindowExA behavior. Cleanup ends with an indirect one-argument call through B61534 at 00727FA2; DestroyWindow is a candidate, not a confirmed mapping.

## F. Direct3D9 findings

### Interface identity and creation

0072E3B9 calls 0087A79C with argument 0x20, storing the result at G+10. 0087A79C forwards through B616CC, whose static value is 008AA1C4. The actual Direct3DCreate9 import is independently referenced at 022CDB73. No static link from B616CC to that import is confirmed. SDK value plus coherent interface use makes IDirect3D9 STRONGLY SUPPORTED.

The engine at G+14 contains caps at its beginning, selected mode index at +180, and mode-vector begin/end/capacity at +184/+188/+18C. Mode records have stride 0x1C; +00 width, +04 height, +08 refresh, +0C adapter ordinal, +10..18 format-related fields.

### Vtable interpretations

Exact offsets/call sites are CONFIRMED; method names below are STRONGLY SUPPORTED standard-layout interpretations until interface provenance is conclusively resolved.

|Interface source|Offset|Method interpretation|Evidence|
|---|---|---|---|
|G+10|+10|GetAdapterCount|0072524C|
|G+10|+14|GetAdapterIdentifier|00725261; NVIDIA PerfHUD comparison|
|G+10|+18|GetAdapterModeCount|0072B048, format 0x16|
|G+10|+1C|EnumAdapterModes|0072B075|
|G+10|+24|CheckDeviceType|0072B0B5|
|G+10|+28|CheckDeviceFormat|00723720,007254xx|
|G+10|+2C|CheckDeviceMultiSampleType|0071DC30/55/73|
|G+10|+30|CheckDepthStencilMatch|00723720|
|G+10|+38|GetDeviceCaps|0072B7D0|
|G+10|+40|CreateDevice|007252CF,007252F5|
|013C6510|+08|Release|00727F31|
|013C6510|+0C|TestCooperativeLevel|0071E630|
|013C6510|+44|Present|00725350, zero arguments after interface|
|013C6510|+5C|CreateTexture|00754785,00729927|
|013C6510|+70|CreateRenderTarget|007540E0|
|013C6510|+74|CreateDepthStencilSurface|007547CE|
|013C6510|+A4/+A8/+AC|BeginScene/EndScene/Clear|00725200 success branch|
|013C6510|+E4|SetRenderState|00725200|
|013C6510|+1D8|CreateQuery|00729891,0072E676|

Device-side vtable offsets must not be decoded using the IDirect3D9 layout.

0072B030 enumerates 0x16 modes and filters width/height against a 15-pair table at 00BAA9B0 (0x78 bytes). Accepted records require a nonnegative CheckDeviceType-shaped result and enter a vector; sorting/uniquing helpers follow. Its decompilation has unassigned-register artifacts, so copying its C literally is unsafe.

007237B0 defaults zero inputs to 640x480 at 60 Hz, first seeks exact width/height/refresh, then scans backwards for aspect difference <= the float at 00B64D88 and pixel count >0x3E7FF, otherwise picks the last record. The tolerance's numeric value was not read. No empty-vector safety should be invented; an empty vector can yield index -1.

### Presentation parameters

Base P=engine+130; 00722EC0 zeroes 0x38 bytes only when selected index >=0. If index is negative, it returns without initializing this region.

|P offset|Engine offset|Field interpretation / assigned value|Write evidence|
|---|---|---|---|
|00|130|BackBufferWidth: selected mode or requested +6C when windowed|00722F3B/00722F50|
|04|134|BackBufferHeight: selected mode or requested +70|00722F5A|
|08|138|BackBufferFormat: selected record +18|00722F91|
|0C|13C|BackBufferCount=1|0072300A|
|10|140|MultiSampleType=table[requested+48]|00722FF3/00722FFA|
|14|144|MultiSampleQuality=0|00723000|
|18|148|SwapEffect=3 under capability/mode/AA condition, otherwise1|00722F7F/00722F8B|
|1C|14C|hDeviceWindow=engine+19C|00722FE4/00722FEA|
|20|150|Windowed=byte engine+198 widened|00722F63|
|24|154|EnableAutoDepthStencil=1|00722F97|
|28|158|AutoDepthStencilFormat=0x4B or0x50 depending global01311CE0|00722FA3..00722FAF|
|2C|15C|Flags=0; windowed ->4|00722FB6/00722FC3|
|30|160|FullScreen_RefreshRateInHz=mode refresh; windowed ->0|00722F2E/00722F46|
|34|164|PresentationInterval=requested VSync !=0 ?1:80000000|00722FD0..00722FDE|

Storage and arithmetic are CONFIRMED; D3DPRESENT_PARAMETERS interpretation STRONGLY SUPPORTED. hDeviceWindow is sourced from engine+19C, initialized from the constructor's handle argument (then zero); later update of engine+19C is NOT established. CreateDevice also receives the later G+18 handle separately. Preserve that distinction.

SwapEffect=3 requires engine low capability bit 0x20 clear, engine+174==0 and requested AA<=0; otherwise1. Numeric enum names are not necessary to implement the observed builder.

AA table at 00CE6A54 is [0,2,4,8]. 0071DC10 checks sample count against formats 0x4B,0x16,0x15, type1, adapter G+64, Windowed=G+3C, quality-output=null. 0071DC80 probes 2, then4, then8 and returns the highest contiguous tier0..3, stopping on first failure.

### Creation, retries and failure caveat

00725200 receives engine in ECX and four stack arguments: D3D9-like interface, adapter ordinal, focus handle, config. It returns EAX=EBX at 0072548A and RET 0x10 at 0072549A, unlike Ghidra's void pseudocode signature.

The PerfHUD loop uses adapter count/identifier calls; matching "NVIDIA PerfHUD" changes the adapter and device type to2. Normal type starts at1.
- 007252CF: CreateDevice-shaped call(interface,adapter,type,handle,0x40,P,&013C6510).
- If its HRESULT is nonzero, 007252F5 retries with original adapter, type1, same handle, flags0x20, same P/output.
- Zero result reaches scene/clear/present calls. State-cache invalidation and later device dereferences occur after the branch merge at 00725352. A safe failure-return path must not be inferred from the pseudocode.
- Outer 00729836 call is tested at 0072983B. Nonzero runs AA masking and a second call at 0072986A. Its result is not checked before resource initialization at 00729872.

Capability follow-up includes shader-profile scanning 0071D300; unresolved profile wrappers prevent isolated semantic validation. 00723720 combines format/depth-match tests for format0x72 and depth0x4B. 00722DB0 contains "AllowR32FAA"/"ForceR32AA" paths, a multisample-shaped check, and vendor-specific behavior; decompiler local/stack anomalies prevent promoting its exact override logic to confirmed behavior.

## G. Recompilation readiness

Ready for isolated implementation from ordinary static logic, with explicit dependency injection and synthetic tests (not game execution):
- 0071D7E0: config clamp; ECX not required by its logic, two stack pointers, RET8. Inputs/output buffers only; no calls. Validate signed/unsigned cases and untouched fields.
- 00723790: selected-mode pointer = vectorBegin + index*0x1C. ECX graphics object; no calls. Caller must satisfy valid-index precondition.
- 007237B0: mode selection; ECX graphics object, three inputs; ordinary arithmetic, mode vector and tolerance global. Validate exact-match/default/aspect/fallback cases.
- 00727FB0: reflection-field derivation; ECX graphics object, one setting; no calls.
- 007530D0: float constant getter from 00BADEAC. Numeric constant still needs a bounded static read before literal implementation.
- 007530E0: clamps supplied float to [0,global1], updates 00CF3EC8 and dirty byte through ECX. Read constants before naming the formula.
- 0071D8F0: setting getter; ECX object and selector. No indirect dependencies in the getter.
- 00727C60: setter is partly ready; several selectors have side-effect calls, so implement only verified cases or preserve injected callbacks.
- 00722EC0: parameter builder is suitable for fake-engine/config fixtures; requires an explicit zero-memory dependency and static enum/numeric mapping, not a real D3D device.

Integration-dependent candidates:
- 0071DC10/80: inject a fake D3D9-shaped interface to validate probe order and stopping behavior.
- 007428B0: validates release order with fake COM objects. It skips releasing member+0C for resource types1 and6, releases +08/+10 when present, and clears active byte+20.
- 00754740: ECX resource descriptor + eight stack args, RET20; texture/surface/depth creation with cleanup on failure. Assembly corrects misleading decompiler register names.
- 00730450: input-edge bookkeeping, but its ECX object is the separate input object (callback supplies 01321188), NOT the graphics object. Do not transplant its +1C/+20..28 writes into G.
- 007661A0: queue-processing entry uses buffer-manager object from global0179F2DC; contains locks, COM lock/unlock-shaped calls and copy helper. Not a pure utility and not frame submission.
- 007408D0: TLS +0C compared with render-thread identifier013C6570; usable once TLS contract is modeled.
- 009782D0 and synchronization wrappers: lifetime/refcount structure visible, OS-slot resolution missing.

No runtime claim or build/test result is made. No recompilation project code was modified.

## H. Remaining blockers

Missing evidence:
- Exact graphics-object size, all writers and complete class/string layout.
- Complete WndProc, callback function boundaries and exact static-initializer dispatcher.
- Numeric constants and full schema for config00..80.
- Later engine+19C handle update; exact final window style and runtime failure semantics.
- Complete callback-to-first-frame submission chain.

Unresolved indirect calls:
- B615xx Win32/callback slots and B616CC interface factory slot; confirmed imports elsewhere do not repair their static values.
- Sync/native-thread wrappers; some helpers have incorrect Ghidra no-return/function-boundary metadata.
- Shader profile wrappers and application-managed globals.

Protected/opaque boundaries:
- 00686000 allocator,00686030 free, B615C4 callback source.
- 0071E380 returns bad-instruction decompilation: stop; do not treat pseudocode as behavior.
- 004A26B0 graphics backend: direct references at 007A416C and007AFC67. Accessible callers 007A40D0/007AF900 prepare application objects but cross this boundary.
- 007A51B0 submission: 152 incoming references retrieved over two pages. Examples007A86E0/007A8785 from accessible wrappers gated by global017AA798. Their decompilation has unassigned stack-return artifacts; not isolated-ready.
- No implementations behind these boundaries were inspected or reconstructed.

Device lifecycle:
00727F40 first calls input cleanup0072E8D0 (00727F49); makes unregister-shaped opaque callbacks (00727F5F/6C/79); calls opaque0071E380 (00727F86); calls resource/device cleanup00727ED0 (00727F8E); releases G+10 (00727F9C); then invokes B61534 on G+18 (00727FA2).
00727ED0 releases engine query+168 at00727F15, zeroes that field, and releases global device at00727F31. Its retrieved body does not zero013C6510 afterwards. Do not infer repeated cleanup is safe.
0072E050, when invoked on render thread, sets G+530=1 and returns; otherwise clears013186D4, waits for013186D8==0 and runs resource cleanup before a window-operation-shaped call. It is not proven to implement a complete IDirect3DDevice9::Reset recovery.
0072E8D0 unacquires/releases01321140, then releases0132113C, zeroing both. Its startup counterpart007304D0 uses +18 window-like handle, COM calls and0x800 version: DirectInput interpretation strongly supported, slot linkage incomplete.

## I. Prioritized next actions

1. Implement/test the pure configuration clamp and getter, preserving signedness, unknown fields and distinct object/config +48. Highest-confidence work.
2. Implement the AA sample table/probe policy and exact outer fallback expression. Use injected interfaces and synthetic HRESULT sequences.
3. Implement presentation-builder fixtures from engine+130 layout. Preserve negative-selected-index early return and windowed/fullscreen refresh rules.
4. Implement mode record/selection logic with explicit preconditions. Keep unknown format fields numeric.
5. Add a reviewed API boundary layer for factory/window/sync dependencies. Do not auto-map historical slots by similar argument patterns.
6. Model requested, capability and selected-mode data separately; include full-preset replacement after settings loading.
7. Implement mock resource cleanup/ownership tests before device integration. Keep input object distinct from graphics object.
8. Keep protected allocator/backend/submission calls opaque and track them explicitly. Preserve FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND until an authorized, independently verified implementation dependency changes.
9. Research unresolved ordinary metadata/data connections and constants, without modifying Ghidra or crossing protected implementations. Existing mis-sized function bodies require careful manual static evidence, not copying decompiled C.

## J. Machine-readable evidence index

See undercover-graphics-evidence-2026-11-03.json beside this report. It records retrieved function addresses, 202 assembly/xref-backed call sites, constructor writes, config setter writes, presentation writes, confirmed imports, slots and confidence classes. It deliberately omits binary byte blocks and opaque implementations. Function retrieval is distinguished from successful decompilation; a retrieved decompilation is not a certification of correctness. This report supplies semantic interpretation and limitations that the compact instruction index alone cannot express.

