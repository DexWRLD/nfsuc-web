"""Phase 43: verified Undercover graphics/config ordinary-code models.

Pure synthetic reimplementations from November 3, 2026 Ghidra evidence and
ordinary .text static reads. No game execution, no protected allocator/backend,
no real D3D9 device. FIRST_FRAME remains blocked.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Tuple

# --- Constants (CONFIRMED ordinary evidence) ---------------------------------

GRAPHICS_OBJECT_BASE = 0x01318170
GRAPHICS_OBJECT_MIN_EXTENT = 0x535  # byte +0x534 accessed; exact sizeof BLOCKED
PCDISPLAYCONFIG_SIZE = 0x84
MODE_RECORD_STRIDE = 0x1C
PRESENT_PARAMS_ENGINE_OFF = 0x130
PRESENT_PARAMS_SIZE = 0x38
AA_SAMPLE_TABLE_VA = 0x00CE6A54
AA_SAMPLES = (0, 2, 4, 8)
ASPECT_TOLERANCE = 0.001  # dword at 0x00B64D88
PIXEL_COUNT_MIN = 0x3E800  # cmp/jae threshold; above 0x3E7FF
DEFAULT_WIDTH = 0x280  # 640
DEFAULT_HEIGHT = 0x1E0  # 480
DEFAULT_REFRESH = 0x3C  # 60
DEVICE_OUT_GLOBAL = 0x013C6510
DEPTH_STENCIL_GLOBAL = 0x01311CE0

# Graphics-object +0x48 = performance level; config +0x48 = FSAA tier.
GOFF_PERF_LEVEL = 0x48
CFG_FSAA = 0x48

# Clamp field policy for FUN_0071D7E0 (stack: caps, requested; RET 8).
CLAMP_SIGNED = (
    0x00, 0x04, 0x08, 0x0C, 0x10, 0x14, 0x24, 0x2C, 0x48, 0x50, 0x58, 0x60,
)
CLAMP_UNSIGNED = (0x18, 0x28, 0x4C, 0x54, 0x1C)

# Getter FUN_0071D8F0: selector IDs 1..30 after (id-1) jump. ("obj", off) or ("cfg", off).
GETTER_SELECTORS: Dict[int, Tuple[str, int]] = {
    1: ("cfg", 0x50),
    2: ("cfg", 0x48),
    3: ("cfg", 0x7C),
    4: ("cfg", 0x2C),
    5: ("cfg", 0x44),
    6: ("cfg", 0x10),
    7: ("cfg", 0x00),
    8: ("cfg", 0x4C),
    9: ("cfg", 0x54),
    10: ("cfg", 0x18),
    11: ("obj", 0x4C),
    12: ("cfg", 0x28),
    13: ("obj", 0x48),
    14: ("cfg", 0x58),
    15: ("cfg", 0x78),
    16: ("cfg", 0x0C),
    17: ("cfg", 0x24),
    18: ("cfg", 0x20),
    # 19 -> default zero (table points at ret)
    20: ("cfg", 0x6C),
    21: ("cfg", 0x70),
    22: ("cfg", 0x74),
    23: ("cfg", 0x1C),
    24: ("cfg", 0x5C),
    25: ("cfg", 0x60),
    26: ("cfg", 0x34),
    27: ("cfg", 0x38),
    28: ("cfg", 0x40),
    29: ("cfg", 0x64),
    30: ("cfg", 0x68),
}

PROTECTED_BOUNDARIES = (
    0x00686000,
    0x00686030,
    0x00B615C4,
    0x004A26B0,
    0x007A51B0,
    0x0071E380,
)

FIRST_FRAME_STATUS = "FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND"


def u32(v: int) -> int:
    return v & 0xFFFFFFFF


def i32(v: int) -> int:
    v = u32(v)
    return v - 0x100000000 if v >= 0x80000000 else v


def dword_view(buf: bytearray, off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]


def set_dword(buf: bytearray, off: int, val: int) -> None:
    struct.pack_into("<I", buf, off, u32(val))


def make_config(initial: Optional[Dict[int, int]] = None) -> bytearray:
    buf = bytearray(PCDISPLAYCONFIG_SIZE)
    if initial:
        for off, val in initial.items():
            set_dword(buf, off, val)
    return buf


# --- FUN_0071D7E0: clamp requested against capabilities ---------------------

def clamp_pc_display_config(caps: bytearray, requested: bytearray) -> None:
    """Mutate requested in place. Does not touch caps. Field-specific signedness."""
    if len(caps) < PCDISPLAYCONFIG_SIZE or len(requested) < PCDISPLAYCONFIG_SIZE:
        raise ValueError("PCDisplayConfig buffers must be 0x84 bytes")

    def clamp_one(off: int, unsigned: bool) -> None:
        req = dword_view(requested, off)
        cap = dword_view(caps, off)
        if unsigned:
            if u32(cap) < u32(req):
                set_dword(requested, off, cap)
        else:
            if i32(cap) < i32(req):
                set_dword(requested, off, cap)

    for off in CLAMP_SIGNED:
        clamp_one(off, False)
    for off in CLAMP_UNSIGNED:
        clamp_one(off, True)


# --- AA fallback at 0x00729848–0x00729854 -----------------------------------

def aa_fallback_mask(capability_aa_tier: int) -> int:
    """Exact: c & (((int32)c > 0) - 1). Valid tiers 0..3 yield 0."""
    c = i32(capability_aa_tier)
    mask = (1 if c > 0 else 0) - 1
    return u32(c & mask)


# --- AA sample table / probe FUN_0071DC10 / FUN_0071DC80 --------------------

AA_PROBE_FORMATS = (0x4B, 0x16, 0x15)
AA_PROBE_SAMPLES = (2, 4, 8)  # tiers 1,2,3


@dataclass
class FakeD3D9:
    """Injected IDirect3D9-shaped MultiSample probe. Keys: (adapter, samples, fmt)."""
    results: Dict[Tuple[int, int, int], int] = field(default_factory=dict)
    calls: List[Tuple[int, int, int, int, int]] = field(default_factory=list)

    def check_device_multisample_type(
        self,
        adapter: int,
        device_type: int,
        fmt: int,
        windowed: int,
        samples: int,
        quality_out_null: int,
    ) -> int:
        self.calls.append((adapter, device_type, fmt, windowed, samples))
        return self.results.get((adapter, samples, fmt), -1)


def check_multisample_supported(
    d3d: FakeD3D9,
    adapter: int,
    windowed: int,
    samples: int,
) -> bool:
    """FUN_0071DC10: all three formats must return HRESULT >= 0."""
    for fmt in AA_PROBE_FORMATS:
        hr = d3d.check_device_multisample_type(
            adapter, 1, fmt, windowed, samples, 0
        )
        if i32(hr) < 0:
            return False
    return True


def probe_aa_tier(
    d3d: FakeD3D9,
    adapter: int,
    windowed: int,
    out_tier: List[int],
) -> bool:
    """FUN_0071DC80: probe 2,4,8; highest contiguous tier; stop on first failure."""
    if not check_multisample_supported(d3d, adapter, windowed, 2):
        out_tier[:] = [0]
        return False
    if not check_multisample_supported(d3d, adapter, windowed, 4):
        out_tier[:] = [1]
        return True
    if not check_multisample_supported(d3d, adapter, windowed, 8):
        out_tier[:] = [2]
        return True
    out_tier[:] = [3]
    return True


def aa_samples_for_tier(tier: int) -> int:
    if not 0 <= tier <= 3:
        raise ValueError("AA tier must be 0..3 for verified table")
    return AA_SAMPLES[tier]


# --- Reflection mapping FUN_00727FB0 / FUN_00729750 -------------------------

def apply_reflection_derived(requested: bytearray, world_lod_setting: int) -> None:
    """Map setting into requested +0x5C and +0x0C. Writes requested config only."""
    v = i32(world_lod_setting)
    if v == 0:
        set_dword(requested, 0x5C, 0)
        set_dword(requested, 0x0C, 0)
    elif v == 1:
        set_dword(requested, 0x5C, 1)
        set_dword(requested, 0x0C, 0)
    else:
        set_dword(requested, 0x5C, 2)
        set_dword(requested, 0x0C, 1)


# --- Settings getter FUN_0071D8F0 -------------------------------------------

def get_setting(graphics_obj: bytearray, requested: bytearray, selector: int) -> int:
    """ECX=graphics object, stack selector. Default/unsupported -> 0. RET 4."""
    if selector < 1 or selector > 30:
        return 0
    if selector == 19:
        return 0
    kind, off = GETTER_SELECTORS[selector]
    if kind == "obj":
        return dword_view(graphics_obj, off)
    return dword_view(requested, off)


# --- Mode helpers FUN_00723790 / FUN_007237B0 --------------------------------

@dataclass
class ModeRecord:
    width: int
    height: int
    refresh: int
    adapter: int = 0
    field_10: int = 0
    field_14: int = 0
    field_18: int = 0  # format-related

    def pack(self) -> bytes:
        return struct.pack(
            "<7I",
            u32(self.width),
            u32(self.height),
            u32(self.refresh),
            u32(self.adapter),
            u32(self.field_10),
            u32(self.field_14),
            u32(self.field_18),
        )


def selected_mode_pointer(vector_begin: int, selected_index: int) -> int:
    """FUN_00723790 arithmetic: begin + index * 0x1C. Valid-index precondition."""
    return u32(vector_begin + selected_index * MODE_RECORD_STRIDE)


def _mode_count(modes: Sequence[ModeRecord]) -> int:
    return len(modes)


def select_display_mode(
    modes: Sequence[ModeRecord],
    width: int,
    height: int,
    refresh: int,
    object_aspect: float,
    aspect_tolerance: float = ASPECT_TOLERANCE,
) -> int:
    """FUN_007237B0 core selection. Returns index stored at engine+0x180.

    Empty collection yields -1 (0xFFFFFFFF as i32). Aspect tolerance injected;
    verified .rdata value is 0.001 at 0x00B64D88.
    """
    w = width if width != 0 else DEFAULT_WIDTH
    h = height if height != 0 else DEFAULT_HEIGHT
    r = refresh if refresh != 0 else DEFAULT_REFRESH
    n = _mode_count(modes)
    if n == 0:
        return -1

    for i, m in enumerate(modes):
        if m.width == w and m.height == h and m.refresh == r:
            return i

    # Scan backwards from last index for aspect + pixel threshold.
    for i in range(n - 1, -1, -1):
        m = modes[i]
        if m.height == 0:
            continue
        ratio = float(m.width) / float(m.height)
        if abs(object_aspect - ratio) <= aspect_tolerance:
            if u32(m.width * m.height) >= PIXEL_COUNT_MIN:
                return i

    return n - 1


# --- Presentation parameters FUN_00722EC0 -----------------------------------

@dataclass
class EnginePresentState:
    """Synthetic D3DEngine fields used by the presentation builder."""
    selected_index: int
    modes: List[ModeRecord]
    windowed: int  # engine+0x198 byte
    caps_low: int  # engine+0x10; bit 0x20 tested
    field_174: int  # engine+0x174
    hwnd_field_19c: int  # engine+0x19C; distinct from graphics-object +0x18
    depth_stencil_global: int = 0  # [0x01311CE0]


def build_present_parameters(
    engine: EnginePresentState,
    requested: bytearray,
    present_region: bytearray,
    guard_before: Optional[bytearray] = None,
    guard_after: Optional[bytearray] = None,
) -> bool:
    """Fill 0x38-byte region at engine+0x130. Returns False if index < 0 (no init)."""
    if len(present_region) < PRESENT_PARAMS_SIZE:
        raise ValueError("present region must be at least 0x38")
    if engine.selected_index < 0:
        return False

    # Clear 0x38 bytes (memset dependency; synthetic).
    for i in range(PRESENT_PARAMS_SIZE):
        present_region[i] = 0

    mode = engine.modes[engine.selected_index]
    windowed = 1 if engine.windowed else 0

    if windowed:
        set_dword(present_region, 0x00, dword_view(requested, 0x6C))
        set_dword(present_region, 0x04, dword_view(requested, 0x70))
        set_dword(present_region, 0x30, 0)  # refresh
    else:
        set_dword(present_region, 0x00, mode.width)
        set_dword(present_region, 0x04, mode.height)
        set_dword(present_region, 0x30, mode.refresh)

    set_dword(present_region, 0x08, mode.field_18)  # BackBufferFormat
    set_dword(present_region, 0x0C, 1)  # BackBufferCount
    tier = i32(dword_view(requested, CFG_FSAA))
    samples = AA_SAMPLES[tier] if 0 <= tier <= 3 else AA_SAMPLES[0]
    set_dword(present_region, 0x10, samples)
    set_dword(present_region, 0x14, 0)  # MultiSampleQuality

    # SwapEffect
    if (engine.caps_low & 0x20) == 0 and engine.field_174 == 0 and tier <= 0:
        swap = 3
    else:
        swap = 1
    set_dword(present_region, 0x18, swap)

    set_dword(present_region, 0x1C, engine.hwnd_field_19c)
    set_dword(present_region, 0x20, windowed)
    set_dword(present_region, 0x24, 1)  # EnableAutoDepthStencil

    # AutoDepthStencilFormat: 0x4B or 0x50 from global
    g = engine.depth_stencil_global
    depth_fmt = 0x50 if g != 0 else 0x4B
    set_dword(present_region, 0x28, depth_fmt)

    flags = 4 if windowed else 0
    set_dword(present_region, 0x2C, flags)

    vsync = dword_view(requested, 0x7C)
    interval = 1 if vsync != 0 else 0x80000000
    set_dword(present_region, 0x34, interval)

    # Guards: ensure callers can detect overruns.
    if guard_before is not None:
        pass  # caller owns; we never write before region
    if guard_after is not None:
        pass
    return True


# --- Device creation sequence FUN_00725200 (mocked) -------------------------

@dataclass
class CreateDeviceAttempt:
    site: int
    flags: int
    adapter: int
    device_type: int
    focus_hwnd: int
    present_ptr: int
    out_ptr: int


@dataclass
class FakeCreateDevice:
    """Records CreateDevice-shaped calls; returns scripted HRESULTs."""
    hresults: List[int]
    attempts: List[CreateDeviceAttempt] = field(default_factory=list)
    out_device: int = 0xDEAD0001
    _idx: int = 0

    def create_device(
        self,
        site: int,
        adapter: int,
        device_type: int,
        focus_hwnd: int,
        flags: int,
        present_ptr: int,
        out_ptr: int,
    ) -> int:
        self.attempts.append(
            CreateDeviceAttempt(
                site=site,
                flags=flags,
                adapter=adapter,
                device_type=device_type,
                focus_hwnd=focus_hwnd,
                present_ptr=present_ptr,
                out_ptr=out_ptr,
            )
        )
        hr = self.hresults[self._idx] if self._idx < len(self.hresults) else -1
        self._idx += 1
        if hr == 0:
            # success publishes out pointer identity (synthetic)
            return 0
        return hr


def create_device_sequence(
    iface: FakeCreateDevice,
    adapter: int,
    device_type: int,
    focus_hwnd: int,
    present_ptr: int,
    out_ptr: int = DEVICE_OUT_GLOBAL,
    original_adapter: Optional[int] = None,
) -> int:
    """Inner 0x00725200 retry: flags 0x40 then 0x20/type1 on nonzero first result."""
    orig = original_adapter if original_adapter is not None else adapter
    hr = iface.create_device(
        0x007252CF, adapter, device_type, focus_hwnd, 0x40, present_ptr, out_ptr
    )
    if hr == 0:
        return 0
    hr2 = iface.create_device(
        0x007252F5, orig, 1, focus_hwnd, 0x20, present_ptr, out_ptr
    )
    return hr2


def outer_device_with_aa_fallback(
    iface: FakeCreateDevice,
    caps: bytearray,
    requested: bytearray,
    adapter: int,
    device_type: int,
    focus_hwnd: int,
    present_ptr: int,
) -> Tuple[int, int]:
    """Outer 0x007297D0 pattern: create; on nonzero apply AA mask and retry once.

    Returns (final_hr, requested_aa_after). Does not check second result before
    continuing (matches observed imperfect outer check).
    """
    hr = create_device_sequence(
        iface, adapter, device_type, focus_hwnd, present_ptr
    )
    if hr == 0:
        return hr, dword_view(requested, CFG_FSAA)
    # Capability AA from caps +0x48
    masked = aa_fallback_mask(dword_view(caps, CFG_FSAA))
    set_dword(requested, CFG_FSAA, masked)
    hr2 = create_device_sequence(
        iface, adapter, device_type, focus_hwnd, present_ptr
    )
    return hr2, dword_view(requested, CFG_FSAA)


# --- Lifecycle / ownership fixtures -----------------------------------------

@dataclass
class SyntheticGraphicsOwnership:
    """Tracks destructor-shaped release order without calling protected frees."""
    caps_ptr: Optional[int] = None
    requested_ptr: Optional[int] = None
    engine_ptr: Optional[int] = None
    sync_wrapper: bool = False
    vector_storage: Optional[int] = None
    title_buffer: Optional[int] = None
    d3d9_iface: Optional[int] = None
    device_global: Optional[int] = None
    query_ptr: Optional[int] = None
    releases: List[str] = field(default_factory=list)
    opaque_calls: List[str] = field(default_factory=list)

    def destructor_00727B60(self) -> List[str]:
        order = []
        if self.caps_ptr is not None:
            order.append("free_caps")
            self.caps_ptr = None
        if self.requested_ptr is not None:
            order.append("free_requested")
            self.requested_ptr = None
        if self.engine_ptr is not None:
            order.append("engine_dtor_00725110")
            order.append("free_engine")
            self.engine_ptr = None
        if self.sync_wrapper:
            order.append("sync_dtor_00977400")
            self.sync_wrapper = False
        if self.vector_storage is not None:
            order.append("free_vector_0xC_stride")
            self.vector_storage = None
        if self.title_buffer is not None:
            order.append("free_title_buffer_conditional")
            self.title_buffer = None
        self.releases.extend(order)
        return order

    def cleanup_device_00727ED0(self) -> List[str]:
        order = []
        if self.query_ptr is not None:
            order.append("release_query_engine_168")
            self.query_ptr = None
        if self.device_global is not None:
            order.append("release_device_013C6510")
            # Observed body does NOT zero 0x013C6510 after release.
        self.releases.extend(order)
        return order

    def live_shutdown_00727F40(self) -> List[str]:
        order = ["input_cleanup_0072E8D0"]
        self.opaque_calls.append("unregister_callbacks_B615C4")
        order.append("opaque_0071E380")
        self.opaque_calls.append("opaque_0071E380")
        order.extend(self.cleanup_device_00727ED0())
        if self.d3d9_iface is not None:
            order.append("release_G+10")
            self.d3d9_iface = None
        order.append("window_slot_B61534_on_G+18")
        self.releases.extend(order)
        return order


@dataclass
class Resource428B0:
    """FUN_007428B0 release rules for resource types 1 and 6."""
    resource_type: int
    member_08: Optional[int] = 1
    member_0C: Optional[int] = 1
    member_10: Optional[int] = 1
    active_byte_20: int = 1
    releases: List[str] = field(default_factory=list)

    def release(self) -> None:
        # Skip releasing +0C for types 1 and 6.
        if self.member_08 is not None:
            self.releases.append("release_+08")
            self.member_08 = None
        if self.resource_type not in (1, 6) and self.member_0C is not None:
            self.releases.append("release_+0C")
            self.member_0C = None
        if self.member_10 is not None:
            self.releases.append("release_+10")
            self.member_10 = None
        self.active_byte_20 = 0
        self.releases.append("clear_active_+20")


# --- Layout metadata helpers ------------------------------------------------

GRAPHICS_OBJECT_FIELDS = {
    "0x00": {"meaning": "title-like buffer begin", "confidence": "STRONGLY_SUPPORTED"},
    "0x04": {"meaning": "buffer end", "confidence": "STRONGLY_SUPPORTED"},
    "0x08": {"meaning": "capacity end", "confidence": "STRONGLY_SUPPORTED"},
    "0x10": {"meaning": "IDirect3D9-like interface", "confidence": "STRONGLY_SUPPORTED"},
    "0x14": {"meaning": "D3DEngine pointer", "confidence": "CONFIRMED"},
    "0x18": {"meaning": "window-like call return; HWND unproven", "confidence": "STRONGLY_SUPPORTED"},
    "0x3C": {"meaning": "windowed-state flag", "confidence": "STRONGLY_SUPPORTED"},
    "0x40": {"meaning": "status", "confidence": "CONFIRMED"},
    "0x48": {"meaning": "performance level", "confidence": "CONFIRMED"},
    "0x4C": {"meaning": "scaled brightness/gamma setting", "confidence": "STRONGLY_SUPPORTED"},
    "0x50": {"meaning": "capability PCDisplayConfig pointer", "confidence": "CONFIRMED"},
    "0x54": {"meaning": "requested PCDisplayConfig pointer", "confidence": "CONFIRMED"},
    "0x64": {"meaning": "adapter ordinal", "confidence": "STRONGLY_SUPPORTED"},
    "0x4F8": {"meaning": "aspect-ratio-like float", "confidence": "STRONGLY_SUPPORTED"},
    "0x4FC": {"meaning": "query-success byte", "confidence": "CONFIRMED"},
    "0x500": {"meaning": "embedded synchronization wrapper", "confidence": "STRONGLY_SUPPORTED"},
    "0x530": {"meaning": "atomic/deferred state", "confidence": "CONFIRMED"},
    "0x534": {"meaning": "feature byte", "confidence": "CONFIRMED"},
}

PCDISPLAYCONFIG_FIELDS = {
    "0x10": "g_RoadReflectionEnable",
    "0x1C": "g_SmokeEnable",
    "0x2C": "g_WorldLodLevel",
    "0x34": "g_WorldFXLevel",
    "0x38": "g_CarEffects",
    "0x44": "g_CarLodLevel",
    "0x48": "g_FSAALevel",
    "0x4C": "g_RainEnable",
    "0x50": "g_TextureFiltering",
    "0x58": "g_ShadowEnable",
    "0x60": "g_CarDamageDetail",
    "0x64": "g_ShaderDetailLevel",
    "0x68": "g_AudioDetail",
    "0x6C": "g_Width",
    "0x70": "g_Height",
    "0x74": "g_Refresh",
    "0x78": "FirstTime / preset-reset trigger",
    "0x7C": "g_VSyncOn",
}
