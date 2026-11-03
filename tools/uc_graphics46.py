#!/usr/bin/env python3
"""Phase 46 ordinary rendering contracts (synthetic).

Models verified stream-cache hit logic, indexed-draw argument preparation,
buffer-range reclamation, and a mock D3D9 command recorder.

Does NOT implement opaque draw targets 0x006860F0 / 0x00686290 / 0x006861B0.
Does NOT claim browser GPU or authentic first-frame display.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple


STREAM_CACHE_BASE = 0x01311AE0
STREAM_RECORD_STRIDE = 0x0C
MESH_MIN_EXTENT = 0xFC
BUFFER_UPDATE_STRIDE = 0x14
SECONDARY_QUEUE_STRIDE = 0x08
OPAQUE_INDEXED_DRAW = 0x006860F0
OPAQUE_USERMEM_DRAW = 0x00686290
OPAQUE_BAD_ENTRY = 0x006861B0

DEVICE_GLOBAL = 0x013C6510


@dataclass
class StreamCache:
    """Per-stream 0x0C records: buffer, byte_offset, stride at 0x01311AE0."""

    records: Dict[int, Tuple[int, int, int]] = field(default_factory=dict)
    miss_setter: Optional[Callable[[int, int, int, int, int], Any]] = None

    def slot(self, stream: int) -> Tuple[int, int, int]:
        return self.records.get(stream & 0xFFFFFFFF, (0, 0, 0))

    def set_slot(self, stream: int, buffer: int, offset: int, stride: int) -> None:
        self.records[stream & 0xFFFFFFFF] = (
            buffer & 0xFFFFFFFF,
            offset & 0xFFFFFFFF,
            stride & 0xFFFFFFFF,
        )

    def cache_hit(
        self,
        device: int,
        stream: int,
        buffer: int,
        offset: int,
        stride: int,
    ) -> int:
        """Verified hit predicate from 0x0071B6B0.

        Args match the five-stack cdecl shape used at 0x00757CC9:
        (device, stream, buffer, offset, stride). Hit path ignores device and
        returns 0 when all three cache DWORDs match. Miss path updates the
        cache then forwards through an injected setter (device vtable +0x190
        shaped); the miss body is independently disassembled but kept behind
        the injection boundary for tests.
        """
        cur = self.slot(stream)
        key = (buffer & 0xFFFFFFFF, offset & 0xFFFFFFFF, stride & 0xFFFFFFFF)
        if cur == key:
            return 0
        self.set_slot(stream, buffer, offset, stride)
        if self.miss_setter is not None:
            return self.miss_setter(device, stream, buffer, offset, stride)
        return 1  # synthetic miss marker when no setter


def indexed_prim_count(index_count: int) -> int:
    """floor(index_count / 3) via the 0xAAAAAAAB magic used at 0x00757C7B."""
    # mul edx:eax = index * 0xAAAAAAAB; shr edx, 1  => floor(n/3) for uint32
    product = (index_count & 0xFFFFFFFF) * 0xAAAAAAAB
    return (product >> 33) & 0xFFFFFFFF


@dataclass
class MeshDescriptor:
    """Instanced mesh fields read by 0x00757B80 (minimum extent 0xFC)."""

    batch_counts: List[int] = field(default_factory=lambda: [0] * 4)
    batch_offsets: List[int] = field(default_factory=lambda: [0] * 4)
    batch_meta: int = 0
    index_count: int = 0
    vertex_count: int = 0
    stride: int = 0

    def field_map(self) -> dict:
        return {
            "+0xA8+4*i": "batch count",
            "+0xDC+4*i": "per-batch offset (shifted left by 6 when applied)",
            "+0xEC": "batch-related metadata",
            "+0xF0": "index count",
            "+0xF4": "vertex count",
            "+0xF8": "stride",
            "minimum_read_extent": MESH_MIN_EXTENT,
        }


@dataclass
class IndexedDrawArgs:
    diagnostic_label: int
    device: int
    prim_type: int
    unused0: int
    unused1: int
    vertex_count: int
    start_index: int
    prim_count: int
    flag: int
    opaque_target: int = OPAQUE_INDEXED_DRAW


def prepare_indexed_draw_args(
    mesh: MeshDescriptor,
    device: int,
    batch_index: int = 0,
    diagnostic_label: int = 0x00BADF84,
) -> Optional[IndexedDrawArgs]:
    """Ordinary argument preparation at 0x00757C75–0x00757C9A.

    Returns None when the selected batch count is empty (early-out shape).
    Does not call or model 0x006860F0.
    """
    if batch_index < 0 or batch_index >= len(mesh.batch_counts):
        return None
    if (mesh.batch_counts[batch_index] & 0xFFFFFFFF) == 0:
        return None
    return IndexedDrawArgs(
        diagnostic_label=diagnostic_label & 0xFFFFFFFF,
        device=device & 0xFFFFFFFF,
        prim_type=4,
        unused0=0,
        unused1=0,
        vertex_count=mesh.vertex_count & 0xFFFFFFFF,
        start_index=0,
        prim_count=indexed_prim_count(mesh.index_count),
        flag=1,
    )


def stream_offset_scaled(mesh: MeshDescriptor, batch_index: int) -> int:
    """Per-batch offset at +0xDC+4*i, shifted left by six (instruction evidence)."""
    return (mesh.batch_offsets[batch_index] & 0xFFFFFFFF) << 6


@dataclass
class RangeNode:
    key: int
    size: int
    free: bool = False


@dataclass
class RangeList:
    """Synthetic circular free-range list matching 0x00766100 observable semantics."""

    nodes: List[RangeNode] = field(default_factory=list)

    @property
    def live_count(self) -> int:
        return sum(1 for n in self.nodes if not n.free)

    def reclaim(self, key: int) -> bool:
        """Find matching key, mark free, coalesce neighboring free ranges."""
        idx = None
        for i, n in enumerate(self.nodes):
            if (n.key & 0xFFFFFFFF) == (key & 0xFFFFFFFF) and not n.free:
                idx = i
                break
        if idx is None:
            return False
        self.nodes[idx].free = True
        # previous-neighbor coalescing
        if idx > 0 and self.nodes[idx - 1].free:
            prev = self.nodes[idx - 1]
            cur = self.nodes[idx]
            cur.key = prev.key
            cur.size = (prev.size + cur.size) & 0xFFFFFFFF
            del self.nodes[idx - 1]
            idx -= 1
        # next-neighbor coalescing
        if idx + 1 < len(self.nodes) and self.nodes[idx + 1].free:
            nxt = self.nodes[idx + 1]
            cur = self.nodes[idx]
            cur.size = (cur.size + nxt.size) & 0xFFFFFFFF
            del self.nodes[idx + 1]
        return True


@dataclass
class BufferUpdateRecord:
    selection: int
    element_offset: int
    copy_size: int
    additional_offset: int
    source_ptr: int

    @staticmethod
    def stride() -> int:
        return BUFFER_UPDATE_STRIDE


@dataclass
class D3D9CommandRecorder:
    """Captures API-shaped commands for synthetic tests only."""

    commands: List[dict] = field(default_factory=list)

    def _rec(self, method: str, **kwargs) -> None:
        self.commands.append({"method": method, **kwargs})

    def BeginScene(self) -> None:
        self._rec("BeginScene")

    def Clear(self, count, rects, flags, color, z, stencil) -> None:
        self._rec(
            "Clear",
            count=count,
            rects=rects,
            flags=flags,
            color=color,
            z=z,
            stencil=stencil,
        )

    def EndScene(self) -> None:
        self._rec("EndScene")

    def Present(self, src=None, dst=None, hwnd=None, dirty=None) -> None:
        self._rec("Present", src=src, dst=dst, hwnd=hwnd, dirty=dirty)

    def SetRenderTarget(self, index, surface) -> None:
        self._rec("SetRenderTarget", index=index, surface=surface)

    def SetDepthStencilSurface(self, surface) -> None:
        self._rec("SetDepthStencilSurface", surface=surface)

    def SetVertexDeclaration(self, decl) -> None:
        self._rec("SetVertexDeclaration", declaration=decl)

    def SetStreamSource(self, stream, buffer, offset, stride) -> None:
        self._rec(
            "SetStreamSource",
            stream=stream,
            buffer=buffer,
            offset=offset,
            stride=stride,
        )

    def SetIndices(self, ib) -> None:
        self._rec("SetIndices", index_buffer=ib)

    def SetVertexShader(self, vs) -> None:
        self._rec("SetVertexShader", shader=vs)

    def SetPixelShader(self, ps) -> None:
        self._rec("SetPixelShader", shader=ps)

    def SetRenderState(self, state, value) -> None:
        self._rec("SetRenderState", state=state, value=value)

    def SetTexture(self, stage, texture) -> None:
        self._rec("SetTexture", stage=stage, texture=texture)

    def record_clear_only_present(self) -> List[dict]:
        """Init presentation sequence from 0x00725200 (no draw between clear and Present)."""
        self.BeginScene()
        self.Clear(0, None, 7, 0, 1.0, 0)
        self.EndScene()
        self.Present(None, None, None, None)
        return list(self.commands)

    def record_later_present_cleanup(self) -> List[dict]:
        """Later EndScene/Present shape from 0x00752AF0 (ordering only)."""
        self.EndScene()
        self.Present(None, None, None, None)
        return list(self.commands)


def opaque_boundaries() -> dict:
    return {
        "0x00686000": "allocator",
        "0x00686030": "free",
        "0x004A26B0": "backend",
        "0x007A51B0": "submission",
        "0x0071E380": "cleanup",
        "0x00B615C4": "protected",
        "0x006860F0": "opaque indexed-draw-shaped handoff",
        "0x00686290": "opaque user-memory draw-shaped handoff",
        "0x006861B0": "opaque bad/overlapping instruction entry",
        "note": "Independently recorded targets; relationship unresolved.",
    }
