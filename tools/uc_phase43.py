#!/usr/bin/env python3
"""Phase 43: integrate Nov 2026 graphics evidence into synthetic ordinary models.

Does not execute nfs.exe. Does not implement protected backends. Does not claim
first-frame readiness. Updates metadata/docs after synthetic validation.
"""
from __future__ import annotations

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import uc_graphics43 as g
import uc_phase7_test as p7
import uc_phase43_test as t43

ROOT = p7.ROOT
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")


def hx(n: int) -> str:
    return "0x%08X" % (n & 0xFFFFFFFF)


def dump(name: str, obj) -> None:
    path = os.path.join(ANALYSIS, name)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(obj, fh, indent=2)
        fh.write("\n")


def load(name: str):
    path = os.path.join(ANALYSIS, name)
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def write_layouts() -> None:
    dump("graphics-object-layout.json", {
        "phase": 43,
        "evidence": "graphics-evidence-2026-11-03.json",
        "base": hx(g.GRAPHICS_OBJECT_BASE),
        "minimum_extent": hx(g.GRAPHICS_OBJECT_MIN_EXTENT),
        "exact_size": "BLOCKED",
        "instance": "static",
        "constructor": "0x007279A0",
        "destructor": "0x00727B60",
        "static_wrapper": "0x00B4FB60",
        "note": "Minimum extent from byte +0x534 access; not proven sizeof.",
        "fields": {
            k: {
                "address": hx(g.GRAPHICS_OBJECT_BASE + int(k, 16)),
                **v,
            }
            for k, v in g.GRAPHICS_OBJECT_FIELDS.items()
        },
        "plus48_distinction": {
            "graphics_object_0x48": "performance level",
            "pcdisplayconfig_0x48": "g_FSAALevel / AA tier",
        },
        "window_field_0x18": {
            "confidence": "STRONGLY_SUPPORTED",
            "hwnd_confirmed": False,
            "note": "Do not hardcode as HWND.",
        },
    })
    dump("pcdisplayconfig-layout.json", {
        "phase": 43,
        "size": hx(g.PCDISPLAYCONFIG_SIZE),
        "dword_count": 33,
        "requested_pointer_offset": "0x54",
        "capabilities_pointer_offset": "0x50",
        "allocator": "0x00686000",
        "allocator_status": "OPAQUE",
        "aa_samples": list(g.AA_SAMPLES),
        "aa_table": hx(g.AA_SAMPLE_TABLE_VA),
        "fields": {
            off: {
                "meaning": meaning,
                "confidence": "CONFIRMED",
            }
            for off, meaning in g.PCDISPLAYCONFIG_FIELDS.items()
        },
        "unmapped_offsets": ["0x30", "0x3C", "0x80"],
        "clamp_signed": [hx(x) for x in g.CLAMP_SIGNED],
        "clamp_unsigned": [hx(x) for x in g.CLAMP_UNSIGNED],
    })


def write_coverage(test_ok: bool) -> dict:
    status = "PASS" if test_ok else "FAIL"
    functions = [
        {
            "address": "0x0071D7E0",
            "role": "PCDisplayConfig clamp",
            "tier": "A",
            "implementation": "SYNTHETIC_PURE",
            "test_status": status,
            "dependency_status": "NONE",
            "runtime_ready": False,
            "classification": "SYNTHETIC_TESTABLE",
        },
        {
            "address": "0x00723790",
            "role": "selected-mode pointer",
            "tier": "A",
            "implementation": "SYNTHETIC_PURE",
            "test_status": status,
            "dependency_status": "VALID_INDEX_PRECONDITION",
            "runtime_ready": False,
            "classification": "SYNTHETIC_TESTABLE",
        },
        {
            "address": "0x007237B0",
            "role": "display-mode selection",
            "tier": "A",
            "implementation": "SYNTHETIC_PURE",
            "test_status": status,
            "dependency_status": "ASPECT_TOLERANCE_INJECTED",
            "runtime_ready": False,
            "classification": "SYNTHETIC_TESTABLE",
        },
        {
            "address": "0x00727FB0",
            "role": "reflection derived fields",
            "tier": "A",
            "implementation": "SYNTHETIC_PURE",
            "test_status": status,
            "dependency_status": "NONE",
            "runtime_ready": False,
            "classification": "SYNTHETIC_TESTABLE",
        },
        {
            "address": "0x0071D8F0",
            "role": "settings getter",
            "tier": "A",
            "implementation": "SYNTHETIC_PURE",
            "test_status": status,
            "dependency_status": "NONE",
            "runtime_ready": False,
            "classification": "SYNTHETIC_TESTABLE",
        },
        {
            "address": "0x00722EC0",
            "role": "D3DPRESENT_PARAMETERS builder",
            "tier": "A",
            "implementation": "SYNTHETIC_PURE",
            "test_status": status,
            "dependency_status": "MEMSET_INJECTED",
            "runtime_ready": False,
            "classification": "SYNTHETIC_TESTABLE",
        },
        {
            "address": "0x0071DC10",
            "role": "AA multisample probe",
            "tier": "B",
            "implementation": "SYNTHETIC_WITH_MOCK_D3D9",
            "test_status": status,
            "dependency_status": "FAKE_IDIRECT3D9",
            "runtime_ready": False,
            "classification": "SYNTHETIC_TESTABLE",
        },
        {
            "address": "0x0071DC80",
            "role": "AA tier probe policy",
            "tier": "B",
            "implementation": "SYNTHETIC_WITH_MOCK_D3D9",
            "test_status": status,
            "dependency_status": "FAKE_IDIRECT3D9",
            "runtime_ready": False,
            "classification": "SYNTHETIC_TESTABLE",
        },
        {
            "address": "0x00725200",
            "role": "CreateDevice retry sequence",
            "tier": "B",
            "implementation": "SYNTHETIC_SEQUENCE_MODEL",
            "test_status": status,
            "dependency_status": "FAKE_CREATEDEVICE",
            "runtime_ready": False,
            "classification": "SYNTHETIC_TESTABLE",
        },
        {
            "address": "0x00727B60",
            "role": "graphics-object destructor ownership",
            "tier": "B",
            "implementation": "SYNTHETIC_OWNERSHIP_FIXTURE",
            "test_status": status,
            "dependency_status": "OPAQUE_FREE",
            "runtime_ready": False,
            "classification": "SYNTHETIC_TESTABLE",
        },
        {
            "address": "0x00727F40",
            "role": "live device shutdown",
            "tier": "B",
            "implementation": "SYNTHETIC_OWNERSHIP_FIXTURE",
            "test_status": status,
            "dependency_status": "OPAQUE_0071E380",
            "runtime_ready": False,
            "classification": "SYNTHETIC_TESTABLE",
        },
        {
            "address": "0x007428B0",
            "role": "resource release rules",
            "tier": "B",
            "implementation": "SYNTHETIC_OWNERSHIP_FIXTURE",
            "test_status": status,
            "dependency_status": "FAKE_COM",
            "runtime_ready": False,
            "classification": "SYNTHETIC_TESTABLE",
        },
        {
            "address": "0x00727C60",
            "role": "settings setter",
            "tier": "B",
            "implementation": "PARTIAL_NOT_FULLY_INTEGRATED",
            "test_status": "DEFERRED",
            "dependency_status": "SIDE_EFFECT_CALLBACKS",
            "runtime_ready": False,
            "classification": "RESEARCH",
            "note": "Verified cases only; side-effect helpers remain injected/deferred.",
        },
        {
            "address": "0x00754740",
            "role": "resource creation candidate",
            "tier": "C",
            "implementation": "NOT_IMPLEMENTED",
            "test_status": "N/A",
            "dependency_status": "DEVICE_SIDE_EFFECTS",
            "runtime_ready": False,
            "classification": "RESEARCH",
        },
        {
            "address": "0x00730450",
            "role": "input-edge processing",
            "tier": "C",
            "implementation": "NOT_IMPLEMENTED",
            "test_status": "N/A",
            "dependency_status": "SEPARATE_INPUT_OBJECT",
            "runtime_ready": False,
            "classification": "RESEARCH",
        },
        {
            "address": "0x007661A0",
            "role": "queued buffer work",
            "tier": "C",
            "implementation": "NOT_IMPLEMENTED",
            "test_status": "N/A",
            "dependency_status": "BUFFER_MANAGER_GLOBAL",
            "runtime_ready": False,
            "classification": "RESEARCH",
        },
        {
            "address": "0x007408D0",
            "role": "TLS render-thread gate",
            "tier": "C",
            "implementation": "NOT_IMPLEMENTED",
            "test_status": "N/A",
            "dependency_status": "TLS_CONTRACT",
            "runtime_ready": False,
            "classification": "RESEARCH",
        },
        {
            "address": "0x009782D0",
            "role": "thread wrapper",
            "tier": "C",
            "implementation": "NOT_IMPLEMENTED",
            "test_status": "N/A",
            "dependency_status": "OS_SLOT_UNRESOLVED",
            "runtime_ready": False,
            "classification": "RESEARCH",
        },
    ]
    cov = {
        "phase": 43,
        "evidence_date": "2026-11-03",
        "game_code_target": "NFS_UNDERCOVER_PC",
        "tooling_origin": "NFSU2-WEB",
        "first_frame": g.FIRST_FRAME_STATUS,
        "d3d9_implementation": "NOT_JUSTIFIED",
        "engine_backend": "NOT_JUSTIFIED",
        "aa_fallback_correction": {
            "site": "0x00729848",
            "expression": "c & (((int32)c > 0) - 1)",
            "not": "tier_minus_one",
            "valid_tiers_0_3_result": 0,
        },
        "functions": functions,
        "protected_boundaries": [hx(x) for x in g.PROTECTED_BOUNDARIES],
        "win32_slot_mapping": {
            "0x00B6157C": "STRONGLY_SUPPORTED CreateWindowExA candidate; static import link BLOCKED",
            "0x00B61578": "UpdateWindow HYPOTHESIS; not hardcoded",
            "0x00B616CC": "Direct3DCreate9 STRONGLY_SUPPORTED; static import link BLOCKED",
        },
    }
    dump("graphics-function-coverage-phase43.json", cov)
    return cov


def update_frontier(test_count: int, test_ok: bool) -> dict:
    fr = load("runtime-frontier.json")
    # Guest metrics were last advanced in Phase 42; synthetic Phase 43 does not bump them.
    prev_phase = 42
    fr["phase"] = 43
    fr["graphics_frozen"] = True
    fr["first_frame"] = g.FIRST_FRAME_STATUS
    fr["graphics_config_phase43"] = {
        "synthetic_implemented": True,
        "tests_executed": test_count,
        "tests_passed": test_ok,
        "first_frame_unblocked": False,
        "d3d9_implementation_justified": False,
        "engine_backend_justified": False,
        "guest_harness_graphics_roots_added": 0,
        "runtime_ready_delta": 0,
        "enterable_delta": 0,
        "unique_executed_delta": 0,
        "note": (
            "Phase 43 adds synthetic ordinary-code models and tests only. "
            "Guest RUNTIME_READY/ENTERABLE/UNIQUE unchanged from Phase 42."
        ),
        "previous_phase": prev_phase,
        "tier_a": [
            "0x0071D7E0", "0x00723790", "0x007237B0",
            "0x00727FB0", "0x0071D8F0", "0x00722EC0",
        ],
        "aa_fallback_corrected": True,
        "evidence": "graphics-evidence-2026-11-03.json",
    }
    fr["recommended_phase44"] = (
        "Integrate verified setter cases of 0x00727C60 with injected side-effect "
        "callbacks; resolve aspect/window slot contracts without fabricating "
        "Win32/D3D9 import links; keep protected backend opaque."
    )
    dump("runtime-frontier.json", fr)
    return fr


def update_status() -> None:
    status = load("project-status.json")
    status["current_phase"] = 43
    status["strategy"] = (
        "Phase 43: graphics evidence integration — synthetic PCDisplayConfig clamp, "
        "AA probe/fallback correction, mode selection, presentation builder, and "
        "ownership fixtures. FIRST_FRAME remains BLOCKED_BY_PROTECTED_BACKEND."
    )
    phases = status.get("phases") or []
    if not any(p.get("phase") == 43 for p in phases):
        phases.append({
            "phase": 43,
            "name": "Graphics evidence integration and synthetic device lifecycle",
            "state": "completed",
        })
    status["phases"] = phases
    dump("project-status.json", status)


def write_report(fr: dict, cov: dict, test_count: int, failures: int) -> None:
    report = os.path.join(ANALYSIS, "runtime-phase43.md")
    lines = [
        "# Undercover Phase 43 — Graphics evidence integration",
        "",
        "Date: 2026-11-03 evidence; implementation phase.",
        "",
        "Target: `nfs.exe` 1.1.2.1  SHA-256 "
        "`6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd`.",
        "",
        "`GAME_CODE_TARGET=NFS_UNDERCOVER_PC`  `TOOLING_ORIGIN=NFSU2-WEB`",
        "",
        "## Status",
        "",
        f"`{g.FIRST_FRAME_STATUS}`",
        "",
        "D3D9: **NOT JUSTIFIED**. ENGINE BACKEND: **NOT JUSTIFIED**.",
        "",
        "This phase implements verified ordinary configuration/presentation logic "
        "as synthetic, testable models. It does not execute protected code and "
        "does not unblock first frame.",
        "",
        "## A. Baseline (Phase 42 guest metrics preserved)",
        "",
        f"- UNIQUE_UC_FUNCTIONS_EXECUTED: {fr.get('unique_uc_functions_executed')}",
        f"- ENTERABLE: {fr.get('enterable')}",
        f"- EXECUTION_RUNS: {fr.get('execution_runs')}",
        f"- RUNTIME_READY: {fr.get('runtime_ready')}",
        f"- NONTRIVIAL_OBJECT_LIFECYCLES: {fr.get('nontrivial_object_lifecycles')}",
        f"- CLEAN_VIRTUAL_CALLS: {fr.get('clean_virtual_calls')}",
        "",
        "Phase 43 guest deltas: **0** (synthetic-only).",
        "",
        "## B. Graphics-object field map",
        "",
        f"- Base `{hx(g.GRAPHICS_OBJECT_BASE)}`, minimum extent "
        f"`{hx(g.GRAPHICS_OBJECT_MIN_EXTENT)}`, exact size **BLOCKED**.",
        "- Static instance; constructor `0x007279A0`, destructor `0x00727B60`.",
        "- `+0x48` = performance level; **not** config FSAA.",
        "- `+0x18` window-like; HWND **unproven**.",
        "",
        "See `graphics-object-layout.json`.",
        "",
        "## C. PCDisplayConfig",
        "",
        f"- Size `{hx(g.PCDISPLAYCONFIG_SIZE)}` (33 DWORDs).",
        "- Dual instances at graphics `+0x50` (caps) and `+0x54` (requested).",
        "- Allocator `0x00686000` remains opaque.",
        "",
        "See `pcdisplayconfig-layout.json`.",
        "",
        "## D. Configuration clamp `0x0071D7E0`",
        "",
        "- Two stack pointers, `RET 8`, no internal calls.",
        "- Signed minima at offsets: "
        + ", ".join(hx(x) for x in g.CLAMP_SIGNED) + ".",
        "- Unsigned minima at: "
        + ", ".join(hx(x) for x in g.CLAMP_UNSIGNED) + ".",
        "- Untouched fields preserved; capability buffer immutable.",
        "",
        "## E. AA fallback correction",
        "",
        "At `0x00729848`–`0x00729854`:",
        "",
        "```",
        "c & (((int32)c > 0) - 1)",
        "```",
        "",
        "For capability AA tiers 0..3 the result is **0**, not tier−1.",
        "Outer device retry uses this exact mask.",
        "",
        "## F. AA probe / sample table",
        "",
        f"- Table `{hx(g.AA_SAMPLE_TABLE_VA)}` → {list(g.AA_SAMPLES)}.",
        "- `0x0071DC10` probes formats `0x4B`, `0x16`, `0x15`.",
        "- `0x0071DC80` probes samples 2→4→8; stops on first failure.",
        "",
        "## G. Display-mode selection",
        "",
        f"- Record stride `{hx(g.MODE_RECORD_STRIDE)}`.",
        "- `0x00723790`: `begin + index * 0x1C`.",
        "- `0x007237B0`: defaults 640×480@60; exact match; aspect ≤ "
        f"{g.ASPECT_TOLERANCE} (`.rdata` `0x00B64D88`); pixel count "
        f">= `{hx(g.PIXEL_COUNT_MIN)}`; else last; empty → −1.",
        "",
        "## H. Presentation parameters `0x00722EC0`",
        "",
        f"- Region engine+`{hx(g.PRESENT_PARAMS_ENGINE_OFF)}`, size "
        f"`{hx(g.PRESENT_PARAMS_SIZE)}`.",
        "- Negative selected index: early return, no init.",
        "- VSync → interval 1; else `0x80000000`.",
        "- Engine `+0x19C` hwnd field distinct from graphics `+0x18`.",
        "",
        "## I. Device creation model `0x00725200`",
        "",
        "- First CreateDevice-shaped call flags `0x40` at `0x007252CF`.",
        "- Nonzero → retry flags `0x20`, type 1 at `0x007252F5`.",
        f"- Output global `{hx(g.DEVICE_OUT_GLOBAL)}`.",
        "- Outer AA mask retry modeled separately; imperfect outer check preserved.",
        "",
        "## J. Ownership / cleanup fixtures",
        "",
        "- Destructor order: caps → requested → engine dtor/free → sync → "
        "vector → title.",
        "- Live shutdown hits opaque `0x0071E380` before device release.",
        "- `0x00727ED0` does not clear device global after Release.",
        "- `0x007428B0` skips `+0x0C` release for resource types 1 and 6.",
        "",
        "## K. Window / Win32 uncertainties",
        "",
        "- Class name `GameFrame` confirmed as data.",
        "- Slot→import mappings for CreateWindowExA/UpdateWindow **not** hardcoded.",
        "- Input object `0x01321188` is separate from the graphics object.",
        "",
        "## L. Function coverage",
        "",
    ]
    for e in cov["functions"]:
        lines.append(
            f"- `{e['address']}` | {e['role']} | {e['implementation']} | "
            f"tests={e['test_status']} | deps={e['dependency_status']}"
        )
    lines += [
        "",
        f"Synthetic tests executed: **{test_count}** (failures={failures}).",
        "",
        "## M. Evidence corrections",
        "",
        "1. AA fallback is zeroing mask, not progressive decrement.",
        "2. Graphics-object `+0x48` ≠ config FSAA `+0x48`.",
        "3. Presentation hwnd source is engine `+0x19C`, not proven alias of G+0x18.",
        "4. Device global not cleared after `0x00727ED0` release.",
        "",
        "## N. Remaining blockers",
        "",
        "### Ordinary / injectable",
        "",
        "- Full setter `0x00727C60` side-effect cases.",
        "- Confirmed Win32/D3D9 slot-to-import provenance.",
        "- Complete mode enumeration (`0x0072B030`) without unsafe decompiler copy.",
        "",
        "### Protected / opaque",
        "",
        "- `0x00686000` / `0x00686030`",
        "- `0x00B615C4`",
        "- `0x0071E380`",
        "- `0x004A26B0` / `0x007A51B0`",
        "",
        "## O. Phase 44 handoff",
        "",
        fr.get("recommended_phase44") or "",
        "",
        "Priorities:",
        "",
        "1. Verified setter cases with injected callbacks.",
        "2. Boundary adapters for factory/window/sync without inventing slot maps.",
        "3. Keep guest ordinary object-family execution separate from graphics "
        "synthetic models until dependency contracts are complete.",
        "",
        "## P. Artifacts",
        "",
        "- `graphics-evidence-2026-11-03.json`",
        "- `graphics-report-2026-11-03.md`",
        "- `graphics-object-layout.json`",
        "- `pcdisplayconfig-layout.json`",
        "- `graphics-function-coverage-phase43.json`",
        "- `tools/uc_graphics43.py`",
        "- `tools/uc_phase43_test.py`",
        "",
    ]
    with open(report, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines))

    handoff = os.path.join(ANALYSIS, "phase44-handoff.md")
    with open(handoff, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join([
            "# Phase 44 handoff",
            "",
            "From Phase 43 synthetic graphics/config integration.",
            "",
            "## Do not",
            "",
            "- Unblock FIRST_FRAME without an authorized backend dependency change.",
            "- Hardcode unresolved B615xx/B616CC slot→import identities.",
            "- Call protected allocator/free from synthetic fixtures.",
            "- Promote Tier C research functions to RUNTIME_READY.",
            "",
            "## Highest-value next targets",
            "",
            "1. `0x00727C60` verified selector cases with injected side-effect hooks.",
            "2. Explicit boundary-adapter interfaces for window/factory/sync.",
            "3. Continue ordinary Family/virtual-call provenance work from Phase 42 "
            "in parallel — independent of graphics synthetic models.",
            "",
            "## Open research questions",
            "",
            "- Numeric completeness of unnamed config DWORDs.",
            "- Whether engine `+0x19C` is ever updated from G+0x18.",
            "- Exact final window style bits behind unresolved helpers.",
            "",
        ]))


def run_logic_tests() -> tuple[int, int]:
    """Run synthetic tests excluding metadata assertions that need written files."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for cls in (
        t43.EvidenceImport,
        t43.ClampTests,
        t43.AAFallbackTests,
        t43.AAProbeTests,
        t43.ReflectionTests,
        t43.GetterTests,
        t43.ModeTests,
        t43.PresentTests,
        t43.DeviceLifecycleTests,
    ):
        suite.addTests(loader.loadTestsFromTestCase(cls))
    # Layout tests need JSON written first — run after write_layouts in main.
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    return result.testsRun, len(result.failures) + len(result.errors)


def run_metadata_tests() -> tuple[int, int]:
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for cls in (t43.GraphicsObjectLayout, t43.MetadataAndFrozen):
        suite.addTests(loader.loadTestsFromTestCase(cls))
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    return result.testsRun, len(result.failures) + len(result.errors)


def main() -> int:
    write_layouts()
    n1, f1 = run_logic_tests()
    ok = f1 == 0
    cov = write_coverage(ok)
    fr = update_frontier(n1, ok)
    update_status()
    write_report(fr, cov, n1, f1)
    n2, f2 = run_metadata_tests()
    total = n1 + n2
    fails = f1 + f2
    print(json.dumps({
        "phase": 43,
        "tests_run": total,
        "failures": fails,
        "first_frame": g.FIRST_FRAME_STATUS,
        "guest_unique": fr.get("unique_uc_functions_executed"),
        "guest_enterable": fr.get("enterable"),
    }, indent=2))
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
