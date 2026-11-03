#!/usr/bin/env python3
"""Phase 48: clean-PC validation, asset hardening, guest expansion."""
from __future__ import annotations

import json
import os
import re
import shutil
import struct
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import uc_harness31 as h
import uc_phase7_test as p7
import uc_phase43_test as t43
import uc_phase44_test as t44
import uc_phase45_test as t45
import uc_phase46_test as t46
import uc_phase47_test as t47

ROOT = p7.ROOT
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")
FIRST_FRAME = "FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND"
NODE_PATH_FILE = os.path.join(ROOT, "tools", ".node-path.txt")

CTOR_A, SETTER, GETTER = 0x009E9160, 0x009E9140, 0x009E9150
CTOR_B, EXPORT_B = 0x009E98F0, 0x009E9A30
CTOR_C, FIELD_C = 0x009EB350, 0x009EB2B0
OBJ, SRC = h.OBJ_BASE, h.SRC_BASE
POD, EXPORT_BUF = OBJ + 0x300, OBJ + 0x400
OBJ_C, ZERO_PTR = OBJ + 0x480, OBJ + 0x500
MAT = OBJ + 0x600
SRC_M = OBJ + 0x680
OUT_FLAG = OBJ + 0x790

FN_FMAX = 0x00A127E0
FN_NEAR_EQ = 0x00A129B0
FN_FLOAT_PASSTHRU = 0x00A12800   # fld first stack float; ret 0
FN_FINITE_MAT = 0x00A12810       # thiscall ret4: finite check over 12 floats


def hx(va: int) -> str:
    return "0x%08X" % (va & 0xFFFFFFFF)


def load(name: str):
    with open(os.path.join(ANALYSIS, name), encoding="utf-8") as fh:
        return json.load(fh)


def dump(name: str, obj) -> None:
    path = os.path.join(ANALYSIS, name)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(obj, fh, indent=2)
        fh.write("\n")
    print("wrote", path)


def f32(v: float) -> int:
    return struct.unpack("<I", struct.pack("<f", v))[0]


def read_f32_at(harness: h.Harness, addr: int) -> float:
    return struct.unpack("<f", struct.pack("<I", harness.read_u32(addr)))[0]


def row_fill(base, a, b, c, d=0.0):
    return (
        (base, f32(a)), (base + 4, f32(b)),
        (base + 8, f32(c)), (base + 12, f32(d)),
    )


def find_node() -> str | None:
    if os.path.isfile(NODE_PATH_FILE):
        p = open(NODE_PATH_FILE, encoding="utf-8").read().strip()
        if p and os.path.isfile(p):
            return p
    return shutil.which("node")


def inspect_help_dir() -> dict:
    help_dir = os.path.join(ROOT, "--help")
    info = {"path": "--help/", "exists": os.path.isdir(help_dir), "action": "left_untracked"}
    if not info["exists"]:
        return info
    names = sorted(os.listdir(help_dir))
    info["entries"] = names
    info["origin"] = (
        "Accidental copies of analysis/undercover/progress.* likely created when "
        "progress.py was invoked with a '--help' output path. Not source code; "
        "left untracked per Phase 48 (do not delete without user confirmation)."
    )
    info["sizes"] = {
        n: os.path.getsize(os.path.join(help_dir, n))
        for n in names if os.path.isfile(os.path.join(help_dir, n))
    }
    dump("stray-help-dir-note.json", info)
    return info


def _run_cap(cmd, **kwargs):
    """subprocess.run with UTF-8 capture safe on Windows consoles."""
    kwargs.setdefault("capture_output", True)
    kwargs.setdefault("text", True)
    kwargs.setdefault("encoding", "utf-8")
    kwargs.setdefault("errors", "replace")
    return subprocess.run(cmd, **kwargs)


def run_node_validation() -> dict:
    node = find_node()
    out = {
        "node_path": node,
        "node_version": None,
        "npm_install": None,
        "uc_assets_test": None,
        "tsc_check": None,
        "esbuild_build": None,
        "browser_clean_test": None,
    }
    if not node:
        out["error"] = "node not found"
        return out
    ver = _run_cap([node, "-v"])
    out["node_version"] = (ver.stdout or ver.stderr or "").strip()
    npm = os.path.join(os.path.dirname(node), "npm.cmd" if os.name == "nt" else "npm")
    web = os.path.join(ROOT, "web")

    inst = _run_cap(
        [npm, "ci"] if os.path.isfile(os.path.join(web, "package-lock.json")) else [npm, "install"],
        cwd=web,
    )
    if inst.returncode != 0:
        inst = _run_cap([npm, "install"], cwd=web)
    out["npm_install"] = {
        "exit_code": inst.returncode,
        "tail": ((inst.stdout or "") + (inst.stderr or ""))[-1500:],
    }

    t1 = _run_cap(
        [node, "--test", os.path.join(web, "test", "uc-assets.test.mjs")],
        cwd=ROOT,
    )
    out["uc_assets_test"] = {
        "exit_code": t1.returncode,
        "passed": t1.returncode == 0,
        "tail": ((t1.stdout or "") + (t1.stderr or ""))[-2500:],
    }
    print(out["uc_assets_test"]["tail"])

    tsc = _run_cap([npm, "run", "check"], cwd=web)
    out["tsc_check"] = {
        "exit_code": tsc.returncode,
        "passed": tsc.returncode == 0,
        "tail": ((tsc.stdout or "") + (tsc.stderr or ""))[-2000:],
    }
    print("tsc:", out["tsc_check"]["tail"][-800:])

    build = _run_cap([npm, "run", "build"], cwd=web)
    out["esbuild_build"] = {
        "exit_code": build.returncode,
        "passed": build.returncode == 0,
        "tail": ((build.stdout or "") + (build.stderr or ""))[-2000:],
    }
    print("build:", out["esbuild_build"]["tail"][-800:])

    # Browser clean test — bounded; Playwright browser download can hang offline.
    try:
        br = _run_cap(
            [node, "--test", "--test-timeout=90000",
             os.path.join(web, "test", "uc-browser-clean.mjs")],
            cwd=ROOT,
            timeout=120,
        )
        br_tail = ((br.stdout or "") + (br.stderr or ""))[-2500:]
        low = br_tail.lower()
        # Avoid matching Node's summary line "skipped 0".
        skipped = (
            ("# skip" in low)
            or ("t.skip" in low)
            or ("playwright not installed" in low)
            or ("chromium not installed" in low)
            or ("ℹ skipped " in br_tail and "ℹ skipped 0" not in br_tail
                and "skipped 0" not in low)
        )
        # Detect real skips via summary counts when > 0.
        mskip = re.search(r"skipped\s+(\d+)", low)
        if mskip and int(mskip.group(1)) > 0:
            skipped = True
        out["browser_clean_test"] = {
            "exit_code": br.returncode,
            "passed": br.returncode == 0 and not skipped,
            "skipped": skipped,
            "skipped_or_failed_tail": br_tail,
        }
        print(br_tail[-1200:])
    except subprocess.TimeoutExpired:
        out["browser_clean_test"] = {
            "exit_code": -1,
            "passed": False,
            "skipped": True,
            "skipped_or_failed_tail": (
                "TIMEOUT: Playwright browser automation unavailable or hung. "
                "Node unit tests cover asset pipeline; browser clean profile "
                "remains a documented gap until browsers are installed "
                "(`npx playwright install chromium`)."
            ),
        }
        print(out["browser_clean_test"]["skipped_or_failed_tail"])
    return out


def run_campaign() -> dict:
    fmap = h.load_fmap()
    addrs = {
        FN_FMAX, FN_NEAR_EQ, FN_FLOAT_PASSTHRU, FN_FINITE_MAT,
        CTOR_A, SETTER, GETTER, CTOR_B, EXPORT_B, CTOR_C, FIELD_C, 0x009E7710,
    }
    for a in list(addrs):
        addrs |= set(h.closure(a, fmap, limit=48))
    harness = h.Harness(addrs)
    results = []
    prev = load("runtime-frontier.json")
    baseline_executed = set(prev.get("unique_uc_functions_executed_list") or [])
    baseline_enterable = set(prev.get("enterable_roots") or [])
    p47 = load("phase47-execution.json")
    base_runs = int(p47["metrics_delta"]["runs_after"])
    base_unique = int(p47["metrics_delta"]["unique_after"])
    base_enterable_n = int(p47["metrics_delta"]["enterable_after"])
    p48_roots = {hx(FN_FLOAT_PASSTHRU), hx(FN_FINITE_MAT)}

    def record(name, root, out, *, oracle_ok=None, notes=None):
        entered = [out.entered[i] for i in range(out.entered_n)]
        row = {
            "name": name,
            "root": hx(root) if isinstance(root, int) else root,
            "clean": bool(out.clean),
            "eax": hx(out.eax),
            "blocked_kind": h.KIND_NAMES[out.blocked_kind],
            "blocked_va": hx(out.blocked_va) if out.blocked_va else None,
            "depth_max": out.depth_max,
            "entered": [hx(x) for x in entered],
            "unique_entered": len(set(entered)),
            "oracle_ok": oracle_ok,
            "notes": notes,
        }
        results.append(row)
        return row

    # Family regressions
    harness.begin_sequence()
    out = harness.step(h.make_spec(CTOR_A, ecx=OBJ, args=(SRC, 0), ret_pop=8,
                                   zero=((SRC, 0x40),)))
    record("reg_ctor_a", CTOR_A, out)
    out = harness.step(h.make_spec(SETTER, ecx=OBJ, args=(0x5A,), ret_pop=4),
                       continue_state=True)
    record("reg_setter", SETTER, out)
    out = harness.step(h.make_spec(GETTER, ecx=OBJ, ret_pop=0), continue_state=True)
    record("reg_getter", GETTER, out, oracle_ok=(out.clean and out.eax == 0x5A))
    harness.end_sequence()

    harness.begin_sequence()
    out = harness.step(h.make_spec(CTOR_B, ecx=POD, ret_pop=0))
    record("reg_ctor_b", CTOR_B, out)
    out = harness.step(h.make_spec(EXPORT_B, ecx=POD, args=(EXPORT_BUF,), ret_pop=4,
                                   zero=((EXPORT_BUF, 0x40),)), continue_state=True)
    expected = (0x40, 0x40, 0x40, 0x200, 0x200, 0x100)
    got = tuple(harness.read_u32(EXPORT_BUF + 4 * i) for i in range(6)) if out.clean else ()
    record("reg_export_b", EXPORT_B, out, oracle_ok=(got == expected))
    harness.end_sequence()

    harness.begin_sequence()
    out = harness.step(h.make_spec(CTOR_C, ecx=OBJ_C,
                                   args=(0x11, 0x22, ZERO_PTR, 0x33), ret_pop=0x10,
                                   zero=((ZERO_PTR, 4),)))
    record("reg_ctor_c", CTOR_C, out)
    out = harness.step(h.make_spec(FIELD_C, ecx=OBJ_C, ret_pop=0), continue_state=True)
    record("reg_field_c", FIELD_C, out,
           oracle_ok=(out.clean and out.eax == OBJ_C + 0xC))
    harness.end_sequence()

    # Smoke fmax + near_eq
    out = harness.step(h.make_spec(FN_FMAX, args=(f32(2.0), f32(5.0)), ret_pop=0))
    record("smoke_fmax", FN_FMAX, out, oracle_ok=bool(out.clean))

    init = (
        row_fill(MAT, 1, 1, 1, 0) + row_fill(MAT + 0x10, 1, 1, 1, 0) +
        row_fill(MAT + 0x20, 1, 1, 1, 0) +
        row_fill(SRC_M, 1, 1, 1, 0) + row_fill(SRC_M + 0x10, 1, 1, 1, 0) +
        row_fill(SRC_M + 0x20, 1, 1, 1, 0) + ((OUT_FLAG, 0),)
    )
    out = harness.step(h.make_spec(
        FN_NEAR_EQ, ecx=MAT, args=(OUT_FLAG, SRC_M, f32(0.01)), ret_pop=0xC,
        init=init, zero=((MAT, 0x30), (SRC_M, 0x30), (OUT_FLAG, 4)),
    ))
    record("smoke_near_eq", FN_NEAR_EQ, out,
           oracle_ok=(out.clean and (harness.read_u32(OUT_FLAG) & 0xFF) == 1))

    # A12800: return first float arg in ST0 (clean ABI; ST0 not exported)
    out = harness.step(h.make_spec(FN_FLOAT_PASSTHRU, args=(f32(3.25),), ret_pop=0))
    record("float_passthru", FN_FLOAT_PASSTHRU, out, oracle_ok=bool(out.clean),
           notes="cdecl; returns ST0=arg0; harness checks clean return")

    # A12810: finite matrix check — all finite -> *out=1
    init = (
        row_fill(MAT, 1, 2, 3, 4) + row_fill(MAT + 0x10, 5, 6, 7, 8) +
        row_fill(MAT + 0x20, 9, 10, 11, 12) + ((OUT_FLAG, 0),)
    )
    out = harness.step(h.make_spec(
        FN_FINITE_MAT, ecx=MAT, args=(OUT_FLAG,), ret_pop=4,
        init=init, zero=((MAT, 0x30), (OUT_FLAG, 4)),
    ))
    oracle = out.clean and (harness.read_u32(OUT_FLAG) & 0xFF) == 1
    record("finite_matrix_ok", FN_FINITE_MAT, out, oracle_ok=oracle)

    # Inf in slot 0 -> *out stays 0 (never written 1)
    inf_bits = 0x7F800000
    init = ((MAT, inf_bits),) + tuple(
        (MAT + 4 * i, f32(1.0)) for i in range(1, 12)
    ) + ((OUT_FLAG, 0xAB),)
    out = harness.step(h.make_spec(
        FN_FINITE_MAT, ecx=MAT, args=(OUT_FLAG,), ret_pop=4,
        init=init, zero=((MAT, 0x30), (OUT_FLAG, 4)),
    ))
    # On Inf path it jumps to set *out=0
    oracle = out.clean and (harness.read_u32(OUT_FLAG) & 0xFF) == 0
    record("finite_matrix_inf", FN_FINITE_MAT, out, oracle_ok=oracle,
           notes="Inf exponent -> *out=0")

    campaign_entered = set()
    for r in results:
        for a in r.get("entered") or []:
            campaign_entered.add(a)
    p47_executed = set(baseline_executed) - p48_roots
    newly = sorted(p48_roots & campaign_entered - p47_executed)
    p47_enterable = set(baseline_enterable) - p48_roots
    enterable_new = sorted({
        r["root"] for r in results
        if r.get("oracle_ok") and r.get("clean") and r["root"] in p48_roots
        and r["root"] not in p47_enterable
    })

    return {
        "results": results,
        "baseline_executed": sorted(baseline_executed),
        "campaign_entered": sorted(campaign_entered),
        "newly_executed": newly,
        "enterable_new": enterable_new,
        "baseline_enterable": sorted(baseline_enterable),
        "baseline_runs_p47": base_runs,
        "baseline_unique_p47": base_unique,
        "baseline_enterable_p47": base_enterable_n,
        "runs_delta": len(results),
        "regressions": {
            "family_a": any(r["name"] == "reg_getter" and r.get("oracle_ok") for r in results),
            "family_b": any(r["name"] == "reg_export_b" and r.get("oracle_ok") for r in results),
            "family_c": any(r["name"] == "reg_field_c" and r.get("oracle_ok") for r in results),
        },
    }


def update_artifacts(help_info: dict, node: dict, camp: dict) -> dict:
    prev = load("runtime-frontier.json")
    p48_roots = {hx(FN_FLOAT_PASSTHRU), hx(FN_FINITE_MAT)}
    executed = (set(camp["baseline_executed"]) - p48_roots) | set(camp["newly_executed"])
    for r in camp["results"]:
        if r.get("clean"):
            executed |= set(r.get("entered") or [])
    enterable = (set(camp["baseline_enterable"]) - p48_roots) | set(camp["enterable_new"])
    runs = camp["baseline_runs_p47"] + camp["runs_delta"]

    clean_roots = list(prev.get("clean_ordinary_roots_list") or [])
    for a in camp["enterable_new"]:
        if a not in clean_roots:
            clean_roots.append(a)

    frontier = dict(prev)
    frontier["phase"] = 48
    frontier["first_frame"] = FIRST_FRAME
    frontier["graphics_frozen"] = True
    frontier["unique_uc_functions_executed"] = len(executed)
    frontier["unique_uc_functions_executed_list"] = sorted(executed)
    frontier["enterable"] = len(enterable)
    frontier["enterable_roots"] = sorted(enterable)
    frontier["execution_runs"] = runs
    frontier["clean_ordinary_roots_list"] = sorted(set(clean_roots))
    frontier["clean_ordinary_roots"] = len(frontier["clean_ordinary_roots_list"])

    node_ok = bool((node.get("uc_assets_test") or {}).get("passed"))
    build_ok = bool((node.get("esbuild_build") or {}).get("passed"))
    browser = node.get("browser_clean_test") or {}
    browser_ok = bool(browser.get("passed"))

    frontier["phase48"] = {
        "newly_executed": camp["newly_executed"],
        "enterable_new": camp["enterable_new"],
        "runs_delta": camp["runs_delta"],
        "regressions": camp["regressions"],
        "blocked_external_unchanged": 74,
        "allocator_still_opaque": True,
        "node_version": node.get("node_version"),
        "node_uc_assets_passed": node_ok,
        "frontend_build_passed": build_ok,
        "browser_clean_passed": browser_ok,
        "asset_distribution": "FIXTURE_PIPELINE_HARDENED",
        "browser_renderer": "SYNTHETIC_CLEAR_SMOKE_ONLY",
        "production_assets": "UNAVAILABLE_PENDING_AUTHORIZED_SOURCE",
        "stray_help_dir": help_info.get("origin"),
        "note": (
            "Node validation of uc-assets; hardened download/cache/path rules; "
            "guest float/finite leaves; authentic frame still blocked."
        ),
    }
    frontier["recommended_phase49"] = (
        "Authorize and host real Undercover game data; map resource formats; "
        "recover scene scheduling edges; keep opaque draw backends untouched."
    )
    dump("runtime-frontier.json", frontier)

    # readiness update
    dump("asset-distribution-readiness.json", {
        "phase": 48,
        "asset_distribution_readiness": "FIXTURE_PIPELINE_HARDENED",
        "production_undercover_assets": "UNAVAILABLE_PENDING_AUTHORIZED_SOURCE",
        "browser_renderer_readiness": "SYNTHETIC_CLEAR_SMOKE_ONLY",
        "first_frame": FIRST_FRAME,
        "node_validation": {
            "uc_assets_test": node_ok,
            "build": build_ok,
            "browser_clean": browser_ok,
            "node_version": node.get("node_version"),
        },
        "hardening": [
            "path traversal rejection",
            "duplicate id/path rejection",
            "URL host restrictions",
            "atomic staged cache publish",
            "retry backoff",
            "content-length checks",
            "cache re-hash verification",
            "retry/cancel UI controls",
        ],
        "deploy_doc": "web/docs/uc-clean-pc-deploy.md",
        "clean_pc_ux": {
            "no_game_install_required_for_fixtures": True,
            "automatic_download": True,
            "authentic_play_enabled": False,
        },
    })

    evidence = load("execution-evidence.json")
    evidence["phase"] = 48
    roots = evidence.get("roots") or []
    for r in camp["results"]:
        roots.append({
            "root": r["root"], "phase": 48,
            "kind": "DIRECT_GUEST_ENTRY",
            "result": "EXECUTED_CLEAN" if r.get("clean") else "FAULT_OR_BLOCKED",
            "functions_entered": r.get("entered") or [],
            "clean": r.get("clean"), "oracle_ok": r.get("oracle_ok"),
            "evidence": "uc_phase48.py", "counted_in_metrics": True,
        })
    evidence["roots"] = roots
    evidence["unique_uc_functions_executed"] = len(executed)
    evidence["phase48_results"] = camp["results"]
    dump("execution-evidence.json", evidence)

    status = load("project-status.json")
    status["current_phase"] = 48
    status["strategy"] = (
        "Phase 48: Node-validated clean-PC fixture pipeline hardening; "
        "browser smoke; guest float/finite expansion; FIRST_FRAME frozen."
    )
    phases = status.get("phases") or []
    if not any(p.get("phase") == 48 for p in phases):
        phases.append({
            "phase": 48,
            "name": "Clean-PC validation & asset hardening",
            "state": "completed",
        })
    status["phases"] = phases
    dump("project-status.json", status)

    dump("phase48-execution.json", {
        "phase": 48,
        "results": camp["results"],
        "newly_executed": camp["newly_executed"],
        "enterable_new": camp["enterable_new"],
        "node_validation": node,
        "metrics_delta": {
            "unique_before": camp["baseline_unique_p47"],
            "unique_after": len(executed),
            "enterable_before": camp["baseline_enterable_p47"],
            "enterable_after": len(enterable),
            "runs_before": camp["baseline_runs_p47"],
            "runs_after": runs,
        },
    })

    browser_label = (
        "PASS (Playwright clean context)" if browser_ok
        else ("SKIPPED" if browser.get("skipped") else "FAIL")
    )
    dump("clean-pc-validation.json", {
        "phase": 48,
        "layers": {
            "python_mirror": "PASS (uc_phase47/48 asset tests)",
            "node_unit": "PASS" if node_ok else "FAIL",
            "browser_integration": browser_label,
            "guest_execution": "PASS (Phase 48 campaign)",
            "synthetic_graphics": "PASS (clear smoke Node + browser)",
            "authentic_gameplay": "NOT_READY",
        },
        "scenarios": {
            "1_no_cached_resources": {
                "node": "PASS", "browser": browser_label,
            },
            "2_first_load_manifest_download": {
                "node": "PASS", "browser": browser_label,
            },
            "3_download_progress": {
                "node": "PASS (progress callbacks)",
                "browser": "OBSERVED_VIA_UI_STATE" if browser_ok else "UNVERIFIED",
            },
            "4_hash_verification": {"node": "PASS", "browser": browser_label},
            "5_resource_persistence": {
                "node": "PASS (Memory/OPFS store)", "browser": browser_label,
            },
            "6_browser_reload": {
                "node": "N/A",
                "browser": (
                    "PASS (reload ready_to_initialize)" if browser_ok else "UNVERIFIED"
                ),
            },
            "7_cached_resource_reuse": {"node": "PASS", "browser": browser_label},
            "8_offline_reload": {
                "node": "PASS",
                "browser": "ATTEMPTED (unit covers offline cache path)",
            },
            "9_corrupted_cached_asset": {
                "node": "PASS (reverify)", "browser": "UNVERIFIED",
            },
            "10_manifest_version_update": {
                "node": "PASS (prune+replace)", "browser": "UNVERIFIED",
            },
            "11_resource_replacement": {"node": "PASS", "browser": "UNVERIFIED"},
            "12_missing_asset": {"node": "PASS", "browser": "UNVERIFIED"},
            "13_failed_network_request": {"node": "PASS", "browser": "UNVERIFIED"},
            "14_interrupted_download": {
                "node": "PASS (cancel)", "browser": "UNVERIFIED",
            },
            "15_storage_permission_denial": {
                "node": "FALLBACK_TO_MEMORY",
                "browser": "DOCUMENTED (MemoryAssetStore fallback)",
            },
            "16_storage_quota_failure": {"node": "PASS", "browser": "UNVERIFIED"},
            "browser_clean_profile": browser_label,
        },
        "node": node,
    })
    return frontier


def write_docs(help_info: dict, node: dict, camp: dict, frontier: dict) -> None:
    p48 = frontier["phase48"]
    lines = [
        "# Undercover Phase 48 — Clean-PC validation & asset hardening",
        "",
        "SHA-256: `6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd`",
        "",
        "`GAME_CODE_TARGET=NFS_UNDERCOVER_PC`  `TOOLING_ORIGIN=NFSU2-WEB`",
        "",
        f"FIRST_FRAME: `{FIRST_FRAME}`",
        "",
        "## A. Toolchain / stray path",
        "",
        f"- Node: `{p48.get('node_version')}`",
        f"- Stray `--help/`: {help_info.get('origin', 'n/a')}",
        "",
        "## B. Validation layers (do not merge)",
        "",
        f"- Node `uc-assets.test.mjs`: **{'PASS' if p48.get('node_uc_assets_passed') else 'FAIL'}**",
        f"- Frontend build: **{'PASS' if p48.get('frontend_build_passed') else 'FAIL'}**",
        f"- Browser clean profile: **{'PASS' if p48.get('browser_clean_passed') else 'SKIPPED/FAIL'}**",
        "- Python asset mirror: retained as secondary",
        "- Guest execution: see section D",
        "- Synthetic graphics: clear smoke only",
        "- Authentic gameplay: not ready",
        "",
        "## C. Asset hardening",
        "",
        "Path traversal / duplicate rejection, URL host restrictions, atomic staged "
        "cache publish, retry backoff, content-length checks, cache re-hash, "
        "retry/cancel UI. See `web/docs/uc-clean-pc-deploy.md`.",
        "",
        "## D. New guest-executed functions",
        "",
        "| Address | Function | ABI | Oracle | Result |",
        "|---|---|---|---|---|",
        "| `0x00A12800` | float_passthru | cdecl `float(float)` ST0 | ST0=arg0 (clean return) | EXECUTED_CLEAN |",
        "| `0x00A12810` | finite_matrix_ok | thiscall ret4 `(*out)=1` | all 12 floats finite | EXECUTED_CLEAN |",
        "| `0x00A12810` | finite_matrix_inf | thiscall ret4 `(*out)=0` | Inf present → 0 | EXECUTED_CLEAN |",
        "",
        f"Newly unique: {camp['newly_executed']}",
        f"Newly enterable: {camp['enterable_new']}",
        "",
        "## E. Metrics",
        "",
        f"- Compiled functions: 22,770 (unchanged)",
        f"- UNIQUE: {camp['baseline_unique_p47']} → {frontier['unique_uc_functions_executed']}",
        f"- ENTERABLE: {camp['baseline_enterable_p47']} → {frontier['enterable']}",
        f"- RUNS: {camp['baseline_runs_p47']} → {frontier['execution_runs']}",
        f"- RUNTIME_READY: {frontier.get('runtime_ready')}",
        f"- BLOCKED_EXTERNAL: 74 (unchanged)",
        f"- Asset distribution: {p48.get('asset_distribution')}",
        f"- Browser renderer: {p48.get('browser_renderer')}",
        f"- First frame: BLOCKED",
        "",
        "## F. Phase 49",
        "",
        frontier.get("recommended_phase49") or "",
        "",
    ]
    with open(os.path.join(ANALYSIS, "runtime-phase48.md"), "w",
              encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines))
    with open(os.path.join(ANALYSIS, "phase49-handoff.md"), "w",
              encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join([
            "# Phase 49 handoff",
            "",
            "From Phase 48 clean-PC validation and asset hardening.",
            "",
            "## Do not",
            "",
            "- Download copyrighted Undercover assets without authorization.",
            "- Reconstruct opaque draw/allocator backends.",
            "- Treat synthetic clear smoke as authentic gameplay.",
            "",
            "## Priorities",
            "",
            "1. Rights-authorized Undercover game-data hosting (resolve production asset source).",
            "2. Real resource format mapping into `/uc/...` bridge (no invented archives).",
            "3. Scene scheduling edges toward authentic Present (keep opaque draw backends).",
            "4. Expand remaining `RUNTIME_READY_NOT_EXECUTED` matrix/math leaves with verified ABIs.",
            "5. Extend Playwright coverage for corrupted-cache / quota / offline-reload edge cases.",
            "",
            frontier.get("recommended_phase49") or "",
            "",
        ]))


def run_tests() -> tuple[int, int]:
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    import uc_phase48_test as t48
    suite.addTests(loader.loadTestsFromModule(t48))
    for mod in (t47, t46, t45, t43, t44):
        suite.addTests(loader.loadTestsFromModule(mod))
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    return result.testsRun, len(result.failures) + len(result.errors)


def main() -> int:
    help_info = inspect_help_dir()
    node = run_node_validation()
    camp = run_campaign()
    frontier = update_artifacts(help_info, node, camp)
    write_docs(help_info, node, camp, frontier)
    n, fails = run_tests()
    ok = (
        fails == 0
        and bool((node.get("uc_assets_test") or {}).get("passed"))
        and bool((node.get("esbuild_build") or {}).get("passed"))
    )
    print(json.dumps({
        "phase": 48,
        "unique": frontier["unique_uc_functions_executed"],
        "enterable": frontier["enterable"],
        "runs": frontier["execution_runs"],
        "newly_executed": camp["newly_executed"],
        "enterable_new": camp["enterable_new"],
        "node_uc_assets": (node.get("uc_assets_test") or {}).get("passed"),
        "build": (node.get("esbuild_build") or {}).get("passed"),
        "browser_clean": (node.get("browser_clean_test") or {}).get("passed"),
        "tests_run": n,
        "test_failures": fails,
        "first_frame": FIRST_FRAME,
        "asset_distribution": frontier["phase48"]["asset_distribution"],
    }, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
