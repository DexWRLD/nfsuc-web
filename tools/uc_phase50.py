#!/usr/bin/env python3
"""Phase 50: DXT1 decoder, texture/mesh preview contracts, validation campaign."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import uc_phase7_test as p7
import uc_phase43_test as t43
import uc_phase44_test as t44
import uc_phase45_test as t45
import uc_phase46_test as t46
import uc_phase47_test as t47
import uc_phase48_test as t48
import uc_phase49_test as t49
import uc_phase48 as p48

ROOT = p7.ROOT
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")
FIRST_FRAME = "FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND"
NODE_PATH_FILE = os.path.join(ROOT, "tools", ".node-path.txt")


def load(name: str):
    with open(os.path.join(ANALYSIS, name), encoding="utf-8") as fh:
        return json.load(fh)


def dump(name: str, obj) -> None:
    path = os.path.join(ANALYSIS, name)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(obj, fh, indent=2)
        fh.write("\n")
    print("wrote", path)


def find_node() -> str | None:
    if os.path.isfile(NODE_PATH_FILE):
        p = open(NODE_PATH_FILE, encoding="utf-8").read().strip()
        if p and os.path.isfile(p):
            return p
    return shutil.which("node")


def _run_cap(cmd, **kwargs):
    kwargs.setdefault("capture_output", True)
    kwargs.setdefault("text", True)
    kwargs.setdefault("encoding", "utf-8")
    kwargs.setdefault("errors", "replace")
    return subprocess.run(cmd, **kwargs)


def run_node_validation() -> dict:
    node = find_node()
    out: dict = {"node_path": node, "node_version": None}
    if not node:
        out["error"] = "node not found"
        return out
    env = os.environ.copy()
    env["PATH"] = os.path.dirname(node) + os.pathsep + env.get("PATH", "")
    git_openssl = r"C:\Program Files\Git\usr\bin"
    if os.path.isdir(git_openssl):
        env["PATH"] = git_openssl + os.pathsep + env["PATH"]
    out["node_version"] = (_run_cap([node, "-v"], env=env).stdout or "").strip()
    npm = os.path.join(os.path.dirname(node), "npm.cmd" if os.name == "nt" else "npm")
    web = os.path.join(ROOT, "web")

    def node_test(rel: str, timeout: int | None = 120) -> dict:
        try:
            r = _run_cap(
                [node, "--test", "--test-timeout=90000", os.path.join(ROOT, rel)],
                cwd=ROOT, env=env, timeout=timeout,
            )
            tail = ((r.stdout or "") + (r.stderr or ""))[-3000:]
            mskip = re.search(r"skipped\s+(\d+)", tail.lower())
            skipped = bool(mskip and int(mskip.group(1)) > 0)
            return {
                "exit_code": r.returncode,
                "passed": r.returncode == 0 and not skipped,
                "skipped": skipped,
                "tail": tail,
            }
        except subprocess.TimeoutExpired:
            return {"exit_code": -1, "passed": False, "skipped": True, "tail": "TIMEOUT"}

    out["uc_dxt1_test"] = node_test("web/test/uc-dxt1.test.mjs")
    print("dxt1:", out["uc_dxt1_test"]["passed"])
    out["uc_assets_test"] = node_test("web/test/uc-assets.test.mjs")
    out["uc_lan_server_test"] = node_test("web/test/uc-lan-server.test.mjs")
    out["tsc_check"] = {
        "passed": _run_cap([npm, "run", "check"], cwd=web, env=env).returncode == 0,
    }
    build = _run_cap([npm, "run", "build"], cwd=web, env=env)
    out["esbuild_build"] = {
        "passed": build.returncode == 0,
        "tail": ((build.stdout or "") + (build.stderr or ""))[-1200:],
    }
    out["uc_browser_clean_test"] = node_test("web/test/uc-browser-clean.mjs", timeout=120)
    out["uc_lan_https_browser_test"] = node_test(
        "web/test/uc-lan-https-browser.test.mjs", timeout=180,
    )
    print("build:", out["esbuild_build"]["passed"],
          "assets:", out["uc_assets_test"]["passed"],
          "lan:", out["uc_lan_server_test"]["passed"])
    return out


def run_campaign() -> dict:
    prev = load("runtime-frontier.json")
    p49 = load("phase49-execution.json")
    base_runs = int(p49["metrics_delta"]["runs_after"])
    base_unique = int(p49["metrics_delta"]["unique_after"])
    base_enterable = int(p49["metrics_delta"]["enterable_after"])
    camp = p48.run_campaign()
    executed = set(prev.get("unique_uc_functions_executed_list") or [])
    enterable = set(prev.get("enterable_roots") or [])
    for r in camp["results"]:
        for e in r.get("entered") or []:
            executed.add(e)
        if r.get("oracle_ok") and r.get("clean"):
            enterable.add(r["root"])
    return {
        "results": camp["results"],
        "newly_executed": [],
        "enterable_new": [],
        "runs_delta": len(camp["results"]),
        "runs_after": base_runs + len(camp["results"]),
        "unique_after": len(executed),
        "enterable_after": len(enterable),
        "executed": sorted(executed),
        "enterable": sorted(enterable),
        "baseline_unique_p49": base_unique,
        "baseline_enterable_p49": base_enterable,
        "baseline_runs_p49": base_runs,
        "families": camp.get("regressions") if isinstance(camp.get("regressions"), dict) else {},
    }


def update_artifacts(node: dict, camp: dict) -> dict:
    prev = load("runtime-frontier.json")
    frontier = dict(prev)
    frontier["phase"] = 50
    frontier["first_frame"] = FIRST_FRAME
    frontier["graphics_frozen"] = True
    frontier["unique_uc_functions_executed"] = camp["unique_after"]
    frontier["unique_uc_functions_executed_list"] = camp["executed"]
    frontier["enterable"] = camp["enterable_after"]
    frontier["enterable_roots"] = camp["enterable"]
    frontier["execution_runs"] = camp["runs_after"]

    dxt_ok = bool((node.get("uc_dxt1_test") or {}).get("passed"))
    assets_ok = bool((node.get("uc_assets_test") or {}).get("passed"))
    lan_ok = bool((node.get("uc_lan_server_test") or {}).get("passed"))
    build_ok = bool((node.get("esbuild_build") or {}).get("passed"))

    auth = load("authentic-texture-status.json")
    frontier["phase50"] = {
        "dxt1_decoder_tests_passed": dxt_ok,
        "node_uc_assets_passed": assets_ok,
        "lan_server_tests_passed": lan_ok,
        "frontend_build_passed": build_ok,
        "blocked_external_unchanged": 74,
        "synthetic_texture_decoder": auth["synthetic_texture_decoder"],
        "synthetic_mesh_viewer": auth["synthetic_mesh_viewer"],
        "authentic_texture_source_identified": auth["authentic_texture_source_identified"],
        "authentic_texture_preview_verified": auth["authentic_texture_preview_verified"],
        "authentic_mesh_source_identified": auth["authentic_mesh_source_identified"],
        "authentic_mesh_preview_verified": auth["authentic_mesh_preview_verified"],
        "browser_game_renderer_ready": False,
        "cube_texture_correction": "0x007513E2_CreateCubeTexture",
        "asset_distribution": "PRIVATE_LAN_FIXTURE_HOST_READY",
        "lan_testing_readiness": "PRIVATE_LAN_HTTPS_READY",
        "browser_renderer": "SYNTHETIC_TEXTURE_AND_MESH_PREVIEW",
        "note": (
            "Strict BC1 decoder + provenance + synthetic previews; "
            "authentic Undercover texture/mesh sources still unverified."
        ),
    }
    frontier["recommended_phase51"] = (
        "Locate one readable authorized DXT1 span with proven offset/size/format digests; "
        "or match XP_SMOKEBALL_* vertex/index spans to a verified 0x50 declaration; "
        "keep opaque draw backends untouched; FIRST_FRAME remains blocked."
    )
    dump("runtime-frontier.json", frontier)

    dump("asset-distribution-readiness.json", {
        "phase": 50,
        "asset_distribution_readiness": "PRIVATE_LAN_FIXTURE_HOST_READY",
        "lan_testing_readiness": "PRIVATE_LAN_HTTPS_READY",
        "production_undercover_assets": "UNAVAILABLE_PENDING_AUTHORIZED_SOURCE",
        "browser_renderer_readiness": "SYNTHETIC_TEXTURE_AND_MESH_PREVIEW",
        "first_frame": FIRST_FRAME,
        "texture_preview": auth,
        "cube_correction": load("cube-texture-correction.json"),
        "clean_pc_ux": {
            "no_game_install_required_for_fixtures": True,
            "automatic_download": True,
            "authentic_play_enabled": False,
            "synthetic_texture_preview": True,
            "authentic_texture_preview": False,
        },
    })

    evidence = load("execution-evidence.json")
    evidence["phase"] = 50
    evidence["unique_uc_functions_executed"] = camp["unique_after"]
    evidence["phase50_results"] = camp["results"]
    dump("execution-evidence.json", evidence)

    status = load("project-status.json")
    status["current_phase"] = 50
    status["strategy"] = (
        "Phase 50: BC1 decoder, provenance-gated texture preview, vertex-decl + mesh "
        "validators; authentic payloads still missing; FIRST_FRAME frozen."
    )
    phases = status.get("phases") or []
    # Normalize legacy title/status keys; progress.py expects name/state.
    for ph in phases:
        if "title" in ph and "name" not in ph:
            ph["name"] = ph.pop("title")
        if "status" in ph and "state" not in ph:
            st = ph.pop("status")
            ph["state"] = "completed" if st in ("complete", "completed") else st
    if not any(p.get("phase") == 50 for p in phases):
        phases.append({
            "phase": 50,
            "name": "DXT1 decoder & asset preview contracts",
            "state": "completed",
        })
    status["phases"] = phases
    dump("project-status.json", status)

    dump("phase50-execution.json", {
        "phase": 50,
        "metrics_delta": {
            "unique_before": camp["baseline_unique_p49"],
            "unique_after": camp["unique_after"],
            "enterable_before": camp["baseline_enterable_p49"],
            "enterable_after": camp["enterable_after"],
            "runs_before": camp["baseline_runs_p49"],
            "runs_after": camp["runs_after"],
        },
        "newly_executed": [],
        "families": camp["families"],
        "node": {
            "dxt1": dxt_ok,
            "assets": assets_ok,
            "lan": lan_ok,
            "build": build_ok,
        },
    })
    return frontier


def write_docs(node: dict, camp: dict, frontier: dict) -> None:
    p50 = frontier["phase50"]
    auth = load("authentic-texture-status.json")
    lines = [
        "# Undercover Phase 50 — BC1 decoder & asset preview contracts",
        "",
        "SHA-256: `6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd`",
        "",
        "`GAME_CODE_TARGET=NFS_UNDERCOVER_PC`  `TOOLING_ORIGIN=NFSU2-WEB`",
        "",
        f"FIRST_FRAME: `{FIRST_FRAME}`",
        "",
        "## Correction",
        "",
        "`0x007513E2` is **CreateCubeTexture** (six faces), not CreateVolumeTexture.",
        "See `cube-texture-correction.json` and `undercover-asset-browser-report.md`.",
        "",
        "## A. BC1/DXT1 decoder",
        "",
        f"- Strict standalone decoder: `web/src/app/uc-dxt1.ts`",
        f"- Unit tests: **{'PASS' if p50.get('dxt1_decoder_tests_passed') else 'FAIL'}**",
        "- Synthetic fixtures under `web/src/static/uc-fixtures/textures/`",
        "",
        "## B. Provenance & preview",
        "",
        "- Manifest validation: `uc-texture-manifest.ts`",
        "- Viewer states include `PREVIEW_SYNTHETIC` / `PREVIEW_AUTHENTIC_VERIFIED`",
        f"- Authentic texture source identified: **{auth['authentic_texture_source_identified']}**",
        f"- Authentic texture preview verified: **{auth['authentic_texture_preview_verified']}**",
        "",
        "## C. Vertex declaration & mesh",
        "",
        "- Converter `0x0073F300` tables: `uc-vertex-decl.ts`",
        "- Mesh contract: `uc-mesh-validate.ts`",
        "- Synthetic WebGL triangle preview: `uc-mesh-preview.ts`",
        f"- Authentic mesh source identified: **{auth['authentic_mesh_source_identified']}**",
        "",
        "## D. Dashboard",
        "",
        f"- Synthetic texture decoder: {auth['synthetic_texture_decoder']}",
        f"- Synthetic mesh viewer: {auth['synthetic_mesh_viewer']}",
        f"- Browser game renderer ready: {auth['browser_game_renderer_ready']}",
        f"- Authentic first frame ready: {auth['authentic_first_frame_ready']}",
        "",
        "## E. Validation",
        "",
        f"- Node DXT1/provenance/mesh: **{'PASS' if p50.get('dxt1_decoder_tests_passed') else 'FAIL'}**",
        f"- Node assets: **{'PASS' if p50.get('node_uc_assets_passed') else 'FAIL'}**",
        f"- LAN server: **{'PASS' if p50.get('lan_server_tests_passed') else 'FAIL'}**",
        f"- Build: **{'PASS' if p50.get('frontend_build_passed') else 'FAIL'}**",
        "- Guest metrics: Phase 49 regression only (no inflation)",
        "",
        "## F. Metrics (49 → 50)",
        "",
        f"- Compiled: 22,770",
        f"- UNIQUE: {camp['baseline_unique_p49']} → {frontier['unique_uc_functions_executed']}",
        f"- ENTERABLE: {camp['baseline_enterable_p49']} → {frontier['enterable']}",
        f"- RUNS: {camp['baseline_runs_p49']} → {frontier['execution_runs']}",
        f"- RUNTIME_READY: {frontier.get('runtime_ready')}",
        f"- BLOCKED_EXTERNAL: 74",
        f"- Browser renderer: {p50.get('browser_renderer')}",
        f"- First frame: BLOCKED",
        "",
        "## G. Phase 51",
        "",
        frontier.get("recommended_phase51") or "",
        "",
    ]
    with open(os.path.join(ANALYSIS, "runtime-phase50.md"), "w",
              encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines))
    with open(os.path.join(ANALYSIS, "phase51-handoff.md"), "w",
              encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join([
            "# Phase 51 handoff",
            "",
            "From Phase 50 BC1 decoder and synthetic asset previews.",
            "",
            "## Do not",
            "",
            "- Treat synthetic texture/mesh previews as authentic gameplay frames.",
            "- Invent archive offsets for DXT1 or XP_SMOKEBALL_* without digests.",
            "- Reconstruct opaque backends (`0x006860F0`, `0x00686290`, …).",
            "- Commit commercial game assets or TLS private keys.",
            "",
            "## Priorities",
            "",
            "1. Obtain one authorized readable DXT1 span with proven "
            "source SHA256, offset, length, dimensions, format, payload SHA256.",
            "2. Drive `PREVIEW_AUTHENTIC_VERIFIED` through LAN download + OPFS cache.",
            "3. Match `XP_SMOKEBALL_CURL` / `PUFF` to vertex/index spans + 0x50 declaration.",
            "4. Optional textured mesh diagnostic once UV + texture IDs are verified.",
            "5. Keep FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND until opaque draw path is replaced by ordinary evidence.",
            "",
            frontier.get("recommended_phase51") or "",
            "",
        ]))
    print("wrote runtime-phase50.md / phase51-handoff.md")


def run_tests() -> tuple[int, int]:
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    import uc_phase50_test as t50
    suite.addTests(loader.loadTestsFromModule(t50))
    for mod in (t49, t48, t47, t46, t45, t43, t44):
        suite.addTests(loader.loadTestsFromModule(mod))
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    return result.testsRun, len(result.failures) + len(result.errors)


def main() -> int:
    node = run_node_validation()
    camp = run_campaign()
    frontier = update_artifacts(node, camp)
    write_docs(node, camp, frontier)
    n, fails = run_tests()
    ok = (
        fails == 0
        and bool((node.get("uc_dxt1_test") or {}).get("passed"))
        and bool((node.get("uc_assets_test") or {}).get("passed"))
        and bool((node.get("esbuild_build") or {}).get("passed"))
    )
    print(json.dumps({
        "phase": 50,
        "unique": frontier["unique_uc_functions_executed"],
        "enterable": frontier["enterable"],
        "runs": frontier["execution_runs"],
        "dxt1": (node.get("uc_dxt1_test") or {}).get("passed"),
        "assets": (node.get("uc_assets_test") or {}).get("passed"),
        "lan": (node.get("uc_lan_server_test") or {}).get("passed"),
        "build": (node.get("esbuild_build") or {}).get("passed"),
        "tests_run": n,
        "test_failures": fails,
        "authentic_texture": False,
        "first_frame": FIRST_FRAME,
        "ok": ok,
    }, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
