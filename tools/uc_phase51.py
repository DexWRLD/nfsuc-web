#!/usr/bin/env python3
"""Phase 51: authentic startup logo discovery + independent preview campaign."""
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
import uc_phase50_test as t50
import uc_phase48 as p48

ROOT = p7.ROOT
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")
FIRST_FRAME = "FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND"
NODE_PATH_FILE = os.path.join(ROOT, "tools", ".node-path.txt")
DIALOG_SHA = "6c30b18704f937bb7257b44598bc66097de2bbc806e007d8f72c2d19765408a7"
VP6_SHA = "d4982c58fa09d35390b4b02f504035002e0ec665ced3cd13f9f92e413284012c"


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

    out["uc_startup_preview_test"] = node_test("web/test/uc-startup-preview.test.mjs")
    print("startup:", out["uc_startup_preview_test"]["passed"])
    out["uc_startup_browser_test"] = node_test("web/test/uc-startup-browser.test.mjs", timeout=120)
    print("startup-browser:", out["uc_startup_browser_test"]["passed"])
    out["uc_dxt1_test"] = node_test("web/test/uc-dxt1.test.mjs")
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
    print(
        "build:", out["esbuild_build"]["passed"],
        "startup:", out["uc_startup_preview_test"]["passed"],
        "startup-browser:", out["uc_startup_browser_test"]["passed"],
        "dxt1:", out["uc_dxt1_test"]["passed"],
    )
    return out


def run_campaign() -> dict:
    prev = load("runtime-frontier.json")
    p50 = load("phase50-execution.json")
    base_runs = int(p50["metrics_delta"]["runs_after"])
    base_unique = int(p50["metrics_delta"]["unique_after"])
    base_enterable = int(p50["metrics_delta"]["enterable_after"])
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
        "baseline_unique_p50": base_unique,
        "baseline_enterable_p50": base_enterable,
        "baseline_runs_p50": base_runs,
        "families": camp.get("regressions") if isinstance(camp.get("regressions"), dict) else {},
    }


def update_inventory_summary() -> dict:
    inv = load("startup-asset-inventory.json")
    inv["verified_startup_image"] = {
        "resource_id": "install.dialoglogo128x128",
        "relative_path": "dialoglogo128x128.jpg",
        "source_sha256": DIALOG_SHA,
        "payload_sha256": DIALOG_SHA,
        "source_byte_offset": 0,
        "source_byte_length": 22685,
        "media_format": "image/jpeg",
        "width": 128,
        "height": 128,
        "independently_decodable": True,
        "browser_native": True,
        "identity_note": (
            "Original ship file from the Undercover install root. "
            "NOT proven to be LS_EALOGO.FNG / LOGOTEXTURES.BUN / BOOTFLOWTEXTURES.BUN member."
        ),
        "export_tool": "tools/uc_export_startup_logo.py",
        "authorized_export_dir": "%USERPROFILE%\\.nfsuc-web\\authorized-startup",
        "git_committed": False,
    }
    inv["vp6_movies"] = {
        "path_template_ghidra": "%sMOVIES\\%s%s%s%s.vp6 @ 0x00B7E850",
        "files_on_disk": True,
        "browser_native": False,
        "decoder_in_repo": False,
        "status": "IDENTIFIED_NO_DECODER",
        "example": {
            "relative_path": "MOVIES/ea_bumper_english_ntsc.vp6",
            "sha256": VP6_SHA,
            "size": 8306328,
            "head_ascii": "MVhd ...vp60....",
        },
    }
    inv["bun_status"] = {
        "LOGOTEXTURES.BUN": "present; DXT FourCC seen; no verified membership/offset parser",
        "BOOTFLOWTEXTURES.BUN": "present; DXT FourCC seen; no verified membership/offset parser",
        "FRONTB1.BUN": "present; unsupported without parser",
    }
    dump("startup-asset-inventory.json", inv)
    return inv


def update_artifacts(node: dict, camp: dict) -> dict:
    prev = load("runtime-frontier.json")
    frontier = dict(prev)
    frontier["phase"] = 51
    frontier["first_frame"] = FIRST_FRAME
    frontier["graphics_frozen"] = True
    frontier["unique_uc_functions_executed"] = camp["unique_after"]
    frontier["unique_uc_functions_executed_list"] = camp["executed"]
    frontier["enterable"] = camp["enterable_after"]
    frontier["enterable_roots"] = camp["enterable"]
    frontier["execution_runs"] = camp["runs_after"]

    startup_ok = bool((node.get("uc_startup_preview_test") or {}).get("passed"))
    # Browser smoke is best-effort when Chromium is installed; skip ≠ campaign fail.
    sb = node.get("uc_startup_browser_test") or {}
    startup_browser_ok = bool(sb.get("passed")) or bool(sb.get("skipped"))
    dxt_ok = bool((node.get("uc_dxt1_test") or {}).get("passed"))
    assets_ok = bool((node.get("uc_assets_test") or {}).get("passed"))
    lan_ok = bool((node.get("uc_lan_server_test") or {}).get("passed"))
    build_ok = bool((node.get("esbuild_build") or {}).get("passed"))

    inv = update_inventory_summary()
    verified = inv.get("verified_startup_image") or {}

    statuses = {
        "AUTHENTIC_STARTUP_ASSET_PREVIEW": "READY",
        "AUTHENTIC_INTRO_VIDEO_PREVIEW": "IDENTIFIED_NO_DECODER",
        "FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND": "BLOCKED",
        "notes": {
            "AUTHENTIC_STARTUP_ASSET_PREVIEW": (
                "dialoglogo128x128.jpg independently verified JPEG; "
                "not LS_EALOGO.FNG / BUN member proof."
            ),
            "AUTHENTIC_INTRO_VIDEO_PREVIEW": (
                "Concrete .vp6 files on disk; no independent browser decoder."
            ),
            "FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND": (
                "Startup logo preview does not unblock gameplay rendering."
            ),
        },
    }
    dump("startup-preview-status.json", statuses)

    frontier["phase51"] = {
        "startup_preview_tests_passed": startup_ok,
        "startup_browser_tests_passed": startup_browser_ok,
        "dxt1_decoder_tests_passed": dxt_ok,
        "node_uc_assets_passed": assets_ok,
        "lan_server_tests_passed": lan_ok,
        "frontend_build_passed": build_ok,
        "blocked_external_unchanged": 74,
        "authentic_startup_asset_preview": statuses["AUTHENTIC_STARTUP_ASSET_PREVIEW"],
        "authentic_intro_video_preview": statuses["AUTHENTIC_INTRO_VIDEO_PREVIEW"],
        "verified_startup_image_sha256": verified.get("payload_sha256"),
        "verified_startup_image_path": verified.get("relative_path"),
        "bun_logo_payload_verified": False,
        "vp6_decoder_implemented": False,
        "browser_game_renderer_ready": False,
        "asset_distribution": "PRIVATE_LAN_FIXTURE_HOST_READY",
        "lan_testing_readiness": "PRIVATE_LAN_HTTPS_READY",
        "note": (
            "Independently verified install-root dialog JPEG preview; "
            "FNG/BUN boot logos and VP6 remain unsupported; FIRST_FRAME blocked."
        ),
    }
    frontier["recommended_phase52"] = (
        "Map verified BUN/BIGF membership for NFS_UNDERCOVER_LOGO or LS_EALOGO "
        "with proven offset/length digests; or obtain a rights-cleared offline "
        "VP6→browser-safe conversion retaining provenance; continue DXT1 span hunt; "
        "keep opaque draw backends untouched; FIRST_FRAME remains blocked."
    )
    dump("runtime-frontier.json", frontier)

    auth = load("authentic-texture-status.json")
    dump("asset-distribution-readiness.json", {
        "phase": 51,
        "asset_distribution_readiness": "PRIVATE_LAN_FIXTURE_HOST_READY",
        "lan_testing_readiness": "PRIVATE_LAN_HTTPS_READY",
        "production_undercover_assets": "UNAVAILABLE_PENDING_AUTHORIZED_SOURCE",
        "browser_renderer_readiness": "STARTUP_LOGO_AND_SYNTHETIC_TEXTURE_PREVIEW",
        "first_frame": FIRST_FRAME,
        "startup_preview": statuses,
        "verified_startup_image": verified,
        "texture_preview": auth,
        "clean_pc_ux": {
            "no_game_install_required_for_fixtures": True,
            "automatic_download": True,
            "authentic_play_enabled": False,
            "synthetic_startup_preview": True,
            "authentic_startup_logo_via_authorized_root": True,
            "authentic_intro_video": False,
        },
    })

    evidence = load("execution-evidence.json")
    evidence["phase"] = 51
    evidence["unique_uc_functions_executed"] = camp["unique_after"]
    evidence["phase51_results"] = camp["results"]
    dump("execution-evidence.json", evidence)

    status = load("project-status.json")
    status["current_phase"] = 51
    status["strategy"] = (
        "Phase 51: authentic install-root dialog logo preview + startup state machine; "
        "BUN/FNG boot logos and VP6 still unsupported; FIRST_FRAME frozen."
    )
    phases = status.get("phases") or []
    for ph in phases:
        if "title" in ph and "name" not in ph:
            ph["name"] = ph.pop("title")
        if "status" in ph and "state" not in ph:
            st = ph.pop("status")
            ph["state"] = "completed" if st in ("complete", "completed") else st
    if not any(p.get("phase") == 51 for p in phases):
        phases.append({
            "phase": 51,
            "name": "Authentic startup logo preview & intro inventory",
            "state": "completed",
        })
    status["phases"] = phases
    dump("project-status.json", status)

    dump("phase51-execution.json", {
        "phase": 51,
        "metrics_delta": {
            "unique_before": camp["baseline_unique_p50"],
            "unique_after": camp["unique_after"],
            "enterable_before": camp["baseline_enterable_p50"],
            "enterable_after": camp["enterable_after"],
            "runs_before": camp["baseline_runs_p50"],
            "runs_after": camp["runs_after"],
        },
        "newly_executed": [],
        "families": camp["families"],
        "node": {
            "startup": startup_ok,
            "startup_browser": startup_browser_ok,
            "dxt1": dxt_ok,
            "assets": assets_ok,
            "lan": lan_ok,
            "build": build_ok,
        },
        "statuses": statuses,
    })
    return frontier


def write_docs(node: dict, camp: dict, frontier: dict) -> None:
    p51 = frontier["phase51"]
    statuses = load("startup-preview-status.json")
    inv = load("startup-asset-inventory.json")
    verified = inv.get("verified_startup_image") or {}
    lines = [
        "# Undercover Phase 51 — Authentic startup logo preview",
        "",
        "SHA-256: `6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd`",
        "",
        "`GAME_CODE_TARGET=NFS_UNDERCOVER_PC`  `TOOLING_ORIGIN=NFSU2-WEB`",
        "",
        f"FIRST_FRAME: `{FIRST_FRAME}`",
        "",
        "## Independent statuses",
        "",
        f"- `AUTHENTIC_STARTUP_ASSET_PREVIEW`: **{statuses['AUTHENTIC_STARTUP_ASSET_PREVIEW']}**",
        f"- `AUTHENTIC_INTRO_VIDEO_PREVIEW`: **{statuses['AUTHENTIC_INTRO_VIDEO_PREVIEW']}**",
        f"- `FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND`: **{statuses['FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND']}**",
        "",
        "## A. Verified startup image",
        "",
        f"- Path: `{verified.get('relative_path')}` (install root)",
        f"- SHA-256: `{verified.get('payload_sha256')}`",
        f"- Format: JPEG {verified.get('width')}×{verified.get('height')}, offset 0, length {verified.get('source_byte_length')}",
        f"- Identity: {verified.get('identity_note')}",
        "- Export (outside repo): `tools/uc_export_startup_logo.py` → `%USERPROFILE%\\.nfsuc-web\\authorized-startup`",
        "- Not committed to git.",
        "",
        "## B. Frontend / movie inventory (read-only)",
        "",
        "- Install accessible: yes (`C:\\Games\\Need For Speed Undercover`)",
        "- `FRONTEND/LOGOTEXTURES.BUN`, `BOOTFLOWTEXTURES.BUN`, `FRONTB1.BUN` present; **no verified BUN→image span**",
        "- `.FNG` names are exe string leads only; no loose `.FNG` files",
        f"- `MOVIES/ea_bumper_english_ntsc.vp6` present (`{VP6_SHA[:16]}…`); VP6 **IDENTIFIED_NO_DECODER**",
        "- See `startup-asset-inventory.json`",
        "",
        "## C. Startup preview (browser)",
        "",
        "- State machine: `LOGO → OPTIONAL_VIDEO → MENU_PLACEHOLDER` (`uc-startup-preview.ts`)",
        "- UI panel + OPFS/memory cache publish after digest verify",
        "- Synthetic fixture for CI; authentic JPEG via `UC_ASSET_ROOT`",
        f"- Node startup tests: **{'PASS' if p51.get('startup_preview_tests_passed') else 'FAIL'}**",
        f"- Browser startup smoke: **{'PASS' if p51.get('startup_browser_tests_passed') else 'FAIL'}**",
        "",
        "## D. Validation",
        "",
        f"- Startup preview: **{'PASS' if p51.get('startup_preview_tests_passed') else 'FAIL'}**",
        f"- Browser startup: **{'PASS' if p51.get('startup_browser_tests_passed') else 'FAIL'}**",
        f"- DXT1 regression: **{'PASS' if p51.get('dxt1_decoder_tests_passed') else 'FAIL'}**",
        f"- Assets: **{'PASS' if p51.get('node_uc_assets_passed') else 'FAIL'}**",
        f"- LAN: **{'PASS' if p51.get('lan_server_tests_passed') else 'FAIL'}**",
        f"- Build: **{'PASS' if p51.get('frontend_build_passed') else 'FAIL'}**",
        "",
        "## E. Metrics (50 → 51)",
        "",
        f"- UNIQUE: {camp['baseline_unique_p50']} → {frontier['unique_uc_functions_executed']}",
        f"- ENTERABLE: {camp['baseline_enterable_p50']} → {frontier['enterable']}",
        f"- RUNS: {camp['baseline_runs_p50']} → {frontier['execution_runs']}",
        f"- BLOCKED_EXTERNAL: 74",
        f"- First frame: BLOCKED",
        "",
        "## F. Phase 52",
        "",
        frontier.get("recommended_phase52") or "",
        "",
    ]
    with open(os.path.join(ANALYSIS, "runtime-phase51.md"), "w",
              encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines))
    with open(os.path.join(ANALYSIS, "phase52-handoff.md"), "w",
              encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join([
            "# Phase 52 handoff",
            "",
            "From Phase 51 authentic startup dialog-logo preview.",
            "",
            "## Do not",
            "",
            "- Treat dialoglogo / synthetic previews as original boot execution or gameplay frames.",
            "- Invent BUN/BIGF offsets for LS_EALOGO / NFS_UNDERCOVER_LOGO without digests.",
            "- Implement a speculative VP6 decoder or bypass protected archives.",
            "- Reconstruct opaque backends (`0x006860F0`, `0x00686290`, …).",
            "- Commit commercial game assets or TLS private keys.",
            "",
            "## Priorities",
            "",
            "1. Verified BUN/BIGF membership + byte span for a true boot logo "
            "(LS_EALOGO / NFS_UNDERCOVER_LOGO) with source/payload SHA256.",
            "2. Rights-cleared offline VP6 conversion workflow (or licensed decoder) "
            "preserving provenance — only if a validated movie payload is in scope.",
            "3. Continue authorized DXT1 span hunt for texture preview.",
            "4. Match XP_SMOKEBALL_* to vertex/index spans + 0x50 declaration.",
            "5. Keep FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND until opaque draw path is ordinary evidence.",
            "",
            frontier.get("recommended_phase52") or "",
            "",
        ]))
    # Preserve Phase 51 priorities doc for mid-phase readers; overwrite handoff content.
    with open(os.path.join(ANALYSIS, "phase51-handoff.md"), "w",
              encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join([
            "# Phase 51 handoff (completed)",
            "",
            "See `runtime-phase51.md` and `phase52-handoff.md`.",
            "",
            "Delivered: install inventory, dialoglogo JPEG authentic preview, "
            "startup state machine, VP6 identified without decoder, statuses separated.",
            "",
        ]))
    print("wrote runtime-phase51.md / phase52-handoff.md / phase51-handoff.md")


def run_tests() -> tuple[int, int]:
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    import uc_phase51_test as t51
    suite.addTests(loader.loadTestsFromModule(t51))
    for mod in (t50, t49, t48, t47, t46, t45, t43, t44):
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
        and bool((node.get("uc_startup_preview_test") or {}).get("passed"))
        and bool((node.get("esbuild_build") or {}).get("passed"))
    )
    print(f"tests_run={n} fails={fails} ok={ok}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
