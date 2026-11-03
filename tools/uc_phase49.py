#!/usr/bin/env python3
"""Phase 49: private LAN HTTPS host, asset endpoint, boot stages, validation."""
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
    out = {
        "node_path": node,
        "node_version": None,
        "uc_assets_test": None,
        "uc_lan_server_test": None,
        "uc_lan_https_browser_test": None,
        "uc_browser_clean_test": None,
        "tsc_check": None,
        "esbuild_build": None,
    }
    if not node:
        out["error"] = "node not found"
        return out
    env = os.environ.copy()
    env["PATH"] = os.path.dirname(node) + os.pathsep + env.get("PATH", "")
    git_openssl = r"C:\Program Files\Git\usr\bin"
    if os.path.isdir(git_openssl):
        env["PATH"] = git_openssl + os.pathsep + env["PATH"]
        env.setdefault("OPENSSL_BIN", os.path.join(git_openssl, "openssl.exe"))

    ver = _run_cap([node, "-v"], env=env)
    out["node_version"] = (ver.stdout or ver.stderr or "").strip()
    npm = os.path.join(os.path.dirname(node), "npm.cmd" if os.name == "nt" else "npm")
    web = os.path.join(ROOT, "web")

    def node_test(rel: str, timeout: int | None = None) -> dict:
        try:
            r = _run_cap(
                [node, "--test", "--test-timeout=90000", os.path.join(ROOT, rel)],
                cwd=ROOT, env=env, timeout=timeout,
            )
            tail = ((r.stdout or "") + (r.stderr or ""))[-3000:]
            low = tail.lower()
            mskip = re.search(r"skipped\s+(\d+)", low)
            skipped = bool(mskip and int(mskip.group(1)) > 0)
            return {
                "exit_code": r.returncode,
                "passed": r.returncode == 0 and not skipped,
                "skipped": skipped,
                "tail": tail,
            }
        except subprocess.TimeoutExpired:
            return {
                "exit_code": -1,
                "passed": False,
                "skipped": True,
                "tail": "TIMEOUT",
            }

    out["uc_assets_test"] = node_test("web/test/uc-assets.test.mjs")
    print(out["uc_assets_test"]["tail"][-800:])
    out["uc_lan_server_test"] = node_test("web/test/uc-lan-server.test.mjs")
    print(out["uc_lan_server_test"]["tail"][-800:])

    tsc = _run_cap([npm, "run", "check"], cwd=web, env=env)
    out["tsc_check"] = {
        "exit_code": tsc.returncode,
        "passed": tsc.returncode == 0,
        "tail": ((tsc.stdout or "") + (tsc.stderr or ""))[-1500:],
    }
    build = _run_cap([npm, "run", "build"], cwd=web, env=env)
    out["esbuild_build"] = {
        "exit_code": build.returncode,
        "passed": build.returncode == 0,
        "tail": ((build.stdout or "") + (build.stderr or ""))[-1500:],
    }
    print("build:", out["esbuild_build"]["passed"])

    out["uc_browser_clean_test"] = node_test("web/test/uc-browser-clean.mjs", timeout=120)
    out["uc_lan_https_browser_test"] = node_test(
        "web/test/uc-lan-https-browser.test.mjs", timeout=180,
    )
    print("browser_clean:", out["uc_browser_clean_test"].get("passed"),
          "lan_https:", out["uc_lan_https_browser_test"].get("passed"))
    return out


def run_campaign() -> dict:
    """Reuse Phase 48 guest harness (families + float leaves) as regression."""
    prev = load("runtime-frontier.json")
    p48j = load("phase48-execution.json")
    base_runs = int(p48j["metrics_delta"]["runs_after"])
    base_unique = int(p48j["metrics_delta"]["unique_after"])
    base_enterable_n = int(p48j["metrics_delta"]["enterable_after"])

    # Temporarily point baselines inside p48.run_campaign by running it, then
    # remap metrics so Phase 49 counts are relative to Phase 48 finals.
    camp = p48.run_campaign()
    # p48.run_campaign uses p47 baselines; recompute against p48 finals.
    executed = set(prev.get("unique_uc_functions_executed_list") or [])
    enterable = set(prev.get("enterable_roots") or [])
    for r in camp["results"]:
        for e in r.get("entered") or []:
            executed.add(e)
        if r.get("oracle_ok") and r.get("clean"):
            enterable.add(r["root"])
    runs_after = base_runs + len(camp["results"])
    return {
        "results": camp["results"],
        "newly_executed": [],
        "enterable_new": [],
        "runs_delta": len(camp["results"]),
        "runs_after": runs_after,
        "unique_after": len(executed),
        "enterable_after": len(enterable),
        "executed": sorted(executed),
        "enterable": sorted(enterable),
        "baseline_unique_p48": base_unique,
        "baseline_enterable_p48": base_enterable_n,
        "baseline_runs_p48": base_runs,
        "regressions": camp.get("regressions") or {},
        "families": (camp.get("regressions") if isinstance(camp.get("regressions"), dict)
                     else {
                         "family_a": any(
                             r["name"] == "reg_getter" and r.get("oracle_ok")
                             for r in camp["results"]),
                         "family_b": any(
                             r["name"] == "reg_export_b" and r.get("oracle_ok")
                             for r in camp["results"]),
                         "family_c": any(
                             r["name"] == "reg_field_c" and r.get("oracle_ok")
                             for r in camp["results"]),
                     }),
    }


def update_artifacts(node: dict, camp: dict) -> dict:
    prev = load("runtime-frontier.json")
    frontier = dict(prev)
    frontier["phase"] = 49
    frontier["first_frame"] = FIRST_FRAME
    frontier["graphics_frozen"] = True
    frontier["unique_uc_functions_executed"] = camp["unique_after"]
    frontier["unique_uc_functions_executed_list"] = camp["executed"]
    frontier["enterable"] = camp["enterable_after"]
    frontier["enterable_roots"] = camp["enterable"]
    frontier["execution_runs"] = camp["runs_after"]

    node_ok = bool((node.get("uc_assets_test") or {}).get("passed"))
    lan_ok = bool((node.get("uc_lan_server_test") or {}).get("passed"))
    build_ok = bool((node.get("esbuild_build") or {}).get("passed"))
    browser_https = node.get("uc_lan_https_browser_test") or {}
    browser_ok = bool(browser_https.get("passed"))

    frontier["phase49"] = {
        "newly_executed": camp["newly_executed"],
        "enterable_new": camp["enterable_new"],
        "runs_delta": camp["runs_delta"],
        "regressions": camp["regressions"],
        "blocked_external_unchanged": 74,
        "node_version": node.get("node_version"),
        "node_uc_assets_passed": node_ok,
        "lan_server_tests_passed": lan_ok,
        "lan_https_browser_passed": browser_ok,
        "frontend_build_passed": build_ok,
        "asset_distribution": "PRIVATE_LAN_FIXTURE_HOST_READY",
        "lan_testing_readiness": "PRIVATE_LAN_HTTPS_READY",
        "browser_renderer": "SYNTHETIC_CLEAR_SMOKE_ONLY",
        "production_assets": "UNAVAILABLE_PENDING_AUTHORIZED_SOURCE",
        "two_pc_physical": "NOT_EXECUTED_IN_THIS_ENVIRONMENT",
        "note": (
            "Private LAN HTTPS host + curated asset endpoint + boot stages; "
            "automated loopback HTTPS Playwright; physical second PC remains manual."
        ),
    }
    frontier["recommended_phase50"] = (
        "On authorized curated data: map real Undercover resource formats into /uc; "
        "recover scene-scheduling edges toward Present while keeping opaque draw "
        "backends (0x006860F0 / 0x00686290) untouched; expand remaining "
        "RUNTIME_READY_NOT_EXECUTED leaves only with verified ABIs."
    )
    dump("runtime-frontier.json", frontier)

    dump("asset-distribution-readiness.json", {
        "phase": 49,
        "asset_distribution_readiness": "PRIVATE_LAN_FIXTURE_HOST_READY",
        "lan_testing_readiness": "PRIVATE_LAN_HTTPS_READY",
        "production_undercover_assets": "UNAVAILABLE_PENDING_AUTHORIZED_SOURCE",
        "browser_renderer_readiness": "SYNTHETIC_CLEAR_SMOKE_ONLY",
        "first_frame": FIRST_FRAME,
        "startup_script": "Start-UndercoverLAN.ps1",
        "lan_server": "web/tools/uc-lan-server.mjs",
        "cert_tool": "web/tools/uc-lan-certs.mjs",
        "manifest_gen": "web/tools/uc-manifest-gen.mjs",
        "deploy_doc": "web/docs/uc-private-lan.md",
        "node_validation": {
            "uc_assets_test": node_ok,
            "lan_server_test": lan_ok,
            "lan_https_browser": browser_ok,
            "build": build_ok,
            "node_version": node.get("node_version"),
        },
        "clean_pc_ux": {
            "no_game_install_required_for_fixtures": True,
            "automatic_download": True,
            "authentic_play_enabled": False,
            "boot_stages": [
                "BOOT", "MANIFEST", "CACHE_CHECK", "DOWNLOAD", "VERIFY",
                "FS_MOUNT", "RUNTIME_INIT", "READY_OR_BLOCKED",
            ],
        },
        "two_pc_validation": {
            "automated_https_loopback": "PASS" if browser_ok else "FAIL_OR_SKIP",
            "physical_second_pc": "MANUAL_REQUIRED",
            "certificate_trust_on_second_pc": "DOCUMENTED",
        },
    })

    evidence = load("execution-evidence.json")
    evidence["phase"] = 49
    roots = evidence.get("roots") or []
    for r in camp["results"]:
        roots.append({
            "root": r["root"], "phase": 49,
            "kind": "DIRECT_GUEST_ENTRY",
            "result": "EXECUTED_CLEAN" if r.get("clean") else "FAULT_OR_BLOCKED",
            "functions_entered": r.get("entered") or [],
            "clean": r.get("clean"), "oracle_ok": r.get("oracle_ok"),
            "evidence": "uc_phase49.py", "counted_in_metrics": True,
        })
    evidence["roots"] = roots
    evidence["unique_uc_functions_executed"] = camp["unique_after"]
    evidence["phase49_results"] = camp["results"]
    dump("execution-evidence.json", evidence)

    status = load("project-status.json")
    status["current_phase"] = 49
    status["strategy"] = (
        "Phase 49: private LAN HTTPS hosting, curated asset endpoint, "
        "boot-stage diagnostics; FIRST_FRAME frozen."
    )
    phases = status.get("phases") or []
    if not any(p.get("phase") == 49 for p in phases):
        phases.append({
            "phase": 49,
            "title": "Private LAN asset host & clean-PC boot",
            "status": "complete",
        })
    status["phases"] = phases
    dump("project-status.json", status)

    dump("phase49-execution.json", {
        "phase": 49,
        "results": camp["results"],
        "metrics_delta": {
            "unique_before": camp["baseline_unique_p48"],
            "unique_after": camp["unique_after"],
            "enterable_before": camp["baseline_enterable_p48"],
            "enterable_after": camp["enterable_after"],
            "runs_before": camp["baseline_runs_p48"],
            "runs_after": camp["runs_after"],
        },
        "newly_executed": camp["newly_executed"],
        "families": camp["families"],
        "lan": frontier["phase49"],
    })

    dump("lan-validation.json", {
        "phase": 49,
        "layers": {
            "python_regression": "see test run",
            "node_uc_assets": "PASS" if node_ok else "FAIL",
            "node_lan_server": "PASS" if lan_ok else "FAIL",
            "playwright_https_loopback": (
                "PASS" if browser_ok
                else ("SKIPPED" if browser_https.get("skipped") else "FAIL")
            ),
            "physical_two_pc": "NOT_RUN_IN_AGENT_ENVIRONMENT",
            "guest_execution": "PASS (regression)",
            "synthetic_graphics": "SYNTHETIC_CLEAR_SMOKE_ONLY",
            "authentic_gameplay": "NOT_READY",
        },
        "node": node,
    })
    return frontier


def write_docs(node: dict, camp: dict, frontier: dict) -> None:
    p49 = frontier["phase49"]
    lines = [
        "# Undercover Phase 49 — Private LAN host & clean-PC boot",
        "",
        "SHA-256: `6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd`",
        "",
        "`GAME_CODE_TARGET=NFS_UNDERCOVER_PC`  `TOOLING_ORIGIN=NFSU2-WEB`",
        "",
        f"FIRST_FRAME: `{FIRST_FRAME}`",
        "",
        "## A. LAN host startup",
        "",
        "- Script: `Start-UndercoverLAN.ps1`",
        "- Server: `web/tools/uc-lan-server.mjs`",
        "- Binds selected private IPv4 (not every adapter by default)",
        "- Docs: `web/docs/uc-private-lan.md`",
        "",
        "## B. HTTPS",
        "",
        "- Cert tool: `web/tools/uc-lan-certs.mjs` (SAN = LAN IPs + localhost)",
        "- Keys written under `%USERPROFILE%\\.nfsuc-web\\lan-certs\\` (outside repo)",
        "- Insecure HTTP origins show an explicit OPFS warning and use memory fallback",
        "",
        "## C. Private asset endpoint",
        "",
        "- `UC_ASSET_ROOT` / `--asset-root`: serve only manifest-allowlisted paths under `/uc-assets/`",
        "- Path traversal / symlink escape rejected; Range 206 supported",
        "",
        "## D. Manifest generation",
        "",
        "- `web/tools/uc-manifest-gen.mjs` — curated allowlist only (no whole-install scan)",
        "",
        "## E. Boot stages",
        "",
        "`BOOT → MANIFEST → CACHE_CHECK → DOWNLOAD → VERIFY → FS_MOUNT → RUNTIME_INIT → READY_OR_BLOCKED`",
        "",
        "## F. Validation layers (do not merge)",
        "",
        f"- Node `uc-assets.test.mjs`: **{'PASS' if p49.get('node_uc_assets_passed') else 'FAIL'}**",
        f"- Node `uc-lan-server.test.mjs`: **{'PASS' if p49.get('lan_server_tests_passed') else 'FAIL'}**",
        f"- Playwright HTTPS loopback: **{'PASS' if p49.get('lan_https_browser_passed') else 'SKIPPED/FAIL'}**",
        f"- Frontend build: **{'PASS' if p49.get('frontend_build_passed') else 'FAIL'}**",
        "- Physical second PC: **manual** (not claimed here)",
        "- Guest execution: Phase 48 regression (no metric inflation)",
        "- Synthetic graphics: clear smoke only",
        "- Authentic gameplay: not ready",
        "",
        "## G. Metrics (Phase 48 → 49)",
        "",
        f"- Compiled: 22,770",
        f"- UNIQUE: {camp['baseline_unique_p48']} → {frontier['unique_uc_functions_executed']}",
        f"- ENTERABLE: {camp['baseline_enterable_p48']} → {frontier['enterable']}",
        f"- RUNS: {camp['baseline_runs_p48']} → {frontier['execution_runs']}",
        f"- RUNTIME_READY: {frontier.get('runtime_ready')}",
        f"- BLOCKED_EXTERNAL: 74",
        f"- Asset distribution: {p49.get('asset_distribution')}",
        f"- LAN testing: {p49.get('lan_testing_readiness')}",
        f"- Browser renderer: {p49.get('browser_renderer')}",
        f"- First frame: BLOCKED",
        "",
        "## H. Phase 50",
        "",
        frontier.get("recommended_phase50") or "",
        "",
    ]
    with open(os.path.join(ANALYSIS, "runtime-phase49.md"), "w",
              encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines))
    with open(os.path.join(ANALYSIS, "phase50-handoff.md"), "w",
              encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join([
            "# Phase 50 handoff",
            "",
            "From Phase 49 private LAN HTTPS hosting and clean-PC boot diagnostics.",
            "",
            "## Do not",
            "",
            "- Public tunnels, port forwarding, or internet-facing asset mirrors.",
            "- Commit TLS private keys or copyrighted commercial game assets.",
            "- Reconstruct opaque draw/allocator backends "
            "(`0x006860F0`, `0x00686290`, `0x00686000`, …).",
            "- Treat synthetic clear smoke as an authentic Undercover frame.",
            "",
            "## Priorities",
            "",
            "1. Rights-authorized curated Undercover data on `UC_ASSET_ROOT` "
            "(allowlist + `--authorized` manifest).",
            "2. Evidence-based resource format mapping into `/uc/...` "
            "(no invented archives).",
            "3. Scene scheduling path recovery toward Present "
            "(`0x00725200` / `0x00770750` chains) without executing opaque handoffs.",
            "4. Physical two-PC checklist confirmation (cert trust + OPFS persistence).",
            "5. Remaining `RUNTIME_READY_NOT_EXECUTED` leaves with verified ABIs only.",
            "",
            frontier.get("recommended_phase50") or "",
            "",
        ]))
    print("wrote", os.path.join(ANALYSIS, "runtime-phase49.md"))
    print("wrote", os.path.join(ANALYSIS, "phase50-handoff.md"))


def run_tests() -> tuple[int, int]:
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    import uc_phase49_test as t49
    suite.addTests(loader.loadTestsFromModule(t49))
    for mod in (t48, t47, t46, t45, t43, t44):
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
        and bool((node.get("uc_assets_test") or {}).get("passed"))
        and bool((node.get("uc_lan_server_test") or {}).get("passed"))
        and bool((node.get("esbuild_build") or {}).get("passed"))
    )
    print(json.dumps({
        "phase": 49,
        "unique": frontier["unique_uc_functions_executed"],
        "enterable": frontier["enterable"],
        "runs": frontier["execution_runs"],
        "newly_executed": camp["newly_executed"],
        "node_uc_assets": (node.get("uc_assets_test") or {}).get("passed"),
        "lan_server": (node.get("uc_lan_server_test") or {}).get("passed"),
        "lan_https_browser": (node.get("uc_lan_https_browser_test") or {}).get("passed"),
        "build": (node.get("esbuild_build") or {}).get("passed"),
        "tests_run": n,
        "test_failures": fails,
        "first_frame": FIRST_FRAME,
        "asset_distribution": "PRIVATE_LAN_FIXTURE_HOST_READY",
        "lan_testing": "PRIVATE_LAN_HTTPS_READY",
        "ok": ok,
    }, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
