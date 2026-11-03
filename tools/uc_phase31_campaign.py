#!/usr/bin/env python3
"""Phase 31 real-execution campaign: 12 ordinary HIGH roots, no stubs.

Graphics frozen. Does not execute nfs.exe. Outcome classification is pure
Python so tests can exercise it without running the guest.
"""
import collections
import ctypes
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import uc_harness31 as h

# Callee inventory used only to classify an UNLIFTED stop, never to execute it.
ALLOCATOR_FUNCS = {0x009EB870, 0x009E9460}
PROTECTED_BOUNDARY = {0x00686000, 0x00686030}

TIMING_IMPORTS = {"GetTickCount", "QueryPerformanceCounter", "QueryPerformanceFrequency",
                  "timeGetTime", "GetSystemTimeAsFileTime", "Sleep"}
FS_IMPORTS = {"CreateFileA", "ReadFile", "WriteFile", "CloseHandle", "FindFirstFileA",
              "FindNextFileA", "FindClose", "GetFileAttributesA", "SetFilePointer"}
TLS_IMPORTS = {"TlsGetValue", "TlsFree"}
THREAD_IMPORTS = {"InitializeCriticalSection", "EnterCriticalSection", "LeaveCriticalSection",
                  "DeleteCriticalSection", "CreateEventA", "CreateMutexA", "CreateThread",
                  "WaitForSingleObject", "SetEvent", "ResetEvent", "ReleaseMutex",
                  "InterlockedIncrement", "InterlockedDecrement"}

OUTCOMES = (
    "EXECUTED_CLEAN", "EXECUTED_CHAIN", "EXECUTED_TO_NEXT_BLOCKER", "BLOCKED_REQUIRED_STATE",
    "BLOCKED_IMPORT", "BLOCKED_INDIRECT", "BLOCKED_MEMORY", "BLOCKED_TLS", "BLOCKED_FILESYSTEM",
    "BLOCKED_TIMING", "BLOCKED_EXTERNAL", "BLOCKED_PROTECTED", "FAULT", "UNKNOWN",
)
REQUIRED_SUBCLASSES = (
    "UNKNOWN_OBJECT", "UNKNOWN_PARENT", "UNKNOWN_GLOBAL", "UNKNOWN_BUFFER",
    "UNKNOWN_CALLBACK", "UNKNOWN_VTABLE", "ALLOCATOR_REQUIRED", "OTHER",
)
HISTOGRAM_KEYS = (
    "REQUIRED_STATE", "IMPORT", "INDIRECT", "MEMORY", "TLS", "FILESYSTEM",
    "TIMING", "EXTERNAL", "PROTECTED", "CLEAN_RETURN",
)


def classify_outcome(root, out_view, fmap_label=None, import_name=None):
    """Pure classifier. out_view is a dict with the harness Out fields."""
    kind = out_view["blocked_kind"]
    depth = out_view["depth_max"]
    entered = set(out_view["entered"])
    res = {"result": "UNKNOWN", "hist": "REQUIRED_STATE", "subclass": None, "detail": ""}
    if kind == h.K_NONE and out_view["clean"]:
        res["result"] = "EXECUTED_CLEAN" if depth <= 1 else "EXECUTED_CHAIN"
        res["hist"] = "CLEAN_RETURN"
        return res
    if kind == h.K_NONE:
        res.update(result="UNKNOWN", hist="REQUIRED_STATE", subclass="OTHER",
                   detail="returned without clean frame contract")
        return res
    va = out_view["blocked_va"]
    if kind == h.K_IMPORT:
        name = import_name or "UNKNOWN_IMPORT"
        res["detail"] = name
        if name in TLS_IMPORTS:
            res.update(result="BLOCKED_TLS", hist="TLS")
        elif name in TIMING_IMPORTS:
            res.update(result="BLOCKED_TIMING", hist="TIMING")
        elif name in FS_IMPORTS:
            res.update(result="BLOCKED_FILESYSTEM", hist="FILESYSTEM")
        else:
            res.update(result="BLOCKED_IMPORT", hist="IMPORT")
        if depth >= 2:
            res["result"] = res["result"]  # reached through a real chain
        return res
    if kind == h.K_TIMING:
        res.update(result="BLOCKED_TIMING", hist="TIMING", detail="rdtsc")
        return res
    if kind == h.K_PROTECTED or va in PROTECTED_BOUNDARY:
        res.update(result="BLOCKED_PROTECTED", hist="PROTECTED", detail="0x%08X" % va)
        return res
    if kind == h.K_UNLIFTED:
        label = (fmap_label or "").upper()
        res["detail"] = "callee 0x%08X (%s)" % (va, fmap_label or "NOT_IN_MAP")
        if "PROTECTED" in label or "EXTERNAL" in label:
            res.update(result="BLOCKED_PROTECTED" if "PROTECTED" in label else "BLOCKED_EXTERNAL",
                       hist="PROTECTED" if "PROTECTED" in label else "EXTERNAL")
        elif "REJECTED" in label or not label:
            res.update(result="UNKNOWN", hist="REQUIRED_STATE", subclass="OTHER")
            res["detail"] += "; callee not ordinary-decodable"
        else:
            res.update(result="BLOCKED_REQUIRED_STATE", hist="REQUIRED_STATE", subclass="OTHER")
        return res
    if kind == h.K_FAULT:
        addr = va
        res["detail"] = "access 0x%08X %s" % (addr, out_view.get("fault_why", ""))
        allocator_entered = bool(entered & ALLOCATOR_FUNCS)
        if addr < 0x10000 and allocator_entered:
            res.update(result="BLOCKED_REQUIRED_STATE", hist="REQUIRED_STATE",
                       subclass="ALLOCATOR_REQUIRED")
        elif addr < 0x10000:
            res.update(result="BLOCKED_REQUIRED_STATE", hist="REQUIRED_STATE",
                       subclass="UNKNOWN_OBJECT")
        else:
            res.update(result="BLOCKED_MEMORY", hist="MEMORY", subclass=None)
        return res
    if kind == h.K_UNSUPPORTED:
        res.update(result="UNKNOWN", hist="REQUIRED_STATE", subclass="OTHER",
                   detail="unsupported_insn: %s" % out_view.get("unsupported_why", ""))
        return res
    if kind == h.K_CPUID:
        res.update(result="UNKNOWN", hist="REQUIRED_STATE", subclass="OTHER", detail="cpuid")
        return res
    return res


def finalize_result(res, depth):
    """EXECUTED_TO_NEXT_BLOCKER when a real chain entered >=2 frames before stopping."""
    if res["result"].startswith("BLOCKED") and depth >= 2 and res["hist"] in (
            "IMPORT", "TIMING", "FILESYSTEM", "TLS", "PROTECTED", "EXTERNAL"):
        res = dict(res)
        res["blocker_result"] = res["result"]
        res["result"] = "EXECUTED_TO_NEXT_BLOCKER"
    return res


def out_to_view(out):
    return {
        "blocked_kind": out.blocked_kind, "blocked_va": out.blocked_va,
        "blocked_fn": out.blocked_fn, "depth_max": out.depth_max,
        "entered": [out.entered[i] for i in range(min(out.entered_n, h.ENT_CAP))],
        "clean": bool(out.clean), "fault_why": out.fault_why.decode("ascii", "replace"),
        "unsupported_why": out.unsupported_why.decode("ascii", "replace"),
    }


def required_state_histogram(rows):
    hist = collections.Counter({k: 0 for k in REQUIRED_SUBCLASSES})
    for r in rows:
        if r.get("hist") == "REQUIRED_STATE":
            hist[r.get("subclass") or "OTHER"] += 1
    return dict(hist)


def real_blocker_histogram(rows):
    hist = collections.Counter({k: 0 for k in HISTOGRAM_KEYS})
    for r in rows:
        hist[r["hist"]] += 1
    return dict(hist)


def clean_root_accounting(rows, prior_clean):
    """Roots that finish their tested contract with no stubs and no blocker."""
    clean = set(prior_clean)
    for r in rows:
        if r["result"] in ("EXECUTED_CLEAN", "EXECUTED_CHAIN") and not r.get("stubs"):
            clean.add(r["root"])
    return sorted(clean)


def ctor_accounting(rows, prior_ctors, ctor_roots):
    """Count only constructors whose body actually ran (entered), strong/proven."""
    ctors = set(prior_ctors)
    for r in rows:
        for fn in r.get("entered") or ():
            if fn in ctor_roots:
                ctors.add(fn)
    return sorted(ctors)


# Campaign specification (priority order from the Phase 31 brief).
def campaign_specs():
    OB, SR = h.OBJ_BASE, h.SRC_BASE
    return [
        dict(root=0x009E9160, kind="ORDINARY_CONSTRUCTOR", priority=1,
             this_source="CALLER_STORAGE", note="live ctor; callees no longer stubbed",
             spec=dict(ecx=OB, args=(SR, 0), ret_pop=8, zero=((SR, 0x40),))),
        dict(root=0x009E98F0, kind="ORDINARY_CONSTRUCTOR", priority=3,
             this_source="STACK_STORAGE", note="non-allocating config ctor; 0x009E9340 local",
             spec=dict(ecx=OB)),
        dict(root=0x00B57CD0, kind="STATIC_INITIALIZER", priority=5,
             this_source="GLOBAL_STORAGE", note="CRT-style static init; string object 0x0189D184",
             spec=dict()),
        dict(root=0x00B52140, kind="STATIC_INITIALIZER", priority=5,
             this_source="GLOBAL_STORAGE", note="static init + atexit; object 0x018738A0",
             spec=dict()),
        dict(root=0x009EBC70, kind="ORDINARY_CONSTRUCTOR", priority=3,
             this_source="CALLER_STORAGE", note="ctor with 0x009E9460(0) + 0x00977E20",
             spec=dict(ecx=OB)),
        dict(root=0x009EB350, kind="ORDINARY_CONSTRUCTOR", priority=3,
             this_source="CALLER_STORAGE", note="ret 0x10; arg2 = pointer to empty handle",
             spec=dict(ecx=OB, args=(0, 0, SR, 0), ret_pop=0x10, zero=((SR, 0x40),))),
        dict(root=0x0097BB30, kind="ORDINARY_CONSTRUCTOR", priority=3,
             this_source="CALLER_STORAGE", note="ret 8; two POD scalar args = 0",
             spec=dict(ecx=OB, args=(0, 0), ret_pop=8)),
        dict(root=0x009D9310, kind="ORDINARY_CONSTRUCTOR", priority=3,
             this_source="CALLER_STORAGE", note="ctor; vector-ctor style helper 0x004026F0",
             spec=dict(ecx=OB)),
        dict(root=0x00808770, kind="ORDINARY_CONSTRUCTOR", priority=3,
             this_source="CALLER_STORAGE", note="four base ctors; SEH frame (prolog only, no delivery)",
             spec=dict(ecx=OB, teb=True)),
        dict(root=0x009EB870, kind="ALLOCATOR_NEGATIVE_CONTROL", priority=4,
             this_source="N/A", note="cdecl(size,name,heap,_) must stop on null manager",
             spec=dict(args=(0x10, 0, 0, 0))),
        dict(root=0x009EB980, kind="STATIC_INITIALIZER", priority=5,
             this_source="GLOBAL_STORAGE", note="singleton-static init [0x189DA90]; PE-zero guard",
             spec=dict()),
        dict(root=0x00B57CF0, kind="STATIC_INITIALIZER", priority=5,
             this_source="GLOBAL_STORAGE", note="static init sibling (independent chain)",
             spec=dict()),
    ]


def run_campaign(specs=None, harness=None, fmap=None):
    specs = specs or campaign_specs()
    fmap = fmap or h.load_fmap()
    if harness is None:
        addrs = set()
        for s in specs:
            addrs |= set(h.closure(s["root"], fmap, limit=48))
        harness = h.Harness(addrs)
    rows = []
    for s in specs:
        spec = h.make_spec(s["root"], **s["spec"])
        out = harness.run(spec)
        view = out_to_view(out)
        imp_name = None
        if view["blocked_kind"] == h.K_IMPORT:
            imp_name = h.import_name_for_target(view["blocked_va"])
        lbl = None
        if view["blocked_kind"] == h.K_UNLIFTED:
            row = fmap.get(view["blocked_va"])
            lbl = row["label"] if row else None
        res = classify_outcome(s["root"], view, lbl, imp_name)
        res = finalize_result(res, view["depth_max"])
        imports = []
        for i in range(min(out.nimp, h.IMP_CAP)):
            nm = h.import_name_for_target(out.imp_target[i]) if not out.imp_ok[i] else "HLE_ok"
            imports.append({"target": "0x%08X" % out.imp_target[i], "ok": bool(out.imp_ok[i]),
                            "name": nm})
        rows.append({
            "root": s["root"], "kind": s["kind"], "priority": s["priority"],
            "this_source": s["this_source"], "note": s["note"],
            "result": res["result"], "hist": res["hist"], "subclass": res.get("subclass"),
            "detail": res.get("detail"), "blocker_result": res.get("blocker_result"),
            "depth_max": view["depth_max"], "entered": view["entered"],
            "unique_entered": len(view["entered"]), "clean": view["clean"],
            "blocked_kind": h.KIND_NAMES[view["blocked_kind"]],
            "blocked_va": view["blocked_va"], "blocked_fn": view["blocked_fn"],
            "import": imp_name, "imports": imports,
            "tls_alloc": out.tls_alloc, "tls_set": out.tls_set,
            "ics_calls": getattr(out, "ics_calls", 0),
            "mutex_calls": getattr(out, "mutex_calls", 0),
            "cs_count": getattr(out, "cs_count", 0),
            "mutex_count": getattr(out, "mutex_count", 0),
            "gpc_calls": getattr(out, "gpc_calls", 0),
            "sem_calls": getattr(out, "sem_calls", 0),
            "sem_count": getattr(out, "sem_count", 0),
            "priority_class": getattr(out, "priority_class", 0),
            "stubs": [], "esp_delta_ok": out.esp == out.esp_expected,
        })
    return rows, harness


DIAG_IAT = {"InitializeCriticalSection": (0x008A9EB4, 1)}


def run_diagnostics(harness):
    """DIAGNOSTIC ONLY. Treat the first blocking import as a no-op to see what
    lies behind it. Never counted in UNIQUE/CLOSURE/DEPTH/CLEAN metrics."""
    OB, SR = h.OBJ_BASE, h.SRC_BASE
    tgt, nargs = DIAG_IAT["InitializeCriticalSection"]
    spec = h.make_spec(0x009E9160, ecx=OB, args=(SR, 0), ret_pop=8, zero=((SR, 0x40),),
                       noop_target=tgt, noop_args=nargs)
    out = harness.run(spec)
    view = out_to_view(out)
    imp = h.import_name_for_target(view["blocked_va"]) if view["blocked_kind"] == h.K_IMPORT else None
    return {
        "root": 0x009E9160, "diagnostic": True, "counted_in_metrics": False,
        "assumption": "InitializeCriticalSection treated as stdcall no-op returning TRUE",
        "noop_hits": out.diag_hits, "entered": view["entered"], "depth_max": view["depth_max"],
        "next_blocker_kind": h.KIND_NAMES[view["blocked_kind"]], "next_blocker_va": view["blocked_va"],
        "next_blocker_import": imp, "blocked_fn": view["blocked_fn"],
    }


if __name__ == "__main__":
    rows, _ = run_campaign()
    for r in rows:
        print("%08x %-27s %-26s d=%d u=%2d blk=%s %s | %s" % (
            r["root"], r["kind"], r["result"], r["depth_max"], r["unique_entered"],
            r["blocked_kind"], "0x%08X" % r["blocked_va"], (r["detail"] or "")[:60]))
        print("         entered:", " ".join("%08x" % x for x in r["entered"]))
