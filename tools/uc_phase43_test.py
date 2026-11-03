#!/usr/bin/env python3
"""Phase 43 synthetic tests: graphics config, AA, modes, presentation, lifecycle.

No game execution. No protected allocator/backend. Graphics first-frame remains blocked.
"""
from __future__ import annotations

import json
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import uc_graphics43 as g
import uc_phase7_test as p7
import uc_target_verify as tv

ROOT = p7.ROOT
ANALYSIS = os.path.join(ROOT, "analysis", "undercover")


def _load(name):
    with open(os.path.join(ANALYSIS, name), encoding="utf-8") as fh:
        return json.load(fh)


class EvidenceImport(unittest.TestCase):
    def test_evidence_files_present(self):
        self.assertTrue(os.path.isfile(
            os.path.join(ANALYSIS, "graphics-evidence-2026-11-03.json")))
        self.assertTrue(os.path.isfile(
            os.path.join(ANALYSIS, "graphics-report-2026-11-03.md")))

    def test_evidence_target_hash(self):
        ev = _load("graphics-evidence-2026-11-03.json")
        self.assertEqual(
            ev["target"]["sha256"],
            "6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd")
        self.assertEqual(
            ev["status"], "FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND")

    def test_aa_fallback_expression_in_evidence(self):
        ev = _load("graphics-evidence-2026-11-03.json")
        aa = ev["config"]["aa_fallback"]
        self.assertEqual(aa["expression"], "c & (((int32)c > 0) - 1)")
        self.assertEqual(aa["valid_tier_result"], 0)


class GraphicsObjectLayout(unittest.TestCase):
    def test_minimum_extent_not_exact_size(self):
        self.assertEqual(g.GRAPHICS_OBJECT_MIN_EXTENT, 0x535)
        meta = _load("graphics-object-layout.json")
        self.assertEqual(int(meta["minimum_extent"], 16), 0x535)
        self.assertEqual(meta["exact_size"], "BLOCKED")
        self.assertEqual(meta["instance"], "static")
        self.assertEqual(int(meta["base"], 16), 0x01318170)

    def test_plus48_not_conflated(self):
        meta = _load("graphics-object-layout.json")
        self.assertEqual(meta["fields"]["0x48"]["meaning"], "performance level")
        cfg = _load("pcdisplayconfig-layout.json")
        self.assertEqual(cfg["fields"]["0x48"]["meaning"], "g_FSAALevel")
        self.assertNotEqual(
            meta["fields"]["0x48"]["meaning"], cfg["fields"]["0x48"]["meaning"])

    def test_hwnd_unproven_at_plus18(self):
        meta = _load("graphics-object-layout.json")
        self.assertIn("HWND unproven", meta["fields"]["0x18"]["meaning"])

    def test_config_size_and_dual_pointers(self):
        cfg = _load("pcdisplayconfig-layout.json")
        self.assertEqual(int(cfg["size"], 16), 0x84)
        self.assertEqual(cfg["requested_pointer_offset"], "0x54")
        self.assertEqual(cfg["capabilities_pointer_offset"], "0x50")


class ClampTests(unittest.TestCase):
    def test_below_capability_unchanged(self):
        caps = g.make_config({0x10: 5, 0x48: 3})
        req = g.make_config({0x10: 2, 0x48: 1})
        g.clamp_pc_display_config(caps, req)
        self.assertEqual(g.dword_view(req, 0x10), 2)
        self.assertEqual(g.dword_view(req, 0x48), 1)

    def test_above_capability_clamped(self):
        caps = g.make_config({0x10: 1, 0x2C: 2, 0x48: 2})
        req = g.make_config({0x10: 5, 0x2C: 9, 0x48: 3})
        g.clamp_pc_display_config(caps, req)
        self.assertEqual(g.dword_view(req, 0x10), 1)
        self.assertEqual(g.dword_view(req, 0x2C), 2)
        self.assertEqual(g.dword_view(req, 0x48), 2)

    def test_equality(self):
        caps = g.make_config({0x58: 3})
        req = g.make_config({0x58: 3})
        g.clamp_pc_display_config(caps, req)
        self.assertEqual(g.dword_view(req, 0x58), 3)

    def test_zero(self):
        caps = g.make_config({0x60: 0})
        req = g.make_config({0x60: 0})
        g.clamp_pc_display_config(caps, req)
        self.assertEqual(g.dword_view(req, 0x60), 0)

    def test_negative_signed(self):
        # signed min: req=-1 (0xFFFFFFFF), cap=1 -> keep -1 (cap > req signed)
        caps = g.make_config({0x10: 1})
        req = g.make_config({0x10: 0xFFFFFFFF})
        g.clamp_pc_display_config(caps, req)
        self.assertEqual(g.dword_view(req, 0x10), 0xFFFFFFFF)
        # req=5, cap=-1 -> clamp to -1
        caps = g.make_config({0x10: 0xFFFFFFFF})
        req = g.make_config({0x10: 5})
        g.clamp_pc_display_config(caps, req)
        self.assertEqual(g.dword_view(req, 0x10), 0xFFFFFFFF)

    def test_unsigned_high_bit(self):
        # unsigned +0x1C: req=0xFFFFFFFF, cap=1 -> clamp to 1
        caps = g.make_config({0x1C: 1})
        req = g.make_config({0x1C: 0xFFFFFFFF})
        g.clamp_pc_display_config(caps, req)
        self.assertEqual(g.dword_view(req, 0x1C), 1)
        # unsigned: req=1, cap=0xFFFFFFFF -> keep 1
        caps = g.make_config({0x4C: 0xFFFFFFFF})
        req = g.make_config({0x4C: 1})
        g.clamp_pc_display_config(caps, req)
        self.assertEqual(g.dword_view(req, 0x4C), 1)

    def test_mixed_and_untouched(self):
        caps = g.make_config({0x10: 1, 0x1C: 1, 0x48: 2})
        req = g.make_config({
            0x10: 9, 0x1C: 9, 0x48: 3,
            0x34: 7, 0x6C: 1920, 0x7C: 1, 0x30: 0xABCD,
        })
        before_untouched = {
            0x34: g.dword_view(req, 0x34),
            0x6C: g.dword_view(req, 0x6C),
            0x7C: g.dword_view(req, 0x7C),
            0x30: g.dword_view(req, 0x30),
        }
        caps_before = bytearray(caps)
        g.clamp_pc_display_config(caps, req)
        self.assertEqual(g.dword_view(req, 0x10), 1)
        self.assertEqual(g.dword_view(req, 0x1C), 1)
        self.assertEqual(g.dword_view(req, 0x48), 2)
        for off, val in before_untouched.items():
            self.assertEqual(g.dword_view(req, off), val)
        self.assertEqual(caps, caps_before)


class AAFallbackTests(unittest.TestCase):
    def test_valid_tiers_zero(self):
        for c in (0, 1, 2, 3):
            self.assertEqual(g.aa_fallback_mask(c), 0, msg="c=%d" % c)

    def test_negative_passthrough(self):
        self.assertEqual(g.aa_fallback_mask(0xFFFFFFFF), 0xFFFFFFFF)

    def test_not_decrement(self):
        # Corrects progressive tier-minus-one assumption.
        self.assertNotEqual(g.aa_fallback_mask(3), 2)
        self.assertNotEqual(g.aa_fallback_mask(2), 1)


class AAProbeTests(unittest.TestCase):
    def _iface(self, supported_samples):
        d3d = g.FakeD3D9()
        for s in supported_samples:
            for fmt in g.AA_PROBE_FORMATS:
                d3d.results[(0, s, fmt)] = 0
        return d3d

    def test_none(self):
        out = []
        ok = g.probe_aa_tier(g.FakeD3D9(), 0, 0, out)
        self.assertFalse(ok)
        self.assertEqual(out, [0])

    def test_2x_only(self):
        out = []
        ok = g.probe_aa_tier(self._iface([2]), 0, 0, out)
        self.assertTrue(ok)
        self.assertEqual(out, [1])

    def test_2x_4x(self):
        out = []
        self.assertTrue(g.probe_aa_tier(self._iface([2, 4]), 0, 0, out))
        self.assertEqual(out, [2])

    def test_all(self):
        out = []
        self.assertTrue(g.probe_aa_tier(self._iface([2, 4, 8]), 0, 0, out))
        self.assertEqual(out, [3])

    def test_intermediate_failure_stops(self):
        # 2 ok, 4 fails even if 8 would be ok — contiguous stop.
        d3d = g.FakeD3D9()
        for fmt in g.AA_PROBE_FORMATS:
            d3d.results[(0, 2, fmt)] = 0
            d3d.results[(0, 8, fmt)] = 0
        out = []
        self.assertTrue(g.probe_aa_tier(d3d, 0, 0, out))
        self.assertEqual(out, [1])
        # Probe order: 2 then 4 (fails formats), no 8 probes after failure.
        samples_seq = [c[4] for c in d3d.calls]
        self.assertEqual(samples_seq[:3], [2, 2, 2])
        self.assertTrue(4 in samples_seq)
        self.assertFalse(8 in samples_seq)

    def test_formats_and_adapter(self):
        d3d = self._iface([2, 4, 8])
        out = []
        g.probe_aa_tier(d3d, 3, 1, out)
        for call in d3d.calls:
            adapter, dtype, fmt, windowed, samples = call
            self.assertEqual(adapter, 3)
            self.assertEqual(dtype, 1)
            self.assertEqual(windowed, 1)
            self.assertIn(fmt, g.AA_PROBE_FORMATS)

    def test_sample_table(self):
        self.assertEqual([g.aa_samples_for_tier(i) for i in range(4)], [0, 2, 4, 8])


class ReflectionTests(unittest.TestCase):
    def test_mapping_table(self):
        cases = [(0, 0, 0), (1, 1, 0), (2, 2, 1), (5, 2, 1), (0xFFFFFFFF, 2, 1)]
        for src, d5c, d0c in cases:
            req = g.make_config()
            g.apply_reflection_derived(req, src)
            self.assertEqual(g.dword_view(req, 0x5C), d5c)
            self.assertEqual(g.dword_view(req, 0x0C), d0c)


class GetterTests(unittest.TestCase):
    def test_all_supported_selectors(self):
        obj = bytearray(0x600)
        req = g.make_config()
        g.set_dword(obj, 0x48, 0xD00D)
        g.set_dword(obj, 0x4C, 0xB00B)
        for sel, (kind, off) in g.GETTER_SELECTORS.items():
            if kind == "cfg":
                g.set_dword(req, off, 0x1000 + sel)
            got = g.get_setting(obj, req, sel)
            if kind == "obj":
                self.assertEqual(got, g.dword_view(obj, off))
            else:
                self.assertEqual(got, 0x1000 + sel)

    def test_default_and_unsupported(self):
        obj = bytearray(0x600)
        req = g.make_config({0x10: 9})
        self.assertEqual(g.get_setting(obj, req, 19), 0)
        self.assertEqual(g.get_setting(obj, req, 0), 0)
        self.assertEqual(g.get_setting(obj, req, 31), 0)
        self.assertEqual(g.get_setting(obj, req, 99), 0)


class ModeTests(unittest.TestCase):
    def test_selected_mode_pointer(self):
        self.assertEqual(g.selected_mode_pointer(0x1000, 0), 0x1000)
        self.assertEqual(g.selected_mode_pointer(0x1000, 1), 0x101C)
        self.assertEqual(g.selected_mode_pointer(0x1000, 3), 0x1000 + 3 * 0x1C)

    def test_exact_match(self):
        modes = [
            g.ModeRecord(800, 600, 60),
            g.ModeRecord(1280, 720, 60),
            g.ModeRecord(1920, 1080, 60),
        ]
        self.assertEqual(g.select_display_mode(modes, 1280, 720, 60, 16 / 9), 1)

    def test_default_resolution(self):
        modes = [g.ModeRecord(640, 480, 60), g.ModeRecord(800, 600, 60)]
        self.assertEqual(g.select_display_mode(modes, 0, 0, 0, 4 / 3), 0)

    def test_refresh_mismatch_falls_through(self):
        modes = [
            g.ModeRecord(1280, 720, 75),
            g.ModeRecord(1920, 1080, 60, field_18=0x16),
        ]
        # No exact match; large 16:9 should win aspect scan.
        idx = g.select_display_mode(modes, 1280, 720, 60, 16 / 9)
        self.assertEqual(idx, 1)

    def test_empty_vector(self):
        self.assertEqual(g.select_display_mode([], 640, 480, 60, 1.0), -1)

    def test_pixel_threshold(self):
        # Tiny mode fails pixel threshold; last record selected if none pass.
        modes = [
            g.ModeRecord(100, 100, 60),  # 10000 < 0x3E800
            g.ModeRecord(200, 200, 60),
        ]
        idx = g.select_display_mode(modes, 999, 999, 60, 1.0)
        self.assertEqual(idx, 1)  # last record fallback

    def test_aspect_fallback(self):
        modes = [
            g.ModeRecord(1024, 768, 60),  # 4:3
            g.ModeRecord(1280, 720, 60),  # 16:9
            g.ModeRecord(1920, 1080, 60),
        ]
        idx = g.select_display_mode(modes, 1600, 900, 60, 16 / 9)
        self.assertIn(idx, (1, 2))  # backwards scan prefers higher indices


class PresentTests(unittest.TestCase):
    def _engine(self, **kw):
        modes = kw.pop("modes", [g.ModeRecord(1920, 1080, 60, field_18=0x16)])
        return g.EnginePresentState(
            selected_index=kw.pop("selected_index", 0),
            modes=modes,
            windowed=kw.pop("windowed", 0),
            caps_low=kw.pop("caps_low", 0),
            field_174=kw.pop("field_174", 0),
            hwnd_field_19c=kw.pop("hwnd", 0x12340000),
            depth_stencil_global=kw.pop("depth_global", 0),
        )

    def test_negative_index_no_init(self):
        region = bytearray(b"\xAA" * 0x38)
        eng = self._engine(selected_index=-1)
        req = g.make_config()
        ok = g.build_present_parameters(eng, req, region)
        self.assertFalse(ok)
        self.assertEqual(region, bytearray(b"\xAA" * 0x38))

    def test_size_and_fields_fullscreen(self):
        region = bytearray(0x40)
        guard = region[0x38:]
        present = memoryview(region)[:0x38]
        buf = bytearray(present)
        eng = self._engine(windowed=0, caps_low=0, field_174=0)
        req = g.make_config({0x48: 0, 0x7C: 1, 0x6C: 800, 0x70: 600})
        self.assertTrue(g.build_present_parameters(eng, req, buf))
        self.assertEqual(len(buf), 0x38)
        self.assertEqual(g.dword_view(buf, 0x00), 1920)
        self.assertEqual(g.dword_view(buf, 0x04), 1080)
        self.assertEqual(g.dword_view(buf, 0x08), 0x16)
        self.assertEqual(g.dword_view(buf, 0x0C), 1)
        self.assertEqual(g.dword_view(buf, 0x10), 0)  # AA tier 0
        self.assertEqual(g.dword_view(buf, 0x14), 0)
        self.assertEqual(g.dword_view(buf, 0x18), 3)  # SwapEffect
        self.assertEqual(g.dword_view(buf, 0x1C), 0x12340000)
        self.assertEqual(g.dword_view(buf, 0x20), 0)
        self.assertEqual(g.dword_view(buf, 0x24), 1)
        self.assertEqual(g.dword_view(buf, 0x28), 0x4B)
        self.assertEqual(g.dword_view(buf, 0x2C), 0)
        self.assertEqual(g.dword_view(buf, 0x30), 60)
        self.assertEqual(g.dword_view(buf, 0x34), 1)

    def test_windowed_vsync_off_aa(self):
        buf = bytearray(0x38)
        eng = self._engine(windowed=1, caps_low=0x20)
        req = g.make_config({0x48: 2, 0x7C: 0, 0x6C: 1280, 0x70: 720})
        g.build_present_parameters(eng, req, buf)
        self.assertEqual(g.dword_view(buf, 0x00), 1280)
        self.assertEqual(g.dword_view(buf, 0x04), 720)
        self.assertEqual(g.dword_view(buf, 0x10), 4)
        self.assertEqual(g.dword_view(buf, 0x18), 1)  # SwapEffect when caps bit
        self.assertEqual(g.dword_view(buf, 0x20), 1)
        self.assertEqual(g.dword_view(buf, 0x2C), 4)
        self.assertEqual(g.dword_view(buf, 0x30), 0)
        self.assertEqual(g.dword_view(buf, 0x34), 0x80000000)

    def test_depth_format_global(self):
        buf = bytearray(0x38)
        eng = self._engine(depth_global=1)
        req = g.make_config({0x48: 1, 0x7C: 1})
        g.build_present_parameters(eng, req, buf)
        self.assertEqual(g.dword_view(buf, 0x28), 0x50)
        self.assertEqual(g.dword_view(buf, 0x10), 2)

    def test_aa_tiers(self):
        for tier, samples in enumerate(g.AA_SAMPLES):
            buf = bytearray(0x38)
            eng = self._engine(caps_low=0x20)
            req = g.make_config({0x48: tier, 0x7C: 0})
            g.build_present_parameters(eng, req, buf)
            self.assertEqual(g.dword_view(buf, 0x10), samples)

    def test_no_write_outside_region(self):
        outer = bytearray(b"\x5A" * 0x80)
        region = memoryview(outer)[0x10:0x10 + 0x38]
        buf = bytearray(region)
        eng = self._engine()
        req = g.make_config({0x48: 0, 0x7C: 1})
        g.build_present_parameters(eng, req, buf)
        # copy back and check guards
        outer[0x10:0x10 + 0x38] = buf
        self.assertEqual(outer[:0x10], b"\x5A" * 0x10)
        self.assertEqual(outer[0x10 + 0x38:], b"\x5A" * (0x80 - 0x48))


class DeviceLifecycleTests(unittest.TestCase):
    def test_create_first_success(self):
        iface = g.FakeCreateDevice(hresults=[0])
        hr = g.create_device_sequence(iface, 0, 1, 0xAABB, 0x1000)
        self.assertEqual(hr, 0)
        self.assertEqual(len(iface.attempts), 1)
        self.assertEqual(iface.attempts[0].flags, 0x40)
        self.assertEqual(iface.attempts[0].site, 0x007252CF)

    def test_create_retry(self):
        iface = g.FakeCreateDevice(hresults=[0x8876086A, 0])
        hr = g.create_device_sequence(iface, 2, 2, 0x100, 0x200)
        self.assertEqual(hr, 0)
        self.assertEqual(len(iface.attempts), 2)
        self.assertEqual(iface.attempts[1].flags, 0x20)
        self.assertEqual(iface.attempts[1].device_type, 1)
        self.assertEqual(iface.attempts[1].adapter, 2)
        self.assertEqual(iface.attempts[1].out_ptr, g.DEVICE_OUT_GLOBAL)

    def test_both_fail(self):
        iface = g.FakeCreateDevice(hresults=[-1, -2])
        hr = g.create_device_sequence(iface, 0, 1, 0, 0)
        self.assertEqual(hr, -2)

    def test_outer_aa_fallback(self):
        iface = g.FakeCreateDevice(hresults=[-1, -1, 0, 0])
        caps = g.make_config({0x48: 3})
        req = g.make_config({0x48: 3})
        hr, aa = g.outer_device_with_aa_fallback(
            iface, caps, req, 0, 1, 0, 0x300)
        self.assertEqual(aa, 0)  # masked to 0, not tier-1
        self.assertEqual(g.dword_view(req, 0x48), 0)
        self.assertEqual(hr, 0)
        self.assertEqual(len(iface.attempts), 3)

    def test_destructor_order(self):
        o = g.SyntheticGraphicsOwnership(
            caps_ptr=1, requested_ptr=2, engine_ptr=3,
            sync_wrapper=True, vector_storage=4, title_buffer=5)
        order = o.destructor_00727B60()
        self.assertEqual(order, [
            "free_caps", "free_requested",
            "engine_dtor_00725110", "free_engine",
            "sync_dtor_00977400",
            "free_vector_0xC_stride",
            "free_title_buffer_conditional",
        ])

    def test_device_cleanup_no_global_zero(self):
        o = g.SyntheticGraphicsOwnership(query_ptr=9, device_global=0x013C6510)
        o.cleanup_device_00727ED0()
        self.assertIsNone(o.query_ptr)
        self.assertEqual(o.device_global, 0x013C6510)  # not cleared

    def test_live_shutdown_opaque(self):
        o = g.SyntheticGraphicsOwnership(
            d3d9_iface=1, query_ptr=2, device_global=3)
        order = o.live_shutdown_00727F40()
        self.assertIn("opaque_0071E380", order)
        self.assertIn("opaque_0071E380", o.opaque_calls)
        self.assertIn("release_G+10", order)

    def test_resource_428b0_skip_types(self):
        for t in (1, 6):
            r = g.Resource428B0(resource_type=t)
            r.release()
            self.assertNotIn("release_+0C", r.releases)
            self.assertEqual(r.active_byte_20, 0)
        r = g.Resource428B0(resource_type=2)
        r.release()
        self.assertIn("release_+0C", r.releases)


class MetadataAndFrozen(unittest.TestCase):
    def test_frontier_phase43(self):
        fr = _load("runtime-frontier.json")
        self.assertGreaterEqual(fr["phase"], 43)
        self.assertEqual(
            fr["first_frame"], "FIRST_FRAME_PATH_BLOCKED_BY_PROTECTED_BACKEND")
        self.assertTrue(fr.get("graphics_frozen"))
        gfx = fr.get("graphics_config_phase43") or {}
        self.assertTrue(gfx.get("synthetic_implemented"))
        self.assertFalse(gfx.get("first_frame_unblocked"))
        self.assertFalse(gfx.get("d3d9_implementation_justified"))

    def test_function_coverage_manifest(self):
        cov = _load("graphics-function-coverage-phase43.json")
        tier_a = {e["address"] for e in cov["functions"] if e["tier"] == "A"}
        for addr in (
            "0x0071D7E0", "0x00723790", "0x007237B0",
            "0x00727FB0", "0x0071D8F0", "0x00722EC0",
        ):
            self.assertIn(addr, tier_a)
        for e in cov["functions"]:
            if e["implementation"] == "SYNTHETIC_PURE":
                self.assertIn(e["test_status"], ("PASS", "PASSING"))
            if e["tier"] == "C":
                self.assertNotEqual(e.get("runtime_ready"), True)

    def test_target_provenance_preserved(self):
        prov = _load("target-provenance.json")
        self.assertIn(prov["verification_status"], (
            "VERIFIED_UNDERCOVER_1_1_2_1",
            "TARGET_BINARY_NOT_AVAILABLE_FOR_REHASH",
        ))
        self.assertEqual(tv.EXPECTED_SHA256, (
            "6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd"))

    def test_phase42_metrics_not_erased(self):
        fr = _load("runtime-frontier.json")
        self.assertGreaterEqual(fr["unique_uc_functions_executed"], 67)
        self.assertGreaterEqual(fr["enterable"], 33)
        self.assertGreaterEqual(fr["nontrivial_object_lifecycles"], 3)
        self.assertEqual(fr["clean_virtual_calls"], 0)
        self.assertEqual(fr["virtual_call_continuation_faults"], 1)


if __name__ == "__main__":
    unittest.main()
