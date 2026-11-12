"""Offline menu tests: no VM, network, service or installation is started."""
import importlib.util
from pathlib import Path
import re
import shutil
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("installer_menu", ROOT / "installer_menu.py")
menu = importlib.util.module_from_spec(spec)
spec.loader.exec_module(menu)


class Screen:
    def __init__(self, keys=(), size=(25, 80)):
        self.keys = iter(keys)
        self.size = size
        self.lines = {}
        self.frames = []

    def getmaxyx(self): return self.size
    def erase(self): self.lines = {}
    def keypad(self, enabled): pass
    def addnstr(self, y, x, text, limit, style):
        if len(text) > limit and self.size[1] >= 76:
            raise AssertionError(f"Clipped menu text: {text}")
        self.lines[y] = text[:limit]
    def refresh(self): self.frames.append(dict(self.lines))
    def getch(self): return next(self.keys)


FAKE_CURSES = types.SimpleNamespace(KEY_UP=259, KEY_DOWN=258, KEY_LEFT=260,
    KEY_RIGHT=261, KEY_ENTER=343, A_NORMAL=0, A_REVERSE=1,
    curs_set=lambda value: None, error=RuntimeError)


class HardwareMenuTests(unittest.TestCase):
    def setUp(self):
        self.big = menu.hardware(ROOT, "Big", {})
        source = (ROOT.parent / "install.sh").read_text(encoding="utf-8")
        self.mini_env = dict(re.findall(r'export ([A-Z0-9]+_(?:CPU|MEM|HDD))="\$\{[A-Z0-9_]+:-([^}]+)\}"', source))
        self.mini = menu.hardware(ROOT, "Mini", self.mini_env)
        self.profiles = {"Big": self.big, "Mini": self.mini}

    def test_current_defaults_and_mini_configuration(self):
        self.assertEqual(menu.totals(self.big["rows"], base_only=True)["memory_mib"], 28672)
        self.assertEqual(menu.totals(self.big["rows"], base_only=True)["cpu"], 20)
        self.assertEqual(menu.totals(self.mini["rows"], base_only=True)["cpu"], 10)
        self.assertEqual(menu.totals(self.mini["rows"], base_only=True)["memory_mib"], 12288)
        tpot = next(r for r in self.big["rows"] if r["tag"] == "TPOT")
        self.assertEqual(tpot["memory_mib"], 16384)
        self.assertEqual(len(self.mini_env), len(menu.VMS) * 3)

    def test_overrides_sockets_and_disk_units(self):
        values = menu.hardware(ROOT, "Big", {"KALI01_CPU":"3", "TPOT01_MEM":"8192", "MRNOBODY_HDD":"512M"})
        rows = {r["tag"]:r for r in values["rows"]}
        self.assertEqual(rows["KALI01"]["cpu"], 3)
        self.assertEqual(rows["TPOT"]["memory_mib"], 8192)
        self.assertEqual(rows["MRNOBODY"]["disk_gib"], 0.5)
        self.assertEqual(menu.disk_gib("2T", "disk"), 2048)
        for value in ["0", "-1", "1;touch bad"]:
            with self.assertRaises(ValueError):
                menu.hardware(ROOT, "Big", {"KALI01_CPU":value})

    def test_reads_defaults_without_executing_installer(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            root = Path(temporary)
            for vm in menu.VMS:
                dest = root / vm[3]
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / vm[3], dest)
            target = root / "TPOT01/TPOT01_installer.sh"
            source = target.read_text().replace("TPOT01_MEM:-16384", "TPOT01_MEM:-20480")
            target.write_text(source + '\nexit 99\n', encoding="utf-8")
            tpot = next(r for r in menu.hardware(root, "Big", {})["rows"] if r["tag"] == "TPOT")
            self.assertEqual(tpot["memory_mib"], 20480)

    def test_selection_validation(self):
        result = menu.validate_selection(dict(profile="Mini", labs=2, components=["MRNOBODY","TPOT","MRNOBODY"]))
        self.assertEqual(result["components"], ["TPOT","MRNOBODY"])
        for data in [dict(profile="Other", labs=1, components=[]),
                     dict(profile="Big", labs=0, components=[]),
                     dict(profile="Big", labs=True, components=[]),
                     dict(profile="Big", labs=1, components=["BAD"])]:
            with self.assertRaises(ValueError): menu.validate_selection(data)

    def test_keyboard_flow_and_live_totals(self):
        # Mini, two labs, options, Wazuh and MrNobody, then accept.
        keys = [258, ord("+"), 10, 258, 258, 258, 258, ord(" "), 258, 258, ord(" "), 10]
        screen = Screen(keys)
        with patch.dict(sys.modules, {"curses": FAKE_CURSES}):
            result = menu.Menu(self.profiles).run(screen)
        self.assertEqual(result, dict(profile="Mini", labs=2, components=["WAZUH","MRNOBODY"]))
        final = screen.frames[-1]
        self.assertIn("Profil: Mini", final[3])
        self.assertNotIn("Big", " ".join(final.values()))
        self.assertIn("28 vCPU | 36 GiB RAM | +476 GiB disk", final[18])
        self.assertIn("10 vCPU | 12 GiB RAM", final[15])
        self.assertIn("20 vCPU | 28 GiB RAM", screen.frames[0][3])

    def test_back_cancel_bounds_and_small_terminal(self):
        controller = menu.Menu(self.profiles)
        with patch.dict(sys.modules, {"curses": FAKE_CURSES}):
            for _ in range(20): controller.handle(ord("+"))
            self.assertEqual(controller.labs, 16)
            controller.handle(10)
            controller.handle(ord(" "))
            controller.handle(ord("b"))
            self.assertEqual(controller.stage, "profile")
            self.assertEqual(controller.selected, {"VULNSRV02"})
            self.assertIsNone(controller.run(Screen([ord("q")], size=(10, 40))))
            self.assertEqual(controller.handle(27), "cancel")

    def test_all_options_fit_minimum_terminal_at_maximum_labs(self):
        controller = menu.Menu(self.profiles)
        controller.labs = 16
        controller.selected = set(menu.OPTIONS)
        with patch.dict(sys.modules, {"curses": FAKE_CURSES}):
            for profile in ["Big", "Mini"]:
                controller.profile = profile
                for stage in ["profile", "options"]:
                    controller.stage = stage
                    self.assertTrue(controller.draw(Screen(size=(24,76))))


if __name__ == "__main__": unittest.main()
