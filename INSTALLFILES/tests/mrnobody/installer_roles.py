"""Offline menu contracts: Master is informational; Big/Mini selection is unchanged."""
import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("installer_menu", ROOT / "installer_menu.py")
menu = importlib.util.module_from_spec(spec)
spec.loader.exec_module(menu)
CURSES = types.SimpleNamespace(
    A_REVERSE=1, A_NORMAL=0, KEY_UP=1001, KEY_DOWN=1002,
    KEY_LEFT=1003, KEY_RIGHT=1004, KEY_ENTER=1005,
)


class Screen:
    def __init__(self, height=24, width=76):
        self.height, self.width, self.lines = height, width, {}
    def getmaxyx(self):
        return self.height, self.width
    def erase(self):
        self.lines = {}
    def addnstr(self, y, x, text, limit, attr):
        self.lines[y] = text[:limit]
    def refresh(self):
        pass


class MenuRoles(unittest.TestCase):
    def setUp(self):
        self.patch = patch.dict(sys.modules, {"curses": CURSES})
        self.patch.start()
        self.addCleanup(self.patch.stop)
        rows = [dict(tag=tag, name=name, base=base, cpu=2, memory_mib=2048, disk_gib=32)
                for tag, prefix, name, relative, base in menu.VMS]
        self.profiles = {profile: dict(profile=profile, rows=rows) for profile in ("Big", "Mini")}
        self.view = menu.Menu(self.profiles)

    def test_minimum_terminal_shows_role_and_single_vm_notice(self):
        screen = Screen()
        self.assertTrue(self.view.draw(screen))
        self.assertIn("agent/slave", screen.lines[18])
        self.assertIn("fremtidig Custom", screen.lines[18])
        self.assertIn("Single VM", screen.lines[19])
        self.assertIn("MrNobody", screen.lines[19])
        self.assertIn("Op/ned: Big/Mini", screen.lines[21])

    def test_profile_keys_cycle_big_mini_single(self):
        for expected in ("Mini", "Single VM", "Big"):
            self.view.handle(CURSES.KEY_DOWN)
            self.assertEqual(self.view.profile, expected)
        before = self.view.profile
        self.view.handle(ord("m"))
        self.assertEqual(self.view.profile, before)

    def test_mrnobody_remains_optional_and_returns_original_selection_shape(self):
        self.assertNotIn("MRNOBODY", self.view.selected)
        self.view.handle(10)
        for _ in range(menu.OPTIONS.index("MRNOBODY")):
            self.view.handle(CURSES.KEY_DOWN)
        self.view.handle(ord(" "))
        screen = Screen()
        self.assertTrue(self.view.draw(screen))
        self.assertIn("MrNobody: agent/slave", screen.lines[20])
        self.assertIn("fremtidig Single VM", screen.lines[20])
        self.assertEqual(self.view.handle(10), "accept")
        selected = menu.validate_selection(dict(profile=self.view.profile, labs=self.view.labs,
                                                components=list(self.view.selected)))
        self.assertEqual(selected, dict(profile="Big", labs=1, components=["MRNOBODY"]))

    def test_single_vm_list_shows_only_mrnobody_before_roles(self):
        self.view.profile, self.view.labs, self.view.selected = "Mini", 3, {"MRNOBODY"}
        self.assertIsNone(self.view.handle(ord("S")))
        screen = Screen()
        self.view.draw(screen)
        self.assertEqual(screen.lines[5], "MrNobody")
        self.assertFalse(any("Master" in line or "Standalone" in line for line in screen.lines.values()))
        self.view.handle(10)
        self.view.draw(screen)
        self.assertIn("Master", screen.lines[5])
        self.assertIn("Slave", screen.lines[6])
        self.assertIn("Standalone", screen.lines[7])
        self.view.handle(ord("B"))
        self.assertEqual(self.view.stage, "single")
        self.view.handle(ord("B"))
        self.assertEqual(self.view.stage, "profile")
        self.assertEqual((self.view.labs, self.view.selected), (3, {"MRNOBODY"}))

    def test_master_and_single_vm_cannot_be_selected(self):
        for profile in ("Single VM", "Single", "Master", "Custom"):
            with self.subTest(profile=profile), self.assertRaises(ValueError):
                menu.validate_selection(dict(profile=profile, labs=1, components=["MRNOBODY"]))
        with self.assertRaises(ValueError):
            menu.validate_selection(dict(profile="Big", labs=1, components=["MASTER"]))

    def test_small_terminal_still_requests_resize(self):
        screen = Screen(23, 75)
        self.assertFalse(self.view.draw(screen))
        self.assertIn("mindst 76 kolonner og 24 linjer", screen.lines[0])


if __name__ == "__main__":
    unittest.main()
