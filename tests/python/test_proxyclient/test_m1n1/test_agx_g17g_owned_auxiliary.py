# SPDX-License-Identifier: GPL-2.0-or-later
"""Owned allocation checks with synthetic geometry; no GPU payload imports."""
import ast
from dataclasses import dataclass, replace
import importlib.util
from pathlib import Path
import sys
import types
from types import SimpleNamespace as N
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
DIRECTORY = ROOT / 'proxyclient/m1n1/drm_shim'


@dataclass
class Parameters:
    buffers: object = None
    auxiliary_object: int = 0

    def validate(self):
        assert self.auxiliary_object in self.buffers.pages


class Auxiliary(unittest.TestCase):
    def setUp(self):
        package = types.ModuleType('owned_scene_fixture')
        package.__path__ = []
        geometry = types.ModuleType('owned_scene_fixture.g17g_render')
        geometry._render_geometry = lambda _: dict(size1=16, size3=16)
        self.modules = patch.dict(sys.modules, {package.__name__: package, geometry.__name__: geometry})
        self.modules.start(); self.addCleanup(self.modules.stop)
        name = 'owned_scene_fixture.g17g_render_buffers'
        spec = importlib.util.spec_from_file_location(name, DIRECTORY / 'g17g_render_buffers.py')
        self.buffers = importlib.util.module_from_spec(spec)
        sys.modules[name] = self.buffers
        self.addCleanup(lambda: sys.modules.pop(name, None))
        spec.loader.exec_module(self.buffers)
        self.params = N(width=32, height=32, layers=1, utile_width=32, utile_height=32)

    def test_auxiliary_is_a_dedicated_page_in_its_scene(self):
        m = self.buffers
        b = m.render_buffers(self.params, m.ARENA_START)
        self.assertEqual(b.auxiliary, b.tpc + m.align(b.tpc_size, m.PAGE))
        self.assertEqual(b.end, b.auxiliary + m.PAGE)
        self.assertIn(b.auxiliary, b.pages)

    def test_two_scenes_do_not_share_auxiliary_or_backing_pages(self):
        m = self.buffers
        first = m.render_buffers(self.params, m.ARENA_START)
        second = m.render_buffers(self.params, m.next_render_buffer_base(first.pages))
        self.assertNotEqual(first.auxiliary, second.auxiliary)
        self.assertTrue(set(first.pages).isdisjoint(second.pages))

    def test_arena_bound_includes_auxiliary_page(self):
        m = self.buffers
        with self.assertRaises(MemoryError):
            m.render_buffers(self.params, m.ARENA_END - 3 * m.PAGE)

    def test_actual_parameter_tail_uses_scene_auxiliary(self):
        path = DIRECTORY / 'g17g_render_submit.py'
        tree = ast.parse(path.read_text())
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'render_parameters')
        start = next(i for i, n in enumerate(function.body) if isinstance(n, ast.ImportFrom) and n.module == 'g17g_render_buffers')
        harness = ast.parse('def bind(params, buffer_base):\n    pass\n')
        harness.body[0].body = function.body[start:]
        namespace = dict(__package__='owned_scene_fixture', replace=replace)
        exec(compile(ast.fix_missing_locations(harness), str(path), 'exec'), namespace)
        # render_buffers consumes this fixture's dimensions through the fake
        # geometry provider; the returned Parameters carries only ownership.
        p = Parameters()
        for key, value in vars(self.params).items():
            setattr(p, key, value)
        bound = namespace['bind'](p, self.buffers.ARENA_START)
        self.assertEqual(bound.auxiliary_object, bound.buffers.auxiliary)


if __name__ == '__main__':
    unittest.main()
