#!/usr/bin/env python3
"""Mutation controls for the formatting preservation checks."""

import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import tinycss2

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("source_style", ROOT / "scripts/source-style.py")
style = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(style)


class PreservationControls(unittest.TestCase):
    def python_candidate(self, before, candidate):
        result = subprocess.CompletedProcess([], 0, stdout=candidate, stderr=b"")
        with mock.patch.object(style, "command", return_value=result):
            return style.python_format(before, "fixture.py", "unused-formatter")

    def test_python_whitespace_is_accepted(self):
        self.assertEqual(self.python_candidate(b"x=1\n", b"x = 1\n"), b"x = 1\n")

    def test_python_number_change_is_rejected(self):
        with self.assertRaises(ValueError):
            self.python_candidate(b"x=1\n", b"x=2\n")

    def test_python_name_change_is_rejected(self):
        with self.assertRaises(ValueError):
            self.python_candidate(b"x=1\n", b"y=1\n")

    def test_python_comment_change_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "comment"):
            self.python_candidate(b"x=1 # invariant\n", b"x=1 # changed\n")

    def test_python_literal_value_is_restored(self):
        before = b'def f():\n    """a\n      b"""\n    pass\n'
        candidate = b'def f():\n    """a\n    b"""\n    pass\n'
        self.assertEqual(self.python_candidate(before, candidate), before)

    def test_python_type_ignore_location_is_not_content(self):
        before = b"x=1 # type: ignore[assignment]\n"
        after = b"\nx = 1  # type: ignore[assignment]\n"
        self.assertEqual(self.python_candidate(before, after), after)

    def test_python_type_ignore_tag_is_content(self):
        with self.assertRaises(ValueError):
            self.python_candidate(b"x=1 # type: ignore[name]\n", b"x=1 # type: ignore[attr]\n")

    def test_python_type_ignore_cannot_move_to_another_statement(self):
        before = b"x=1 # type: ignore[assignment]\ny=2\n"
        after = b"x=1\ny=2 # type: ignore[assignment]\n"
        with self.assertRaisesRegex(ValueError, "binding"):
            self.python_candidate(before, after)

    def test_python_type_ignore_multiline_statement_keeps_binding(self):
        before = b"x = (1 + 2) # type: ignore[assignment]\n"
        after = b"x = (\n    1 + 2\n) # type: ignore[assignment]\n"
        self.assertEqual(self.python_candidate(before, after), after)

    def test_python_file_ignore_cannot_move_after_code(self):
        before = b"# type: ignore[assignment]\nx=1\n"
        after = b"x=1\n# type: ignore[assignment]\n"
        with self.assertRaisesRegex(ValueError, "binding"):
            self.python_candidate(before, after)

    def test_html_text_scripts_entities_and_void_spelling_are_preserved(self):
        before = '<meta charset="utf-8"><p>A &amp; B</p><script>let x = " a ";</script>'
        candidate = '<meta\n charset="utf-8" />\n<p> A &amp; B </p>\n<script>let x="a";</script>'
        result = style.html_format(before, candidate)
        self.assertEqual(style.Markup(before).events, style.Markup(result).events)
        self.assertEqual(style.Markup(before).gaps(), style.Markup(result).gaps())
        self.assertIn('let x = " a ";', result)
        self.assertNotIn('/>', result)

    def test_html_attribute_change_is_rejected(self):
        with self.assertRaises(ValueError):
            style.html_format('<a href="/safe">x</a>', '<a href="/other">x</a>')

    def test_html_comment_change_is_rejected(self):
        with self.assertRaises(ValueError):
            style.html_format('<!-- invariant --><p>x</p>', '<!-- changed --><p>x</p>')

    def test_css_layout_retains_exact_values(self):
        before = '@media (min-width:1px){a:hover{color:#AAbBcC;opacity:.5;content:" a "}}'
        after, original = style.css_tree(tinycss2.parse_stylesheet(before))
        _, checked = style.css_tree(tinycss2.parse_stylesheet(after))
        self.assertEqual(original, checked)
        self.assertIn('#AAbBcC', after)
        self.assertIn('opacity:.5;', after)
        self.assertIn('content:" a ";', after)

    def test_css_value_change_is_detected(self):
        original = style.css_tree(tinycss2.parse_stylesheet('a{opacity:.5}'))[1]
        mutated = style.css_tree(tinycss2.parse_stylesheet('a{opacity:.6}'))[1]
        self.assertNotEqual(original, mutated)

    def test_view_transition_uses_declarations(self):
        source = '@view-transition{navigation:auto}'
        formatted, key = style.css_tree(tinycss2.parse_stylesheet(source))
        self.assertEqual(key, style.css_tree(tinycss2.parse_stylesheet(formatted))[1])

    def test_pinned_and_frozen_files_are_excluded(self):
        pinned, patterns = style.protected_paths()
        for name in (
            'vendor/pqc/provenance/PQC_PROVENANCE.tsv',
            'website/hosted-wallet/asset-sha256.json',
            'website/hosted-wallet/wallet-history-v1.js',
            'tests/fixtures/veldhash-3.0.9-vectors.txt',
        ):
            self.assertTrue(style.exclusion(name, pinned, patterns), name)
        self.assertFalse(style.exclusion('src/veld-node.cpp', pinned, patterns))

    def test_cpp_lexical_controls(self):
        compiler = shutil.which('clang++')
        self.assertIsNotNone(compiler, 'Clang is required; lexical controls must not be skipped')
        before = '// invariant\nint amount = 3; const char* s = "coin";\n'
        with tempfile.TemporaryDirectory(prefix='veld-style-controls-') as directory:
            source = Path(directory) / 'fixture.cpp'
            source.write_text(before)
            baseline = style.cpp_tokens(source, compiler)
            source.write_text('// invariant\nint amount=3;\nconst char *s="coin";\n')
            self.assertEqual(baseline, style.cpp_tokens(source, compiler))
            for changed in (
                before.replace('amount', 'quantity'),
                before.replace('3;', '4;'),
                before.replace('"coin"', '"other"'),
                before.replace('=', '+='),
                before.replace('invariant', 'changed'),
            ):
                with self.subTest(changed=changed):
                    source.write_text(changed)
                    self.assertNotEqual(baseline, style.cpp_tokens(source, compiler))

    def test_cpp_preprocessor_boundaries_and_macro_kind(self):
        compiler = shutil.which('clang++')
        self.assertIsNotNone(compiler)
        cases = (
            ('#define F(x) x\n', '#define F (x) x\n'),
            ('#define X 1\nint y;\n', '#define X 1 int y;\n'),
            ('#if X\nint y;\n#endif\n', '#if X int y;\n#endif\n'),
            ('#define F(x) x\n', '#define F/**/(x) x\n'),
        )
        with tempfile.TemporaryDirectory(prefix='veld-directive-controls-') as directory:
            source = Path(directory) / 'fixture.cpp'
            for before, after in cases:
                with self.subTest(before=before, after=after):
                    source.write_text(before)
                    original = style.cpp_source(source, compiler)
                    source.write_text(after)
                    self.assertNotEqual(original, style.cpp_source(source, compiler))

    def test_cpp_escaped_newline_keeps_directive(self):
        compiler = shutil.which('clang++')
        self.assertIsNotNone(compiler)
        before = '#define F(x) (x + 1)\nint y;\n'
        after = '#define F(x) ' + '\\' + '\n    (x + 1)\nint y;\n'
        with tempfile.TemporaryDirectory(prefix='veld-directive-controls-') as directory:
            source = Path(directory) / 'fixture.cpp'
            source.write_text(before)
            original = style.cpp_source(source, compiler)
            source.write_text(after)
            self.assertEqual(original, style.cpp_source(source, compiler))


if __name__ == '__main__':
    unittest.main(verbosity=2)
