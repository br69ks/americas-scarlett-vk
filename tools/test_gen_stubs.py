#!/usr/bin/env python3
"""Regression tests for tools/gen_stubs.py."""

import tempfile
import unittest
from pathlib import Path

import gen_stubs


GNU_IMPORTS = """\
DLL Name: KERNEL32.dll
\tvma:     Ordinal  Hint  Member-Name  Bound-To
\t00000000  <none>  0001  CreateFileW
\t00000008  0007    0002  <none>

DLL Name: api-ms-win-crt-heap-l1-1-0.dll
\tvma:     Ordinal  Hint  Member-Name  Bound-To
\t00000010  <none>  0016  malloc
\t00000018  <none>  0017  free
"""

LLVM_IMPORTS = """\
Name: KERNEL32.dll
  Symbol: CreateFileW (1)
  Symbol:  (7)
"""


class ParseImportsTests(unittest.TestCase):
    def test_gnu_named_and_ordinal(self):
        parsed = gen_stubs.parse_imports(GNU_IMPORTS)
        self.assertEqual(
            parsed["kernel32.dll"],
            [("CreateFileW", None), ("Ordinal_7", 7)],
        )
        self.assertEqual(
            parsed["api-ms-win-crt-heap-l1-1-0.dll"],
            [("malloc", None), ("free", None)],
        )

    def test_llvm_named_and_ordinal(self):
        parsed = gen_stubs.parse_imports(LLVM_IMPORTS)
        self.assertEqual(
            parsed["kernel32.dll"],
            [("CreateFileW", None), ("Ordinal_7", 7)],
        )

    def test_deduplicates_in_order(self):
        text = """\
DLL Name: kernel32.dll
\t00000000  <none>  0001  CreateFileW
\t00000008  <none>  0001  CreateFileW
"""
        self.assertEqual(
            gen_stubs.parse_imports(text)["kernel32.dll"],
            [("CreateFileW", None)],
        )

    def test_zig_identifier(self):
        self.assertEqual(gen_stubs.sanitize_zig_ident("CreateFileW"), "CreateFileW")
        self.assertEqual(
            gen_stubs.sanitize_zig_ident("??0?$basic_string@DU?$char_traits@D@std@@"),
            "__0__basic_string_DU__char_traits_D_std__",
        )
        self.assertEqual(gen_stubs.sanitize_zig_ident("123abc"), "_123abc")

    def test_string_literal_escaping(self):
        self.assertEqual(gen_stubs.zig_string_literal('a"b\\c\n'), '"a\\"b\\\\c\\n"')


class GenerateTests(unittest.TestCase):
    def test_generated_stub_uses_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            gen_stubs.generate_zig_files(
                {"kernel32.dll": [("CreateFileW", None), ("Ordinal_7", 7)]},
                out,
            )
            stub_text = (out / "kernel32.zig").read_text(encoding="utf-8")
            self.assertIn("stub_policy.zig", stub_text)
            self.assertIn(".missing(", stub_text)
            self.assertIn("stub_CreateFileW", stub_text)
            self.assertNotIn("return 0;", stub_text)

            registry_text = (out / "registry.zig").read_text(encoding="utf-8")
            self.assertIn(".dll = \"kernel32.dll\"", registry_text)
            self.assertIn(".name = \"CreateFileW\"", registry_text)
            self.assertIn(".ordinal = 7", registry_text)


if __name__ == "__main__":
    unittest.main()
