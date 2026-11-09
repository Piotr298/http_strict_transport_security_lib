"""Tests for the HSTS header parser.

The tests exercise the cases that actually occur in the wild: mixed case,
whitespace, unknown directives, duplicate directives, and malformed values.
They do not assert anything the implementation does not promise.
"""

import unittest

from http_strict_transport_security_lib import HSTSPolicy, parse_hsts


class ParseHSTSTests(unittest.TestCase):
    def test_simple_max_age(self) -> None:
        policy = parse_hsts("max-age=31536000")
        self.assertEqual(
            policy,
            HSTSPolicy(max_age=31536000, include_subdomains=False, preload=False),
        )

    def test_all_directives(self) -> None:
        policy = parse_hsts("max-age=63072000; includeSubDomains; preload")
        self.assertEqual(
            policy,
            HSTSPolicy(max_age=63072000, include_subdomains=True, preload=True),
        )

    def test_case_insensitive_names(self) -> None:
        policy = parse_hsts("MAX-AGE=100; INCLUDESUBDOMAINS; PRELOAD")
        self.assertEqual(
            policy,
            HSTSPolicy(max_age=100, include_subdomains=True, preload=True),
        )

    def test_whitespace_around_equals(self) -> None:
        policy = parse_hsts("max-age = 42")
        self.assertEqual(
            policy,
            HSTSPolicy(max_age=42, include_subdomains=False, preload=False),
        )

    def test_empty_header_returns_none(self) -> None:
        self.assertIsNone(parse_hsts(""))

    def test_missing_max_age_returns_none(self) -> None:
        self.assertIsNone(parse_hsts("includeSubDomains; preload"))

    def test_bare_max_age_returns_none(self) -> None:
        self.assertIsNone(parse_hsts("max-age"))

    def test_negative_max_age_returns_none(self) -> None:
        self.assertIsNone(parse_hsts("max-age=-1"))

    def test_non_numeric_max_age_returns_none(self) -> None:
        self.assertIsNone(parse_hsts("max-age=abc"))

    def test_float_max_age_returns_none(self) -> None:
        self.assertIsNone(parse_hsts("max-age=1.5"))

    def test_unknown_directives_are_ignored(self) -> None:
        policy = parse_hsts("max-age=60; foo=bar; baz")
        self.assertEqual(
            policy,
            HSTSPolicy(max_age=60, include_subdomains=False, preload=False),
        )

    def test_duplicate_max_age_last_wins(self) -> None:
        policy = parse_hsts("max-age=10; max-age=20")
        self.assertEqual(
            policy,
            HSTSPolicy(max_age=20, include_subdomains=False, preload=False),
        )

    def test_duplicate_flags_are_idempotent(self) -> None:
        policy = parse_hsts("max-age=10; preload; preload; includeSubDomains; includeSubDomains")
        self.assertEqual(
            policy,
            HSTSPolicy(max_age=10, include_subdomains=True, preload=True),
        )

    def test_trailing_semicolon_is_ignored(self) -> None:
        policy = parse_hsts("max-age=10;")
        self.assertEqual(
            policy,
            HSTSPolicy(max_age=10, include_subdomains=False, preload=False),
        )

    def test_leading_semicolon_is_ignored(self) -> None:
        policy = parse_hsts("; max-age=10")
        self.assertEqual(
            policy,
            HSTSPolicy(max_age=10, include_subdomains=False, preload=False),
        )

    def test_zero_max_age_is_valid(self) -> None:
        policy = parse_hsts("max-age=0")
        self.assertEqual(
            policy,
            HSTSPolicy(max_age=0, include_subdomains=False, preload=False),
        )


if __name__ == "__main__":
    unittest.main()
