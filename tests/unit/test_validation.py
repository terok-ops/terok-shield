# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for validation.py shared validators."""

import unittest

from terok_shield.validation import (
    SAFE_CONTAINER,
    SAFE_NAME,
    parse_entries,
    validate_container_name,
    validate_safe_name,
)


class TestValidateContainerName(unittest.TestCase):
    """Tests for validate_container_name."""

    def test_simple_name(self) -> None:
        """Accept simple alphanumeric name."""
        self.assertEqual(validate_container_name("mycontainer"), "mycontainer")

    def test_with_dots_and_dashes(self) -> None:
        """Accept names with dots, dashes, and underscores."""
        self.assertEqual(validate_container_name("my-ctr.123_test"), "my-ctr.123_test")

    def test_leading_underscore(self) -> None:
        """Accept leading underscore (podman convention)."""
        self.assertEqual(validate_container_name("_hidden"), "_hidden")

    def test_rejects_empty(self) -> None:
        """Reject empty string."""
        with self.assertRaises(ValueError):
            validate_container_name("")

    def test_rejects_path_traversal(self) -> None:
        """Reject path traversal."""
        with self.assertRaises(ValueError):
            validate_container_name("../etc/passwd")

    def test_rejects_slash(self) -> None:
        """Reject names with slashes."""
        with self.assertRaises(ValueError):
            validate_container_name("foo/bar")

    def test_rejects_absolute_path(self) -> None:
        """Reject absolute paths."""
        with self.assertRaises(ValueError):
            validate_container_name("/etc/passwd")

    def test_rejects_space(self) -> None:
        """Reject names with spaces."""
        with self.assertRaises(ValueError):
            validate_container_name("my container")

    def test_rejects_special_chars(self) -> None:
        """Reject names with special characters."""
        for char in ["@", "!", "$", "&", ";", "|"]:
            with self.assertRaises(ValueError, msg=f"Should reject '{char}'"):
                validate_container_name(f"name{char}")


class TestValidateSafeName(unittest.TestCase):
    """Tests for validate_safe_name (stricter than container name)."""

    def test_simple_name(self) -> None:
        """Accept simple alphanumeric name."""
        self.assertEqual(validate_safe_name("dev-standard"), "dev-standard")

    def test_with_dots_and_dashes(self) -> None:
        """Accept names with dots, dashes, and underscores."""
        self.assertEqual(validate_safe_name("my.profile-v2"), "my.profile-v2")

    def test_rejects_leading_underscore(self) -> None:
        """Reject leading underscore (unlike container name)."""
        with self.assertRaises(ValueError):
            validate_safe_name("_hidden")

    def test_rejects_leading_dot(self) -> None:
        """Reject leading dot."""
        with self.assertRaises(ValueError):
            validate_safe_name(".hidden")

    def test_rejects_leading_dash(self) -> None:
        """Reject leading dash."""
        with self.assertRaises(ValueError):
            validate_safe_name("-flag")

    def test_rejects_empty(self) -> None:
        """Reject empty string."""
        with self.assertRaises(ValueError):
            validate_safe_name("")

    def test_rejects_path_traversal(self) -> None:
        """Reject path traversal."""
        with self.assertRaises(ValueError):
            validate_safe_name("../etc/passwd")


class TestParseEntries(unittest.TestCase):
    """Tests for parse_entries."""

    def test_basic_lines(self) -> None:
        """Parse simple domain/IP lines."""
        text = "example.com\n192.0.2.1\n"
        self.assertEqual(parse_entries(text), ["example.com", "192.0.2.1"])

    def test_comments_stripped(self) -> None:
        """Skip comment lines."""
        text = "# comment\nexample.com\n# another\ntest.org\n"
        self.assertEqual(parse_entries(text), ["example.com", "test.org"])

    def test_blank_lines(self) -> None:
        """Skip blank lines."""
        text = "\nexample.com\n\n\ntest.org\n"
        self.assertEqual(parse_entries(text), ["example.com", "test.org"])

    def test_whitespace_stripped(self) -> None:
        """Strip whitespace from entries."""
        text = "  example.com  \n  test.org  \n"
        self.assertEqual(parse_entries(text), ["example.com", "test.org"])

    def test_empty(self) -> None:
        """Empty text returns empty list."""
        self.assertEqual(parse_entries(""), [])

    def test_comment_after_whitespace(self) -> None:
        """Comment after whitespace is still stripped."""
        text = "  # indented comment\nexample.com\n"
        self.assertEqual(parse_entries(text), ["example.com"])


class TestRegexPatterns(unittest.TestCase):
    """Verify regex patterns directly."""

    def test_safe_container_accepts_underscore_prefix(self) -> None:
        """SAFE_CONTAINER allows leading underscore."""
        self.assertIsNotNone(SAFE_CONTAINER.fullmatch("_test"))

    def test_safe_name_rejects_underscore_prefix(self) -> None:
        """SAFE_NAME rejects leading underscore."""
        self.assertIsNone(SAFE_NAME.fullmatch("_test"))

    def test_safe_container_rejects_newline(self) -> None:
        """SAFE_CONTAINER rejects embedded newlines."""
        self.assertIsNone(SAFE_CONTAINER.fullmatch("test\nname"))

    def test_safe_name_rejects_newline(self) -> None:
        """SAFE_NAME rejects embedded newlines."""
        self.assertIsNone(SAFE_NAME.fullmatch("test\nname"))
