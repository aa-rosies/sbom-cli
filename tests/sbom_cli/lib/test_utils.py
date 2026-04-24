import pytest

from sbom_cli.lib.utils import truncate


class TestTruncate:
    def test_short_string_unchanged(self):
        assert truncate("hello", 10) == "hello"

    def test_exact_length_unchanged(self):
        assert truncate("hello", 5) == "hello"

    def test_truncates_with_suffix(self):
        assert truncate("hello world", 8) == "hello..."

    def test_custom_suffix(self):
        assert truncate("hello world", 7, suffix="--") == "hello--"

    def test_suffix_too_long_raises(self):
        with pytest.raises(ValueError, match="max_length must be"):
            truncate("hello", 2, suffix="...")
