# -*- coding: utf-8 -*-
"""Tests for the validation module."""

import pytest

from ghas_cli.utils.validation import (
    ValidationError,
    validate_branch_name,
    validate_organization_name,
    validate_repository_name,
)


class TestValidateOrganizationName:
    """Tests for validate_organization_name function."""

    def test_valid_organization_name(self):
        """Test that valid organization names are accepted."""
        assert validate_organization_name("Malwarebytes") == "Malwarebytes"
        assert validate_organization_name("my-org") == "my-org"
        assert validate_organization_name("a") == "a"
        assert validate_organization_name("org123") == "org123"

    def test_organization_name_with_numbers(self):
        """Test organization names with numbers."""
        assert validate_organization_name("org123") == "org123"
        assert validate_organization_name("123org") == "123org"

    def test_organization_name_max_length(self):
        """Test organization names at maximum length (39 chars)."""
        name = "a" * 39
        assert validate_organization_name(name) == name

    def test_empty_organization_name_raises_error(self):
        """Test that empty organization name raises ValidationError."""
        with pytest.raises(ValidationError, match="cannot be empty"):
            validate_organization_name("")

    def test_organization_name_too_long(self):
        """Test that organization names over 39 chars are rejected."""
        name = "a" * 40
        with pytest.raises(ValidationError, match="1-39 characters"):
            validate_organization_name(name)

    def test_organization_name_with_special_chars(self):
        """Test that special characters are rejected."""
        with pytest.raises(ValidationError):
            validate_organization_name("org_name")  # underscore not allowed
        with pytest.raises(ValidationError):
            validate_organization_name("org.name")  # period not allowed
        with pytest.raises(ValidationError):
            validate_organization_name("org/name")  # slash not allowed

    def test_organization_name_starting_with_hyphen(self):
        """Test that names starting with hyphen are rejected."""
        with pytest.raises(ValidationError, match="cannot start or end with a hyphen"):
            validate_organization_name("-myorg")

    def test_organization_name_ending_with_hyphen(self):
        """Test that names ending with hyphen are rejected."""
        with pytest.raises(ValidationError, match="cannot start or end with a hyphen"):
            validate_organization_name("myorg-")

    def test_path_traversal_rejected(self):
        """Test that path traversal attempts are rejected."""
        with pytest.raises(ValidationError):
            validate_organization_name("../etc")
        with pytest.raises(ValidationError):
            validate_organization_name("..%2f")

    def test_no_raise_returns_none(self):
        """Test that raise_error=False returns None instead of raising."""
        assert validate_organization_name("", raise_error=False) is None
        assert validate_organization_name("-invalid", raise_error=False) is None


class TestValidateRepositoryName:
    """Tests for validate_repository_name function."""

    def test_valid_repository_name(self):
        """Test that valid repository names are accepted."""
        assert validate_repository_name("ghas-cli") == "ghas-cli"
        assert validate_repository_name("my_repo") == "my_repo"
        assert validate_repository_name("repo.name") == "repo.name"
        assert validate_repository_name("REPO123") == "REPO123"

    def test_repository_name_max_length(self):
        """Test repository names at maximum length (100 chars)."""
        name = "a" * 100
        assert validate_repository_name(name) == name

    def test_empty_repository_name_raises_error(self):
        """Test that empty repository name raises ValidationError."""
        with pytest.raises(ValidationError, match="cannot be empty"):
            validate_repository_name("")

    def test_repository_name_too_long(self):
        """Test that repository names over 100 chars are rejected."""
        name = "a" * 101
        with pytest.raises(ValidationError, match="1-100 characters"):
            validate_repository_name(name)

    def test_path_traversal_rejected(self):
        """Test that path traversal attempts are rejected."""
        with pytest.raises(ValidationError, match="path traversal"):
            validate_repository_name("../etc")
        with pytest.raises(ValidationError, match="path traversal"):
            validate_repository_name("/etc/passwd")
        with pytest.raises(ValidationError, match="path traversal"):
            validate_repository_name("..\\windows")

    def test_repository_name_with_special_chars(self):
        """Test that certain special characters are rejected."""
        with pytest.raises(ValidationError):
            validate_repository_name("repo/name")  # slash not allowed
        with pytest.raises(ValidationError):
            validate_repository_name("repo:name")  # colon not allowed
        with pytest.raises(ValidationError):
            validate_repository_name("repo name")  # space not allowed

    def test_no_raise_returns_none(self):
        """Test that raise_error=False returns None instead of raising."""
        assert validate_repository_name("", raise_error=False) is None
        assert validate_repository_name("../invalid", raise_error=False) is None


class TestValidateBranchName:
    """Tests for validate_branch_name function."""

    def test_valid_branch_name(self):
        """Test that valid branch names are accepted."""
        assert validate_branch_name("main") == "main"
        assert validate_branch_name("feature/my-feature") == "feature/my-feature"
        assert validate_branch_name("release-1.0") == "release-1.0"
        assert validate_branch_name("fix_bug") == "fix_bug"

    def test_empty_branch_name_raises_error(self):
        """Test that empty branch name raises ValidationError."""
        with pytest.raises(ValidationError, match="cannot be empty"):
            validate_branch_name("")

    def test_branch_name_with_double_dots(self):
        """Test that branch names with .. are rejected."""
        with pytest.raises(ValidationError, match="cannot contain"):
            validate_branch_name("feature/../main")

    def test_branch_name_starting_with_slash(self):
        """Test that branch names starting with / are rejected."""
        with pytest.raises(ValidationError, match="start/end with"):
            validate_branch_name("/feature")

    def test_branch_name_ending_with_slash(self):
        """Test that branch names ending with / are rejected."""
        with pytest.raises(ValidationError, match="start/end with"):
            validate_branch_name("feature/")

    def test_no_raise_returns_none(self):
        """Test that raise_error=False returns None instead of raising."""
        assert validate_branch_name("", raise_error=False) is None
        assert validate_branch_name("/invalid", raise_error=False) is None
