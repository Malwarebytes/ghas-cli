# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""Input validation utilities for GitHub API parameters."""

import re
from typing import Optional

# GitHub naming constraints
# See: https://docs.github.com/en/get-started/learning-about-github/types-of-github-accounts
ORGANIZATION_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,37}[a-zA-Z0-9])?$")
REPOSITORY_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9._-]{1,100}$")
BRANCH_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9._/-]{1,255}$")


class ValidationError(ValueError):
    """Raised when input validation fails."""

    pass


def validate_organization_name(name: str, raise_error: bool = True) -> Optional[str]:
    """Validate a GitHub organization name.

    Args:
        name: The organization name to validate.
        raise_error: If True, raise ValidationError on invalid input.
                     If False, return None on invalid input.

    Returns:
        The validated organization name, or None if invalid and raise_error is False.

    Raises:
        ValidationError: If the name is invalid and raise_error is True.
    """
    if not name:
        if raise_error:
            raise ValidationError("Organization name cannot be empty")
        return None

    if not ORGANIZATION_NAME_PATTERN.match(name):
        if raise_error:
            raise ValidationError(
                f"Invalid organization name '{name}'. "
                "Organization names must be 1-39 characters, "
                "contain only alphanumeric characters or hyphens, "
                "and cannot start or end with a hyphen."
            )
        return None

    return name


def validate_repository_name(name: str, raise_error: bool = True) -> Optional[str]:
    """Validate a GitHub repository name.

    Args:
        name: The repository name to validate.
        raise_error: If True, raise ValidationError on invalid input.
                     If False, return None on invalid input.

    Returns:
        The validated repository name, or None if invalid and raise_error is False.

    Raises:
        ValidationError: If the name is invalid and raise_error is True.
    """
    if not name:
        if raise_error:
            raise ValidationError("Repository name cannot be empty")
        return None

    # Check for path traversal attempts
    if ".." in name or name.startswith("/") or name.startswith("\\"):
        if raise_error:
            raise ValidationError(
                f"Invalid repository name '{name}'. "
                "Repository names cannot contain path traversal sequences."
            )
        return None

    if not REPOSITORY_NAME_PATTERN.match(name):
        if raise_error:
            raise ValidationError(
                f"Invalid repository name '{name}'. "
                "Repository names must be 1-100 characters and "
                "contain only alphanumeric characters, hyphens, underscores, or periods."
            )
        return None

    return name


def validate_branch_name(name: str, raise_error: bool = True) -> Optional[str]:
    """Validate a Git branch name.

    Args:
        name: The branch name to validate.
        raise_error: If True, raise ValidationError on invalid input.
                     If False, return None on invalid input.

    Returns:
        The validated branch name, or None if invalid and raise_error is False.

    Raises:
        ValidationError: If the name is invalid and raise_error is True.
    """
    if not name:
        if raise_error:
            raise ValidationError("Branch name cannot be empty")
        return None

    # Check for path traversal and other dangerous patterns
    if ".." in name or name.startswith("/") or name.endswith("/"):
        if raise_error:
            raise ValidationError(
                f"Invalid branch name '{name}'. "
                "Branch names cannot contain '..' or start/end with '/'."
            )
        return None

    if not BRANCH_NAME_PATTERN.match(name):
        if raise_error:
            raise ValidationError(
                f"Invalid branch name '{name}'. "
                "Branch names must be 1-255 characters and "
                "contain only alphanumeric characters, hyphens, underscores, periods, or slashes."
            )
        return None

    return name
