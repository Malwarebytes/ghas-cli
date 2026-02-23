# -*- coding: utf-8 -*-
"""Tests for the template loader module."""

import pytest

from ghas_cli.utils.template_loader import load_template


class TestLoadTemplate:
    """Tests for the load_template function."""

    def test_load_codeql_template(self):
        """Test loading the CodeQL markdown template."""
        content = load_template("codeql.md")
        assert isinstance(content, str)
        assert len(content) > 0
        assert "CodeQL" in content

    def test_load_secret_scanner_template(self):
        """Test loading the secret scanner markdown template."""
        content = load_template("secret_scanner.md")
        assert isinstance(content, str)
        assert len(content) > 0
        assert "Secret" in content

    def test_load_dependabot_template(self):
        """Test loading the Dependabot markdown template."""
        content = load_template("dependabot.md")
        assert isinstance(content, str)
        assert len(content) > 0
        assert "Dependabot" in content

    def test_load_codeql_analysis_workflow(self):
        """Test loading the CodeQL analysis workflow template."""
        content = load_template("codeql-analysis-default.yml")
        assert isinstance(content, str)
        assert len(content) > 0
        assert "codeql" in content.lower()

    def test_load_dependency_enforcement_workflow(self):
        """Test loading the dependency enforcement workflow template."""
        content = load_template("dependency_enforcement.yml")
        assert isinstance(content, str)
        assert len(content) > 0

    def test_load_nonexistent_template_raises_error(self):
        """Test that loading a nonexistent template raises an error."""
        with pytest.raises(FileNotFoundError):
            load_template("nonexistent_template.md")
