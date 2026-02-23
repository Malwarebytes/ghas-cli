# -*- coding: utf-8 -*-
"""Tests for the repositories module."""

import pytest

from ghas_cli.utils.repositories import Repository


class TestRepository:
    """Tests for the Repository class."""

    def test_default_values(self):
        """Test that Repository initializes with correct default values."""
        repo = Repository()
        assert repo.name == ""
        assert repo.orga == "Malwarebytes"
        assert repo.owner == ""
        assert repo.url == ""
        assert repo.description == ""
        assert repo.main_language == ""
        assert repo.languages == []
        assert repo.default_branch == "main"
        assert repo.license == ""
        assert repo.archived is False
        assert repo.disabled is False
        assert repo.updated_at == ""
        assert repo.ghas is False
        assert repo.secret_scanner is False
        assert repo.secret_push_prot is False
        assert repo.dependabot is False
        assert repo.dependabot_alerts is False
        assert repo.codeql is False

    def test_custom_values(self):
        """Test that Repository accepts custom values."""
        repo = Repository(
            name="test-repo",
            orga="TestOrg",
            owner="testuser",
            url="https://github.com/TestOrg/test-repo",
            description="A test repository",
            main_language="Python",
            languages=["Python", "JavaScript"],
            default_branch="develop",
            license="MIT",
            archived=True,
            disabled=True,
            updated_at="2024-01-01T00:00:00Z",
            ghas=True,
            secret_scanner=True,
            secret_push_prot=True,
            dependabot=True,
            dependabot_alerts=True,
            codeql=True,
        )
        assert repo.name == "test-repo"
        assert repo.orga == "TestOrg"
        assert repo.owner == "testuser"
        assert repo.url == "https://github.com/TestOrg/test-repo"
        assert repo.description == "A test repository"
        assert repo.main_language == "Python"
        assert repo.languages == ["Python", "JavaScript"]
        assert repo.default_branch == "develop"
        assert repo.license == "MIT"
        assert repo.archived is True
        assert repo.disabled is True
        assert repo.updated_at == "2024-01-01T00:00:00Z"
        assert repo.ghas is True
        assert repo.secret_scanner is True
        assert repo.secret_push_prot is True
        assert repo.dependabot is True
        assert repo.dependabot_alerts is True
        assert repo.codeql is True

    def test_to_json(self):
        """Test that to_json returns correct dictionary."""
        repo = Repository(
            name="test-repo",
            orga="TestOrg",
            main_language="Python",
        )
        json_data = repo.to_json()

        assert isinstance(json_data, dict)
        assert json_data["name"] == "test-repo"
        assert json_data["orga"] == "TestOrg"
        assert json_data["main_language"] == "Python"
        assert "ghas" in json_data
        assert "secret_scanner" in json_data

    def test_to_ghas(self):
        """Test that to_ghas returns correct format."""
        repo = Repository(name="test-repo", orga="TestOrg")
        ghas_data = repo.to_ghas()

        assert isinstance(ghas_data, dict)
        assert ghas_data["repo"] == "TestOrg/test-repo"

    def test_str_representation(self):
        """Test that __str__ returns a readable string."""
        repo = Repository(
            name="test-repo",
            orga="TestOrg",
            url="https://github.com/TestOrg/test-repo",
        )
        str_rep = str(repo)

        assert "[test-repo]" in str_rep
        assert "Organization: TestOrg" in str_rep
        assert "https://github.com/TestOrg/test-repo" in str_rep

    def test_ghas_type_is_bool(self):
        """Test that ghas field is properly a boolean, not a tuple."""
        repo = Repository(ghas=True)
        assert repo.ghas is True
        assert isinstance(repo.ghas, bool)

        repo2 = Repository(ghas=False)
        assert repo2.ghas is False
        assert isinstance(repo2.ghas, bool)
