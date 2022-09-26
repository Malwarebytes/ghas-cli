# -*- coding: utf-8 -*-
#!/usr/bin/env python3

from typing import List
import requests
from . import network


class Repository:
    def __init__(
        self,
        name="",
        orga="Malwarebytes",
        owner="",
        url="",
        description="",
        language="",
        default_branch="main",
        license="",
        archived=False,
        disabled=False,
        updated_at="",
        ghas=False,
        secret_scanner=False,
        secret_push_prot=False,
        dependabot=False,
        dependabot_alerts=False,
        codeql=False,
    ):
        self.name: str = name
        self.orga: str = orga
        self.owner: str = owner
        self.url: str = url
        self.description: str = description
        self.language: str = language
        self.default_branch: str = default_branch
        self.license: str = license  # spdx_id
        self.archived: bool = archived
        self.disabled: bool = disabled
        self.updated_at: str = updated_at
        self.ghas: bool = (ghas,)
        self.secret_scanner: bool = secret_scanner
        self.secret_push_prot: bool = secret_push_prot
        self.dependabot: bool = dependabot
        self.dependabot_alerts: bool = dependabot_alerts
        self.codeql: bool = codeql

    def load_json(self, obj, token=None):
        """Load and parse a repository from an API json object"""

        self.name = obj["name"]
        if obj["owner"]["type"] == "Organization":
            self.orga = obj["owner"]["login"]
        else:
            self.orga = ""
        self.owner = obj["owner"]["login"]
        self.url = obj["html_url"]
        self.description = obj["description"]
        self.language = obj["language"]
        self.default_branch = obj["default_branch"]
        try:
            self.license = obj["license"]["spdx_id"]
        except Exception:
            self.license = None
        self.archived = obj["archived"]
        self.disabled = obj["disabled"]
        self.updated_at = obj["updated_at"]
        try:
            self.ghas = obj["security_and_analysis"]["advanced_security"]["status"]
        except Exception as e:
            self.ghas = False
        try:
            self.secret_scanner = obj["security_and_analysis"]["advanced_security"][
                "secret_scanning"
            ]["status"]
        except Exception as e:
            self.secret_scanner = False
        try:
            self.secret_push_prot = obj["security_and_analysis"]["advanced_security"][
                "secret_scanning_push_protection"
            ]["status"]
        except Exception as e:
            self.secret_push_prot = False
        self.dependabot = False
        if token:
            self.dependabot_alerts = check_dependabot_alerts_enabled(
                token, self.orga, self.name
            )
        else:
            self.dependabot_alerts = False
        self.codeql = False

    def __str__(self):
        return f"""[{self.name}]
        * Organization: {self.orga}
        * Owner: {self.owner}
        * Url: {self.url}
        * Description: {self.description}
        * Language: {self.language}
        * Default branch: {self.default_branch}
        * License: {self.license}
        * Archived: {self.archived}
        * Disabled: {self.disabled}
        * Last updated at: {self.updated_at}
        * GHAS: {self.ghas}
        * Secret Scanner: {self.secret_scanner}
        * Secret Scanner Push Protection: {self.secret_push_prot}
        * Dependabot: {self.dependabot}
        * Dependabot alerts: {self.dependabot_alerts}
        * CodeQL: {self.codeql}
        """

    def to_json(self):
        return {
            "name": self.name,
            "orga": self.orga,
            "owner": self.owner,
            "url": self.url,
            "description": self.description,
            "language": self.language,
            "default_branch": self.default_branch,
            "license": self.license,
            "archived": self.archived,
            "disabled": self.disabled,
            "updated_at": self.updated_at,
            "ghas": self.ghas,
            "secret_scanner": self.secret_scanner,
            "secret_push_prot": self.secret_push_prot,
            "dependabot": self.dependabot,
            "dependabot_alerts": self.dependabot_alerts,
            "codeql": self.codeql,
        }

    def to_ghas(self):
        return {"repo": f"{self.orga}/{self.name}"}


def get_org_repositories(
    status: str,
    organization: str,
    token: str,
    language: str = "",
    default_branch: str = "",
    license: str = "",
    archived: bool = False,
    disabled: bool = False,
) -> List:
    page = 1

    headers = network.get_github_headers(token)
    while True:
        params = {
            "type": f"{status}",
            "sort": "full_name",
            "per_page": 100,
            "page": page,
        }
        repos = requests.get(
            url=f"https://api.github.com/orgs/{organization}/repos",
            params=params,
            headers=headers,
        )
        if network.check_rate_limit(repos):
            break

        if repos.status_code != 200:
            break

        if [] == repos.json():
            break

        repos_list = []
        for r in repos.json():

            repo = Repository()
            repo.load_json(r, token=token)

            if language != "" and repo.language != language:
                continue
            if default_branch != "" and repo.default_branch != default_branch:
                continue
            if license != "" and repo.license != license:
                continue
            if repo.archived != archived:
                continue
            if repo.disabled != disabled:
                continue

            repos_list.append(repo)

        page += 1

    return repos_list


def check_dependabot_alerts_enabled(
    token: str, organization: str, repository_name: str
) -> bool:

    headers = network.get_github_headers(token)

    status = requests.get(
        url=f"https://api.github.com/orgs/{organization}/repos/vulnerability-alerts",
        headers=headers,
    )

    if status.status_code != 204:
        return False
    else:
        return True


def enable_secret_scanner(organization: str, token: str, repository: str) -> bool:
    headers = network.get_github_headers(token)

    payload = {
        "security_and_analysis": {
            "advanced_security": {
                "status": "enabled",
            },
            "secret_scanning": {"status": "enabled"},
        }
    }

    status = requests.patch(
        url=f"https://api.github.com/repos/{organization}/{repository}",
        headers=headers,
        json=payload,
    )

    if status.status_code != 200:
        return False
    else:
        return True


def enable_secret_scanner_push_protection(
    organization: str, token: str, repository: str
) -> bool:
    headers = network.get_github_headers(token)

    payload = {
        "security_and_analysis": {
            "advanced_security": {
                "status": "enabled",
            },
            "secret_scanning": {"status": "enabled"},
            "secret_scanning_push_protection": {"status": "enabled"},
        }
    }

    status = requests.patch(
        url=f"https://api.github.com/repos/{organization}/{repository}",
        headers=headers,
        json=payload,
    )

    if status.status_code != 200:
        return False
    else:
        return True


def enable_dependabot(organization: str, token: str, repository: str) -> bool:
    headers = network.get_github_headers(token)

    status_alerts = requests.put(
        url=f"https://api.github.com/repos/{organization}/{repository}/vulnerability-alerts",
        headers=headers,
    )

    status_fixes = requests.put(
        url=f"https://api.github.com/repos/{organization}/{repository}/automated-security-fixes",
        headers=headers,
    )

    if status_alerts.status_code != 204 and status_fixes != 204:
        return False
    else:
        return True


def get_default_branch(organization: str, token: str, repository: str) -> str:
    """Get the default branch slug for a repository"""
    headers = network.get_github_headers(token)

    repo = requests.get(
        url=f"https://api.github.com/repos/{organization}/{repository}",
        headers=headers,
    )
    if repo.status_code != 200:
        return False

    repo = repo.json()
    try:
        return repo["default_branch"]
    except Exception:
        return False


def create_codeql_pr(organization: str, token: str, repository: str) -> bool:
    """
    1. Retrieve the repository main language. Select the `codeql-analysis.yml` file for that language.
    2. Create a branch
    3. Push a .github/workflows/codeql-analysis.yml to the repository on that branch
    3. Create an associated issue
    """
    headers = network.get_github_headers(token)
    target_branch = "appsec:ghas:codeql_enable"

    # Get the default branch
    default_branch = get_default_branch(organization, token, repository)
    if not default_branch:
        return False

    # Create a branch
    branch_resp = requests.get(
        url=f"https://api.github.com/repos/{organization}/{repository}/git/refs/heads",
        headers=headers,
    )
    if branch_resp.status_code != 200:
        return False

    refs = branch_resp.json()
    sha1 = ""
    for ref in refs:
        if ref["ref"] == f"refs/heads/{default_branch}":
            sha1 = ref["object"]["sha"]

    if sha1 == "":
        return False

    payload = {
        "ref": f"refs/heads/{target_branch}",
        "sha": sha1,
    }

    branch_resp = requests.post(
        url=f"https://api.github.com/repos/{organization}/{repository}/git/refs",
        headers=headers,
        json=payload,
    )
    if branch_resp.status_code != 201:
        return False

    # Create commit

    payload = {
        "message": "Enable CodeQL analysis",
        "content": "bXkgbmV3IGZpbGUgY29udGVudHM=",  # TODO: load the proper yaml template based on the main language
        "branch": target_branch,
    }

    commit_resp = requests.put(
        url=f"https://api.github.com/repos/{organization}/{repository}/contents/.github/workflows/codeql-analysis.yml",
        headers=headers,
        json=payload,
    )
    if commit_resp.status_code != 201:
        return False

    # Create PR
    payload = {
        "title": "Enable CodeQL analysis",
        "body": "Please pull these awesome changes in!",  # TODO: change the body accordingly, per language
        "head": target_branch,
        "base": default_branch,
    }

    pr_resp = requests.post(
        url=f"https://api.github.com/repos/{organization}/{repository}/pulls",
        headers=headers,
        json=payload,
    )
    if pr_resp.status_code != 201:
        return False

    return True
