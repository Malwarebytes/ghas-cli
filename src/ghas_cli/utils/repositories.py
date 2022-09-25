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

    def load_json(self, obj):
        """Load and parse a repository from an API json object"""

        self.name = r["name"]
        self.orga = organization
        self.owner = r["owner"]["login"]
        self.url = r["html_url"]
        self.description = r["description"]
        self.language = r["language"]
        self.default_branch = r["default_branch"]
        try:
            self.license = r["license"]["spdx_id"]
        except Exception:
            self.license = None
        self.archived = r["archived"]
        self.disabled = r["disabled"]
        self.updated_at = r["updated_at"]
        try:
            self.ghas = r["security_and_analysis"]["advanced_security"]["status"]
        except Exception as e:
            self.ghas = False
        try:
            self.secret_scanner = r["security_and_analysis"]["advanced_security"][
                "secret_scanning"
            ]["status"]
        except Exception as e:
            self.secret_scanner = False
        try:
            self.secret_push_prot = r["security_and_analysis"]["advanced_security"][
                "secret_scanning_push_protection"
            ]["status"]
        except Exception as e:
            self.secret_push_prot = False
        self.dependabot = False
        self.dependabot_alerts = check_dependabot_alerts_enabled(
            token, repo.orga, repo.name
        )
        self.codeql = False


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

    headers = {
        "accept": "application/vnd.github+json",
        "authorization": f"Bearer {token}",
        "User-Agent": "jboursier-mwb/fetch_org_ghas_metrics",
    }
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
            repo.load_json(r)

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

    headers = {
        "accept": "application/vnd.github+json",
        "authorization": f"Bearer {token}",
        "User-Agent": "jboursier-mwb/fetch_org_ghas_metrics",
    }

    status = requests.get(
        url=f"https://api.github.com/orgs/{organization}/repos/vulnerability-alerts",
        headers=headers,
    )

    if status.status_code != 204:
        return False
    else:
        return True
