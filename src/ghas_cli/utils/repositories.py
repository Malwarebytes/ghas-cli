# -*- coding: utf-8 -*-
#!/usr/bin/env python3

from typing import List
import requests
from . import network


class Repository:
    name: str = ""
    orga: str = "Malwarebytes"
    owner: str = ""
    url: str = ""
    description: str = ""
    language: str = ""
    default_branch: str = "main"
    license: str = ""  # spdx_id
    archived: bool = False
    disabled: bool = False
    updated_at: str = ""
    secret_scanner: bool = False
    secret_push_prot: bool = False
    dependabot: bool = False
    dependabot_alerts: bool = False
    codeql: bool = False


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

            repo.name = r["name"]
            repo.orga = organization
            repo.owner = r["owner"]["login"]
            repo.url = r["html_url"]
            repo.description = r["description"]
            repo.language = r["language"]
            repo.default_branch = r["default_branch"]
            try:
                repo.license = r["license"]["spdx_id"]
            except Exception:
                repo.license = None
            repo.archived = r["archived"]
            repo.disabled = r["disabled"]
            repo.updated_at = r["updated_at"]
            try:
                repo.secret_scanner = r["security_and_analysis"]["advanced_security"][
                    "secret_scanning"
                ]["status"]
            except Exception as e:
                repo.secret_scanner = False

            try:
                repo.secret_push_prot = r["security_and_analysis"]["advanced_security"][
                    "secret_scanning_push_protection"
                ]["status"]
            except Exception as e:
                repo.secret_push_prot = False
            repo.dependabot = False
            repo.dependabot_alerts = check_dependabot_alerts_enabled(
                token, repo.orga, repo.name
            )
            repo.codeql = False

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
