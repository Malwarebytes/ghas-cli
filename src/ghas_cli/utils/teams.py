# -*- coding: utf-8 -*-
#!/usr/bin/env python3

from typing import List
import requests
from . import network, repositories


def get_repositories(team_slug: str, organization: str, token: str) -> List:
    """Get repositories for a specific team"""

    headers = {
        "accept": "application/vnd.github+json",
        "authorization": f"Bearer {token}",
        "User-Agent": "jboursier-mwb/fetch_org_ghas_metrics",
    }

    repos_list = []
    page = 1

    while True:

        params = {"per_page": 100, "page": page}
        repos = requests.get(
            url=f"https://api.github.com/orgs/{organization}/teams/{team_slug}/repos",
            params=params,
            headers=headers,
        )
        if network.check_rate_limit(repos):
            break

        if repos.status_code != 200:
            break

        if [] == repos.json():
            break

        for r in repos.json():

            repo = repositories.Repository()

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
                repo.ghas = r["security_and_analysis"]["advanced_security"]["status"]
            except Exception as e:
                repo.ghas = False

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
            repo.dependabot_alerts = repositories.check_dependabot_alerts_enabled(
                token, repo.orga, repo.name
            )
            repo.codeql = False

            repos_list.append(repo)
        page += 1

    return repos_list


def list(organization: str, token: str) -> str:
    """Get Teams for a specific organization"""

    headers = {
        "accept": "application/vnd.github+json",
        "authorization": f"Bearer {token}",
        "User-Agent": "jboursier-mwb/fetch_org_ghas_metrics",
    }

    teams_list = []
    page = 1

    while True:

        params = {"per_page": 100, "page": page}

        teams = requests.get(
            url=f"https://api.github.com/orgs/{organization}/teams",
            params=params,
            headers=headers,
        )
        if network.check_rate_limit(teams):
            break
        if teams.status_code != 200:
            break
        if [] == teams.json():
            break

        teams = teams.json()
        for team in teams:
            teams_list.append(team["slug"])

        page += 1

    return teams_list
