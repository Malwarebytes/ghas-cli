# -*- coding: utf-8 -*-
#!/usr/bin/env python3

from typing import List
import requests
from . import network, repositories


def get_repositories(team_slug: str, organization: str, token: str) -> List:
    """Get repositories for a specific team"""

    headers = network.get_github_headers(token)

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
            repo.load_json(r, token=token)
            repos_list.append(repo)

        page += 1

    return repos_list


def list(organization: str, token: str) -> str:
    """Get Teams for a specific organization"""

    headers = network.get_github_headers(token)

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
