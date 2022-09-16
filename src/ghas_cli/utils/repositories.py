# -*- coding: utf-8 -*-
#!/usr/bin/env python3

from typing import List
import requests
from . import network


def get_org_repositories(status: str, organization: str, token: str) -> List:
    repositories = []
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
        for r in repos.json():
            repositories.append(r["name"])

        if [] == repos.json():
            break
        page += 1

    return repositories
