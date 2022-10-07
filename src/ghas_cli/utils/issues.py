# -*- coding: utf-8 -*-
#!/usr/bin/env python3

from typing import List
import requests
from . import network


def create(
    title: str,
    content: str,
    repository: str,
    organization: str,
    token: str,
) -> None:
    """Create an issue on a repository"""
    headers = network.get_github_headers(token)

    data = {
        "title": title,
        "body": content,
        "assignee": None,
        "milestone": None,
        "labels": ["info", "security"],
    }

    # Retry if rate-limited
    i = 0
    while i < 5:
        issue = requests.post(
            url=f"https://api.github.com/repos/{organization}/{repository}/issues",
            json=data,
            headers=headers,
        )
        if issue.status_code == 201:
            return issue.json()["html_url"]

        if network.check_rate_limit(issue):
            time.sleep(60)
        i += 1

    if issue.status_code != 201:
        return False
    else:
        return issue.json()["html_url"]
