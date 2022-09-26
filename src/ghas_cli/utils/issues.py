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
    headers = {
        "accept": "application/vnd.github+json",
        "authorization": f"Bearer {token}",
        "User-Agent": "jboursier-mwb/fetch_org_ghas_metrics",
    }
    data = {
        "title": title,
        "body": content,
        "assignee": None,
        "milestone": None,
        "labels": ["info", "security"],
    }

    issue = requests.post(
        url=f"https://api.github.com/repos/{organization}/{repository}/issues",
        json=data,
        headers=headers,
    )
    if network.check_rate_limit(issue):
        return False
    if issue.status_code != 201:
        return False
    return issue.json()["html_url"]
