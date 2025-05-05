# -*- coding: utf-8 -*-
#!/usr/bin/env python3

import time
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
    while i < network.RETRIES:
        issue = requests.post(
            url=f"https://api.github.com/repos/{organization}/{repository}/issues",
            json=data,
            headers=headers,
        )
        if issue.status_code == 201:
            return issue.json()["html_url"]

        if network.check_rate_limit(issue):
            time.sleep(network.SLEEP_1_MINUTE)

        i += 1

    if issue.status_code != 201:
        return False
    else:
        return issue.json()["html_url"]


def search(
    creator: str,
    repository: str,
    organization: str,
    token: str,
) -> List:
    """List issues of a repository"""

    headers = network.get_github_headers(token)

    params = {"state": "open", "creator": creator, "per_page": 100}

    # Retry if rate-limited
    i = 0
    while i < network.RETRIES:
        issue = requests.get(
            url=f"https://api.github.com/repos/{organization}/{repository}/issues",
            params=params,
            headers=headers,
        )
        if issue.status_code == 200:
            break

        if network.check_rate_limit(issue):
            time.sleep(network.SLEEP_1_MINUTE)

        i += 1

    if issue.status_code != 200:
        return False

    issue_list = []
    for i in issue.json():
        issue_list.append(i["number"])

    return issue_list


def close_issues(
    issue_numbers: List,
    repository: str,
    organization: str,
    token: str,
) -> None:
    """Close a list of issues on a repository"""

    headers = network.get_github_headers(token)

    payload = {"state": "closed", "state_reason": "not_planned"}

    success_count = 0
    for issue_number in issue_numbers:
        # Retry if rate-limited
        i = 0
        while i < network.RETRIES:
            issue = requests.patch(
                url=f"https://api.github.com/repos/{organization}/{repository}/issues/{issue_number}",
                json=payload,
                headers=headers,
            )

            if issue.status_code == 200:
                success_count += 1
                break

            if network.check_rate_limit(issue):
                time.sleep(network.SLEEP_1_MINUTE)

            i += 1

    if issue.status_code != 200:
        return False

    return success_count
