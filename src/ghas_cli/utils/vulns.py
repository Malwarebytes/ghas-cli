# -*- coding: utf-8 -*-
#!/usr/bin/env python3

from typing import Dict, List
import requests

from . import network


def get_codeql_alerts_repo(
    repos: List, organization: str, status: str, token: str
) -> Dict:
    """Get CodeQL alerts for one or several repositories"""

    headers = network.get_github_headers(token)

    repositories_alerts = {}

    for repo in repos:
        alerts_repo = []
        page = 1

        while True:
            params = {"state": status, "per_page": 100, "page": page}
            alerts = requests.get(
                url=f"https://api.github.com/repos/{organization}/{repo.name}/code-scanning/alerts",
                params=params,
                headers=headers,
            )
            if network.check_rate_limit(alerts):
                break

            if alerts.status_code != 200:
                break

            for a in alerts.json():
                if not a:
                    continue

                alert_summary = {}
                alert_summary["number"] = a["number"]
                alert_summary["created_at"] = a["created_at"]
                alert_summary["state"] = a["state"]
                alert_summary["severity"] = a["rule"]["severity"]
                alert_summary["description"] = a["rule"]["description"]
                alerts_repo.append(alert_summary)

            if not alerts.json():
                break

            page += 1

        repositories_alerts[repo.name] = alerts_repo

    return repositories_alerts


def get_codeql_alerts_org( organization: str, status: str, token: str) -> Dict:
    """Get CodeQL alerts for an entire org"""

    headers = network.get_github_headers(token)

    codeql_alerts = []

    page = 1

    while True:
        params = {"state": status, "per_page": 100, "page": page}
        alerts = requests.get(
            url=f"https://api.github.com/orgs/{organization}/code-scanning/alerts",
            params=params,
            headers=headers,
        )
        if network.check_rate_limit(alerts):
            print("network_ratelimit")
            break

        if alerts.status_code != 200:
            print(f"{alerts.status_code}")
            break
        for a in alerts.json():
            if not a:
                print(f"not a")
                continue

            alert_summary = f"{a['number']}, {a['created_at']},  {a['state']}, {a['rule']['severity']}, {a['rule']['description']}, {a['repository']['name']}, {a['repository']['owner']['login']}"
            codeql_alerts.append(alert_summary)

        if not alerts.json():
            break

        page += 1

    return codeql_alerts