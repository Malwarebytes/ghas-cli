# -*- coding: utf-8 -*-
#!/usr/bin/env python3

from typing import Dict, List

import requests

from . import network

def get_codeql_analyses_repo(
    repository_name: str, organization: str, token: str
) -> Dict:
    """Get CodeQL analyses for a single repository, grouped by commit SHA"""

    headers = network.get_github_headers(token)

    analyses_repo = {}
    page = 1
    

    while True:
        params = {"per_page": 100, "page": page}
        analyses = requests.get(
            url=f"https://api.github.com/repos/{organization}/{repository_name}/code-scanning/analyses",
            params=params,
            headers=headers,
        )
        if network.check_rate_limit(analyses):
            break

        if analyses.status_code != 200:
            break

        analyses_data = analyses.json()
        if not analyses_data:
            break

        for analysis in analyses_data:
            if not analysis:
                continue

            commit_sha = analysis.get("commit_sha")
            if not commit_sha:
                continue

            # Initialize list for this commit if it doesn't exist
            if commit_sha not in analyses_repo:
                analyses_repo[commit_sha] = []

            analysis_summary = {
                "id": analysis.get("id"),
                "ref": analysis.get("ref"),
                "commit_sha": commit_sha,
                "analysis_key": analysis.get("analysis_key"),
                "environment": analysis.get("environment"),
                "error": analysis.get("error"),
                "category": analysis.get("category"),
                "created_at": analysis.get("created_at"),
                "results_count": analysis.get("results_count"),
                "rules_count": analysis.get("rules_count"),
                "sarif_id": analysis.get("sarif_id"),
                "tool": analysis.get("tool", {}).get("name"),
                "deletable": analysis.get("deletable"),
                "warning": analysis.get("warning")
            }

            analyses_repo[commit_sha].append(analysis_summary)

        page += 1

    return analyses_repo


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
            params = {"state": "open", "per_page": 100, "page": page}
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
                alerts_repo.append(alert_summary)

            if not alerts.json():
                break

            page += 1

        repositories_alerts[repo.name] = alerts_repo

    return repositories_alerts
