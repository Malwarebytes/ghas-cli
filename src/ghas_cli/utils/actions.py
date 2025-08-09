# -*- coding: utf-8 -*-
#!/usr/bin/env python3

import logging
import re
import requests
from datetime import datetime, timedelta

from . import network

GHAS_RELATED_RUNS = {
    "actor": [
        "github-advanced-security[bot]",
        "dependabot[bot]",
    ],
    "path": [
        "dynamic/github-code-scanning/codeql",
        "dynamic/dependabot/dependabot-updates",
        ".github/workflows/codeql.yml",
    ],
}
def set_permissions(
    token: str,
    organization: str,
    repository_name: str,
    enabled: bool,
    allowed_actions: str,
) -> bool:
    """Set Actions permissions for a repository"""
    headers = network.get_github_headers(token)

    payload = {"enabled": enabled, "allowed_actions": allowed_actions}

    status = requests.put(
        url=f"https://api.github.com/repos/{organization}/{repository_name}/actions/permissions",
        headers=headers,
        json=payload,
    )

    if status.status_code != 204:
        return False
    else:
        return True

def get_ghas_workflow_runs(token: str, organization: str, repository_name: str, days: int = 3) -> list:
    """Get GHAS-related workflow runs for a repository filtered by days (default: last 3 days)"""
    headers = network.get_github_headers(token)
    
    cutoff_date = datetime.now() - timedelta(days=days)
    cutoff_date_str = cutoff_date.strftime('%Y-%m-%d')

    response = requests.get(
        url=f"https://api.github.com/repos/{organization}/{repository_name}/actions/runs",
        headers=headers,
        params={
            'created': f'>={cutoff_date_str}',
            'per_page': 100
        }
    )

    runs = response.json()
    ghas_runs = []

    if response.status_code != 200:
        logging.error(f"Failed to get GHAS-related workflow runs for {organization}/{repository_name}: {response.status_code}")
        return []
    else:
        workflow_runs = runs.get('workflow_runs', [])
        for run in workflow_runs:
            is_ghas_related = False
            
            if run.get("actor", {}).get("login") in GHAS_RELATED_RUNS["actor"]:
                is_ghas_related = True
            elif run.get("head_commit", {}).get("author", {}).get("name") in GHAS_RELATED_RUNS["actor"]:
                is_ghas_related = True
            
            if is_ghas_related:
                ghas_runs.append(run)

        return ghas_runs