# -*- coding: utf-8 -*-
#!/usr/bin/env python3

from typing import Dict, List
import requests

from . import network


def list_alerts_repo(repository: str, organization: str, token: str) -> Dict:
    """Get Dependabot alerts for one repository"""

    headers = network.get_github_headers(token)

    alerts_repo = []
    page = 1
    while True:
        params = {"state": "open", "per_page": 100, "page": page}
        alerts = requests.get(
            url=f"https://api.github.com/repos/{organization}/{repository}/dependabot/alerts",
            params=params,
            headers=headers,
        )
        if network.check_rate_limit(alerts):
            break
        if alerts.status_code != 200:
            break
        if not alerts.json():
            break
        for a in alerts.json():
            if not a:
                continue
            alerts_repo.append(alerts.json())
        page += 1

    return alerts_repo
