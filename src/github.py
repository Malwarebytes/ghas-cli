# -*- coding: utf-8 -*-
#!/usr/bin/env python3

__author__ = "jboursier"
__copyright__ = "Copyright 2022, Malwarebytes"
__version__ = "0.0.1"
__maintainer__ = "jboursier"
__email__ = "jboursier@malwarebytes.com"
__status__ = "Development"

try:
    import click
    import requests
    import json
    import time
    import typing
    from typing import List, Dict, Any
    from datetime import datetime
except ImportError:
    import sys

    print("Missing dependencies. Please reach @jboursier if needed.")
    sys.exit(255)

from click.exceptions import ClickException
from requests.exceptions import Timeout

ORG_NAME = ""
GH_TOKEN = ""


def check_rate_limit(response: Any) -> bool:
    if "0" == response.headers["x-ratelimit-remaining"]:
        reset_time = datetime.fromtimestamp(int(response.headers["x-ratelimit-reset"]))
        print(
            f"Rate limit reached: {response.headers['x-ratelimit-remaining']}/{response.headers['x-ratelimit-limit']} - {reset_time}"
        )
        return True
    else:
        return False


def get_org_repositories(org_name: str, exclude_archived: bool, session: Any) -> List:

    repositories = []
    page = 1
    while True:
        params = {
            "type": "all",
            "sort": "full_name",
            "per_page": 100,
            "page": page,
        }
        repos = session.get(
            url=f"https://api.github.com/orgs/{org_name}/repos",
            params=params,
        )
        if check_rate_limit(repos):
            break

        if repos.status_code != 200:
            break
        for r in repos.json():
            print(
                f"{page} - {r['name']} - {repos.headers['x-ratelimit-remaining']} / {repos.headers['x-ratelimit-limit']} - {repos.headers['x-ratelimit-reset']}"
            )
            repositories.append(r["name"])

        if [] == repos.json():
            break
        page += 1

    return repositories


def get_codeql_alerts_repo(repo_name: str, org_name: str, session: Any) -> List:

    #   https://api.github.com/repos/OWNER/REPO/code-scanning/alerts

    alerts_repo = []
    page = 1
    while True:
        params = {"state": "open", "per_page": 100, "page": page}
        alerts = session.get(
            url=f"https://api.github.com/repos/{org_name}/{repo_name}/code-scanning/alerts",
            params=params,
        )
        print(
            f"https://api.github.com/repos/{org_name}/{repo_name}/code-scanning/alerts"
        )

        if check_rate_limit(alerts):
            break

        if alerts.status_code != 200:
            break

        for a in alerts.json():
            print(
                f"{page} - {a} - {alerts.headers['x-ratelimit-remaining']} / {alerts.headers['x-ratelimit-limit']} - {alerts.headers['x-ratelimit-reset']}"
            )
            alerts_repo.append(a)

        if [] == alerts.json():
            break

        page += 1

    return alerts_repo


def output_to_csv(alerts_per_repos: Dict, location: str) -> bool:
    try:
        with open(location, "w") as log_file:
            log_file.write(json.dumps(alerts_per_repos))
    except Exception as e:
        print(str(e))
        print(f"Failure to write the output to {location}")
        return False
    return True


def main():

    s = requests.Session()
    s.headers.update(
        {
            "accept": "application/vnd.github+json",
            "authorization": f"Bearer {GH_TOKEN}",
            "User-Agent": "jboursier-mwb/fetch_org_ghas_metrics",
        }
    )

    exclude_archived = False

    org_repos = get_org_repositories(ORG_NAME, exclude_archived, s)

    print(org_repos)

    alerts_per_repo = {}
    output = "./codescanning_alerts.json"

    for repo in org_repos:
        alerts_per_repo[repo] = get_codeql_alerts_repo(repo, ORG_NAME, s)

    print(alerts_per_repo)

    output_to_csv(alerts_per_repo, location=output)


if __name__ == "__main__":
    main()
