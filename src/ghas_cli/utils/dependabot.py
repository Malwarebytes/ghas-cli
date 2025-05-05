# -*- coding: utf-8 -*-
#!/usr/bin/env python3

import json
import logging
from typing import List

import requests

from . import network


def list_alerts_repo(repository: str, organization: str, token: str) -> List:
    """Get Dependabot alerts for one repository"""

    headers = network.get_github_headers(token)

    alerts_repo = []
    page = 1
    while True:
        i = 0
        while i < network.RETRIES:
            params = {"state": "open", "per_page": 100, "page": page}
            alerts = requests.get(
                url=f"https://api.github.com/repos/{organization}/{repository}/dependabot/alerts",
                params=params,
                headers=headers,
            )
            if network.check_rate_limit(alerts):
                i += 1
            else:
                break

        if alerts.status_code != 200:
            break
        if not alerts.json():
            break
        for a in alerts.json():
            if not a:
                continue
            alerts_repo.append(json.dumps(a))
        page += 1

    return alerts_repo



def get_dependencies(repository: str, organization: str, token: str, format:str ="sbom"):
    """
    Get the list of dependencies for one repository.

    Available formats:
    - `sbom` - SPDX json
    - `CSV` - CSV export
    - `txt` - basic export

    https://docs.github.com/en/rest/dependency-graph/sboms?apiVersion=2022-11-28
    """
    headers = network.get_github_headers(token)

    dependencies = requests.get(
                url=f"https://api.github.com/repos/{organization}/{repository}/dependency-graph/sbom",
                headers=headers,
            )


    if dependencies.status_code != 200:
        logging.error(f"Unable to retrieve the dependencies for {repository} - {dependencies.status_code} - {dependencies.content}")
        return False

    if "sbom" == format:
        return dependencies.json()
    elif "csv" == format:
        deps = ""
        for dep in dependencies.json()["sbom"]["packages"]:
            try:
                license = dep['licenseConcluded']
            except:
                try:
                    license = dep['licenseDeclared']
                except:
                    license = "Unknown"

            deps += f"{repository}, {dep['name']},{dep['versionInfo']}, {license}\n"
        return deps
    elif "txt" == format:
        deps = ""
        for dep in dependencies.json()["sbom"]["packages"]:
            deps += dep["name"] + "\n"
        return deps
    else:
        logging.error(f"Invalid export format {format}. Must be one of `sbom`, `csv` or `txt`.")
    return False
