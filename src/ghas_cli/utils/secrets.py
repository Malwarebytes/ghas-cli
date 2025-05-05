# -*- coding: utf-8 -*-
#!/usr/bin/env python3

from typing import List

import requests

from . import network


def export_secrets(
    state: str, token: str, organization: str, secrets_filter: str
) -> List:
    """Get all secrets from the organization"""

    headers = network.get_github_headers(token)

    secret_list = []
    page = 1
    while True:
        params = {"state": state, "per_page": 100, "page": page}

        secrets = requests.get(
            url=f"https://api.github.com/orgs/{organization}/secret-scanning/alerts",
            params=params,
            headers=headers,
        )

        if network.check_rate_limit(secrets):
            break
        if secrets.status_code != 200:
            break

        if not secrets.json():
            break

        for secret in secrets.json():
            s = {}
            s["state"] = secret["state"]
            s["resolution"] = secret["resolution"]
            s["resolved_at"] = secret["resolved_at"]
            s["repository_full_name"] = secret["repository"]["full_name"]
            s["url"] = secret["url"]
            s["secret_type"] = secret["secret_type"]
            s["secret"] = secret["secret"]

            if secrets_filter == "all" or s["secret_type"] == secrets_filter:
                secret_list.append(s)

        page += 1
    return secret_list
