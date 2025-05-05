# -*- coding: utf-8 -*-
#!/usr/bin/env python3

from typing import List

import requests

from . import network


# https://docs.github.com/en/rest/orgs/custom-roles#create-a-custom-role
def create_role(
    name: str, description: str, base_role: str, permissions: List, org: str, token: str
) -> bool:
    """Create a custom role"""

    headers = network.get_github_headers(token)

    payload = {
        "name": name,
        "description": description,
        "base_role": base_role,
        "permissions": permissions,
    }

    role_resp = requests.post(
        url=f"https://api.github.com/orgs/{organization}/custom_roles",
        headers=headers,
        json=payload,
    )

    if role_resp.status_code != 201:
        return False
    else:
        return True


def assign_role(team: str, role: str, repository: str, organization: str, token: str):
    """Assign a custom role to a team"""
    headers = network.get_github_headers(token)

    payload = {
        "permission": role,
    }

    role_resp = requests.put(
        url=f"https://api.github.com/orgs/{organization}/teams/{team}/repos/{organization}/{repository}",
        headers=headers,
        json=payload,
    )

    if role_resp.status_code != 204:
        return False
    else:
        return True
