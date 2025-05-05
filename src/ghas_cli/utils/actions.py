# -*- coding: utf-8 -*-
#!/usr/bin/env python3

import requests

from . import network


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
