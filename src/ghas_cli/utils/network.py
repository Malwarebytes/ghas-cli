# -*- coding: utf-8 -*-
#!/usr/bin/env python3

from typing import Any, Dict
from datetime import datetime
import time
import requests

# If the rate-limit is reached, sleep X seconds
SLEEP_1_MINUTE = 60

# Sleep x seconds between two requests
SLEEP_BETWEEN_REQUESTS = 2

# Number of times to try a network request before failing
RETRIES = 5


def get_github_headers(token: str) -> Dict:
    return {
        "accept": "application/vnd.github+json",
        "authorization": f"Bearer {token}",
        "User-Agent": "malwarebytes/bulk_enable_ghas",
        "X-GitHub-Api-Version": "2022-11-28",  # https://docs.github.com/en/rest/overview/api-versions#supported-api-versions
    }


def check_rate_limit(response: Any) -> bool:

    if "0" == response.headers["x-ratelimit-remaining"]:
        reset_time = datetime.fromtimestamp(int(response.headers["x-ratelimit-reset"]))
        print(
            f"Rate limit reached: {response.headers['x-ratelimit-remaining']}/{response.headers['x-ratelimit-limit']} - {reset_time}"
        )

        time.sleep(int(response.headers["x-ratelimit-remaining"]))
        return True

    if response.status_code == 403:
        print("Secondary rate limit reached. Need to wait...")
        return True

    time.sleep(SLEEP_BETWEEN_REQUESTS)
    return False

def check_unauthorized(response: Any):
    if response.status_code == 401:
        print(response.json()["message"])
        return False
    return True

def check_response(response: any):
    check_rate_limit(response)
    check_unauthorized(response)

def get(*args, **kwargs):
    response = requests.get(*args, **kwargs)
    check_response(response)
    return response

def post(*args, **kwargs):
    response = requests.post(*args, **kwargs)
    check_response(response)
    return response

def put(*args, **kwargs):
    response = requests.put(*args, **kwargs)
    check_response(response)
    return response

def patch(*args, **kwargs):
    response = requests.patch(*args, **kwargs)
    check_response(response)
    return response
