# -*- coding: utf-8 -*-
#!/usr/bin/env python3

import logging
import time
from datetime import datetime
from typing import Any, Dict

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
        "User-Agent": "malwarebytes/ghas-cli",
        "X-GitHub-Api-Version": "2022-11-28",  # https://docs.github.com/en/rest/overview/api-versions#supported-api-versions
    }


def check_rate_limit(response: Any) -> bool:
    # Check if rate limit headers exist before accessing them
    if "x-ratelimit-remaining" in response.headers and "0" == response.headers["x-ratelimit-remaining"]:
        reset_time = datetime.fromtimestamp(int(response.headers.get("x-ratelimit-reset", 0)))
        logging.warn(
            f"Rate limit reached: {response.headers.get('x-ratelimit-remaining', 'unknown')}/{response.headers.get('x-ratelimit-limit', 'unknown')} - {reset_time}"
        )

        time_to_wait = int(reset_time.timestamp()) - (time.time())
        
        logging.info(f"Waiting {time_to_wait} seconds before retrying.")
        time.sleep(time_to_wait)

        return True

    if response.status_code == 403:
        # This can be secondary rate limit or SSO error
        try:
            error_message = response.json().get("message", "Unknown error")
            logging.warn(error_message)
        except (ValueError, KeyError):
            logging.warn("403 error occurred")
        return True

    time.sleep(SLEEP_BETWEEN_REQUESTS)
    return False


def check_unauthorized(response: Any):
    if response.status_code == 401:
        logging.error(response.json()["message"])
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
