# -*- coding: utf-8 -*-
#!/usr/bin/env python3

from typing import Any, Dict
from datetime import datetime
import time


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
    }


def check_rate_limit(response: Any) -> bool:

    if "0" == response.headers["x-ratelimit-remaining"]:
        reset_time = datetime.fromtimestamp(int(response.headers["x-ratelimit-reset"]))
        print(
            f"Rate limit reached: {response.headers['x-ratelimit-remaining']}/{response.headers['x-ratelimit-limit']} - {reset_time}"
        )
        time.sleep(reset_time)
        return True

    if response.status_code == 403:
        print("Secondary rate limit reached. Need to wait...")
        return True

    time.sleep(SLEEP_BETWEEN_REQUESTS)
    return False
