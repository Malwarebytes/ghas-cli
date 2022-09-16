# -*- coding: utf-8 -*-
#!/usr/bin/env python3

from typing import List, Any
import requests
import json


def check_rate_limit(response: Any) -> bool:
    if "0" == response.headers["x-ratelimit-remaining"]:
        reset_time = datetime.fromtimestamp(int(response.headers["x-ratelimit-reset"]))
        print(
            f"Rate limit reached: {response.headers['x-ratelimit-remaining']}/{response.headers['x-ratelimit-limit']} - {reset_time}"
        )
        return True
    else:
        return False
