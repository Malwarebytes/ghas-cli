# -*- coding: utf-8 -*-
#!/usr/bin/env python3

import logging
import time
from typing import Any, Dict, List

from . import network


def get_code_security_configurations(enterprise: str, token: str) -> List[Dict]:
    """
    Get the list of code security configurations enabled in an enterprise.
    
    Args:
        enterprise: The enterprise slug
        token: GitHub API token
        
    Returns:
        List of code security configuration objects or empty list if failed
    """
    headers = network.get_github_headers(token)
    
    i = 0
    while i < network.RETRIES:
        response = network.get(
            url=f"https://api.github.com/enterprises/{enterprise}/code-security/configurations",
            headers=headers,
        )
        
        if response.status_code == 200:
            return response.json()
            
        if network.check_rate_limit(response):
            time.sleep(network.SLEEP_1_MINUTE)
            
        i += 1
    
    if response.status_code != 200:
        logging.error(f"Failed to get code security configurations: {response.status_code}")
        return []
    
    return []
