# -*- coding: utf-8 -*-
#!/usr/bin/env python3

import logging
import time
from typing import Any, Dict, List

from . import network


def get_code_security_configuration_details(org: str, configuration_id: str, token: str) -> dict:
    """
    Get details of a specific code security configuration.
    
    Args:
        org: The organization name
        configuration_id: The ID of the code security configuration
        token: GitHub API token
        
    Returns:
        Dictionary containing configuration details or None if not found
    """
    headers = network.get_github_headers(token)
    
    i = 0
    while i < network.RETRIES:
        response = network.get(
            url=f"https://api.github.com/orgs/{org}/code-security/configurations/{configuration_id}",
            headers=headers,
        )
        
        if response.status_code == 200:
            return response.json()
            
        if network.check_rate_limit(response):
            time.sleep(network.SLEEP_1_MINUTE)
            
        i += 1
    
    if response.status_code == 404:
        logging.error(f"Configuration '{configuration_id}' not found in organization '{org}'")
    else:
        logging.error(f"Failed to get configuration details for '{configuration_id}': {response.status_code}")
        if response.content:
            logging.error(f"Response content: {response.text}")
    
    return None


def attach_code_security_configuration_by_repository_names(
    org: str,
    configuration_id: str,
    scope: str,
    repository_names: List[str],
    token: str
) -> bool:
    """
    Attach a code security configuration to repositories by their names.
    
    Args:
        org: The organization name
        configuration_id: The ID of the code security configuration
        scope: The scope of the attachment ("selected" or "all")
        repository_names: List of repository names to attach to (required if scope is "selected")
        token: GitHub API token
        
    Returns:
        True if successful, False otherwise
    """
    from . import repositories
    
    if scope == "selected" and not repository_names:
        logging.error("Repository names are required when scope is 'selected'")
        return False
    
    selected_repository_ids = []
    failed_repositories = []
    
    for repo_name in repository_names:
        repo_name = repo_name.strip()
        if not repo_name:
            continue
            
        repo_details = repositories.get_repository_details(org, token, repo_name)
        if repo_details and 'id' in repo_details:
            selected_repository_ids.append(repo_details['id'])
            logging.info(f"Found repository '{repo_name}' with ID: {repo_details['id']}")
        else:
            failed_repositories.append(repo_name)
            logging.error(f"Failed to get details for repository '{repo_name}'")
    
    if failed_repositories:
        logging.error(f"Failed to get details for repositories: {', '.join(failed_repositories)}")
        if not selected_repository_ids:
            return False
    
    return attach_code_security_configuration(
        org=org,
        configuration_id=configuration_id,
        scope=scope,
        selected_repository_ids=selected_repository_ids,
        token=token
    )


def attach_code_security_configuration(
    org: str, 
    configuration_id: str, 
    scope: str, 
    selected_repository_ids: List[int], 
    token: str
) -> bool:
    """
    Attach a code security configuration to repositories in an organization.
    
    Args:
        org: The organization name
        configuration_id: The ID of the code security configuration
        scope: The scope of the attachment ("selected" or "all")
        selected_repository_ids: List of repository IDs to attach to (required if scope is "selected")
        token: GitHub API token
        
    Returns:
        True if successful, False otherwise
    """
    headers = network.get_github_headers(token)
    
    payload = {
        "scope": scope
    }
    
    if scope == "selected" and selected_repository_ids:
        payload["selected_repository_ids"] = selected_repository_ids
    
    i = 0
    while i < network.RETRIES:
        response = network.post(
            url=f"https://api.github.com/orgs/{org}/code-security/configurations/{configuration_id}/attach",
            headers=headers,
            json=payload,
        )
        
        if response.status_code in [200, 201, 202, 204]:
            logging.info(f"Received response {response.status_code} for configuration {configuration_id} from GitHub API")
            return True
            
        if network.check_rate_limit(response):
            time.sleep(network.SLEEP_1_MINUTE)
            
        i += 1
    
    if response.status_code not in [200, 201, 202, 204]:
        logging.error(f"Failed to attach configuration {configuration_id} to organization {org}: {response.status_code}")
        if response.content:
            logging.error(f"Response: {response.text}")
        return False
    
    return False


def get_code_security_configurations(org: str, token: str) -> List[Dict]:
    """
    Get the list of code security configurations enabled in an organization.
    
    Args:
        org: The organization name
        token: GitHub API token
        
    Returns:
        List of code security configuration objects or empty list if failed
    """
    headers = network.get_github_headers(token)
    
    i = 0
    while i < network.RETRIES:
        response = network.get(
            url=f"https://api.github.com/orgs/{org}/code-security/configurations",
            headers=headers,
        )
        
        if response.status_code == 200:
            return response.json()
            
        if network.check_rate_limit(response):
            time.sleep(network.SLEEP_1_MINUTE)
            
        i += 1
    
    if response.status_code != 200:
        logging.error(f"Failed to get organization code security configurations: {response.status_code}")
        return []
    
    return []
