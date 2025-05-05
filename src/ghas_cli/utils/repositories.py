# -*- coding: utf-8 -*-
#!/usr/bin/env python3

import base64
import datetime
import logging
import secrets
import time
from typing import Any, List

from . import network


class Repository:
    def __init__(
        self,
        name="",
        orga="Malwarebytes",
        owner="",
        url="",
        description="",
        main_language="",
        languages=[],
        default_branch="main",
        license="",
        archived=False,
        disabled=False,
        updated_at="",
        ghas=False,
        secret_scanner=False,
        secret_push_prot=False,
        dependabot=False,
        dependabot_alerts=False,
        codeql=False,
    ):
        self.name: str = name
        self.orga: str = orga
        self.owner: str = owner
        self.url: str = url
        self.description: str = description
        self.main_language: str = main_language
        self.languages: List = languages
        self.default_branch: str = default_branch
        self.license: str = license  # spdx_id
        self.archived: bool = archived
        self.disabled: bool = disabled
        self.updated_at: str = updated_at
        self.ghas: bool = (ghas,)
        self.secret_scanner: bool = secret_scanner
        self.secret_push_prot: bool = secret_push_prot
        self.dependabot: bool = dependabot
        self.dependabot_alerts: bool = dependabot_alerts
        self.codeql: bool = codeql

    def load_json(self, obj, token=None):
        """Load and parse a repository from an API json object"""

        self.name = obj["name"]
        if obj["owner"]["type"] == "Organization":
            self.orga = obj["owner"]["login"]
        else:
            self.orga = ""
        self.owner = obj["owner"]["login"]
        self.url = obj["html_url"]
        self.description = obj["description"]
        self.main_language = obj["language"]
        self.languages = get_languages(self.orga, token, self.name)
        self.default_branch = obj["default_branch"]
        try:
            self.license = obj["license"]["spdx_id"]
        except Exception:
            self.license = None
        self.archived = obj["archived"]
        self.disabled = obj["disabled"]
        self.updated_at = obj["updated_at"]
        try:
            self.ghas = obj["security_and_analysis"]["advanced_security"]["status"]
        except Exception:
            self.ghas = False
        try:
            self.secret_scanner = obj["security_and_analysis"]["advanced_security"][
                "secret_scanning"
            ]["status"]
        except Exception:
            self.secret_scanner = False
        try:
            self.secret_push_prot = obj["security_and_analysis"]["advanced_security"][
                "secret_scanning_push_protection"
            ]["status"]
        except Exception:
            self.secret_push_prot = False
        self.dependabot = False
        if token:
            self.dependabot_alerts = check_dependabot_alerts_enabled(
                token, self.orga, self.name
            )
        else:
            self.dependabot_alerts = False
        self.codeql = False

    def __str__(self):
        return f"""[{self.name}]
        * Organization: {self.orga}
        * Owner: {self.owner}
        * Url: {self.url}
        * Description: {self.description}
        * Main language: {self.main_language}
        * All languages: {self.languages}
        * Default branch: {self.default_branch}
        * License: {self.license}
        * Archived: {self.archived}
        * Disabled: {self.disabled}
        * Last updated at: {self.updated_at}
        * GHAS: {self.ghas}
        * Secret Scanner: {self.secret_scanner}
        * Secret Scanner Push Protection: {self.secret_push_prot}
        * Dependabot: {self.dependabot}
        * Dependabot alerts: {self.dependabot_alerts}
        * CodeQL: {self.codeql}
        """

    def to_json(self):
        return {
            "name": self.name,
            "orga": self.orga,
            "owner": self.owner,
            "url": self.url,
            "description": self.description,
            "main_language": self.main_language,
            "languages": self.languages,
            "default_branch": self.default_branch,
            "license": self.license,
            "archived": self.archived,
            "disabled": self.disabled,
            "updated_at": self.updated_at,
            "ghas": self.ghas,
            "secret_scanner": self.secret_scanner,
            "secret_push_prot": self.secret_push_prot,
            "dependabot": self.dependabot,
            "dependabot_alerts": self.dependabot_alerts,
            "codeql": self.codeql,
        }

    def to_ghas(self):
        return {"repo": f"{self.orga}/{self.name}"}


def get_org_repositories(
    status: str,
    organization: str,
    token: str,
    language: str = "",
    default_branch: str = "",
    license: str = "",
    archived: bool = False,
    disabled: bool = False,
) -> List:
    page = 1

    headers = network.get_github_headers(token)
    repos_list = []
    while True:
        params = {
            "type": f"{status}",
            "sort": "full_name",
            "per_page": 100,
            "page": page,
        }
        repos = network.get(
            url=f"https://api.github.com/orgs/{organization}/repos",
            params=params,
            headers=headers,
        )

        if repos.status_code != 200:
            break

        if [] == repos.json():
            break

        for r in repos.json():
            repo = Repository()
            repo.load_json(r, token=token)
            # repo.load_json(r, token=None)

            if language != "" and repo.main_language != language:
                logging.info(
                    f"{repo.name} ignored because of language: {language} vs. {repo.main_language}"
                )
                continue
            if default_branch != "" and repo.default_branch != default_branch:
                logging.info(
                    f"{repo.name} ignored because of default branch: {default_branch} vs. {repo.default_branch}"
                )
                continue
            if license != "" and repo.license != license:
                logging.info(
                    f"{repo.name} ignored because of license: {license} vs. {repo.license}"
                )
                continue
            if repo.archived != archived:
                logging.info(
                    f"{repo.name} ignored because of archived: {archived} vs. {repo.archived}"
                )
                continue
            if repo.disabled != disabled:
                logging.info(
                    f"{repo.name} ignored because of license: {archived} vs. {repo.archived}"
                )
                continue

            repos_list.append(repo)

        page += 1

    return repos_list


def get_default_branch_last_updated(
    token: str, organization: str, repository_name: str, default_branch: str
) -> Any:
    """
    Return the latest commit date on the default branch
    """
    headers = network.get_github_headers(token)

    branch_res = network.get(
        url=f"https://api.github.com/repos/{organization}/{repository_name}/branches/{default_branch}",
        headers=headers,
    )

    if branch_res.status_code != 200:
        return False

    branch_res = branch_res.json()

    return datetime.datetime.strptime(
        branch_res["commit"]["commit"]["author"]["date"].split("T")[0], "%Y-%m-%d"
    )


def get_topics(token: str, organization: str, repository_name: str) -> List:
    """
    Return the repository topics
    """
    headers = network.get_github_headers(token)

    topic_res = network.get(
        url=f"https://api.github.com/repos/{organization}/{repository_name}/topics",
        headers=headers,
    )

    if topic_res.status_code != 200:
        return False

    topics_res = topic_res.json()

    return topics_res["names"]


def archive(
    organization: str, token: str, repository: str, archive: bool = True
) -> bool:
    headers = network.get_github_headers(token)

    payload = {"archived": archive}

    status = network.patch(
        url=f"https://api.github.com/repos/{organization}/{repository}",
        headers=headers,
        json=payload,
    )

    if status.status_code != 200:
        return False
    else:
        return True


def check_dependabot_alerts_enabled(
    token: str, organization: str, repository_name: str
) -> bool:
    headers = network.get_github_headers(token)

    status = network.get(
        url=f"https://api.github.com/orgs/{organization}/repos/vulnerability-alerts",
        headers=headers,
    )

    if status.status_code != 204:
        return False
    else:
        return True


def enable_secret_scanner(organization: str, token: str, repository: str) -> bool:
    headers = network.get_github_headers(token)

    payload = {
        "security_and_analysis": {
            "advanced_security": {
                "status": "enabled",
            },
            "secret_scanning": {"status": "enabled"},
        }
    }

    status = network.patch(
        url=f"https://api.github.com/repos/{organization}/{repository}",
        headers=headers,
        json=payload,
    )

    if status.status_code != 200:
        return False
    else:
        return True


def enable_secret_scanner_push_protection(
    organization: str, token: str, repository: str
) -> bool:
    headers = network.get_github_headers(token)

    payload = {
        "security_and_analysis": {
            "advanced_security": {
                "status": "enabled",
            },
            "secret_scanning": {"status": "enabled"},
            "secret_scanning_push_protection": {"status": "enabled"},
        }
    }

    status = network.patch(
        url=f"https://api.github.com/repos/{organization}/{repository}",
        headers=headers,
        json=payload,
    )

    if status.status_code != 200:
        return False
    else:
        return True


def enable_dependabot(organization: str, token: str, repository: str) -> bool:
    headers = network.get_github_headers(token)

    status_alerts = network.put(
        url=f"https://api.github.com/repos/{organization}/{repository}/vulnerability-alerts",
        headers=headers,
    )

    status_fixes = network.put(
        url=f"https://api.github.com/repos/{organization}/{repository}/automated-security-fixes",
        headers=headers,
    )

    if status_alerts.status_code != 204 and status_fixes != 204:
        return False
    else:
        return True


def get_default_branch(organization: str, token: str, repository: str) -> str:
    """Get the default branch slug for a repository"""
    headers = network.get_github_headers(token)

    repo = network.get(
        url=f"https://api.github.com/repos/{organization}/{repository}",
        headers=headers,
    )
    if repo.status_code != 200:
        return False

    repo = repo.json()
    try:
        return repo["default_branch"]
    except Exception:
        return False


def get_languages(
    organization: str,
    token: str,
    repository: str,
    only_codeql: bool = False,
) -> List:
    """Get the main language for a repository"""

    codeql_languages = ["cpp", "csharp", "go", "java", "javascript", "python", "ruby", "swift"]
    codeql_aliased_languages = {
        "typescript": "javascript",
        "kotlin": "java",
        "c#": "csharp",
        "c++": "cpp",
    }

    headers = network.get_github_headers(token)
    languages_resp = network.get(
        url=f"https://api.github.com/repos/{organization}/{repository}/languages",
        headers=headers,
    )

    if languages_resp.status_code != 200:
        logging.warn(
            f"Received status code {languages_resp.status_code} while retrieving repository languages."
        )
        return ["default"]

    languages = ["actions"] #https://github.blog/changelog/2024-12-17-find-and-fix-actions-workflows-vulnerabilities-with-codeql-public-preview/
    for language in [l.lower() for l in languages_resp.json()]:
        if only_codeql:
            if language in codeql_languages:
                languages.append(language)
            elif language in codeql_aliased_languages:
                languages.append(codeql_aliased_languages[language])
        else:
            languages.append(language)

    return languages


def load_codeql_base64_template(languages: List, branches: List = ["main"]) -> str:
    minute = secrets.randbelow(60)
    hour = secrets.randbelow(24)
    day = secrets.randbelow(7)
    with open("./templates/codeql-analysis-default.yml", "r") as f:
        data = "".join(f.readlines())
        data = data.replace(
            """branches: [ ]""",
            f"""branches: [{', '.join(f"'{branch}'" for branch in branches)   }]""",
        )
        data = data.replace("""language: [ ]""", f"""language: {languages}""")
        data = data.replace(
            """cron: '36 4 * * 3'""", f"""cron: '{minute} {hour} * * {day}'"""
        )
        return base64.b64encode(data.encode("utf-8")).decode("utf-8")


def load_codeql_config_base64_template() -> str:
    with open("./templates/codeql-config-default.yml", "r") as f:
        template = f.read()
        return base64.b64encode(template.encode(encoding="utf-8")).decode("utf-8")


def create_branch(
    headers, organization: str, repository: str, default_branch: str, target_branch: str
):
    branch_resp = network.get(
        url=f"https://api.github.com/repos/{organization}/{repository}/git/refs/heads",
        headers=headers,
    )

    if branch_resp.status_code != 200:
        return False

    refs = branch_resp.json()
    sha1 = ""
    for ref in refs:
        if ref["ref"] == f"refs/heads/{default_branch}":
            sha1 = ref["object"]["sha"]

    if sha1 == "":
        return False

    payload = {
        "ref": f"refs/heads/{target_branch}",
        "sha": sha1,
    }

    branch_resp = network.post(
        url=f"https://api.github.com/repos/{organization}/{repository}/git/refs",
        headers=headers,
        json=payload,
    )

    if branch_resp.status_code == 422:
        logging.error("Branch already exists")
        return False

    if branch_resp.status_code == 201:
        return True

    return False


def create_codeql_pr(
    organization: str,
    token: str,
    repository: str,
    target_branch: str = "appsec-ghas-codeql_enable",
) -> bool:
    """
    1. Retrieve the repository languages. Select the `codeql-analysis.yml` file for that language.
    2. Create a branch
    3. Push a .github/workflows/codeql-analysis.yml to the repository on that branch
    3. Create an associated PR
    """
    headers = network.get_github_headers(token)

    # Get the default branch
    default_branch = get_default_branch(organization, token, repository)
    if not default_branch:
        return False

    # Create a branch
    new_branch = create_branch(
        headers, organization, repository, default_branch, target_branch
    )

    if not new_branch:
        logging.error(f"Couldn't create branch {target_branch}")
        return False

    # Create commit

    languages = get_languages(organization, token, repository, only_codeql=True)

    # Workflow config
    template = load_codeql_base64_template(languages, [default_branch])
    workflow_commit_payload = {
        "message": "Create CodeQL analysis workflow",
        "content": template,
        "branch": target_branch,
        "sha": get_file_sha(
            organization,
            repository,
            headers,
            ".github/workflows/codeql-analysis-default.yml",
        ),
    }

    if workflow_commit_payload["sha"]:
        workflow_commit_payload["message"] = "Update CodeQL analysis workflow"

    workflow_commit_resp = network.put(
        url=f"https://api.github.com/repos/{organization}/{repository}/contents/.github/workflows/codeql-analysis-default.yml",
        headers=headers,
        json=workflow_commit_payload,
    )

    if workflow_commit_resp.status_code not in [200, 201]:
        logging.error(
            f"Commit response for CodeQL workflow: {workflow_commit_resp.status_code}"
        )
        return False

    # CodeQL config file
    template = load_codeql_config_base64_template()
    config_commit_payload = {
        "message": "Create CodeQL config file",
        "content": template,
        "branch": target_branch,
        "sha": get_file_sha(
            organization,
            repository,
            headers,
            ".github/codeql/codeql-config-default.yml",
        ),
    }

    if config_commit_payload["sha"]:
        config_commit_payload["message"] = "Update CodeQL config file"

    config_commit_resp = network.put(
        url=f"https://api.github.com/repos/{organization}/{repository}/contents/.github/codeql/codeql-config-default.yml",
        headers=headers,
        json=config_commit_payload,
    )

    if config_commit_resp.status_code not in [200, 201]:
        logging.error(
            f"Commit response for CodeQL config: {config_commit_resp.status_code}"
        )
        return False

    is_config_update = (
        workflow_commit_payload["sha"] != None or config_commit_payload["sha"] != None
    )

    pr_payload = {
        "head": target_branch,
        "base": default_branch,
    }

    if is_config_update:
        logging.info(f"Updating configuration for {repository}")
        pr_payload["title"] = "Security Code Scanning - updated configuration files"
        pr_payload["body"] = (
            f"This PR updates the Security scanning (CodeQL) configuration files for your repository languages ({', '.join(languages)}).We also just opened an informative issue in this repository to give you the context and assistance you need. In most cases you will be able to merge this PR as is and start benefiting from security scanning right away, as a check in each PR, and in the [Security tab](https://github.com/{organization}/{repository}/security/code-scanning) of this repository. \nHowever, we encourage you to review the configuration files and tag @{organization}/security-appsec (or `#github-appsec-security` on Slack) if you have any questions.\n\nWe are here to help! :thumbsup:\n\n - Application Security team."
        )
    else:
        logging.info(f"Creating configuration for {repository}")
        pr_payload["title"] = "Security Code Scanning - configuration files"
        pr_payload["body"] = (
            f"This PR creates the Security scanning (CodeQL) configuration files for your repository languages ({', '.join(languages)}).\n\n We also just opened an informative issue in this repository to give you the context and assistance you need. In most cases you will be able to merge this PR as is and start benefiting from security scanning right away, as a check in each PR, and in the [Security tab](https://github.com/{organization}/{repository}/security/code-scanning) of this repository. \nHowever, we encourage you to review the configuration files and tag @{organization}/security-appsec (or `#github-appsec-security` on Slack) if you have any questions.\n\nWe are here to help! :thumbsup:\n\n - Application Security team."
        )

    # Retry if rate-limited
    i = 0
    while i < network.RETRIES:
        pr_resp = network.post(
            url=f"https://api.github.com/repos/{organization}/{repository}/pulls",
            headers=headers,
            json=pr_payload,
        )
        if pr_resp.status_code == 201:
            return True

        if network.check_rate_limit(pr_resp):
            time.sleep(network.SLEEP_1_MINUTE)

        i += 1

    if pr_resp.status_code != 201:
        print(pr_resp.json())
        return False

    return True


###### Dependency Review


def load_dependency_review_base64_template() -> str:
    with open("./templates/dependency_enforcement.yml", "r") as f:
        template = f.read()

    return str(base64.b64encode(template.encode(encoding="utf-8")), "utf-8")


def create_dependency_enforcement_pr(
    organization: str,
    token: str,
    repository: str,
    target_branch: str = "appsec-ghas-dep-enforcement-enable",
) -> bool:
    """
    2. Create a branch
    3. Push a .github/workflows/dependency_enforcement.yml to the repository on that branch
    3. Create an associated PR
    """
    headers = network.get_github_headers(token)

    # Get the default branch
    default_branch = get_default_branch(organization, token, repository)
    if not default_branch:
        return False

    # Create a branch

    new_branch = create_branch(
        headers, organization, repository, default_branch, target_branch
    )

    if not new_branch:
        return False

    # # Create commit
    template = load_dependency_review_base64_template()
    payload = {
        "message": "Enable Dependency reviewer",
        "content": template,
        "branch": target_branch,
    }

    commit_resp = network.put(
        url=f"https://api.github.com/repos/{organization}/{repository}/contents/.github/workflows/dependency_enforcement.yml",
        headers=headers,
        json=payload,
    )
    if commit_resp.status_code != 201:
        return False

    # Create PR
    payload = {
        "title": "Dependency reviewer",
        "body": f"This PR enables the Dependency Reviewer in your repository. It is enabled to prevent vulnerable dependencies from reaching your codebase. In most cases you will be able to merge this PR as is and start benefiting from its features right away, as a check in each PR. \nHowever, we encourage you to tag @{organization}/security-appsec (or `#github-appsec-security` on Slack) if you have any questions.\n\nWe are here to help! :thumbsup:\n\n - Application Security team.",
        "head": target_branch,
        "base": default_branch,
    }

    # Retry if rate-limited
    i = 0
    while i < network.RETRIES:
        pr_resp = network.post(
            url=f"https://api.github.com/repos/{organization}/{repository}/pulls",
            headers=headers,
            json=payload,
        )

        if pr_resp.status_code == 201:
            return True

        if network.check_rate_limit(pr_resp):
            time.sleep(network.SLEEP_1_MINUTE)

        i += 1

    if pr_resp.status_code != 201:
        return False

    return True


def get_file_sha(organization, repository, headers, file):
    file_resp = network.get(
        url=f"https://api.github.com/repos/{organization}/{repository}/contents/{file}",
        headers=headers,
    )
    if file_resp.status_code == 200:
        return file_resp.json()["sha"]
    return None
