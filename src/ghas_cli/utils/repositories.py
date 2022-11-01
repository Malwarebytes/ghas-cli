# -*- coding: utf-8 -*-
#!/usr/bin/env python3

from typing import List
import base64
import requests
from . import network
import time


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
        self.languages = get_languages(self.orga, token, self.name, False, False)
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
        except Exception as e:
            self.ghas = False
        try:
            self.secret_scanner = obj["security_and_analysis"]["advanced_security"][
                "secret_scanning"
            ]["status"]
        except Exception as e:
            self.secret_scanner = False
        try:
            self.secret_push_prot = obj["security_and_analysis"]["advanced_security"][
                "secret_scanning_push_protection"
            ]["status"]
        except Exception as e:
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
        repos = requests.get(
            url=f"https://api.github.com/orgs/{organization}/repos",
            params=params,
            headers=headers,
        )
        if network.check_rate_limit(repos):
            break

        if repos.status_code != 200:
            break

        if [] == repos.json():
            break

        for r in repos.json():

            repo = Repository()
            repo.load_json(r, token=token)
            # repo.load_json(r, token=None)

            if language != "" and repo.main_language != language:
                print(
                    f"{repo.name} ignored because of language: {language} vs. {repo.main_language}"
                )
                continue
            if default_branch != "" and repo.default_branch != default_branch:
                print(
                    f"{repo.name} ignored because of default branch: {default_branch} vs. {repo.default_branch}"
                )
                continue
            if license != "" and repo.license != license:
                print(
                    f"{repo.name} ignored because of license: {license} vs. {repo.license}"
                )
                continue
            if repo.archived != archived:
                print(
                    f"{repo.name} ignored because of archived: {archived} vs. {repo.archived}"
                )
                continue
            if repo.disabled != disabled:
                print(
                    f"{repo.name} ignored because of license: {archived} vs. {repo.archived}"
                )
                continue

            repos_list.append(repo)

        page += 1

    return repos_list


def check_dependabot_alerts_enabled(
    token: str, organization: str, repository_name: str
) -> bool:

    headers = network.get_github_headers(token)

    status = requests.get(
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

    status = requests.patch(
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

    status = requests.patch(
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

    status_alerts = requests.put(
        url=f"https://api.github.com/repos/{organization}/{repository}/vulnerability-alerts",
        headers=headers,
    )

    status_fixes = requests.put(
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

    repo = requests.get(
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
    only_interpreted: False,
    only_codeql: False,
) -> List:
    """Get the main language for a repository"""

    interpreted_languages = {"javascript", "python", "ruby"}
    aliased_interpreted_languages = {"typescript": "javascript"}

    headers = network.get_github_headers(token)
    languages = requests.get(
        url=f"https://api.github.com/repos/{organization}/{repository}/languages",
        headers=headers,
    )
    if languages.status_code != 200:
        return ["default"]

    lang = set()
    for l in languages.json():
        if only_interpreted:
            if l.lower() in interpreted_languages:
                lang.add(l.lower())
            else:
                if only_codeql:
                    try:
                        lang.add(aliased_interpreted_languages[l.lower()])
                    except Exception as e:
                        continue
        else:
            lang.add(l.lower())

    if not lang:
        return ["default"]
    else:
        return list(lang)


def load_codeql_base64_template(language: str, default_branch: str = "main") -> tuple:
    language = language.lower()
    try:
        with open(f"./templates/codeql-analysis-{language.lower()}.yml", "r") as f:
            # Ugly af but `yaml` transforms `on:` to `True:` which is obviously annoying to parse GitHub Actions files..
            template = f.readlines()
            template_new = ""
            for l in template:
                if l == '    branches: ["main"]\n':
                    template_new += f"    branches: ['{default_branch}']\n"
                else:
                    template_new += l
    except Exception as e:
        with open(f"./templates/codeql-analysis-default.yml", "r") as f:
            language = "default"
            template = f.readlines()
            template_new = ""
            for l in template:
                if l == '    branches: ["main"]\n':
                    template_new += f"    branches: ['{default_branch}']\n"
                else:
                    template_new += l
    return language, str(
        base64.b64encode(template_new.encode(encoding="utf-8")), "utf-8"
    )


def load_codeql_config_base64_template(language: str) -> tuple:
    language = language.lower()
    try:
        with open(f"./templates/codeql-config-{language.lower()}.yml", "r") as f:
            template = f.read()
    except Exception as e:
        with open(f"./templates/codeql-config-default.yml", "r") as f:
            template = f.read()
    return language, str(base64.b64encode(template.encode(encoding="utf-8")), "utf-8")


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
    branch_resp = requests.get(
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

    branch_resp = requests.post(
        url=f"https://api.github.com/repos/{organization}/{repository}/git/refs",
        headers=headers,
        json=payload,
    )

    if branch_resp.status_code != 201:
        return False

    # Create commit
    languages = get_languages(
        organization, token, repository, only_interpreted=True, only_codeql=True
    )

    for language in languages:

        # Workflow config
        lang, template = load_codeql_base64_template(language, default_branch)
        payload = {
            "message": f"Enable CodeQL analysis for {language}",
            "content": template,
            "branch": target_branch,
        }

        commit_resp = requests.put(
            url=f"https://api.github.com/repos/{organization}/{repository}/contents/.github/workflows/codeql-analysis-{lang}.yml",
            headers=headers,
            json=payload,
        )

        if commit_resp.status_code != 201:
            return False

        # CodeQL config file
        lang, template = load_codeql_config_base64_template(language)
        payload = {
            "message": f"Enable CodeQL config file for {language}",
            "content": template,
            "branch": target_branch,
        }

        commit_resp = requests.put(
            url=f"https://api.github.com/repos/{organization}/{repository}/contents/.github/codeql/codeql-config-{lang}.yml",
            headers=headers,
            json=payload,
        )
        if commit_resp.status_code != 201:
            return False

    # Create PR
    payload = {
        "title": "Security Code Scanning - configuration files",
        "body": f"This PR creates the Security scanning (CodeQL) configuration files for your repository languages ({languages}).\n\n We also just opened an informative issue in this repository to give you the context and assistance you need. In most cases you will be able to merge this PR as is and start benefiting from security scanning right away, as a check in each PR, and in the [Security tab](https://github.com/{organization}/{repository}/security/code-scanning) of this repository. \nHowever, we encourage you to review the configuration files and tag @{organization}/security-appsec (or `#github-appsec-security` on Slack) if you have any questions.\n\nWe are here to help! :thumbsup:\n\n - Application Security team.",
        "head": target_branch,
        "base": default_branch,
    }

    # Retry if rate-limited
    i = 0
    while i < network.RETRIES:
        pr_resp = requests.post(
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


###### Dependency Review


def load_dependency_review_base64_template() -> str:
    with open(f"./templates/dependency_enforcement.yml", "r") as f:
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
    branch_resp = requests.get(
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

    branch_resp = requests.post(
        url=f"https://api.github.com/repos/{organization}/{repository}/git/refs",
        headers=headers,
        json=payload,
    )

    if branch_resp.status_code != 201:
        return False

    # Create commit
    template = load_dependency_review_base64_template()
    payload = {
        "message": f"Enable Dependency reviewer",
        "content": template,
        "branch": target_branch,
    }

    commit_resp = requests.put(
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
        pr_resp = requests.post(
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
