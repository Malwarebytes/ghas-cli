# -*- coding: utf-8 -*-
#!/usr/bin/env python3

__author__ = "jboursier"
__copyright__ = "Copyright 2025, Malwarebytes"
__version__ = "1.6.2"
__maintainer__ = "jboursier"
__email__ = "jboursier@malwarebytes.com"
__status__ = "Production"

try:
    import json
    import logging
    from datetime import datetime
    from typing import Any, Dict, List

    import click

    logging.getLogger().setLevel(level=logging.INFO)
except ImportError:
    import sys

    logging.error("Missing dependencies. Please reach @jboursier if needed.")
    sys.exit(255)

from ghas_cli.utils import (
    actions,
    dependabot,
    issues,
    repositories,
    roles,
    secrets,
    teams,
    vulns,
)


def main() -> None:
    try:
        cli()
    except Exception as e:
        click.echo(e)


@click.group()
def cli() -> None:
    """ghas-cli is a Python3 utility to interact with GitHub Advanced Security.

    Get help: `@jboursier` on Slack
    """


##########
# CodeQL #
##########


@cli.group()
def vuln_alerts() -> None:
    """Manage vulnerability alerts"""
    pass


@vuln_alerts.command("list")
@click.option(
    "-s",
    "--status",
    prompt="Alert status",
    type=click.Choice(["open", "closed", ""], case_sensitive=False),
    default="open",
)
@click.option(
    "-r",
    "--repos",
    prompt="Repositories name. Use `all` to retrieve alerts for all repos.",
    type=str,
    multiple=True,
)
@click.option("-o", "--organization", prompt="Organization name", type=str)
@click.option(
    "-t",
    "--token",
    prompt=False,
    type=str,
    default=None,
    hide_input=True,
    confirmation_prompt=False,
    show_envvar=True,
)
def vulns_alerts_list(repos: str, organization: str, status: str, token: str) -> Dict:
    """Get CodeQL alerts for one or several repositories"""

    repositories_alerts = {}
    if repos == ("all",):
        repos_list = repositories.get_org_repositories(
            status="all", organization=organization, token=token
        )
    else:
        repos_list = []
        for rep in repos:
            r = repositories.Repository()
            r.name = rep
            repos_list.append(r)

    repositories_alerts = vulns.get_codeql_alerts_repo(
        repos_list, organization, status, token
    )
    click.echo(repositories_alerts)
    return repositories_alerts


################
# Repositories #
################


@cli.group(name="repositories")
def repositories_cli() -> None:
    """Manage repositories"""
    pass


@repositories_cli.command("list")
@click.option(
    "-s",
    "--status",
    prompt="Repository status",
    type=click.Choice(
        ["all", "public", "private", "forks", "sources", "member", "internal"],
        case_sensitive=False,
    ),
    default="all",
)
@click.option(
    "-l",
    "--language",
    prompt="Primary language",
    type=str,
    default="",
)
@click.option(
    "-b",
    "--default_branch",
    prompt="Default branch",
    type=str,
    default="",
)
@click.option(
    "-r",
    "--license",
    prompt="License (spdx_id)",
    type=str,
    default="",
)
@click.option(
    "-a",
    "--archived",
    prompt="Archived?",
    type=bool,
    default=False,
)
@click.option(
    "-d",
    "--disabled",
    prompt="Disabled?",
    type=bool,
    default=False,
)
@click.option(
    "-f",
    "--format",
    prompt="Output format",
    type=click.Choice(
        ["human", "ghas", "json", "list"],
        case_sensitive=False,
    ),
    default="human",
)
@click.argument("output", type=click.File("w"))
@click.option(
    "-t",
    "--token",
    prompt=False,
    type=str,
    default=None,
    hide_input=True,
    confirmation_prompt=False,
    show_envvar=True,
)
@click.option("-o", "--organization", prompt="Organization name", type=str)
def repositories_list(
    status: str,
    language: str,
    default_branch: str,
    license: str,
    archived: bool,
    disabled: bool,
    format: str,
    output: Any,
    organization: str,
    token: str,
) -> None:
    """List repositories"""
    res = repositories.get_org_repositories(
        status,
        organization,
        token,
        language,
        default_branch,
        license,
        archived,
        disabled,
    )

    if "human" == format:
        for r in res:
            output.write(r + "\n")
            click.echo(r)
    elif "ghas" == format:
        repos = []
        for r in res:
            repos.append(r.to_ghas())
        output.write(json.dumps([{"login": organization, "repos": repos}]) + "\n")
        click.echo([{"login": organization, "repos": repos}])
    elif "json" == format:
        repos = []
        for r in res:
            repos.append(r.to_json())
        output.write(json.dumps(repos) + "\n")
        click.echo(repos)
    elif "list" == format:
        for r in res:
            output.write(r.name + "\n")
            click.echo(r.name)


@repositories_cli.command("get_topics")
@click.option(
    "-r",
    "--repository",
    prompt="Repository name",
)
@click.option(
    "-t",
    "--token",
    prompt=False,
    type=str,
    default=None,
    hide_input=True,
    confirmation_prompt=False,
    show_envvar=True,
)
@click.option("-o", "--organization", prompt="Organization name", type=str)
def repositories_get_topics(
    repository: str,
    organization: str,
    token: str,
) -> None:
    """Get a repository topics"""
    click.echo(
        repositories.get_topics(
            token=token, organization=organization, repository_name=repository
        )
    )


@repositories_cli.command("enable_ss_protection")
@click.option(
    "-r",
    "--repository",
    prompt="Repository name",
)
@click.option(
    "-t",
    "--token",
    prompt=False,
    type=str,
    default=None,
    hide_input=True,
    confirmation_prompt=False,
    show_envvar=True,
)
@click.option("-o", "--organization", prompt="Organization name", type=str)
def repositories_enable_ss(
    repository: str,
    organization: str,
    token: str,
) -> None:
    """Enable secret scanner on a repository"""
    click.echo(
        repositories.enable_secret_scanner_push_protection(
            organization, token, repository
        )
    )


@repositories_cli.command("enable_ss")
@click.option(
    "-r",
    "--repository",
    prompt="Repository name",
)
@click.option(
    "-t",
    "--token",
    prompt=False,
    type=str,
    default=None,
    hide_input=True,
    confirmation_prompt=False,
    show_envvar=True,
)
@click.option("-o", "--organization", prompt="Organization name", type=str)
def repositories_enable_ss(
    repository: str,
    organization: str,
    token: str,
) -> None:
    """Enable secret scanner on a repository"""
    click.echo(repositories.enable_secret_scanner(organization, token, repository))


@repositories_cli.command("enable_dependabot")
@click.option(
    "-r",
    "--repository",
    prompt="Repository name",
)
@click.option(
    "-t",
    "--token",
    prompt=False,
    type=str,
    default=None,
    hide_input=True,
    confirmation_prompt=False,
    show_envvar=True,
)
@click.option("-o", "--organization", prompt="Organization name", type=str)
def repositories_enable_dependabot(
    repository: str,
    organization: str,
    token: str,
) -> None:
    """Enable Dependabot on a repository"""
    click.echo(repositories.enable_dependabot(organization, token, repository))


@repositories_cli.command("create_codeql_pr")
@click.option(
    "-r",
    "--repository",
    prompt="Repository name",
)
@click.option(
    "-b",
    "--branch",
    prompt="Branch name to create",
    default="appsec-ghas-codeql_enable",
)
@click.option(
    "-t",
    "--token",
    prompt=False,
    type=str,
    default=None,
    hide_input=True,
    confirmation_prompt=False,
    show_envvar=True,
)
@click.option("-o", "--organization", prompt="Organization name", type=str)
def repositories_create_codeql_pr(
    repository: str, organization: str, token: str, branch: str
) -> None:
    """Create a CodeQL PR"""
    click.echo(
        repositories.create_codeql_pr(
            organization, token, repository, target_branch=branch
        )
    )


@repositories_cli.command("create_dep_enforcement_pr")
@click.option(
    "-r",
    "--repository",
    prompt="Repository name",
)
@click.option(
    "-b",
    "--branch",
    prompt="Branch name to create",
    default="appsec-ghas-dep-enforcement-enable",
)
@click.option(
    "-t",
    "--token",
    prompt=False,
    type=str,
    default=None,
    hide_input=True,
    confirmation_prompt=False,
    show_envvar=True,
)
@click.option("-o", "--organization", prompt="Organization name", type=str)
def repositories_create_dep_enforcement_pr(
    repository: str, organization: str, token: str, branch: str
) -> None:
    """Create a Dependency enforcement PR"""
    click.echo(
        repositories.create_dependency_enforcement_pr(
            organization, token, repository, target_branch=branch
        )
    )


@repositories_cli.command("archivable")
@click.option(
    "-f",
    "--format",
    prompt="Output format",
    type=click.Choice(
        ["human", "list"],
        case_sensitive=False,
    ),
    default="list",
)
@click.option(
    "-u", "--last_updated_before", prompt="Last updated before YYYY-MM-DD", type=str
)
@click.argument("input_repos_list", type=click.File("r"))
@click.argument("output", type=click.File("w"))
@click.option(
    "-t",
    "--token",
    prompt=False,
    type=str,
    default=None,
    hide_input=True,
    confirmation_prompt=False,
    show_envvar=True,
)
@click.option("-o", "--organization", prompt="Organization name", type=str)
def repositories_archivable(
    last_updated_before: str,
    format: str,
    input_repos_list: Any,
    output: Any,
    organization: str,
    token: str,
) -> bool:
    """Find potentially archivable repositories"""

    try:
        threshold_date = datetime.strptime(last_updated_before, "%Y-%m-%d")
    except Exception:
        click.echo(f"Invalid time: {last_updated_before}")
        return False

    # 1. Get list repositories passed as argument
    res = input_repos_list.readlines()

    logging.info(len(res))
    for repo in res:
        repo = repo.rstrip("\n")

        # 2. get default branch
        default_branch = repositories.get_default_branch(
            organization=organization, token=token, repository=repo
        )
        if not default_branch:
            continue

        # 3. get default branch last commit date
        branch_last_commit_date = repositories.get_default_branch_last_updated(
            token=token,
            organization=organization,
            repository_name=repo,
            default_branch=default_branch,
        )
        if not branch_last_commit_date:
            click.echo(f"No branch last commit date for {repo}", err=True)
            continue

        # 4. Compare with the threshold
        if branch_last_commit_date > threshold_date:
            continue

        if "human" == format:
            output.write(repo + "\n")
            click.echo(repo)
        elif "list" == format:
            output.write(f"{repo}, {branch_last_commit_date.strftime('%Y-%m-%d')}\n")
            click.echo(f"{repo}, {branch_last_commit_date.strftime('%Y-%m-%d')}")

    return True


@repositories_cli.command("archive")
@click.option(
    "-r",
    "--repository",
    prompt="Repository name",
)
@click.option(
    "-t",
    "--token",
    prompt=False,
    type=str,
    default=None,
    hide_input=True,
    confirmation_prompt=False,
    show_envvar=True,
)
@click.option("-o", "--organization", prompt="Organization name", type=str)
def repositories_archive(
    repository: str,
    organization: str,
    token: str,
) -> None:
    """Archive a repository"""
    click.echo(repositories.archive(organization, token, repository, archive=True))


@repositories_cli.command("unarchive")
@click.option(
    "-r",
    "--repository",
    prompt="Repository name",
)
@click.option(
    "-t",
    "--token",
    prompt=False,
    type=str,
    default=None,
    hide_input=True,
    confirmation_prompt=False,
    show_envvar=True,
)
@click.option("-o", "--organization", prompt="Organization name", type=str)
def repositories_unarchive(
    repository: str,
    organization: str,
    token: str,
) -> None:
    """Unarchive a repository"""
    click.echo(repositories.archive(organization, token, repository, archive=False))


#########
# Teams #
#########


@cli.group(name="teams")
def teams_cli() -> None:
    """Manage Teams"""
    pass


@teams_cli.command("list")
@click.option("-o", "--organization", prompt="Organization name", type=str)
@click.option(
    "-t",
    "--token",
    prompt=False,
    type=str,
    default=None,
    hide_input=True,
    confirmation_prompt=False,
    show_envvar=True,
)
def teams_list(organization: str, token: str) -> None:
    """List team for a specific organization"""
    click.echo(teams.list(organization=organization, token=token))


@teams_cli.command("repositories")
@click.option("-o", "--organization", prompt="Organization name", type=str)
@click.option("-s", "--team", prompt="Team slug", type=str)
@click.option(
    "-f",
    "--format",
    prompt="Output format",
    type=click.Choice(
        ["human", "ghas", "json", "list"],
        case_sensitive=False,
    ),
    default="human",
)
@click.option(
    "-t",
    "--token",
    prompt=False,
    type=str,
    default=None,
    hide_input=True,
    confirmation_prompt=False,
    show_envvar=True,
)
def teams_get_repositories(
    organization: str, team: str, token: str, format: str
) -> None:
    """List repositories for a specific team"""
    team_repos = teams.get_repositories(
        team_slug=team, organization=organization, token=token
    )

    if "human" == format:
        for repo in team_repos:
            click.echo(f"{team}: {repo}")
    elif "ghas" == format:
        for repo in team_repos:
            click.echo(repo.to_ghas())
    elif "json" == format:
        for repo in team_repos:
            click.echo(repo.to_json())
    elif "list" == format:
        for repo in team_repos:
            click.echo(f"{repo.orga}/{repo.name}")


@teams_cli.command("permissions")
@click.option("-o", "--organization", prompt="Organization name", type=str)
@click.option("-s", "--team", prompt="Team slug", type=str)
@click.option("-r", "--repository", prompt="Repository name", type=str)
@click.option(
    "-t",
    "--token",
    prompt=False,
    type=str,
    default=None,
    hide_input=True,
    confirmation_prompt=False,
    show_envvar=True,
)
def teams_get_permissions(
    organization: str, team: str, repository: str, token: str
) -> None:
    """List permissions for a specific team for a repository"""
    team_repo_perms = teams.get_repo_perms(
        team=team, repo=repository, organization=organization, token=token
    )

    click.echo(team_repo_perms)


##########
# Issues #
##########


@cli.group(name="issues")
def issues_cli() -> None:
    """Manage issues"""
    pass


@issues_cli.command("create")
@click.option(
    "-n",
    "--title",
    prompt="Issue title",
)
@click.argument("issue_markdown_template", type=click.File("r"))
@click.option(
    "-r",
    "--repository",
    prompt="Repository name",
)
@click.option(
    "-t",
    "--token",
    prompt=False,
    type=str,
    default=None,
    hide_input=True,
    confirmation_prompt=False,
    show_envvar=True,
)
@click.option("-o", "--organization", prompt="Organization name", type=str)
def issues_create(
    title: str,
    issue_markdown_template: str,
    repository: str,
    organization: str,
    token: str,
) -> None:
    """Create an issue on a repository"""
    content = issue_markdown_template.read()

    issue = issues.create(
        title=title,
        content=content,
        repository=repository,
        organization=organization,
        token=token,
    )

    click.echo(issue)


@issues_cli.command("list")
@click.option(
    "-c",
    "--creator",
    default="mend-for-github-com[bot]",
    prompt="Creator username",
)
@click.option(
    "-r",
    "--repository",
    prompt="Repository name",
)
@click.option(
    "-t",
    "--token",
    prompt=False,
    type=str,
    default=None,
    hide_input=True,
    confirmation_prompt=False,
    show_envvar=True,
)
@click.option("-o", "--organization", prompt="Organization name", type=str)
def issues_list(
    creator: str,
    repository: str,
    organization: str,
    token: str,
) -> None:
    """Get issues created by an user on a repository"""

    issues_res = issues.search(
        creator=creator,
        repository=repository,
        organization=organization,
        token=token,
    )

    click.echo(issues_res)


@issues_cli.command("close_mend")
@click.option(
    "-c",
    "--creator",
    default="mend-for-github-com[bot]",
    prompt="Creator username",
)
@click.option(
    "-r",
    "--repository",
    prompt="Repository name",
)
@click.option(
    "-t",
    "--token",
    prompt=False,
    type=str,
    default=None,
    hide_input=True,
    confirmation_prompt=False,
    show_envvar=True,
)
@click.option("-o", "--organization", prompt="Organization name", type=str)
def issues_close_mend(
    creator: str,
    repository: str,
    organization: str,
    token: str,
) -> None:
    """Close all issues created by a specific user on a repository"""

    issues_res = issues.search(
        creator=creator,
        repository=repository,
        organization=organization,
        token=token,
    )

    if not issues_res:
        return

    res = issues.close_issues(
        issue_numbers=issues_res,
        repository=repository,
        organization=organization,
        token=token,
    )

    click.echo(f"Closed {res} issues from {creator} on {organization}/{repository}.")


###########
# Secrets #
###########


@cli.group(name="secrets")
def secret_alerts_cli() -> None:
    """Manage Secret Scanner alerts"""
    pass


@secret_alerts_cli.command("export")
@click.option(
    "-s",
    "--state",
    type=click.Choice(["open", "resolved"]),
    default="open",
    prompt="Secrets state",
)
@click.argument("output_csv", type=click.File("a", lazy=True))
@click.option(
    "-t",
    "--token",
    prompt=False,
    type=str,
    default=None,
    hide_input=True,
    confirmation_prompt=False,
    show_envvar=True,
)
@click.option("-o", "--organization", prompt="Organization name", type=str)
@click.option(
    "-f",
    "--secrets-filter",
    prompt=True,
    type=click.Choice(
        [
            "all",
            "atlassian_api_token",
            "slack_incoming_webhook_url",
            "github_ssh_private_key",
            "slack_api_token",
            "mailgun_api_key",
            "firebase_cloud_messaging_server_key",
            "jfrog_platform_api_key",
            "google_api_key",
            "azure_storage_account_key",
            "new_relic_license_key",
            "github_personal_access_token",
            "sendgrid_api_key",
            "azure_devops_personal_access_token",
            "jfrog_platform_access_token",
            "google_cloud_private_key_id",
            "google_oauth_access_token",
        ]
    ),
    default="all",
    hide_input=False,
)
def secret_alerts_export(
    state: str, output_csv: Any, token: str, organization: str, secrets_filter: str
) -> None:
    """Export secrets to a csv"""

    secrets_list = secrets.export_secrets(state, token, organization, secrets_filter)
    for secret in secrets_list:
        output_csv.write(
            f"{secret['state']}, {secret['resolution']}, {secret['resolved_at']}, {secret['repository_full_name']}, {secret['url']}, {secret['secret_type']}, {secret['secret']}\n"
        )
    logging.info(f"Retrieved {len(secrets_list)} secrets.")


##############
# Dependabot #
##############


@cli.group(name="dependabot")
def dependabot_alerts() -> None:
    """Manage Dependabot alerts"""
    pass


@dependabot_alerts.command("get_alerts")
@click.option(
    "-r",
    "--repos",
    prompt="Repositories name. Use `all` to retrieve alerts for all repos.",
    type=str,
    multiple=True,
)
@click.option(
    "-t",
    "--token",
    prompt=False,
    type=str,
    default=None,
    hide_input=True,
    confirmation_prompt=False,
    show_envvar=True,
)
@click.option("-o", "--organization", prompt="Organization name", type=str)
def dependabot_alerts_list(
    repos: List,
    organization: str,
    token: str,
) -> None:
    """Get Dependabot alerts for a repository"""

    for repo in repos:
        dependabot_res = dependabot.list_alerts_repo(
            repository=repo,
            organization=organization,
            token=token,
        )

        for res in dependabot_res:
            click.echo(res)


@dependabot_alerts.command("get_dependencies")
@click.option(
    "-f",
    "--format",
    prompt="Output format",
    type=click.Choice(
        ["sbom", "csv", "txt"],
        case_sensitive=True,
    ),
    default="sbom",
)
@click.option(
    "-r",
    "--repository",
    prompt="Repository name",
)
@click.option(
    "-t",
    "--token",
    prompt=False,
    type=str,
    default=None,
    hide_input=True,
    confirmation_prompt=False,
    show_envvar=True,
)
@click.option("-o", "--organization", prompt="Organization name", type=str)
def dependabot_get_dependencies(
    repository: str, organization: str, token: str, format: str = "sbom"
) -> None:
    """Get a list of dependencies for a repository"""

    res = dependabot.get_dependencies(repository, organization, token, format=format)
    click.echo(res, nl=False)


###########
# Actions #
###########


@cli.group(name="actions")
def actions_cli() -> None:
    """Manage Actions and their workflows"""
    pass


@actions_cli.command("set_permissions")
@click.option(
    "-e",
    "--enabled",
    type=click.BOOL,
    default=True,
    prompt="Enable Actions?",
)
@click.option(
    "-a",
    "--allowed_actions",
    type=click.Choice(["all", "local_only", "selected"]),
    default="selected",
    prompt="Allowed Actions",
)
@click.option(
    "-r",
    "--repository",
    prompt="Repository name",
)
@click.option(
    "-t",
    "--token",
    prompt=False,
    type=str,
    default=None,
    hide_input=True,
    confirmation_prompt=False,
    show_envvar=True,
)
@click.option("-o", "--organization", prompt="Organization name", type=str)
def actions_set_permissions(
    enabled: bool,
    allowed_actions: str,
    repository: str,
    organization: str,
    token: str,
) -> None:
    """Set Actions permissions on a repository"""

    permissions = actions.set_permissions(
        repository_name=repository,
        organization=organization,
        token=token,
        enabled=enabled,
        allowed_actions=allowed_actions,
    )

    click.echo(permissions)


###############
# Roles #
###############


@cli.group(name="roles")
def roles_cli() -> None:
    """Manage roles"""
    pass


@roles_cli.command("add")
@click.option(
    "-n",
    "--name",
    type=click.STRING,
    prompt="Role name",
)
@click.option(
    "-d",
    "--description",
    type=click.STRING,
    prompt="Description",
)
@click.option(
    "-b",
    "--base_role",
    type=click.STRING,
    prompt="Base role",
)
@click.option(
    "-p",
    "--permission",
    type=click.STRING,
    prompt="Additional permission",
    multiple=True,
)
@click.option(
    "-t",
    "--token",
    prompt=False,
    type=str,
    default=None,
    hide_input=True,
    confirmation_prompt=False,
    show_envvar=True,
)
@click.option("-o", "--organization", prompt="Organization name", type=str)
def roles_add(
    name: str,
    description: str,
    base_role: str,
    permissions: List,
    organization: str,
    token: str,
) -> None:
    if roles.create_role(
        name, description, base_role, permissions, organization, token
    ):
        click.echo(f"Custom role {name} created with success!")
    else:
        click.echo(f"Failure to create the custom role {name}.")


@roles_cli.command("assign")
@click.option(
    "-n",
    "--name",
    type=click.STRING,
    prompt="Team name",
)
@click.option(
    "-p",
    "--permission",
    type=click.STRING,
    prompt="Role to assign",
    default="Developer",
)
@click.option(
    "-r",
    "--repository",
    type=click.STRING,
    prompt="Repository",
)
@click.option(
    "-t",
    "--token",
    prompt=False,
    type=str,
    default=None,
    hide_input=True,
    confirmation_prompt=False,
    show_envvar=True,
)
@click.option("-o", "--organization", prompt="Organization name", type=str)
def roles_assign(
    name: str, permission: str, repository: str, organization: str, token: str
):
    if roles.assign_role(
        team=name,
        role=permission,
        repository=repository,
        organization=organization,
        token=token,
    ):
        click.echo(f"Assigned {permission} to {name} with success.")
    else:
        click.echo(f"Failure to assign {permission} to {name}.")


###############
# Mass deploy #
###############


@cli.group(name="mass")
def mass_cli() -> None:
    """Manage large scale deployment"""
    pass


@mass_cli.command("deploy")
@click.option(
    "-a",
    "--actions_enable",
    type=click.BOOL,
    prompt="Enable GH Actions (to `selected`)?",
)
@click.option(
    "-s",
    "--secretscanner",
    type=click.BOOL,
    prompt="Enable Secret Scanner?",
)
@click.option(
    "-p",
    "--pushprotection",
    type=click.BOOL,
    prompt="Enable Push Protection?",
)
@click.option(
    "-d",
    "--dependabot",
    type=click.BOOL,
    prompt="Enable Dependabot?",
)
@click.option(
    "-c",
    "--codeql",
    type=click.BOOL,
    prompt="Deploy CodeQL?",
)
@click.option(
    "-r",
    "--reviewer",
    type=click.BOOL,
    prompt="Deploy the Dependency Reviewer?",
)
@click.option(
    "-m",
    "--mend",
    type=click.BOOL,
    default=False,
    prompt="Close Mend issues?",
)
@click.argument("input_repos_list", type=click.File("r"))
@click.argument("output_csv", type=click.File("a", lazy=True))
@click.option(
    "-t",
    "--token",
    prompt=False,
    type=str,
    default=None,
    hide_input=True,
    confirmation_prompt=False,
    show_envvar=True,
)
@click.option("-o", "--organization", prompt="Organization name", type=str)
def mass_deploy(
    actions_enable: bool,
    secretscanner: bool,
    pushprotection: bool,
    dependabot: bool,
    codeql: bool,
    reviewer: bool,
    mend: bool,
    input_repos_list: Any,
    output_csv: Any,
    organization: str,
    token: str,
) -> None:
    """Mass deploy all GHAS to a list of repositories"""

    repos_list = input_repos_list.readlines()

    with open("./templates/secret_scanner.md", "r") as f:
        template_secretscanner = f.read()
    with open("./templates/secret_scanner_push_protection.md", "r") as f:
        template_pushprotection = f.read()
    with open("./templates/dependabot.md", "r") as f:
        template_dependabot = f.read()
    with open("./templates/codeql.md", "r") as f:
        template_codeql = f.read()

    logging.info(
        f"Enabling Actions ({actions_enable}), Secret Scanner ({secretscanner}), Push Protection ({pushprotection}), Dependabot ({dependabot}), CodeQL ({codeql}), Dependency Reviewer ({reviewer}) to {len(repos_list)} repositories."
    )

    for repo in repos_list:
        repo = repo.rstrip("\n")
        issue_secretscanner_res = None
        issue_pushprotection_res = None
        issue_dependabot_res = None
        issue_codeql_res = None
        actions_res = None
        secretscanner_res = None
        pushprotection_res = None
        dependabot_res = None
        codeql_res = None
        reviewer_res = None
        mend_res = 0

        logging.info(f"{repo}....")

        if actions_enable:
            actions_res = actions.set_permissions(
                repository_name=repo,
                organization=organization,
                token=token,
                enabled=True,
                allowed_actions="selected",
            )
        if secretscanner:
            secretscanner_res = repositories.enable_secret_scanner(
                organization, token, repo
            )
            if secretscanner_res != False:
                issue_secretscanner_res = issues.create(
                    title="About Secret Scanner",
                    content=template_secretscanner,
                    repository=repo,
                    organization=organization,
                    token=token,
                )
        if pushprotection:
            pushprotection_res = repositories.enable_secret_scanner_push_protection(
                organization, token, repo
            )
            if pushprotection_res != False:
                issue_pushprotection_res = issues.create(
                    title="About Secret Push Protection",
                    content=template_pushprotection,
                    repository=repo,
                    organization=organization,
                    token=token,
                )
        if dependabot:
            dependabot_res = repositories.enable_dependabot(organization, token, repo)
            if dependabot_res != False:
                issue_dependabot_res = issues.create(
                    title="About Dependabot",
                    content=template_dependabot,
                    repository=repo,
                    organization=organization,
                    token=token,
                )
        if codeql:
            codeql_res = repositories.create_codeql_pr(organization, token, repo)
            if codeql_res != False:
                issue_codeql_res = issues.create(
                    title="About Security code scanning",
                    content=template_codeql,
                    repository=repo,
                    organization=organization,
                    token=token,
                )
        if reviewer:
            reviewer_res = repositories.create_dependency_enforcement_pr(
                organization, token, repo
            )

        if mend:
            issues_res = issues.search(
                creator="mend-for-github-com[bot]",
                repository=repo,
                organization=organization,
                token=token,
            )

            if issues_res:
                mend_res = issues.close_issues(
                    issue_numbers=issues_res,
                    repository=repo,
                    organization=organization,
                    token=token,
                )

        logging.info(
            f"Done: {actions_res},{secretscanner_res}, {pushprotection_res}, {dependabot_res}, {codeql_res}, {reviewer_res}, {issue_secretscanner_res}, {issue_pushprotection_res}, {issue_dependabot_res}, {issue_codeql_res}, {mend_res}"
        )
        # CSV columns
        # Organization, repo_name, Actions Enabled?, SS enabled?, PushProtection Enabled?, Dependabot Enabled?, CodeQL enabled?, Dep Reviewer Enabled?, Issue SS created?, Issue PP created?, Issue Dependabot created?, Issue CodeQL created?, Mend issues closed
        output_csv.write(
            f"{organization},{repo},{actions_res},{secretscanner_res}, {pushprotection_res}, {dependabot_res}, {codeql_res}, {reviewer_res}, {issue_secretscanner_res}, {issue_pushprotection_res}, {issue_dependabot_res}, {issue_codeql_res}, {mend_res}\n"
        )


@mass_cli.command("archive")
@click.argument("input_repos_list", type=click.File("r"))
@click.option(
    "-t",
    "--token",
    prompt=False,
    type=str,
    default=None,
    hide_input=True,
    confirmation_prompt=False,
    show_envvar=True,
)
@click.option("-o", "--organization", prompt="Organization name", type=str)
def mass_archive(
    input_repos_list: Any,
    organization: str,
    token: str,
) -> None:
    repos_list = input_repos_list.readlines()

    for repo in repos_list:
        repo = repo.rstrip("\n")

        click.echo(f"{repo}...", nl=False)

        if repositories.archive(
            organization=organization, token=token, repository=repo, archive=True
        ):
            click.echo(" Archived.")
        else:
            click.echo(" Not Archived.", err=True)


@mass_cli.command("unarchive")
@click.argument("input_repos_list", type=click.File("r"))
@click.option(
    "-t",
    "--token",
    prompt=False,
    type=str,
    default=None,
    hide_input=True,
    confirmation_prompt=False,
    show_envvar=True,
)
@click.option("-o", "--organization", prompt="Organization name", type=str)
def mass_unarchive(
    input_repos_list: Any,
    organization: str,
    token: str,
) -> None:
    repos_list = input_repos_list.readlines()

    for repo in repos_list:

        repo = repo.rstrip("\n")

        click.echo(f"{repo}...", nl=False)

        if repositories.archive(
            organization=organization, token=token, repository=repo, archive=False
        ):
            click.echo(" Unarchived.")
        else:
            click.echo(" Not Unarchived.", err=True)


@mass_cli.command("issue_upcoming_archive")
@click.argument("input_repos_list", type=click.File("r"))
@click.option(
    "-u",
    "--archived_date",
    prompt="Target date when the repositories will be archived",
    type=str,
)
@click.option(
    "-t",
    "--token",
    prompt=False,
    type=str,
    default=None,
    hide_input=True,
    confirmation_prompt=False,
    show_envvar=True,
)
@click.option("-o", "--organization", prompt="Organization name", type=str)
def mass_issue_archive(
    input_repos_list: Any,
    archived_date: str,
    organization: str,
    token: str,
) -> None:
    """Create an issue to inform that repositories will be archived at a specific date."""

    repos_list = input_repos_list.readlines()

    for repo in repos_list:
        repo = repo.rstrip("\n")

        issue_res = issues.create(
            title=f"This repository will be archived on {archived_date}  :warning: :wastebasket:",
            content=f"""
Hello,

Due to inactivity, this repository will be archived automatically on {archived_date}.

This means that it will become read-only: `git clone` will still work, and the repository can be unarchived at anytime if needed.

For more information, see https://docs.github.com/en/repositories/archiving-a-github-repository/archiving-repositories#about-repository-archival

If you think this is a mistake, please inform the Security team *ASAP* on Slack at `#github-appsec-security`.

Thanks! :handshake:""",
            repository=repo,
            organization=organization,
            token=token,
        )
        if issue_res:
            click.echo(f"{repo}... {issue_res}")
        else:
            click.echo(f"{repo}... Failure", err=True)


@mass_cli.command("set_developer_role")
@click.option(
    "-p",
    "--permission",
    type=click.STRING,
    prompt="Role to assign",
    default="Developer",
)
@click.argument("input_perms_list", type=click.File("r"))
@click.argument("output_perms_list", type=click.File("a", lazy=True))
@click.option(
    "-t",
    "--token",
    prompt=False,
    type=str,
    default=None,
    hide_input=True,
    confirmation_prompt=False,
    show_envvar=True,
)
@click.option("-o", "--organization", prompt="Organization name", type=str)
def mass_set_developer_role(
    permission: str,
    input_perms_list: Any,
    output_perms_list: Any,
    token: str,
    organization: str,
) -> None:
    """Convert all teams with `Write` access to `Developer` on all repository they have `Write` access to.

    1. List teams
    2. List their repository
    3. Get permissions and only filter the ones with `Write` role_name
    4. Assign `Developer` role
    """

    write_perms = []

    # Ability to resume a previous run if needed.
    input_perms = input_perms_list.readlines()
    for perms in input_perms:
        perms = perms.rstrip("\n").split(",")
        write_perms.append([perms[0].strip(" "), perms[1].strip(" "), perms[2]])

    if len(write_perms) < 1:
        # List teams
        teams_list = teams.list(organization, token)

        # List team's repositories
        for team in teams_list:
            team_repos = teams.get_repositories(team, organization, token)

            # List teams' permissions + filter only Write
            for repo in team_repos:
                perms = teams.get_repo_perms(team, repo.name, organization, token)
                if "write" == perms[-1]:
                    write_perms.append([team, repo.name, perms[-1]])
                    logging.info([team, repo.name, perms[-1]])
                    output_perms_list.write(f"{team}, {repo.name}, {perms[-1]}\n")

    # Assign the Developer role
    for perms in write_perms:
        if roles.assign_role(
            team=perms[0],
            role=permission,
            repository=perms[1],
            organization=organization,
            token=token,
        ):
            click.echo(
                f"Assigned {permission} to {perms[0]} on {perms[1]} with success."
            )
        else:
            click.echo(f"Failure to assign {permission} to {perms[0]} on {perms[1]}.")

    return None


@mass_cli.command("topics")
@click.argument("input_repos_list", type=click.File("r"))
@click.option(
    "-t",
    "--token",
    prompt=False,
    type=str,
    default=None,
    hide_input=True,
    confirmation_prompt=False,
    show_envvar=True,
)
@click.option("-o", "--organization", prompt="Organization name", type=str)
def mass_get_topics(
    input_repos_list: Any,
    organization: str,
    token: str,
) -> None:
    repos_list = input_repos_list.readlines()

    for repo in repos_list:
        repo = repo.rstrip("\n")

        click.echo(f"{repo},", nl=False)
        click.echo(
            repositories.get_topics(
                token=token, organization=organization, repository_name=repo
            )
        )


@mass_cli.command("dependencies")
@click.argument("input_repos_list", type=click.File("r"))
@click.option(
    "-t",
    "--token",
    prompt=False,
    type=str,
    default=None,
    hide_input=True,
    confirmation_prompt=False,
    show_envvar=True,
)
@click.option("-o", "--organization", prompt="Organization name", type=str)
@click.option(
    "-f",
    "--format",
    prompt="Output format",
    type=click.Choice(
        ["sbom", "csv", "txt"],
        case_sensitive=True,
    ),
    default="csv",
)
def mass_get_dependencies(
    format: str,
    input_repos_list: Any,
    organization: str,
    token: str,
) -> None:
    repos_list = input_repos_list.readlines()

    for repo in repos_list:
        repo = repo.rstrip("\n")

        click.echo(f"{repo},", nl=False)
        click.echo(
            dependabot.get_dependencies(
                repository=repo, organization=organization, token=token, format=format
            ),
            nl=False,
        )


if __name__ == "__main__":
    main()
