# -*- coding: utf-8 -*-
#!/usr/bin/env python3

__author__ = "jboursier"
__copyright__ = "Copyright 2022, Malwarebytes"
__version__ = "1.2.1"
__maintainer__ = "jboursier"
__email__ = "jboursier@malwarebytes.com"
__status__ = "Production"

try:
    import click
    import json
    from typing import Dict, Any
    from datetime import datetime
except ImportError:
    import sys

    print("Missing dependencies. Please reach @jboursier if needed.")
    sys.exit(255)

from ghas_cli.utils import repositories, vulns, teams, issues, actions


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
    "-t",
    "--token",
    prompt=False,
    type=str,
    default=None,
    hide_input=True,
    confirmation_prompt=False,
    show_envvar=True,
)
def teams_get_repositories(organization: str, team: str, token: str) -> None:
    """List repositories for a specific team"""
    team_repos = teams.get_repositories(
        team_slug=team, organization=organization, token=token
    )
    for repo in team_repos:
        click.echo(f"{team}: {repo}")


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


@cli.group()
def secret_alerts() -> None:
    """Manage Secret Scanner alerts"""
    pass


##############
# Dependabot #
##############


@cli.group()
def dependabot_alerts() -> None:
    """Manage Dependabot alerts"""
    pass


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

    print(
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

        print(f"{repo}....", end="")

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

        print(
            f"Done: {actions_res},{secretscanner_res}, {pushprotection_res}, {dependabot_res}, {codeql_res}, {reviewer_res}, {issue_secretscanner_res}, {issue_pushprotection_res}, {issue_dependabot_res}, {issue_codeql_res}, {mend_res}"
        )
        # CSV columns
        # Organization, repo_name, Actions Enabled?, SS enabled?, PushProtection Enabled?, Dependabot Enabled?, CodeQL enabled?, Dep Reviewer Enabled?, Issue SS created?, Issue PP created?, Issue Dependabot created?, Issue CodeQL created?, Mend issues closed
        output_csv.write(
            f"{organization},{repo},{actions_res},{secretscanner_res}, {pushprotection_res}, {dependabot_res}, {codeql_res}, {reviewer_res}, {issue_secretscanner_res}, {issue_pushprotection_res}, {issue_dependabot_res}, {issue_codeql_res}, {mend_res}\n"
        )


if __name__ == "__main__":
    main()
