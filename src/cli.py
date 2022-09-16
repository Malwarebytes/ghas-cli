# -*- coding: utf-8 -*-
#!/usr/bin/env python3

__author__ = "jboursier"
__copyright__ = "Copyright 2022, Malwarebytes"
__version__ = "0.0.1"
__maintainer__ = "jboursier"
__email__ = "jboursier@malwarebytes.com"
__status__ = "Development"

try:
    import click
    import requests
    from typing import Dict
    from datetime import datetime
except ImportError:
    import sys

    print("Missing dependencies. Please reach @jboursier if needed.")
    sys.exit(255)

from ghas_cli.utils import repositories, vulns


def main() -> None:
    try:
        cli()
    except Exception as e:
        click.echo(e)


@click.group()
def cli() -> None:
    """ghas-cli is a Python3 utility to interact with Github Advanced Security.

    Get help: `@jboursier` on Slack
    """


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
        repos = repositories.get_org_repositories(
            status="all", organization=organization, token=token
        )

    repositories_alerts = vulns.get_codeql_alerts_repo(
        repos, organization, status, token
    )
    click.echo(repositories_alerts)
    return repositories_alerts


@cli.group()
def secret_alerts() -> None:
    """Manage Secret Scanner alerts"""
    pass


@cli.group()
def dependabot_alerts() -> None:
    """Manage Dependabot alerts"""
    pass


if __name__ == "__main__":
    main()
