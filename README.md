# ghas-cli

[![CodeQL](https://github.com/Malwarebytes/ghas-cli/actions/workflows/codeql-analysis.yml/badge.svg?branch=main)](https://github.com/Malwarebytes/ghas-cli/actions/workflows/codeql-analysis.yml)
[![CI - Ruff](https://github.com/Malwarebytes/ghas-cli/actions/workflows/ruff.yml/badge.svg)](https://github.com/Malwarebytes/ghas-cli/actions/workflows/ruff.yml)
[![Downloads](https://static.pepy.tech/personalized-badge/ghas-cli?period=total&units=international_system&left_color=grey&right_color=blue&left_text=Downloads)](https://pepy.tech/project/ghas-cli)
[![Supported Versions](https://img.shields.io/pypi/pyversions/ghas-cli.svg)](https://pypi.org/project/ghas-cli)
[![Contributors](https://img.shields.io/github/contributors/malwarebytes/ghas-cli.svg)](https://github.com/malwarebytes/ghas-cli/graphs/contributors)

CLI utility to interact with [GitHub Advanced Security](https://docs.github.com/en/enterprise-cloud@latest/get-started/learning-about-github/about-github-advanced-security) (_"GHAS"_).

It allows to deploy GHAS features individually or at scale, while taking into account each repository configuration.

More specifically, it automates the following:

* Ensure GitHub Actions are properly enabled for the repository (required for CodeQL),
* Enable [Secret Scanner](https://docs.github.com/en/enterprise-cloud@latest/code-security/secret-scanning/about-secret-scanning), and create an informative issue
* Enable [Push Protection](https://docs.github.com/en/enterprise-cloud@latest/code-security/secret-scanning/protecting-pushes-with-secret-scanning), and create an informative issue
* Enable [Dependabot](https://docs.github.com/en/enterprise-cloud@latest/code-security/dependabot/working-with-dependabot) and create an informative issue
* Enable the [Dependency Reviewer](https://docs.github.com/en/enterprise-cloud@latest/code-security/supply-chain-security/about-dependency-review) and create an informative issue
* Open a PR to deploy [Code Scanning](https://docs.github.com/en/enterprise-cloud@latest/code-security/code-scanning/automatically-scanning-your-code-for-vulnerabilities-and-errors/about-code-scanning) with a custom configuration tuned for each repository's languages and _non-main default branch_ (e.g `main` or `master` are not hardcoded, it determines the proper default branch automatically),
* Cleanup legacy Mend issues on each repository


Each of these actions can also open an issue explaining each feature, how to use them, and what to eventually do before they are fully enabled.
See `./templates` to get an overview of these issues!

To follow your deployment, `ghas-cli` outputs results in a csv file indicating the deployment status of each feature for each repository.

You can work on a single repository or on thousands of them. In that case, `ghas-cli` does its best to overcome [GitHub's rate limits](https://docs.github.com/en/enterprise-cloud@latest/rest/rate-limit)...


## Installation

Builds are available in the [`Releases`](https://github.com/Malwarebytes/ghas-cli/releases) tab.

* Pypi:

```bash
pip install ghas-cli
```

* Manually:

```bash
python -m pip install /full/path/to/ghas-cli-xxx.whl

# e.g: python3 -m pip install Downloads/ghas-cli-0.5.0-none-any.whl
```

## Usage

`ghas-cli -h` or see the [wiki](https://github.com/Malwarebytes/ghas-cli/wiki).


## Development

### Build

[Install uv](https://docs.astral.sh/uv/getting-started/installation/) first, then:

```bash
make dev
```

### Bump the version number

* Bump the version number: `uv version --bump minor`
* Update the `__version__` field in `src/cli.py` accordingly.

### Publish a new version

**Requires `syft` to be installed to generate the sbom.**

1. Bump the version number as described above
2. `make release` to build the packages
3. `git commit -a -S Bump to version 1.1.2` and `git tag -s v1.1.2 -m "1.1.2"`
4. Upload `dist/*`, `checksums.sha512` and `checksums.sha512.asc` to a new release in GitHub.
5. Upload to [PyPi](https://pypi.org/project/ghas-cli/): `uv publish`.


## Why not use `ghas-enablement`?

GitHub suggests using [ghas-enablement](https://github.com/NickLiffen/ghas-enablement) to deploy GHAS at scale. Unfortunately, it has many limitations that make it a non viable tool as you understood if you read the beginning of this README, including:

* Only support for one default branch name: If you repositories are mixing `master`, `main`, `dev`, `test`... as the repository default branch, you will end up creating the CodeQL config to another branch than the default's.
    - `ghas-cli` uses the correct default branch for each repo.
* Non per-language CodeQL workflow configuration: You can only automate the PR creation for a single CodeQL workflow config file. Your repositories are likely a mix of many languages combinations, so pushing a single workflow configuration accross an organization is not efficient.
    - `ghas-cli` adjusts the CodeQL configuration to each repository languages.
* Doesn't check if Actions are properly enabled on your organization repositories: Running `ghas-enablement` when Actions are disabled will fail.
    - `ghas-cli` makes sure Actions are enabled before doing anything else. If they're not, it enables them.
* More broadly, `ghas-cli` creates more educative issues on each repositories. It also provides more flexibility with an extensive CLI to pipe in/out data.



# Miscellaneous

This repository is provided as-is and isn't bound to Malwarebytes' SLA.
