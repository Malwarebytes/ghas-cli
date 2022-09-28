# Security-ghas-cli

[![CodeQL](https://github.com/Malwarebytes/Security-ghas-cli/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/Malwarebytes/Security-ghas-cli/actions/workflows/codeql-analysis.yml)

CLI utility to interact with GHAS.

## Installation

Builds are available in the [`Releases`](https://github.com/Malwarebytes/Security-ghas-cli/releases) tab.

```bash
python -m pip install /full/path/to/ghas-cli-xxx.whl

# e.g: python3 -m pip install Downloads/ghas-cli-0.5.0-none-any.whl
```

## Usage

`ghas-cli -h` or see the [wiki](https://github.com/Malwarebytes/Security-ghas-cli/wiki).


## Development

### Build

[Install Poetry](https://python-poetry.org/docs/#installation) first, then:

```bash
make release
```

### Bump the version number

* Update the `version` field in `pyproject.toml`.
* Update the `__version__` field in `src/cli.py`.

### Publish a new version

1. Bump the version number as described above
2. `make deps` to update the dependencies
3. `make release` to build the packages
4. `git commit -a -S Bump to version 1.1.2` and `git tag -s v1.1.2 -m "1.1.2"`
5. Upload `dist/*`, `checksums.sha512` and `checksums.sha512.asc` to a new release in Github.

# Resources

Please reach Jérôme Boursier for any issues or question:

* jboursier@malwarebytes.com
* `jboursier` on Slack
