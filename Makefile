.DEFAULT_GOAL=help
.PHONY=help

ZIP = zip
PIP3 = python3 -m pip
PYTHON3 = python3
UV = uv
SYFT = syft


clean: ## clean existing builds
	rm -rf ./dist || true
	rm -rf ./src/ghas-cli/ghas-cli.egg-info || true
	rm checksums.sha512 || true
	rm checksums.sha512.asc || true

release: ## Build a wheel
	$(UV) build
	$(SYFT) packages file:uv.lock -o spdx-json > dist/sbom.json
	cd dist && sha512sum * > ../checksums.sha512
	gpg --detach-sign --armor checksums.sha512

dev: ## Build for dev
	$(UV) build

shell: ## Generate the shell autocompletion
	_GHAS_CLI_COMPLETE=source_bash ghas-cli > ghas-cli-complete.sh || true

help:
	@awk -F ':|##' '/^[^\t].+?:.*?##/ { printf "\033[36m%-30s\033[0m %s\n", $$1, $$NF }' $(MAKEFILE_LIST) | sort


.PHONY: help
