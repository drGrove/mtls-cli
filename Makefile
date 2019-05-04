.PHONY: setup env clean lint build test
SHELL := /bin/bash
PIP_ENV := $(shell pipenv --venv)
ROOT_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

setup:
	@pipenv install
	@pipenv run easy_install pyinstaller==3.4

setup-dev: set-hooks
	@pipenv install --dev
	@pipenv run easy_install pyinstaller==3.4

pipenv-lock:
	@pipenv update
	@pipenv lock -r > requirements.txt

set-hooks:
	@echo "Setting commit hooks"
	@ ([ ! -L ".git/hooks/pre-commit" ] && \
		ln -s $(PWD)/scripts/git-hooks/pre-commit.sh .git/hooks/pre-commit) \
		|| true

install:
	@pipenv run pip3 install -r requirements.txt

install-bin: build
	@mkdir -p ~/.local/bin
	@echo "Copying mtls/mtls to ~/.local/bin, Please ensure you have ~/.local/bin in your PATH"
	@cp mtls/mtls ~/.local/bin/

lint:
	@$(PIP_ENV)/bin/pycodestyle --first mtls.py

build:
	@$(PIP_ENV)/bin/pyinstaller --onefile mtls.spec

run:
	@$(PIP_ENV)/bin/python3 cli.py $(ARGS)

test:
	@$(PIP_ENV)/bin/coverage run -m unittest -v

test-by-name:
	@$(PIP_ENV)/bin/coverage run -m unittest $(TEST) -v

coverage:
	@$(PIP_ENV)/bin/coverage report -m

coveralls:
	@$(PIP_ENV)/bin/coveralls


pkg: build
	@echo "Generating sha256sum of Binary"
	@sha256sum mtls/mtls > mtls/mtls.sha256sum
	@echo "Signing binary"
	@gpg --sign --detach-sign --output mtls/mtls.sig mtls/mtls

clean:
	@rm -r build dist $(PIP_ENV)
