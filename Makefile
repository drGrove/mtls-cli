.PHONY: setup env clean lint build test
SHELL := /bin/bash
PIP_ENV:=$(shell pipenv --venv)
ROOT_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
DESTDIR ?= ~/.local/bin/

setup: set-hooks
	@pipenv install --dev
	@pipenv run easy_install PyInstaller==3.4

pipenv-lock:
	@pipenv update
	@pipenv lock -r > requirements.txt

set-hooks:
	@echo "Setting commit hooks"
	@ ([ ! -L ".git/hooks/pre-commit" ] && \
		ln -s $(PWD)/scripts/git-hooks/pre-commit.sh .git/hooks/pre-commit) \
		|| true

install: build
	@mkdir -p $(DESTDIR)
	@echo "Copying mtls/mtls to $(DESTDIR), Please ensure you have $(DESTDIR) in your PATH"
	@cp mtls/mtls $(DESTDIR)

lint:
	@pipenv run pycodestyle --first ./mtls.py

build: setup
	@pipenv run pyinstaller --onefile ./mtls.spec

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
	@tar -zcvf mtls-$$(git describe --tags `git rev-list --tags --max-count=1`).tar.gz mtls

clean:
	@rm -r build dist $(PIP_ENV)
