.PHONY: setup env clean lint build test
SHELL := /bin/bash
PIP_ENV:=$(shell pipenv --venv)
ROOT_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
DESTDIR ?= ~/.local/bin/
SIGN := 1

ifeq ($(OS),Windows_NT)
    UNAME := Windows
else
    UNAME := $(shell uname -s)
endif

setup: set-hooks
	@pipenv --three install --dev
	@pipenv run easy_install PyInstaller==3.4
	@./scripts/get_build_version.sh > VERSION

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
	@cp mtls-$(UNAME)/mtls $(DESTDIR)

lint:
	@pipenv run pycodestyle --first ./mtls.py

build: setup
	@./scripts/get_build_version.sh > VERSION
	@pipenv run pyinstaller --onefile --distpath=mtls-$(UNAME) mtls.spec

run:
	@$(PIP_ENV)/bin/python3 cli.py $(ARGS)

run-build:
	@./mtls-$(UNAME)/mtls $(ARGS)

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
ifeq ($(UNAME), "Darwin")
	@shasum -a256 mtls-$(UNAME)/mtls > mtls-$(UNAME)/mtls.sha256sum
else
	@sha256sum mtls-$(UNAME)/mtls > mtls-$(UNAME)/mtls.sha256sum
endif
ifeq ($(SIGN), 1)
	@echo "Signing binary"
	@gpg --sign --detach-sign --output mtls-$(UNAME)/mtls.sig mtls-$(UNAME)/mtls
endif
	@tar -zcvf mtls-$(UNAME)-$$(git describe --tags `git rev-list --tags --max-count=1`).tar.gz mtls-$(UNAME)

clean:
	@rm -r build dist $(PIP_ENV) mtls-$(UNAME)
