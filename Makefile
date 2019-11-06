SHELL := /bin/bash
PIP_ENV:=$(shell pipenv --venv)
ROOT_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
DESTDIR ?= ~/.local/bin/
SIGN := 1
VERSION := $(shell pipenv run python3 setup.py --version)

ifeq ($(OS),Windows_NT)
    UNAME := Windows
else
    UNAME := $(shell uname -s)
endif

.PHONY: shell
shell:
	@pipenv shell

.PHONY: setup
setup: set-hooks
	@pipenv sync --dev

.PHONY: pipenv-lock
pipenv-lock:
	@pipenv update
	@pipenv lock -r > requirements.txt

.PHONY: set-hooks
set-hooks:
	@echo "Setting commit hooks"
	@ ([ ! -L ".git/hooks/pre-commit" ] && \
		ln -s $(PWD)/scripts/git-hooks/pre-commit.sh .git/hooks/pre-commit) \
		|| true

.PHONY: format
format:
	@pipenv run black -l 79 ./mtls/*.py
	@pipenv run black -l 79 ./test/*.py

.PHONY: lint
lint:
	@pipenv run pycodestyle **/*.py

.PHONY: build-develop
build-develop:
	@pipenv run python setup.py develop

.PHONY: build-pypi
build-pypi:
	@pipenv run python setup.py sdist bdist_wheel

.PHONY: build
build: setup
	@pipenv run python setup.py build

.PHONY: run
run:
	@pipenv run python3 bin/mtls $(ARGS)

.PHONY: test
test: setup
	-@$(PIP_ENV)/bin/coverage run -m unittest -v

.PHONY: test-by-name
test-by-name:
	-@$(PIP_ENV)/bin/coverage run -m unittest $(TEST) -v

.PHONY: coverage
coverage:
	@$(PIP_ENV)/bin/coverage report -m

.PHONY: coveralls
coveralls:
	@$(PIP_ENV)/bin/coveralls

.PHONY: pkg
pkg: build
	@pipenv run python setup.py sdist bdist_wheel

.PHONY: clean
clean:
	@rm -r build dist $(PIP_ENV) mtls-$(UNAME)
