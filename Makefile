.PHONY: setup env clean lint build test
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

shell:
	@pipenv shell

setup: set-hooks
	@pipenv --three install --dev
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
	@cp mtls-$(UNAME)/mtls $(DESTDIR)

format:
	@pipenv run black -l 79 ./mtls/*.py
	@pipenv run black -l 79 ./test/*.py

lint:
	@pipenv run pycodestyle **/*.py

build-develop:
	@pipenv run python setup.py develop

build-pyinstaller-binary:
	@pipenv run pyinstaller --onefile --distpath=mtls-$(UNAME) mtls.spec

build-pypi:
	@pipenv run python setup.py sdist bdist_wheel

build: setup
	@pipenv run python setup.py build

run:
	@pipenv run python3 bin/mtls $(ARGS)

run-build:
	@./mtls-$(UNAME)/mtls $(ARGS)

test: setup
	-@$(PIP_ENV)/bin/coverage run -m unittest -v

test-by-name:
	-@$(PIP_ENV)/bin/coverage run -m unittest $(TEST) -v

coverage:
	@$(PIP_ENV)/bin/coverage report -m

coveralls:
	@$(PIP_ENV)/bin/coveralls


pkg: build-pyinstaller-binary
	@echo "Generating sha256sum of Binary"
	@shasum -a256 mtls-$(UNAME)/mtls > mtls-$(UNAME)/mtls.sha256sum
ifeq ($(SIGN), 1)
	@echo "Signing binary"
	@gpg --sign --detach-sign --output mtls-$(UNAME)/mtls.sig mtls-$(UNAME)/mtls
endif
	@tar -zcvf mtls-$(UNAME)-$(VERSION).tar.gz mtls-$(UNAME)

pkg-pypi: build
	@pipenv run python setup.py sdist bdist_wheel

clean:
	@rm -r build dist $(PIP_ENV) mtls-$(UNAME)
