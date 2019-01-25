.PHONY: setup env clean lint build
SHELL := /bin/bash
PIP_ENV := $(shell pipenv --venv)

setup: set-hooks
	@pipenv update
	@pipenv install --dev
	@pipenv lock -r > requirements.txt


set-hooks:
	@echo "Setting commit hooks"
	@ ([ ! -L ".git/hooks/pre-commit" ] && ln -s $(PWD)/scripts/git-hooks/pre-commit.sh .git/hooks/pre-commit) || true

install:
	@$(PIP_ENV)/bin/pip install -r requirements.txt
	@$(PIP_ENV)/bin/easy_install PyInstaller==3.4

lint:
	@$(PIP_ENV)/bin/pycodestyle --first mtls.py

build:
	@$(PIP_ENV)/bin/pyinstaller --onefile mtls.spec

run:
	@$(PIP_ENV)/bin/python mtls.py -s $(SERVER)

clean:
	@rm -r build dist
