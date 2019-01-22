.PHONY: setup env clean lint build
SHELL := /bin/bash

setup: set-hooks
	@ ([ ! -d "env" ] && python3 -m virtualenv env) || true

set-hooks:
	@echo "Setting commit hooks"
	@ ([ ! -L ".git/hooks/pre-commit" ] && ln -s $(PWD)/scripts/git-hooks/pre-commit.sh .git/hooks/pre-commit) || true

install:
	@pip install -r requirements.txt

env:
	@source env/bin/activate

lint:
	@pycodestyle --first mtls.py

build:
	./env/bin/pyinstaller --onefile mtls.spec

clean:
	@rm -r env build dist mtls.spec
